// RSA-PSS signing on 64-bit words, which a host object holds beside
// rsa_sign.c's ladder (rsa_sign64.h): RSASP1 (RFC 8017 5.2.1) by the
// Chinese remainder theorem, as two fixed-window exponentiations over
// rsa_mont64.c's Montgomery arithmetic, one for each prime, constant time
// in every integer of the key. rsa_sign64.h states what that claim covers
// and what it does not.
//
// The window is four bits: one hexadecimal digit of the exponent a step,
// the high half of each byte and then the low half, so reading it is a
// shift and a mask of one byte. A table holds the base's powers 0 to 15.
// A step squares four times, reads the table entry the digit names and
// multiplies by it. The entry for digit 0 is 1, so a zero digit runs the
// same multiplication as any other.
//
// The two halves are joined by Garner's formula, s = m2 + q * h with
// h = qinv * (m1 - m2) mod p, and the signature is raised to the public
// exponent and compared with the encoded message before a byte of it is
// written (RFC 8017 5.2.1 note, and Boneh, DeMillo and Lipton's attack on
// a CRT signature computed with a fault). A signature that fails the
// comparison is not returned.
//
// On x86-64, a session whose ch_cfg.cpu holds CH_CPU_AVX512_IFMA beside
// CH_CPU_CONSTANT_TIME_MULTIPLY runs the two exponentiations on
// rsa_ifma_sign.c's AVX-512 IFMA kernel, side by side, and the check on
// rsa_ifma.c's public operation through rsa_vp1_cpu (docs/decisions.md
// 120). After each of the two calls, the function that made it wipes the
// stack below its frame and the vector and mask registers, where the
// compiler keeps what no wipe in C names. Every other session runs the
// window below and checks on rsa_mont64_public.
//
// The branches this file compiles to are loops over word counts, the
// sixteen table entries, the four squarings and the exponent's digits,
// whose count comes from the exponent's length in bytes, the CH_ASSERTs
// on a key's public length, the test of the session's ch_cfg.cpu, which
// the caller states, and the two verdicts a caller sees anyway: whether
// the key is one the file signs with, and whether the signature passed
// its check.
#include "rsa_sign64.h"

#ifdef CH_CPU_RUNTIME

#include <string.h>

#include "ch_assert.h"
#include "cpu_cfg.h"
#include "ct.h"

// rsa_ifma_sign.h's declarations exist in an x86-64 host object and in a
// test unit that defines CH_RSA_IFMA_MODEL, which runs the kernel over a
// scalar model of each instruction. The IFMA path compiles under the same
// condition. avx512_wipe.h's exists on x86-64 alone, and the model leaves
// nothing in a vector register, so a model build does not call it.
#if defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL)
#include "rsa_ifma_sign.h"
#define RSA_SIGN64_IFMA 1
#endif
#if defined(__x86_64__) && !defined(CH_RSA_IFMA_MODEL)
#include "avx512_wipe.h"
#endif

// The bits of the exponent one step reads, and the powers the table holds
// for them.
#define WINDOW_BITS 4
#define TABLE_ENTRIES 16

_Static_assert(TABLE_ENTRIES == 1 << WINDOW_BITS,
               "the table holds one power for each window value");

// The words of one prime: half the modulus's bytes, in words of 8.
#define PRIME_WORDS_MAX ((CH_RSA_MODULUS_MAX / 2 + 7) / 8)

// The base's powers 0 to 15, each in the Montgomery domain of one prime.
// It is a struct so that the read below can take it as a pointer to
// const: C has no such conversion for an array of arrays.
typedef struct {
    uint64_t powers[TABLE_ENTRIES][PRIME_WORDS_MAX];
} power_table;

// All ones when bit is 1, all zeros when bit is 0, in the form
// rsa_mont64.c's mask_of_bit takes and for its reason.
static uint64_t mask_of_bit(uint64_t bit) {
    return (uint64_t)((int64_t)(bit << 63) >> 63);
}

// o = the table's power at index, for an index below TABLE_ENTRIES, with
// no memory index that comes from it: the loop reads every entry and a
// mask keeps the one at index. The exclusive or of the two positions is
// below 16, so adding 15 to it carries into bit 4 exactly when they
// differ.
//
// Under an all-ones mask o takes the entry and under a zero mask it keeps
// the words it has, so the loop writes no zeros to o first and o may hold
// any words when it starts. The first form wrote the zeros in a loop of
// their own, which clang compiled to a call to the C library's fill. The
// digit was computed before that call and read after it, so clang for
// arm64 kept it in a register a callee saves, and the multiplication
// after the read saved that register in its frame: four bits of the
// exponent in a dead frame, which no wipe names. This function now calls
// nothing, and its loop over the words is neither a fill nor a copy, the
// two loops a compiler replaces with a call. bin/rsa_sign_equiv_test
// requires one stack after two exponents
// (test/rsa_sign_equiv_differential.h).
//
// The mask is all ones at one entry and zero at the others, and a
// compiler that sees how it was computed knows which. clang for x86-64
// compiled this loop to a comparison of the two positions, a branch on
// it, and a read of the one entry that matched: a branch and a memory
// access that follow a digit of the exponent. So each mask is written
// through a volatile pointer and read back before it is used. The value
// read back is one the compiler knows nothing about, so the loop reads
// every entry and ands it with that value, whatever it is.
static void table_select(uint64_t *o, const power_table *table, uint64_t index, size_t k) {
    uint64_t kept = 0;
    volatile uint64_t *hidden = &kept;
    for (uint64_t entry = 0; entry < TABLE_ENTRIES; entry++) {
        uint64_t differ = ((entry ^ index) + (TABLE_ENTRIES - 1)) >> WINDOW_BITS;
        *hidden = mask_of_bit(differ ^ 1);
        uint64_t mask = *hidden;
        for (size_t i = 0; i < k; i++) {
            o[i] = (o[i] & ~mask) | (table->powers[entry][i] & mask);
        }
    }
    // The word ends on zero and not on the last entry's mask, which says
    // whether the digit was the last index. The write goes through the
    // volatile pointer, so no compiler may drop it.
    *hidden = 0;
}

// Digit i of the e_len-byte exponent e, counted from the most significant:
// the high half of byte i / 2 for an even i and the low half for an odd
// one.
static uint64_t exponent_digit(const uint8_t *e, size_t i) {
    return ((uint64_t)e[i >> 1] >> (WINDOW_BITS * (1 - (i & 1)))) & (TABLE_ENTRIES - 1);
}

void rsa_sign64_power(uint64_t *o, const uint64_t *base, const uint8_t *e, size_t e_len,
                      const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    CH_ASSERT(k >= 1 && k <= PRIME_WORDS_MAX);
    // Zeroed at declaration, as rsa_mont64_public's arrays are: the words
    // past k are never read.
    power_table table = {0};
    uint64_t pick[PRIME_WORDS_MAX] = {0};

    // powers[i] = base^i in the domain. 1 in the domain is R mod m, which
    // one multiplication of the plain 1 by r2 gives.
    pick[0] = 1;
    rsa_mont64_mont_mul(table.powers[0], pick, mod->r2, mod);
    memcpy(table.powers[1], base, k * sizeof(uint64_t));
    for (size_t i = 2; i < TABLE_ENTRIES; i++) {
        rsa_mont64_mont_mul(table.powers[i], table.powers[i - 1], base, mod);
    }

    // The running power starts at 1. Each step raises it to the 16th
    // power and multiplies by the base to the digit: two steps for each
    // byte of e, so the step count is a function of e_len alone.
    memcpy(o, table.powers[0], k * sizeof(uint64_t));
    for (size_t i = 0; i < 2 * e_len; i++) {
        for (int square = 0; square < WINDOW_BITS; square++) {
            rsa_mont64_mont_square(o, o, mod);
        }
        table_select(pick, &table, exponent_digit(e, i), k);
        rsa_mont64_mont_mul(o, o, pick, mod);
    }
    ct_wipe(&table, sizeof table);
    ct_wipe(pick, sizeof pick);
}

// o = em mod the prime, in the Montgomery domain of mod, the prime's
// record: the base of one half of a signature. em is em_words words, the
// encoded message, which is twice as long as the prime.
//
// With k the prime's word count and R = 2^(64k), em = high * R + low,
// where low is its k low words and high the words above them, k of them
// or k - 1. A multiplication divides by R, so high times R^3 is
// high * R^2 and low times R^2 is low * R, each below the prime, and
// their sum modulo the prime is em * R: em in the domain. Neither product
// needs its first operand below the prime, only its second, which r2 and
// r3 are.
static void message_mod_prime(uint64_t *o, const uint64_t *em, size_t em_words,
                              const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    uint64_t low[PRIME_WORDS_MAX];
    uint64_t high[PRIME_WORDS_MAX];
    uint64_t r3[PRIME_WORDS_MAX];
    for (size_t i = 0; i < k; i++) {
        low[i] = em[i];
        high[i] = 0;
    }
    for (size_t i = k; i < em_words; i++) {
        high[i - k] = em[i];
    }
    rsa_mont64_mont_square(r3, mod->r2, mod);
    rsa_mont64_mont_mul(high, high, r3, mod);
    rsa_mont64_mont_mul(low, low, mod->r2, mod);
    rsa_mont64_add(o, low, high, mod);
    ct_wipe(low, sizeof low);
    ct_wipe(high, sizeof high);
    ct_wipe(r3, sizeof r3);
}

// Garner's formula: s = m2 + q * h, with h = qinv * (m1 - m2) mod p. m1
// and m2 are the two halves, each in the Montgomery domain of its prime,
// and s takes 2k plain words for primes of k words. s is below p * q,
// because m2 is below q and h is below p.
//
// No step tests a value. m2 leaves q's domain by a multiplication with
// the plain 1. It is below q, and q is below twice p, because the two
// primes have the same length and p has its top bit; so one subtraction
// of p, chosen by a mask, reduces it modulo p. The difference m1 - m2 is
// taken in p's domain and adds p back under a mask when it borrowed. The
// product by the plain qinv leaves the domain, so h is plain and below p.
// m1 and m2 are overwritten.
static void crt_combine(uint64_t *s, uint64_t *m1, uint64_t *m2, const uint8_t *qinv,
                        size_t half_len, const rsa_mont64_modulus *mod_p,
                        const rsa_mont64_modulus *mod_q) {
    size_t k = mod_p->words;
    uint64_t t[PRIME_WORDS_MAX];
    uint64_t h[PRIME_WORDS_MAX];
    for (size_t i = 0; i < k; i++) {
        t[i] = 0;
    }
    t[0] = 1;
    rsa_mont64_mont_mul(m2, t, m2, mod_q);

    rsa_mont64_reduce_once(t, m2, mod_p);
    rsa_mont64_mont_mul(t, t, mod_p->r2, mod_p);
    rsa_mont64_sub(m1, m1, t, mod_p);
    rsa_mont64_from_bytes(t, k, qinv, half_len);
    rsa_mont64_mont_mul(h, t, m1, mod_p);

    rsa_mont64_mul_add(s, mod_q->m, h, m2, k);
    ct_wipe(t, sizeof t);
    ct_wipe(h, sizeof h);
}

#ifdef RSA_SIGN64_IFMA
// Whether a signature runs on AVX-512 IFMA: where cpu, the session's
// ch_cfg.cpu, holds both CH_CPU_AVX512_IFMA, which says the CPU has the
// instructions, and CH_CPU_CONSTANT_TIME_MULTIPLY, whose statement covers
// their 52-bit products (cpu_cfg.h). The caller sets both from its own
// probe of the CPU; chapulin probes none.
static int use_ifma(uint32_t cpu) {
    uint32_t both = CH_CPU_AVX512_IFMA | CH_CPU_CONSTANT_TIME_MULTIPLY;
    return (cpu & both) == both;
}

// Zeros the vector and mask registers, which hold what the last IFMA
// product left in them: avx512_wipe_registers on the instructions. Over
// the model the lanes are words in memory and general registers, and no
// vector register holds them.
static void wipe_vector_registers(void) {
#ifndef CH_RSA_IFMA_MODEL
    avx512_wipe_registers();
#endif
}
#endif

int rsa_sign64_key_ok(const ch_rsa_priv *k) {
    if (!rsa_pss_sign_key_ok(k)) {
        return 0;
    }
    size_t half_len = k->n_len / 2;
    size_t words = (half_len + 7) >> 3;
    uint64_t p[PRIME_WORDS_MAX];
    uint64_t q[PRIME_WORDS_MAX];
    const uint64_t zero[PRIME_WORDS_MAX] = {0};
    uint64_t product[2 * PRIME_WORDS_MAX];
    uint64_t n[2 * PRIME_WORDS_MAX];
    rsa_mont64_from_bytes(p, words, k->p, half_len);
    rsa_mont64_from_bytes(q, words, k->q, half_len);
    rsa_mont64_mul_add(product, p, q, zero, words);
    rsa_mont64_from_bytes(n, 2 * words, k->n, k->n_len);
    // Every word is read whatever the values are, and the one thing that
    // leaves is whether they all matched, which the caller sees as the
    // key being refused.
    uint64_t differ = 0;
    for (size_t i = 0; i < 2 * words; i++) {
        differ |= product[i] ^ n[i];
    }
    ct_wipe(p, sizeof p);
    ct_wipe(q, sizeof q);
    ct_wipe(product, sizeof product);
    return differ == 0;
}

// power = candidate^65537 mod n, the power the check compares. Where cpu
// names IFMA it runs on rsa_ifma.c through rsa_vp1_cpu, which takes every
// modulus rsa_sign64_key_ok admits: odd, of 32 words or more, with its
// top bit set. Its frames hold the candidate in digits and slots of the
// compiler's own, and its registers the last product, so the stack under
// this frame and the registers are wiped after it. Every other value runs
// rsa_mont64_public. Both are constant time in their base.
static void check_power(uint32_t cpu, const ch_rsa_priv *k, const uint8_t *candidate,
                        uint8_t *power) {
#ifdef RSA_SIGN64_IFMA
    if (use_ifma(cpu)) {
        rsa_vp1_cpu(cpu, k->n, k->n_len, candidate, power);
        rsa_ifma_sign_wipe_below();
        wipe_vector_registers();
        return;
    }
#else
    // arm64 has no such kernel, so no bit picks here.
    (void)cpu;
#endif
    rsa_mont64_modulus mod;
    // rsa_pss_sign_key_ok admits a modulus with its top bit set and no
    // other, so its bit length is 8 * n_len.
    rsa_mont64_modulus_init(&mod, k->n, k->n_len, 8 * k->n_len);
    rsa_mont64_public(power, candidate, k->n_len, &mod);
}

// Whether candidate^65537 mod n is em: the check a signature passes
// before it leaves. A candidate that fails it differs from the signature
// modulo one prime and not the other, and one such value factors n, so
// the power is computed in constant time in its base (check_power),
// compared by ct_memeq and wiped.
static int signature_verifies(uint32_t cpu, const ch_rsa_priv *k, const uint8_t *em,
                              const uint8_t *candidate) {
    uint8_t power[CH_RSA_MODULUS_MAX];
    check_power(cpu, k, candidate, power);
    int same = ct_memeq(power, em, k->n_len) != 0;
    ct_wipe(power, sizeof power);
    return same;
}

// sig = candidate when candidate passes signature_verifies, and no byte
// of sig when it fails. Returns 1 when it wrote. This is the one place
// the file writes a signature, so the check and the copy are one
// function, and proof/rsa_sign64_crt_harness.c proves that sig keeps
// every byte it held unless the power was em. The verdict is what the
// caller sees, so the branch on it tells nothing more.
static int write_if_verified(uint32_t cpu, const ch_rsa_priv *k, const uint8_t *em,
                             const uint8_t *candidate, uint8_t *sig) {
    int verified = signature_verifies(cpu, k, em, candidate);
    if (verified) {
        memcpy(sig, candidate, k->n_len);
    }
    return verified;
}

// m1 = m1^dp mod p and m2 = m2^dq mod q, each in its prime's Montgomery
// domain. Where cpu names IFMA the two run side by side on
// rsa_ifma_sign.c, and the stack under this frame and the registers are
// wiped after the call: the kernel's frames lay there, with the slots the
// compiler kept words and 512-bit registers in (rsa_ifma_sign.h). Every
// other value runs the window above, once for each prime.
static void both_powers(uint32_t cpu, uint64_t *m1, uint64_t *m2, const ch_rsa_priv *k,
                        size_t half_len, const rsa_mont64_modulus *mod_p,
                        const rsa_mont64_modulus *mod_q) {
#ifdef RSA_SIGN64_IFMA
    if (use_ifma(cpu)) {
        rsa_ifma_sign_power_pair(m1, m1, k->dp, mod_p, m2, m2, k->dq, mod_q, half_len);
        rsa_ifma_sign_wipe_below();
        wipe_vector_registers();
        return;
    }
#else
    // arm64 has no such kernel, so no bit picks here.
    (void)cpu;
#endif
    rsa_sign64_power(m1, m1, k->dp, half_len, mod_p);
    rsa_sign64_power(m2, m2, k->dq, half_len, mod_q);
}

int rsa_sign64_sp1(uint32_t cpu, const ch_rsa_priv *k, const uint8_t *em, uint8_t *sig) {
    CH_ASSERT(k->n_len >= 256 && k->n_len <= CH_RSA_MODULUS_MAX && (k->n_len & 7) == 0);
    size_t half_len = k->n_len / 2;
    size_t em_words = k->n_len / 8;
    rsa_mont64_modulus mod_p;
    rsa_mont64_modulus mod_q;
    uint64_t em_plain[RSA_MONT64_WORDS_MAX];
    uint64_t m1[PRIME_WORDS_MAX];
    uint64_t m2[PRIME_WORDS_MAX];
    // Zeroed at declaration: the words past twice the primes' are never
    // written, and rsa_mont64_to_bytes reads none of them.
    uint64_t s[2 * PRIME_WORDS_MAX] = {0};
    uint8_t candidate[CH_RSA_MODULUS_MAX];

    // rsa_sign64_key_ok admits primes whose product is the modulus. The
    // modulus is odd and has its top bit, so each prime is odd and has
    // its own top bit: the bit length of each is 8 * half_len.
    rsa_mont64_modulus_init(&mod_p, k->p, half_len, 8 * half_len);
    rsa_mont64_modulus_init(&mod_q, k->q, half_len, 8 * half_len);
    rsa_mont64_from_bytes(em_plain, em_words, em, k->n_len);

    // The two halves: the message modulo each prime, raised to dp and dq.
    message_mod_prime(m1, em_plain, em_words, &mod_p);
    message_mod_prime(m2, em_plain, em_words, &mod_q);
    both_powers(cpu, m1, m2, k, half_len, &mod_p, &mod_q);
    crt_combine(s, m1, m2, k->qinv, half_len, &mod_p, &mod_q);
    rsa_mont64_to_bytes(candidate, k->n_len, s);

    // The check, and the signature written only when it passed. Every
    // array below is wiped on either verdict: a candidate that failed is
    // as secret as a prime.
    int verified = write_if_verified(cpu, k, em, candidate, sig);

    ct_wipe(&mod_p, sizeof mod_p);
    ct_wipe(&mod_q, sizeof mod_q);
    ct_wipe(em_plain, sizeof em_plain);
    ct_wipe(m1, sizeof m1);
    ct_wipe(m2, sizeof m2);
    ct_wipe(s, sizeof s);
    ct_wipe(candidate, sizeof candidate);
    return verified;
}

// The entry, rsa_sign64_pss. rsa_sign.c holds the test of cap and the PSS
// encoder of both signers, so the two cannot differ: under CH_RSA_SIGN64
// it compiles those alone, around rsa_sign64_key_ok and rsa_sign64_sp1,
// and the rename gives its entry this file's name. The entry takes the
// session's ch_cfg.cpu first there, which it hands to rsa_sign64_sp1.
#define CH_RSA_SIGN64 1
#define rsa_pss_sign_cpu rsa_sign64_pss
#include "rsa_sign.c"

#endif // CH_CPU_RUNTIME
