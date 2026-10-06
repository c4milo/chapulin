// RSA-PSS signing on 64-bit limbs, which a host object holds beside
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
// The branches this file compiles to are loops over limb counts, the
// sixteen table entries, the four squarings and the exponent's digits,
// whose count comes from the exponent's length in bytes, the CH_ASSERTs
// on a key's public length, and the two verdicts a caller sees anyway:
// whether the key is one the file signs with, and whether the signature
// passed its check.
#include "rsa_sign64.h"

#ifdef CH_CPU_RUNTIME

#include <string.h>

#include "ch_assert.h"
#include "ct.h"

// The bits of the exponent one step reads, and the powers the table holds
// for them.
#define WINDOW_BITS 4
#define TABLE_ENTRIES 16

_Static_assert(TABLE_ENTRIES == 1 << WINDOW_BITS,
               "the table holds one power for each window value");

// The limbs of one prime: half the modulus's bytes, in limbs of 8.
#define PRIME_LIMBS_MAX ((CH_RSA_MODULUS_MAX / 2 + 7) / 8)

// The base's powers 0 to 15, each in the Montgomery domain of one prime.
// It is a struct so that the read below can take it as a pointer to
// const: C has no such conversion for an array of arrays.
typedef struct {
    uint64_t powers[TABLE_ENTRIES][PRIME_LIMBS_MAX];
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
// the limbs it has, so the loop writes no zeros to o first and o may hold
// any limbs when it starts. The first form wrote the zeros in a loop of
// their own, which clang compiled to a call to the C library's fill. The
// digit was computed before that call and read after it, so clang for
// arm64 kept it in a register a callee saves, and the multiplication
// after the read saved that register in its frame: four bits of the
// exponent in a dead frame, which no wipe names. This function now calls
// nothing, and its loop over the limbs is neither a fill nor a copy, the
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
    // The limb ends on zero and not on the last entry's mask, which says
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
    size_t k = mod->limbs;
    CH_ASSERT(k >= 1 && k <= PRIME_LIMBS_MAX);
    // Zeroed at declaration, as rsa_mont64_public's arrays are: the limbs
    // past k are never read.
    power_table table = {0};
    uint64_t pick[PRIME_LIMBS_MAX] = {0};

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
// record: the base of one half of a signature. em is em_limbs limbs, the
// encoded message, which is twice as long as the prime.
//
// With k the prime's limb count and R = 2^(64k), em = high * R + low,
// where low is its k low limbs and high the limbs above them, k of them
// or k - 1. A multiplication divides by R, so high times R^3 is
// high * R^2 and low times R^2 is low * R, each below the prime, and
// their sum modulo the prime is em * R: em in the domain. Neither product
// needs its first operand below the prime, only its second, which r2 and
// r3 are.
static void message_mod_prime(uint64_t *o, const uint64_t *em, size_t em_limbs,
                              const rsa_mont64_modulus *mod) {
    size_t k = mod->limbs;
    uint64_t low[PRIME_LIMBS_MAX];
    uint64_t high[PRIME_LIMBS_MAX];
    uint64_t r3[PRIME_LIMBS_MAX];
    for (size_t i = 0; i < k; i++) {
        low[i] = em[i];
        high[i] = 0;
    }
    for (size_t i = k; i < em_limbs; i++) {
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
// and s takes 2k plain limbs for primes of k limbs. s is below p * q,
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
    size_t k = mod_p->limbs;
    uint64_t t[PRIME_LIMBS_MAX];
    uint64_t h[PRIME_LIMBS_MAX];
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

int rsa_sign64_key_ok(const ch_rsa_priv *k) {
    if (!rsa_pss_sign_key_ok(k)) {
        return 0;
    }
    size_t half_len = k->n_len / 2;
    size_t limbs = (half_len + 7) >> 3;
    uint64_t p[PRIME_LIMBS_MAX];
    uint64_t q[PRIME_LIMBS_MAX];
    const uint64_t zero[PRIME_LIMBS_MAX] = {0};
    uint64_t product[2 * PRIME_LIMBS_MAX];
    uint64_t n[2 * PRIME_LIMBS_MAX];
    rsa_mont64_from_bytes(p, limbs, k->p, half_len);
    rsa_mont64_from_bytes(q, limbs, k->q, half_len);
    rsa_mont64_mul_add(product, p, q, zero, limbs);
    rsa_mont64_from_bytes(n, 2 * limbs, k->n, k->n_len);
    // Every limb is read whatever the values are, and the one thing that
    // leaves is whether they all matched, which the caller sees as the
    // key being refused.
    uint64_t differ = 0;
    for (size_t i = 0; i < 2 * limbs; i++) {
        differ |= product[i] ^ n[i];
    }
    ct_wipe(p, sizeof p);
    ct_wipe(q, sizeof q);
    ct_wipe(product, sizeof product);
    return differ == 0;
}

// Whether candidate^65537 mod n is em: the check a signature passes
// before it leaves. A candidate that fails it differs from the signature
// modulo one prime and not the other, and one such value factors n, so
// the power is computed by rsa_mont64_public, which is constant time in
// its base, compared by ct_memeq and wiped.
static int signature_verifies(const ch_rsa_priv *k, const uint8_t *em, const uint8_t *candidate) {
    rsa_mont64_modulus mod;
    uint8_t power[CH_RSA_MODULUS_MAX];
    // rsa_pss_sign_key_ok admits a modulus with its top bit set and no
    // other, so its bit length is 8 * n_len.
    rsa_mont64_modulus_init(&mod, k->n, k->n_len, 8 * k->n_len);
    rsa_mont64_public(power, candidate, k->n_len, &mod);
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
static int write_if_verified(const ch_rsa_priv *k, const uint8_t *em, const uint8_t *candidate,
                             uint8_t *sig) {
    int verified = signature_verifies(k, em, candidate);
    if (verified) {
        memcpy(sig, candidate, k->n_len);
    }
    return verified;
}

int rsa_sign64_sp1(const ch_rsa_priv *k, const uint8_t *em, uint8_t *sig) {
    CH_ASSERT(k->n_len >= 256 && k->n_len <= CH_RSA_MODULUS_MAX && (k->n_len & 7) == 0);
    size_t half_len = k->n_len / 2;
    size_t em_limbs = k->n_len / 8;
    rsa_mont64_modulus mod_p;
    rsa_mont64_modulus mod_q;
    uint64_t em_plain[RSA_MONT64_LIMBS_MAX];
    uint64_t m1[PRIME_LIMBS_MAX];
    uint64_t m2[PRIME_LIMBS_MAX];
    // Zeroed at declaration: the limbs past twice the primes' are never
    // written, and rsa_mont64_to_bytes reads none of them.
    uint64_t s[2 * PRIME_LIMBS_MAX] = {0};
    uint8_t candidate[CH_RSA_MODULUS_MAX];

    // rsa_sign64_key_ok admits primes whose product is the modulus. The
    // modulus is odd and has its top bit, so each prime is odd and has
    // its own top bit: the bit length of each is 8 * half_len.
    rsa_mont64_modulus_init(&mod_p, k->p, half_len, 8 * half_len);
    rsa_mont64_modulus_init(&mod_q, k->q, half_len, 8 * half_len);
    rsa_mont64_from_bytes(em_plain, em_limbs, em, k->n_len);

    // The two halves: the message modulo each prime, raised to dp and dq.
    message_mod_prime(m1, em_plain, em_limbs, &mod_p);
    rsa_sign64_power(m1, m1, k->dp, half_len, &mod_p);
    message_mod_prime(m2, em_plain, em_limbs, &mod_q);
    rsa_sign64_power(m2, m2, k->dq, half_len, &mod_q);
    crt_combine(s, m1, m2, k->qinv, half_len, &mod_p, &mod_q);
    rsa_mont64_to_bytes(candidate, k->n_len, s);

    // The check, and the signature written only when it passed. Every
    // array below is wiped on either verdict: a candidate that failed is
    // as secret as a prime.
    int verified = write_if_verified(k, em, candidate, sig);

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
// and the rename gives its entry this file's name.
#define CH_RSA_SIGN64 1
#define rsa_pss_sign rsa_sign64_pss
#include "rsa_sign.c"

#endif // CH_CPU_RUNTIME
