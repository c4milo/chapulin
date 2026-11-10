// RSA modular exponentiation with the fixed public exponent 65537
// (RSAVP1, RFC 8017 5.2.2). Verify only: the modulus, the signature, and
// the result are all public, so the arithmetic is variable time and skips
// the constant-time discipline the secret-handling modules carry. Words
// are little-endian uint32 and every product or carry lives in uint64,
// the same shape as p256.c. Montgomery CIOS multiplication drives a
// square-and-multiply exponentiation; 65537 = 2^16 + 1 costs 16 squares
// and one multiply. Sizes run up to CH_RSA_MODULUS_MAX bytes (rsa_key.h):
// RSA-3072, or RSA-4096 under CH_TRUST_WEBPKI.
//
// That is a device object's rsa_vp1, and the reference. A host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h) compiles the first arm below in its
// place: the same exponentiation on rsa_mont64.c's 64-bit words, in every
// session, because nothing here is secret and so no caller has to state
// the multiply's timing (docs/decisions.md 95). For a modulus whose top
// bit is set, that arm computes no R^2. A long division of its own, in
// rsa_mont_division.h, which branches on the modulus and the signature,
// multiplies the signature by R modulo n (docs/decisions.md 103 and 208).
// bin/rsa_equiv_test compiles both arms into one binary and requires the
// same bytes from each.
//
// The host arm also defines rsa_vp1_cpu, which takes a session's
// ch_cfg.cpu. On x86-64 it hands the public operation to rsa_ifma.h's
// rsa_ifma_public where the value holds CH_CPU_AVX512_IFMA, and else to
// rsa_avx2.h's rsa_avx2_public where it holds CH_CPU_AVX2, with the power
// of two each call needs, which the same division computes. Every other
// session, and every call of rsa_vp1, which takes no value, runs
// rsa_mont64.c (docs/decisions.md 119 and 122).
#include "rsa.h"

#ifdef CH_CPU_RUNTIME

#include <string.h>

#include "cpu_cfg.h"
#include "ct.h"
#include "rsa_mont64.h"
#include "rsa_mont_division.h"

// rsa_ifma.h's declarations exist in an x86-64 host object and in a test
// unit that defines CH_RSA_IFMA_MODEL, test/rsa_ifma_model.c, which runs
// the kernel over a scalar model of each instruction on any host, and
// rsa_avx2.h's in an x86-64 host object and in a test unit that defines
// CH_RSA_AVX2_MODEL, test/rsa_avx2_model.c. The dispatch to each kernel
// compiles under its kernel's condition, and the division that serves
// both under either.
#if defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL)
#include "rsa_ifma.h"
#endif
#if defined(__x86_64__) || defined(CH_RSA_AVX2_MODEL)
#include "rsa_avx2.h"
#endif

// The bit length of the n_len-byte n: the position of its top set bit,
// plus one, and 0 for n == 0, which no caller passes. rsa.c holds the
// same count for emBits; n is public, so both read it byte by byte.
static size_t bit_length(const uint8_t *n, size_t n_len) {
    size_t i = 0;
    while (i < n_len && n[i] == 0) {
        i++;
    }
    if (i == n_len) {
        return 0;
    }
    size_t bits = 8 * (n_len - i);
    uint8_t top = n[i];
    while ((top & 0x80) == 0) {
        bits--;
        top = (uint8_t)(top << 1);
    }
    return bits;
}

// em = sig^65537 mod m (RSAVP1), sig and em both len big-endian bytes, for
// the modulus in mod, of k >= 2 words with its top bit set. It reads
// mod->m, mod->m0inv and mod->words, and never mod->r2.
//
// rsa_mont64_public moves the base into the Montgomery domain with a
// product by R^2 mod m, which costs the setup of R^2 and that product.
// Here rsa_mont_division.h's times_r_mod writes base * R mod m from the
// base, in half the multiplies of one Montgomery product
// (docs/decisions.md 208). The
// rest is rsa_mont64_public's: sixteen squares, and a last product by the
// base itself, outside the domain, which divides by R.
// spec/lean/Spec/RsaDivision.lean proves that the result is sig^65537 mod
// m, as `publicOp_eq`.
static void public_by_division(uint8_t *em, const uint8_t *sig, size_t len,
                               const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    // Zeroed at declaration, as rsa_mont64_public's are.
    uint64_t base[RSA_MONT64_WORDS_MAX] = {0};
    uint64_t acc[RSA_MONT64_WORDS_MAX] = {0};
    rsa_mont64_from_bytes(base, k, sig, len);
    // The division needs a base below m. The base is below R and m is at
    // least R / 2, so one subtraction of m gives it.
    rsa_mont64_reduce_once(base, base, mod);
    memcpy(acc, base, k * sizeof(uint64_t));
    times_r_mod(acc, mod->m, k);
    for (int i = 0; i < 16; i++) {
        rsa_mont64_mont_square(acc, acc, mod);
    }
    rsa_mont64_mont_mul(acc, base, acc, mod);
    rsa_mont64_to_bytes(em, len, acc);
}

// A modulus whose top word has its top bit set, as every RSA key's does,
// takes the public operation by the division. Any other modulus
// takes rsa_mont64_modulus_init and rsa_mont64_public. That setup doubles
// 2k + 1 times and squares five times, in a time that depends on the
// modulus's length alone, which the signer needs for its secret primes
// and the verifier does not (docs/decisions.md 103).
void rsa_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em) {
    rsa_mont64_modulus mod;
    size_t k = (n_len + 7) / 8;
    size_t bits = bit_length(n, n_len);
    if (k >= 2 && bits == 64 * k) {
        rsa_mont64_modulus_load(&mod, n, n_len);
        public_by_division(em, sig, n_len, &mod);
        return;
    }
    rsa_mont64_modulus_init(&mod, n, n_len, bits);
    rsa_mont64_public(em, sig, n_len, &mod);
}

#if defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL)
// Whether rsa_vp1_cpu hands the public operation to rsa_ifma_public: where
// cpu, the session's ch_cfg.cpu, holds CH_CPU_AVX512_IFMA, which the
// caller sets from its own probe of the CPU. chapulin probes no CPU
// (docs/decisions.md 89).
static int use_ifma(uint32_t cpu) {
    return (cpu & CH_CPU_AVX512_IFMA) != 0;
}
#endif

#if defined(__x86_64__) || defined(CH_RSA_AVX2_MODEL)
// Whether rsa_vp1_cpu hands the public operation to rsa_avx2_public, where
// the IFMA kernel does not take it: where cpu holds CH_CPU_AVX2. Every
// x86-64 CPU with AVX-512 IFMA has AVX2, and the IFMA kernel ran an
// RSA-2048 verification in less time on each runner that had both
// (docs/decisions.md 122).
static int use_avx2(uint32_t cpu) {
    return (cpu & CH_CPU_AVX2) != 0;
}
#endif

#if defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL) || defined(CH_RSA_AVX2_MODEL)
// Whether rsa_vp1_cpu may hand the n_len-byte n to a kernel: an odd
// modulus of k = ceil(n_len / 8) words, at least words_min, whose bit
// length is 64k, so its top word's top bit is set.
static int kernel_takes(const uint8_t *n, size_t n_len, size_t words_min) {
    size_t k = (n_len + 7) / 8;
    return k >= words_min && bit_length(n, n_len) == 64 * k && (n[n_len - 1] & 1) == 1;
}

// rem = 2^exponent mod m, for an odd m of k >= 2 words whose top bit is
// set and an exponent of at least 64(k - 1). It writes the k words of rem
// and reads the k words of m.
//
// It starts rem at 2^(64(k - 1) + exponent mod 64), a single bit in rem's
// top word. That is at most 2^(64k - 1), and m is above it, because m has
// that bit and is odd. Each step of times_word_mod multiplies rem by 2^64
// modulo m, so floor(exponent / 64) - (k - 1) steps end at 2^exponent mod
// m. For rsa_ifma_public's 2^(104n) that is 34, 50 and 65 steps at
// RSA-2048, RSA-3072 and RSA-4096, and for rsa_avx2_public's 2^(2Dn) 33,
// 49 and 65, where times_r_mod takes 32, 48 and 64.
static void power_of_two_mod(uint64_t *rem, const uint64_t *m, size_t k, size_t exponent) {
    for (size_t j = 0; j + 1 < k; j++) {
        rem[j] = 0;
    }
    rem[k - 1] = (uint64_t)1 << (exponent & 63);
    size_t steps = (exponent >> 6) - (k - 1);
    for (size_t i = 0; i < steps; i++) {
        times_word_mod(rem, m, k);
    }
}
#endif

// A session whose value holds CH_CPU_AVX512_IFMA, on x86-64, takes
// rsa_ifma_public for a modulus that call takes: at least
// RSA_IFMA_WORDS_MIN words, its top bit set, and odd. Else a session whose
// value holds CH_CPU_AVX2 takes rsa_avx2_public for a modulus that call
// takes, the same moduli from RSA_AVX2_WORDS_MIN words. The division above
// computes the power of two each needs, and mod.r2 stays unwritten,
// because neither call reads it. Every other modulus and every other value
// take rsa_vp1, so each input gets rsa_vp1's bytes.
void rsa_vp1_cpu(uint32_t cpu, const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em) {
#if defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL) || defined(CH_RSA_AVX2_MODEL)
    size_t k = (n_len + 7) / 8;
    rsa_mont64_modulus mod;
    uint64_t digit_r2[RSA_MONT64_WORDS_MAX];
#endif
#if defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL)
    if (use_ifma(cpu) && kernel_takes(n, n_len, RSA_IFMA_WORDS_MIN)) {
        rsa_mont64_modulus_load(&mod, n, n_len);
        power_of_two_mod(digit_r2, mod.m, k, 104 * rsa_ifma_digit_count(k));
        rsa_ifma_public(em, sig, n_len, &mod, digit_r2);
        return;
    }
#endif
#if defined(__x86_64__) || defined(CH_RSA_AVX2_MODEL)
    if (use_avx2(cpu) && kernel_takes(n, n_len, RSA_AVX2_WORDS_MIN)) {
        rsa_mont64_modulus_load(&mod, n, n_len);
        power_of_two_mod(digit_r2, mod.m, k, rsa_avx2_r2_exponent(k));
        rsa_avx2_public(em, sig, n_len, &mod, digit_r2);
        return;
    }
#endif
#if !defined(__x86_64__) && !defined(CH_RSA_IFMA_MODEL) && !defined(CH_RSA_AVX2_MODEL)
    // arm64 has no such kernel, so no bit picks here.
    (void)cpu;
#endif
    rsa_vp1(n, n_len, sig, em);
}

#else // !CH_CPU_RUNTIME

#include <string.h>

// The most 32-bit words a big number holds: 96 for RSA-3072 and 128 for
// RSA-4096. The count follows the one modulus bound rsa.h defines.
#define WORDS_MAX (CH_RSA_MODULUS_MAX / 4)

// 32 big-endian bytes per word -> k little-endian words, byte by byte.
static void from_bytes(uint32_t *o, const uint8_t *b, size_t k) {
    for (size_t i = 0; i < k; i++) {
        size_t j = (k - 1 - i) * 4; // most significant word sits at the front
        o[i] = ((uint32_t)b[j] << 24) | ((uint32_t)b[j + 1] << 16) | ((uint32_t)b[j + 2] << 8) |
               (uint32_t)b[j + 3];
    }
}

// k little-endian words -> big-endian bytes.
static void to_bytes(uint8_t *b, const uint32_t *a, size_t k) {
    for (size_t i = 0; i < k; i++) {
        size_t j = (k - 1 - i) * 4;
        b[j] = (uint8_t)(a[i] >> 24);
        b[j + 1] = (uint8_t)(a[i] >> 16);
        b[j + 2] = (uint8_t)(a[i] >> 8);
        b[j + 3] = (uint8_t)a[i];
    }
}

static int cmp(const uint32_t *a, const uint32_t *b, size_t k) {
    for (size_t i = k; i-- > 0;) {
        if (a[i] != b[i]) {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}

static uint32_t sub_raw(uint32_t *o, const uint32_t *a, const uint32_t *b, size_t k) {
    uint64_t borrow = 0;
    for (size_t i = 0; i < k; i++) {
        uint64_t v = (uint64_t)a[i] - b[i] - borrow;
        o[i] = (uint32_t)v;
        borrow = (v >> 32) & 1;
    }
    return (uint32_t)borrow;
}

// -m^-1 mod 2^32 by Newton iteration. m0 is odd (n is a product of odd
// primes), so x doubles its correct low bits each step and five steps
// cover all 32.
static uint32_t mont_m0inv(uint32_t m0) {
    uint32_t x = 1;
    for (int i = 0; i < 5; i++) {
        x *= 2U - m0 * x;
    }
    return 0U - x;
}

// r2 = 2^(64k) mod m, the entry ticket to the Montgomery domain. Start at
// 1 and double 64k times; each double is a shift with one conditional
// subtract, since the pre-shift value is below m.
static void mont_r2(uint32_t *r2, const uint32_t *m, size_t k) {
    memset(r2, 0, k * sizeof(uint32_t));
    r2[0] = 1;
    for (size_t i = 0; i < 64 * k; i++) {
        uint32_t carry = 0;
        for (size_t j = 0; j < k; j++) {
            uint32_t shifted = (r2[j] << 1) | carry;
            carry = r2[j] >> 31;
            r2[j] = shifted;
        }
        if (carry || cmp(r2, m, k) >= 0) {
            (void)sub_raw(r2, r2, m, k);
        }
    }
}

// Montgomery product o = a*b / 2^(32k) mod m (CIOS, Koç et al.). Inputs
// below m, result below m; o may alias a or b, since o is written only
// after both are fully read. Each round adds one word of a into t, folds
// a multiple of m in to zero t's low word, and shifts down one word.
static void mont_mul(uint32_t *o, const uint32_t *a, const uint32_t *b, const uint32_t *m,
                     uint32_t m0inv, size_t k) {
    uint32_t t[WORDS_MAX + 2];
    memset(t, 0, (k + 2) * sizeof(uint32_t));
    for (size_t i = 0; i < k; i++) {
        uint64_t c = 0;
        for (size_t j = 0; j < k; j++) {
            uint64_t v = (uint64_t)a[i] * b[j] + t[j] + c;
            t[j] = (uint32_t)v;
            c = v >> 32;
        }
        uint64_t v = (uint64_t)t[k] + c;
        t[k] = (uint32_t)v;
        t[k + 1] = (uint32_t)(v >> 32);

        uint32_t u = t[0] * m0inv;
        c = ((uint64_t)u * m[0] + t[0]) >> 32;
        for (size_t j = 1; j < k; j++) {
            v = (uint64_t)u * m[j] + t[j] + c;
            t[j - 1] = (uint32_t)v;
            c = v >> 32;
        }
        v = (uint64_t)t[k] + c;
        t[k - 1] = (uint32_t)v;
        t[k] = t[k + 1] + (uint32_t)(v >> 32);
        t[k + 1] = 0;
    }
    // t < 2m with at most one bit in t[k]; the subtraction's borrow
    // cancels that bit exactly, so the low words are the answer.
    if (t[k] || cmp(t, m, k) >= 0) {
        (void)sub_raw(o, t, m, k);
    } else {
        memcpy(o, t, k * sizeof(uint32_t));
    }
}

void rsa_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em) {
    size_t k = n_len / 4;
    uint32_t m[WORDS_MAX] = {0};
    uint32_t base[WORDS_MAX] = {0};
    uint32_t r2[WORDS_MAX];
    uint32_t base_mont[WORDS_MAX];
    uint32_t acc[WORDS_MAX];
    uint32_t one[WORDS_MAX];
    from_bytes(m, n, k);
    from_bytes(base, sig, k);
    uint32_t m0inv = mont_m0inv(m[0]);
    mont_r2(r2, m, k);

    // acc holds the running power in the Montgomery domain. Start at
    // base*R (sig^1), square 16 times to reach sig^(2^16), then one
    // multiply by base*R for the +1, giving sig^65537.
    mont_mul(base_mont, base, r2, m, m0inv, k);
    memcpy(acc, base_mont, k * sizeof(uint32_t));
    for (int i = 0; i < 16; i++) {
        mont_mul(acc, acc, acc, m, m0inv, k);
    }
    mont_mul(acc, acc, base_mont, m, m0inv, k);

    // Multiply by 1 to strip the R factor, then serialize.
    memset(one, 0, k * sizeof(uint32_t));
    one[0] = 1;
    mont_mul(acc, acc, one, m, m0inv, k);
    to_bytes(em, acc, k);
}

#endif // CH_CPU_RUNTIME
