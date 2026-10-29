// The x86-64 X25519 field (x25519_adx.h). An element is four 64-bit words,
// least significant first, a value under 2^256 that is not reduced mod p:
// 2^256 = 38 mod p, so every operation folds what passes 2^256 back in at
// word 0 times 38. Five operations are inline assembly, in x25519_adx_asm.h:
// the product, the square, the sum, the difference and the product by
// 121666. The ladder, the inversion and the final reduction are C over them.
//
// The model build, under CH_X25519_ADX_MODEL, takes the five operations from
// test/x25519_adx_model.h, portable C that writes the same four words. The
// CBMC harnesses and the model test compile this file that way, on any
// host, and bin/x25519_adx_equiv_test holds the assembly to the model on a
// CPU with BMI2 and ADX (docs/decisions.md 165).
//
// Timing: no instruction here branches, and every address is a pointer the
// caller passed plus a constant. The C branches read the bit index of the
// ladder and the counts of the inversion chain, which are public. The swap
// and the final reduction choose by mask.
#include "x25519_adx.h"

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_X25519_ADX_MODEL))

#include <stddef.h>

#include "ct.h"

typedef uint64_t fe[4];

#ifdef CH_X25519_ADX_MODEL
#include "x25519_adx_model.h"
#else
#include "x25519_adx_asm.h"
#endif // CH_X25519_ADX_MODEL

// Swaps p and q when bit is 1, by mask, as x25519_wide.c's cswap. The bit is
// a scalar's, so it is read back from a volatile object before the mask is
// built: inlined into the ladder, clang 23 for x86-64 saw that the mask was
// all ones or zero and wrote the swap as a jump on the bit, eight jumps a
// step (docs/decisions.md 125 and 165).
static void adx_cswap(fe p, fe q, uint64_t bit) {
    volatile uint64_t chosen = bit;
    uint64_t mask = (uint64_t)((int64_t)(chosen << 63) >> 63);
    for (size_t i = 0; i < 4; i++) {
        uint64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void adx_sqr_times(fe o, const fe a, int n) {
    adx_sqr(o, a);
    for (int i = 1; i < n; i++) {
        adx_sqr(o, o);
    }
}

// o = z^(p-2), the inverse of z: x25519_wide.c's chain of 254 squares and 11
// products.
static void adx_invert(fe o, const fe z) {
    fe z2;
    fe z9;
    fe z11;
    fe z2_5_0;
    fe z2_10_0;
    fe z2_20_0;
    fe z2_50_0;
    fe z2_100_0;
    fe t;
    adx_sqr(z2, z);
    adx_sqr_times(t, z2, 2);
    adx_mul(z9, t, z);
    adx_mul(z11, z9, z2);
    adx_sqr(t, z11);
    adx_mul(z2_5_0, t, z9);
    adx_sqr_times(t, z2_5_0, 5);
    adx_mul(z2_10_0, t, z2_5_0);
    adx_sqr_times(t, z2_10_0, 10);
    adx_mul(z2_20_0, t, z2_10_0);
    adx_sqr_times(t, z2_20_0, 20);
    adx_mul(t, t, z2_20_0);
    adx_sqr_times(t, t, 10);
    adx_mul(z2_50_0, t, z2_10_0);
    adx_sqr_times(t, z2_50_0, 50);
    adx_mul(z2_100_0, t, z2_50_0);
    adx_sqr_times(t, z2_100_0, 100);
    adx_mul(t, t, z2_100_0);
    adx_sqr_times(t, t, 50);
    adx_mul(t, t, z2_50_0);
    adx_sqr_times(t, t, 5);
    adx_mul(o, t, z11);
    ct_wipe(z2, sizeof z2);
    ct_wipe(z9, sizeof z9);
    ct_wipe(z11, sizeof z11);
    ct_wipe(z2_5_0, sizeof z2_5_0);
    ct_wipe(z2_10_0, sizeof z2_10_0);
    ct_wipe(z2_20_0, sizeof z2_20_0);
    ct_wipe(z2_50_0, sizeof z2_50_0);
    ct_wipe(z2_100_0, sizeof z2_100_0);
    ct_wipe(t, sizeof t);
}

// a + c, word by word with the carry, and the carry out of 2^256.
static uint64_t add_word(fe a, uint64_t c) {
    for (size_t i = 0; i < 4; i++) {
        ct_u128 t = (ct_u128)a[i] + c;
        a[i] = (uint64_t)t;
        c = (uint64_t)(t >> 64);
    }
    return c;
}

// a mod p, the one value under p. Twice, bit 255 moves to word 0 times 19,
// which leaves a under 2^255 + 19. Then a + 19 reaches 2^255 exactly when a
// is p or more, and in that case a + 19 - 2^255 = a - p is the value.
static void adx_reduce(fe a) {
    for (int k = 0; k < 2; k++) {
        uint64_t top = a[3] >> 63;
        a[3] &= UINT64_C(0x7fffffffffffffff);
        (void)add_word(a, top * 19);
    }
    fe b;
    for (size_t i = 0; i < 4; i++) {
        b[i] = a[i];
    }
    (void)add_word(b, 19);
    uint64_t mask = (uint64_t)((int64_t)(b[3] & (UINT64_C(1) << 63)) >> 63);
    b[3] &= UINT64_C(0x7fffffffffffffff);
    for (size_t i = 0; i < 4; i++) {
        a[i] = (a[i] & ~mask) | (b[i] & mask);
    }
    ct_wipe(b, sizeof b);
}

// The ladder's state: x1, the point, and the two projective points (x2 : z2)
// and (x3 : z3), and four values each step computes.
typedef struct {
    fe x1;
    fe x2;
    fe z2;
    fe x3;
    fe z3;
    fe d;
    fe b;
    fe aa;
    fe bb;
    fe e;
} adx_state;

// One step of RFC 7748 section 5's ladder, its operations in the order
// OpenSSL's x25519_scalar_mulx runs them: two independent operations side by
// side wherever the formulas allow, so the core runs one beside the other.
// In RFC 7748's order a shared secret took 1.27 times as long on an EPYC 7763
// (docs/decisions.md 165).
static void adx_step(adx_state *s) {
    adx_sub(s->d, s->x3, s->z3);  // D = x3 - z3
    adx_sub(s->b, s->x2, s->z2);  // B = x2 - z2
    adx_add(s->x2, s->x2, s->z2); // A = x2 + z2
    adx_add(s->z2, s->x3, s->z3); // C = x3 + z3
    adx_mul(s->z3, s->x2, s->d);  // DA
    adx_mul(s->z2, s->z2, s->b);  // CB
    adx_sqr(s->bb, s->b);         // BB
    adx_sqr(s->aa, s->x2);        // AA
    adx_add(s->x3, s->z3, s->z2); // DA + CB
    adx_sub(s->z2, s->z3, s->z2); // DA - CB
    adx_mul(s->x2, s->aa, s->bb); // x2 = AA * BB
    adx_sub(s->e, s->aa, s->bb);  // E = AA - BB
    adx_sqr(s->z2, s->z2);        // (DA - CB)^2
    adx_mul_a24(s->z3, s->e);     // 121666 E
    adx_sqr(s->x3, s->x3);        // x3 = (DA + CB)^2
    adx_add(s->bb, s->bb, s->z3); // BB + 121666 E = AA + 121665 E
    adx_mul(s->z3, s->x1, s->z2); // z3 = x1 (DA - CB)^2
    adx_mul(s->z2, s->e, s->bb);  // z2 = E (AA + 121665 E)
}

static uint64_t load_le64(const uint8_t b[8]) {
    uint64_t v = 0;
    for (size_t i = 8; i > 0; i--) {
        v = (v << 8) | b[i - 1];
    }
    return v;
}

void x25519_adx_ladder(uint8_t out[X25519_LEN], const uint8_t clamped[X25519_LEN],
                       const uint8_t point[X25519_LEN]) {
    adx_state s = {0};
    for (size_t i = 0; i < 4; i++) {
        s.x1[i] = load_le64(&point[8 * i]);
    }
    s.x1[3] &= UINT64_C(0x7fffffffffffffff); // RFC 7748 masks the top bit off
    s.x2[0] = 1;
    s.z3[0] = 1;
    for (size_t i = 0; i < 4; i++) {
        s.x3[i] = s.x1[i];
    }
    // Each step swaps by its bit exclusive-or the bit before, and the last
    // swap below restores the order, as x25519_wide.c's ladder does.
    uint64_t swap = 0;
    for (int t = 254; t >= 0; t--) {
        uint64_t bit = (uint64_t)(clamped[t >> 3] >> (t & 7)) & 1;
        adx_cswap(s.x2, s.x3, swap ^ bit);
        adx_cswap(s.z2, s.z3, swap ^ bit);
        swap = bit;
        adx_step(&s);
    }
    adx_cswap(s.x2, s.x3, swap);
    adx_cswap(s.z2, s.z3, swap);
    adx_invert(s.z2, s.z2);
    adx_mul(s.x2, s.x2, s.z2);
    adx_reduce(s.x2);
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 8; j++) {
            out[8 * i + j] = (uint8_t)(s.x2[i] >> (8 * j));
        }
    }
    ct_wipe(&s, sizeof s);
    ct_wipe(&swap, sizeof swap);
}

#ifdef CH_X25519_ADX_TEST
// The five operations and the final reduction, for bin/x25519_adx_equiv_test,
// which holds each assembly operation to its model. No library object
// defines CH_X25519_ADX_TEST.
void x25519_adx_test_mul(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]) {
    adx_mul(o, a, b);
}
void x25519_adx_test_sqr(uint64_t o[4], const uint64_t a[4]) {
    adx_sqr(o, a);
}
void x25519_adx_test_add(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]) {
    adx_add(o, a, b);
}
void x25519_adx_test_sub(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]) {
    adx_sub(o, a, b);
}
void x25519_adx_test_mul_a24(uint64_t o[4], const uint64_t a[4]) {
    adx_mul_a24(o, a);
}
void x25519_adx_test_reduce(uint64_t a[4]) {
    adx_reduce(a);
}
#endif

// x25519 on this field: x25519.c's clamp and all-zero check over
// x25519_adx_ladder.
#define CH_X25519_ADX 1
#define x25519 x25519_adx
#include "x25519.c"

#endif
