// The wide inverse (see p256_wide_inverse.h for the contract): the optimized binary GCD of
// Pornin's "Optimized Binary GCD for Modular Inversion" (https://eprint.iacr.org/2020/972), on
// four 64-bit words.
//
// The binary GCD holds a and b, b odd, from a = y and b = m. A step halves a when a is even.
// When a is odd, it replaces a by |a - b| / 2, and when a was below b it first moves a into b.
// While a is not zero, each step shortens a and b by at least one bit between them, and once a
// is zero, b is gcd(y, m). Beside a and b the algorithm keeps u and v, from u = 1 and v = 0, with
// a = u y and b = v y modulo m, so v ends as y^-1 when gcd(y, m) is 1.
//
// A step on the whole of a and b would subtract and compare four words. A round here runs STEPS
// steps on 64-bit approximations of a and b instead, records them as four factors f0, g0, f1
// and g1, and applies them once: a becomes (a f0 + b g0) / 2^STEPS, b becomes
// (a f1 + b g1) / 2^STEPS, and u and v take the same sums of u and v, divided by 2^STEPS modulo
// m. The approximations hold the STEPS low bits of a and b, which decide every halving as a and
// b would, and their top 33 bits, which decide the comparisons. A comparison of the
// approximations can differ from the comparison of a and b, and then a sum comes out below
// zero: the round negates it and the factors that made it. spec/lean/Spec/P256WideInverse.lean
// proves that a round still shortens a and b by STEPS bits between them while a is not zero, so
// ROUNDS rounds leave a = 0.
#include "p256_wide_inverse.h"

#ifdef CH_CPU_RUNTIME

#include <stddef.h>

#include "ct.h"
#include "p256_wide_word.h"

#define WORDS P256_WIDE_INVERSE_WORDS

// The steps of a round. After STEPS steps each factor is between -(2^STEPS - 1) and 2^STEPS, so
// with 31 a factor and the one beside it share a word in step_factors.
#define STEPS 31

// The rounds. y and m are below 2^256, so a and b start at 512 bits at most between them. A
// round removes STEPS of them while a is not zero, and a nonzero a beside an odd b keeps at
// least two, so 17 rounds, 527 bits, leave a = 0.
#define ROUNDS 17

// An approximation's bits below STEPS, which are a's or b's own low bits.
#define LOW_BITS ((UINT64_C(1) << STEPS) - 1)

// All ones when x is not zero, and zero when it is: x or -x has its top bit set exactly then.
// The negation wraps on purpose. p256_wide_field.c's zero_mask_word takes a 128-bit sum that
// wraps nothing, and here, where six of these masks run one after another in each
// approximations call, that form took 1.59 µs an inverse on the M1 Pro where this one takes 1.42.
static inline uint64_t nonzero_mask(uint64_t x) {
    return p256_wide_mask((x | (0 - x)) >> 63);
}

// |f| for a two's complement word f, and all ones in *negative when f is below zero. A negative
// f is not zero, so ~f + 1 wraps nothing.
static inline uint64_t magnitude(uint64_t f, uint64_t *negative) {
    *negative = p256_wide_mask(f >> 63);
    return (f ^ *negative) + (*negative & 1);
}

// Shifts the 128 bits (*high : *low) left by s where mask is all ones, and leaves them where it
// is zero. s is from 1 to 32.
static inline void shift_left_masked(uint64_t *high, uint64_t *low, unsigned s, uint64_t mask) {
    uint64_t shifted_high = (*high << s) | (*low >> (64 - s));
    uint64_t shifted_low = *low << s;
    *high = (shifted_high & mask) | (*high & ~mask);
    *low = (shifted_low & mask) | (*low & ~mask);
}

// The approximations of a and b that a round's steps run on. For n the bit length of a | b:
// a's and b's low words when n is at most 64, and otherwise each one's STEPS low bits beside its
// 33 bits from bit n - 33 up. For the second, the loop finds the top nonzero word of a | b above
// the low word, and the word under it, in a and in b, and the shifts move both pairs left until
// bit n - 1 is bit 127.
//
// The C chooses each shift with masks, and clang turns some of those choices into a shift by a
// register whose value the mask chose: at -O2 the last step shifts by 0 or 1, and at -Os every
// step shifts by 0 or s. A shift by a register takes the same time for every amount on the cores
// a host object runs on: Arm lists LSLV and LSRV among the instructions whose timing does not
// depend on their data, and Intel lists the shifts among its data operand independent timing
// instructions. Reading each mask through a volatile kept the masks but cost 0.34 µs of an
// inverse's 1.42 on the M1 Pro (docs/decisions.md 115).
static void approximations(uint64_t *xa, uint64_t *xb, const uint64_t a[WORDS],
                           const uint64_t b[WORDS]) {
    uint64_t a_high = a[0];
    uint64_t a_low = 0;
    uint64_t b_high = b[0];
    uint64_t b_low = 0;
    uint64_t above_64 = 0; // all ones when n is above 64
    for (size_t i = 1; i < WORDS; i++) {
        uint64_t nonzero = nonzero_mask(a[i] | b[i]);
        a_high = (a[i] & nonzero) | (a_high & ~nonzero);
        a_low = (a[i - 1] & nonzero) | (a_low & ~nonzero);
        b_high = (b[i] & nonzero) | (b_high & ~nonzero);
        b_low = (b[i - 1] & nonzero) | (b_low & ~nonzero);
        above_64 |= nonzero;
    }
    // Shifts of 32, 16, 8, 4, 2 and 1 bits, each where the bits it moves out of a_high | b_high
    // are zero.
    for (unsigned s = 32; s > 0; s >>= 1) {
        uint64_t mask = ~nonzero_mask((a_high | b_high) >> (64 - s));
        shift_left_masked(&a_high, &a_low, s, mask);
        shift_left_masked(&b_high, &b_low, s, mask);
    }
    uint64_t wide_a = (a[0] & LOW_BITS) | (a_high & ~LOW_BITS);
    uint64_t wide_b = (b[0] & LOW_BITS) | (b_high & ~LOW_BITS);
    *xa = (wide_a & above_64) | (a[0] & ~above_64);
    *xb = (wide_b & above_64) | (b[0] & ~above_64);
}

// One step on the approximations *xa and *xb, *xb odd, and on the factors, packed in *pair0 and
// *pair1 (step_factors). *odd is all ones when *xa is odd and zero when it is even, and the
// step leaves it so for the next *xa. A step on xa and xb is a step on a and b: when xa is even
// it becomes xa / 2, and when it is odd it becomes |xa - xb| / 2, and xb becomes the old xa
// when xa was below xb.
static inline void step(uint64_t *xa, uint64_t *xb, uint64_t *pair0, uint64_t *pair1,
                        uint64_t *odd) {
    // xb is subtracted where xa is odd, so the subtraction borrows only where xa is odd and below
    // xb, the steps that swap.
    uint64_t borrow = 0;
    uint64_t difference = p256_wide_sub_borrow(&borrow, *xa, *xb & *odd);
    uint64_t swap = p256_wide_mask(borrow);
    uint64_t pair_difference = *pair0 - (*pair1 & *odd);
    *xb ^= (*xa ^ *xb) & swap;
    *pair1 ^= (*pair0 ^ *pair1) & swap;
    *xa = ((difference ^ swap) - swap) >> 1;
    // The next xa is |difference| / 2. Where xa was odd, difference is a difference of two odd
    // words, so it is even, and an even word and its negation agree in bit 1. Where xa was
    // even, difference is xa.
    *odd = p256_wide_mask((difference >> 1) & 1);
    *pair0 = (pair_difference ^ swap) - swap;
    *pair1 <<= 1;
}

// The four factors from the two pairs, f0 and g0 from pair0 and f1 and g1 from pair1, as two's
// complement words. Each factor is between -(2^31 - 1) and 2^31, so adding 2^31 - 1 to each half
// of a pair puts both halves in [0, 2^32), where they separate.
static inline void unpack_factors(uint64_t factor[4], uint64_t pair0, uint64_t pair1) {
    uint64_t bias = (UINT64_C(1) << 31) - 1;
    uint64_t biases = bias | (bias << 32);
    pair0 += biases;
    pair1 += biases;
    factor[0] = (pair0 & UINT32_MAX) - bias;
    factor[1] = (pair0 >> 32) - bias;
    factor[2] = (pair1 & UINT32_MAX) - bias;
    factor[3] = (pair1 >> 32) - bias;
}

// The factors of STEPS steps on the approximations xa and xb, xb odd: f0, g0, f1 and g1 in
// factor[0] to factor[3], each a two's complement word. From f0 = g1 = 1 and f1 = g0 = 0, the
// factors take each step xa and xb take: a halving doubles f1 and g1, a difference subtracts
// f1 and g1 from f0 and g0, and a swap exchanges the two pairs. After i steps
// xa 2^i = xa0 f0 + xb0 g0 and xb 2^i = xa0 f1 + xb0 g1, for xa0 and xb0 the approximations the
// call took.
//
// Each pair travels in one word, f + 2^32 g modulo 2^64. A swap, a difference, a negation and a
// doubling are linear, so the two words stay exact modulo 2^64.
static void step_factors(uint64_t factor[4], uint64_t xa, uint64_t xb) {
    uint64_t pair0 = 1;                 // f0 + 2^32 g0
    uint64_t pair1 = UINT64_C(1) << 32; // f1 + 2^32 g1
    uint64_t odd = p256_wide_mask(xa & 1);
    for (int i = 0; i < STEPS; i++) {
        step(&xa, &xb, &pair0, &pair1, &odd);
    }
    unpack_factors(factor, pair0, pair1);
}

// o = x * k, five words, for a word k.
static void multiply_word(uint64_t o[WORDS + 1], const uint64_t x[WORDS], uint64_t k) {
    o[0] = 0;
    o[1] = 0;
    o[2] = 0;
    o[3] = 0;
    o[4] = p256_wide_mul_row(&o[0], &o[1], &o[2], &o[3], k, x[0], x[1], x[2], x[3]);
}

// o = -o modulo 2^320 where mask is all ones, and o where it is zero.
static void negate_masked(uint64_t o[WORDS + 1], uint64_t mask) {
    uint64_t carry = mask & 1;
    for (size_t i = 0; i < WORDS + 1; i++) {
        o[i] = p256_wide_add_carry(&carry, o[i] ^ mask, 0);
    }
}

// o = |x f + y g| / 2^STEPS, for f and g two's complement words with |f| + |g| at most 2^STEPS,
// and all ones returned when x f + y g is below zero. A round's factors make the sum's STEPS
// low bits zero and its quotient below 2^256, so the division drops no bit and o holds all of
// it. |x f + y g| is below 2^(256 + STEPS), so five words hold the sum and its sign.
static uint64_t combine_exact(uint64_t o[WORDS], const uint64_t x[WORDS], const uint64_t y[WORDS],
                              uint64_t f, uint64_t g) {
    uint64_t f_negative;
    uint64_t g_negative;
    uint64_t f_magnitude = magnitude(f, &f_negative);
    uint64_t g_magnitude = magnitude(g, &g_negative);
    uint64_t product_x[WORDS + 1];
    uint64_t product_y[WORDS + 1];
    multiply_word(product_x, x, f_magnitude);
    multiply_word(product_y, y, g_magnitude);
    negate_masked(product_x, f_negative);
    negate_masked(product_y, g_negative);
    uint64_t sum[WORDS + 1];
    uint64_t carry = 0;
    for (size_t i = 0; i < WORDS + 1; i++) {
        sum[i] = p256_wide_add_carry(&carry, product_x[i], product_y[i]);
    }
    uint64_t negative = p256_wide_mask(sum[WORDS] >> 63);
    negate_masked(sum, negative);
    for (size_t i = 0; i < WORDS; i++) {
        o[i] = (sum[i] >> STEPS) | (sum[i + 1] << (64 - STEPS));
    }
    return negative;
}

// o = s (x f + y g) / 2^STEPS mod m, for x and y below m, f and g two's complement words with
// |f| + |g| at most 2^STEPS, and s = -1 where negate is all ones and 1 where it is zero. Where
// s f is below zero, x becomes m - x, which is -x modulo m, and the same for y, so both
// products are of numbers at or above zero and their sum t is at most m 2^STEPS. A Montgomery
// reduction adds q m, for the q below 2^STEPS that makes the low STEPS bits zero, and drops
// them: (t + q m) / 2^STEPS is below 2m, and one subtraction of m chosen by a mask leaves it
// below m.
static void combine_modular(uint64_t o[WORDS], const uint64_t x[WORDS], const uint64_t y[WORDS],
                            uint64_t f, uint64_t g, uint64_t negate, const p256_wide_modulus *m) {
    uint64_t f_negative;
    uint64_t g_negative;
    uint64_t f_magnitude = magnitude(f, &f_negative);
    uint64_t g_magnitude = magnitude(g, &g_negative);
    f_negative ^= negate;
    g_negative ^= negate;
    uint64_t operand_x[WORDS];
    uint64_t operand_y[WORDS];
    uint64_t borrow_x = 0;
    uint64_t borrow_y = 0;
    for (size_t i = 0; i < WORDS; i++) {
        uint64_t negated_x = p256_wide_sub_borrow(&borrow_x, m->word[i], x[i]);
        uint64_t negated_y = p256_wide_sub_borrow(&borrow_y, m->word[i], y[i]);
        operand_x[i] = (negated_x & f_negative) | (x[i] & ~f_negative);
        operand_y[i] = (negated_y & g_negative) | (y[i] & ~g_negative);
    }
    // t, five words: the two products and q m, each row's word above the four added to t[4].
    uint64_t t[WORDS + 1] = {0, 0, 0, 0, 0};
    t[4] = p256_wide_mul_row(&t[0], &t[1], &t[2], &t[3], f_magnitude, operand_x[0], operand_x[1],
                             operand_x[2], operand_x[3]);
    t[4] += p256_wide_mul_row(&t[0], &t[1], &t[2], &t[3], g_magnitude, operand_y[0], operand_y[1],
                              operand_y[2], operand_y[3]);
    // The low 64 bits of the product: the cast drops the high half on purpose.
    uint64_t q = (uint64_t)ct_mul128(t[0], m->negated_inverse) & LOW_BITS;
    t[4] += p256_wide_mul_row(&t[0], &t[1], &t[2], &t[3], q, m->word[0], m->word[1], m->word[2],
                              m->word[3]);
    uint64_t s[WORDS + 1];
    for (size_t i = 0; i < WORDS; i++) {
        s[i] = (t[i] >> STEPS) | (t[i + 1] << (64 - STEPS));
    }
    s[WORDS] = t[WORDS] >> STEPS;
    uint64_t reduced[WORDS];
    uint64_t borrow = 0;
    for (size_t i = 0; i < WORDS; i++) {
        reduced[i] = p256_wide_sub_borrow(&borrow, s[i], m->word[i]);
    }
    (void)p256_wide_sub_borrow(&borrow, s[WORDS], 0);
    uint64_t below_m = p256_wide_mask(borrow);
    for (size_t i = 0; i < WORDS; i++) {
        o[i] = (s[i] & below_m) | (reduced[i] & ~below_m);
    }
}

// A value of the rounds: four words, least significant first.
typedef struct {
    uint64_t word[WORDS];
} inverse_value;

// What the rounds work on: a, b, u and v, and the next values and the factors one round computes,
// in one object, so one wipe clears all of it.
typedef struct {
    inverse_value a;
    inverse_value b;
    inverse_value u;
    inverse_value v;
    inverse_value next_a;
    inverse_value next_b;
    inverse_value next_u;
    inverse_value next_v;
    uint64_t factor[4];
} inverse_state;

// One round: the steps on the approximations of a and b, and their factors applied to a, b, u
// and v.
static void run_round(inverse_state *s, const p256_wide_modulus *m) {
    uint64_t xa;
    uint64_t xb;
    approximations(&xa, &xb, s->a.word, s->b.word);
    step_factors(s->factor, xa, xb);
    uint64_t negative_a =
        combine_exact(s->next_a.word, s->a.word, s->b.word, s->factor[0], s->factor[1]);
    uint64_t negative_b =
        combine_exact(s->next_b.word, s->a.word, s->b.word, s->factor[2], s->factor[3]);
    // u and v take the sign a and b took, so a = u y and b = v y modulo m still hold.
    combine_modular(s->next_u.word, s->u.word, s->v.word, s->factor[0], s->factor[1], negative_a,
                    m);
    combine_modular(s->next_v.word, s->u.word, s->v.word, s->factor[2], s->factor[3], negative_b,
                    m);
    s->a = s->next_a;
    s->b = s->next_b;
    s->u = s->next_u;
    s->v = s->next_v;
}

void p256_wide_inverse(uint64_t o[WORDS], const uint64_t y[WORDS], const p256_wide_modulus *m) {
    inverse_state s;
    for (size_t i = 0; i < WORDS; i++) {
        s.a.word[i] = y[i];
        s.b.word[i] = m->word[i];
        s.u.word[i] = 0;
        s.v.word[i] = 0;
    }
    s.u.word[0] = 1;
    for (int round = 0; round < ROUNDS; round++) {
        run_round(&s, m);
    }
    // a is zero and b is gcd(y, m), so v y = 1 modulo m when that is 1. For y = 0, every round
    // left a and v zero.
    for (size_t i = 0; i < WORDS; i++) {
        o[i] = s.v.word[i];
    }
    ct_wipe(&s, sizeof s);
}

#endif // CH_CPU_RUNTIME
