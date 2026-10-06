#include "mlkem_vector.h"

// The whole file compiles only in a host object (mlkem_vector.h).
#ifdef CH_CPU_RUNTIME

#include "mlkem_lanes.h"
#include "mlkem_zetas.h"

// A twiddle factor for each lane, beside the low 16 bits of its product
// with -3327, which lanes_fqmul takes with it.
typedef struct {
    lanes zeta;
    lanes zeta_qinv;
} twiddle;

static inline twiddle twiddle_of(lanes zeta) {
    twiddle w;
    w.zeta = zeta;
    w.zeta_qinv = lanes_mul_low(zeta, lanes_broadcast(-3327));
    return w;
}

// mlk_poly_ntt's butterfly on eight pairs: lo + zeta*hi and lo - zeta*hi.
static inline void butterfly(lanes *lo, lanes *hi, twiddle w) {
    lanes t = lanes_fqmul(*hi, w.zeta, w.zeta_qinv);
    *hi = lanes_sub(*lo, t);
    *lo = lanes_add(*lo, t);
}

// mlk_poly_invntt's butterfly on eight pairs: lo + hi, Barrett-reduced, and
// zeta*(hi - lo).
static inline void butterfly_inverse(lanes *lo, lanes *hi, twiddle w) {
    lanes t = *lo;
    *lo = lanes_barrett_reduce(lanes_add(t, *hi));
    *hi = lanes_fqmul(lanes_sub(*hi, t), w.zeta, w.zeta_qinv);
}

// The four vectors at p, p + span, p + 2*span and p + 3*span.
typedef struct {
    lanes v[4];
} four;

static inline four four_load(const int16_t *p, size_t span) {
    four f;
    f.v[0] = lanes_load(p);
    f.v[1] = lanes_load(p + span);
    f.v[2] = lanes_load(p + 2 * span);
    f.v[3] = lanes_load(p + 3 * span);
    return f;
}

static inline void four_store(int16_t *p, size_t span, four f) {
    lanes_store(p, f.v[0]);
    lanes_store(p + span, f.v[1]);
    lanes_store(p + 2 * span, f.v[2]);
    lanes_store(p + 3 * span, f.v[3]);
}

// Two forward layers on four vectors span coefficients apart: the layer of
// span 2*span pairs vectors 0 and 2 and vectors 1 and 3 under wide, then
// the layer of span span pairs vectors 0 and 1 under low and vectors 2 and
// 3 under high.
static inline four four_forward(four f, twiddle wide, twiddle low, twiddle high) {
    butterfly(&f.v[0], &f.v[2], wide);
    butterfly(&f.v[1], &f.v[3], wide);
    butterfly(&f.v[0], &f.v[1], low);
    butterfly(&f.v[2], &f.v[3], high);
    return f;
}

// The same two layers inverted, in the inverse order.
static inline four four_inverse(four f, twiddle low, twiddle high, twiddle wide) {
    butterfly_inverse(&f.v[0], &f.v[1], low);
    butterfly_inverse(&f.v[2], &f.v[3], high);
    butterfly_inverse(&f.v[0], &f.v[2], wide);
    butterfly_inverse(&f.v[1], &f.v[3], wide);
    return f;
}

static inline twiddle twiddle_at(size_t k) {
    return twiddle_of(lanes_broadcast(MLK_ZETAS[k]));
}

// The forward layers of span 8, 4 and 2 on the 16 coefficients at p, the
// block-th 16 of the polynomial, and the Barrett reduction mlk_poly_ntt
// ends with. mlk_poly_ntt reads twiddle 16 + block for the span 8 layer,
// 32 + 2*block and the one after it for span 4, and 64 + 4*block and the
// three after it for span 2.
static inline void forward_last_layers(int16_t *p, size_t block) {
    lanes a = lanes_load(p);
    lanes b = lanes_load(p + 8);
    lanes lo;
    lanes hi;
    butterfly(&a, &b, twiddle_at(16 + block));
    lanes_split_quads(a, b, &lo, &hi);
    butterfly(&lo, &hi, twiddle_of(lanes_quads(&MLK_ZETAS[32 + 2 * block])));
    lanes_join_quads(lo, hi, &a, &b);
    lanes_split_pairs(a, b, &lo, &hi);
    butterfly(&lo, &hi, twiddle_of(lanes_pairs(&MLK_ZETAS[64 + 4 * block])));
    lanes_join_pairs(lo, hi, &a, &b);
    lanes_store(p, lanes_barrett_reduce(a));
    lanes_store(p + 8, lanes_barrett_reduce(b));
}

// The inverse layers of span 2, 4 and 8 on the 16 coefficients at p, the
// block-th 16 of the polynomial. mlk_poly_invntt reads its twiddles from
// the top of the table down: 127 - 4*block and the three below it for
// span 2, 63 - 2*block and the one below it for span 4, and 31 - block for
// span 8.
static inline void inverse_first_layers(int16_t *p, size_t block) {
    lanes a = lanes_load(p);
    lanes b = lanes_load(p + 8);
    lanes lo;
    lanes hi;
    lanes_split_pairs(a, b, &lo, &hi);
    butterfly_inverse(&lo, &hi, twiddle_of(lanes_pairs_reversed(&MLK_ZETAS[124 - 4 * block])));
    lanes_join_pairs(lo, hi, &a, &b);
    lanes_split_quads(a, b, &lo, &hi);
    butterfly_inverse(&lo, &hi, twiddle_of(lanes_quads_reversed(&MLK_ZETAS[62 - 2 * block])));
    lanes_join_quads(lo, hi, &a, &b);
    butterfly_inverse(&a, &b, twiddle_at(31 - block));
    lanes_store(p, a);
    lanes_store(p + 8, b);
}

// The forward layers of span 128 and 64, under twiddle 1, then 2 and 3.
static void forward_first_layers(int16_t r[MLKEM_N]) {
    twiddle wide = twiddle_at(1);
    twiddle low = twiddle_at(2);
    twiddle high = twiddle_at(3);
    for (size_t j = 0; j < 64; j += 8) {
        four_store(r + j, 64, four_forward(four_load(r + j, 64), wide, low, high));
    }
}

// The forward layers of span 32 and 16 in each block of 64 coefficients,
// under twiddle 4 + block, then 8 + 2*block and 9 + 2*block.
static void forward_middle_layers(int16_t r[MLKEM_N]) {
    for (size_t block = 0; block < 4; block++) {
        twiddle wide = twiddle_at(4 + block);
        twiddle low = twiddle_at(8 + 2 * block);
        twiddle high = twiddle_at(9 + 2 * block);
        for (size_t j = 64 * block; j < 64 * block + 16; j += 8) {
            four_store(r + j, 16, four_forward(four_load(r + j, 16), wide, low, high));
        }
    }
}

// mlk_poly_ntt's seven layers in three passes over the polynomial, with
// the Barrett reduction it ends with in the last pass.
void mlk_vector_ntt(mlk_poly *p) {
    forward_first_layers(p->coeffs);
    forward_middle_layers(p->coeffs);
    for (size_t block = 0; block < 16; block++) {
        forward_last_layers(p->coeffs + 16 * block, block);
    }
}

// The inverse layers of span 16 and 32 in each block of 64 coefficients,
// under twiddles 15 - 2*block and 14 - 2*block, then 7 - block.
static void inverse_middle_layers(int16_t r[MLKEM_N]) {
    for (size_t block = 0; block < 4; block++) {
        twiddle low = twiddle_at(15 - 2 * block);
        twiddle high = twiddle_at(14 - 2 * block);
        twiddle wide = twiddle_at(7 - block);
        for (size_t j = 64 * block; j < 64 * block + 16; j += 8) {
            four_store(r + j, 16, four_inverse(four_load(r + j, 16), low, high, wide));
        }
    }
}

// The inverse layers of span 64 and 128, under twiddles 3 and 2, then 1,
// and the multiply by 1441 = 2^32 / 128 mod q that mlk_poly_invntt ends
// with.
static void inverse_last_layers(int16_t r[MLKEM_N]) {
    twiddle low = twiddle_at(3);
    twiddle high = twiddle_at(2);
    twiddle wide = twiddle_at(1);
    twiddle factor = twiddle_of(lanes_broadcast(1441));
    for (size_t j = 0; j < 64; j += 8) {
        four f = four_inverse(four_load(r + j, 64), low, high, wide);
        f.v[0] = lanes_fqmul(f.v[0], factor.zeta, factor.zeta_qinv);
        f.v[1] = lanes_fqmul(f.v[1], factor.zeta, factor.zeta_qinv);
        f.v[2] = lanes_fqmul(f.v[2], factor.zeta, factor.zeta_qinv);
        f.v[3] = lanes_fqmul(f.v[3], factor.zeta, factor.zeta_qinv);
        four_store(r + j, 64, f);
    }
}

// mlk_poly_invntt's seven layers in the reverse order, in three passes.
void mlk_vector_invntt(mlk_poly *p) {
    for (size_t block = 0; block < 16; block++) {
        inverse_first_layers(p->coeffs + 16 * block, block);
    }
    inverse_middle_layers(p->coeffs);
    inverse_last_layers(p->coeffs);
}

// mlk_poly_basemul's products, on 16 coefficients at a time. Lane i of the
// even and odd vectors holds one pair (c0, c1), the polynomial c0 + c1·X,
// and the product of a's pair with b's modulo X^2 - zeta is
// (a0·b0 + zeta·a1·b1, a0·b1 + a1·b0), with each product Montgomery-
// reduced as mlk_basemul reduces it. mlk_poly_basemul reads twiddle
// 64 + i for the first pair of its block i of four coefficients and the
// negation for the second, so the 16 coefficients of block take entries
// 64 + 4*block to 67 + 4*block, each twice, with alternate signs.
void mlk_vector_basemul(mlk_poly *r, const mlk_poly *a, const mlk_poly *b) {
    lanes signs = lanes_alternate_signs();
    lanes qinv = lanes_broadcast(-3327);
    for (size_t block = 0; block < 16; block++) {
        size_t at = 16 * block;
        lanes a_even;
        lanes a_odd;
        lanes b_even;
        lanes b_odd;
        lanes_split_even_odd(lanes_load(a->coeffs + at), lanes_load(a->coeffs + at + 8), &a_even,
                             &a_odd);
        lanes_split_even_odd(lanes_load(b->coeffs + at), lanes_load(b->coeffs + at + 8), &b_even,
                             &b_odd);
        twiddle w = twiddle_of(lanes_mul_low(lanes_pairs(&MLK_ZETAS[64 + 4 * block]), signs));
        lanes b_even_qinv = lanes_mul_low(b_even, qinv);
        lanes b_odd_qinv = lanes_mul_low(b_odd, qinv);
        lanes odd_product = lanes_fqmul_wide(a_odd, b_odd, b_odd_qinv);
        lanes r_even = lanes_add(lanes_fqmul(odd_product, w.zeta, w.zeta_qinv),
                                 lanes_fqmul_wide(a_even, b_even, b_even_qinv));
        lanes r_odd = lanes_add(lanes_fqmul_wide(a_even, b_odd, b_odd_qinv),
                                lanes_fqmul_wide(a_odd, b_even, b_even_qinv));
        lanes r_low;
        lanes r_high;
        lanes_join_even_odd(r_even, r_odd, &r_low, &r_high);
        lanes_store(r->coeffs + at, r_low);
        lanes_store(r->coeffs + at + 8, r_high);
    }
}

#endif // CH_CPU_RUNTIME
