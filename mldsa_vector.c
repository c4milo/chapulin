#include "mldsa_vector.h"

// The whole file compiles only in a host object (mldsa_vector.h): the NEON
// arm for arm64 and the AVX2 arm for x86-64. Each arm reads the twiddle
// factors from the one table in mldsa_zetas.h.
#if MLD_VECTOR

#include "mldsa_zetas.h"

#ifdef __ARM_NEON

#include <arm_neon.h>

// Four int32 coefficients in one NEON register. Each operation below
// works on the four lanes at once, with no branch and no memory access
// that depends on a lane's value.
typedef int32x4_t lanes;

// mld_montgomery_reduce(a * b) in each lane, for |a * b| at most 2^62.
// mldsa_poly.h computes (ab - tq) >> 32, where t is the low 32 bits of
// ab * q^-1. t is also the low 32 bits of (low 32 bits of ab) * q^-1, which
// two MULs give. ab - tq is a multiple of 2^32, so 2ab and 2tq agree in
// their low 33 bits. SQDMULH gives the high 32 bits of a doubled product,
// floor(2xy / 2^32), so high - low is exactly (ab - tq) / 2^31, an even
// value. SHSUB subtracts and halves in a wider intermediate, so each lane
// holds (ab - tq) / 2^32, the value of the scalar shift. That value is
// under 2^30 + q in absolute value, so it fits in 32 bits. SQDMULH
// saturates only when both operands are INT32_MIN. q is not, and no caller
// passes INT32_MIN for b: b is a twiddle factor, 41978, or a reduced
// coefficient, under 6291200 in absolute value.
static inline lanes montgomery_multiply(lanes a, lanes b) {
    lanes t = vmulq_s32(vmulq_s32(a, b), vdupq_n_s32((int32_t)MLD_QINV));
    lanes high = vqdmulhq_s32(a, b);
    lanes low = vqdmulhq_s32(t, vdupq_n_s32(MLD_Q));
    return vhsubq_s32(high, low);
}

// mld_reduce32(a) in each lane: a - t*q, where t = (a + 2^22) >> 23 in 64
// bits. Write a = 2^23*h + r with 0 <= r < 2^23. Then t = h + 1 when
// r >= 2^22 and t = h otherwise, so t is a >> 23 plus bit 22 of a, and no
// sum can overflow. MLS subtracts t*q modulo 2^32, and a - t*q fits in 32
// bits, so the lane holds it exactly. The shifts, the AND and the add are
// not one SRSHR, because Arm's list of data-independent-time instructions
// names SRSHR in its scalar form alone. clang joins the shift by 23 and
// the add into SSRA, as poly1305_vector.c's carry is USRA.
static inline lanes reduce32(lanes a) {
    uint32x4_t bit22 = vandq_u32(vshrq_n_u32(vreinterpretq_u32_s32(a), 22), vdupq_n_u32(1));
    lanes t = vaddq_s32(vshrq_n_s32(a, 23), vreinterpretq_s32_u32(bit22));
    return vmlsq_s32(a, t, vdupq_n_s32(MLD_Q));
}

// mld_poly_reduce: mld_reduce32 on every coefficient.
static void reduce_poly(int32_t w[MLD_N]) {
    for (unsigned i = 0; i < MLD_N; i += 4) {
        vst1q_s32(w + i, reduce32(vld1q_s32(w + i)));
    }
}

// (MLD_ZETAS[a], MLD_ZETAS[b], MLD_ZETAS[c], MLD_ZETAS[d]), each entry
// negated when negate is 1. The indices are the loops', which are public.
static inline lanes zetas_at(unsigned a, unsigned b, unsigned c, unsigned d, int negate) {
    int32_t sign = negate ? -1 : 1;
    const int32_t z[4] = {sign * MLD_ZETAS[a], sign * MLD_ZETAS[b], sign * MLD_ZETAS[c],
                          sign * MLD_ZETAS[d]};
    return vld1q_s32(z);
}

// Four vectors as a 4x4 matrix of coefficients: row r, lane l moves to row
// l, lane r. TRN1 and TRN2 exchange the odd lanes of rows 0 and 1 and of
// rows 2 and 3, and the 64-bit halves then move across.
static inline void transpose(lanes v[4]) {
    int32x4x2_t first = vtrnq_s32(v[0], v[1]);
    int32x4x2_t second = vtrnq_s32(v[2], v[3]);
    v[0] = vcombine_s32(vget_low_s32(first.val[0]), vget_low_s32(second.val[0]));
    v[1] = vcombine_s32(vget_low_s32(first.val[1]), vget_low_s32(second.val[1]));
    v[2] = vcombine_s32(vget_high_s32(first.val[0]), vget_high_s32(second.val[0]));
    v[3] = vcombine_s32(vget_high_s32(first.val[1]), vget_high_s32(second.val[1]));
}

// mld_poly_ntt's butterfly on four pairs: lo + zeta*hi and lo - zeta*hi.
static inline void butterfly(lanes *lo, lanes *hi, lanes zeta) {
    lanes t = montgomery_multiply(*hi, zeta);
    *hi = vsubq_s32(*lo, t);
    *lo = vaddq_s32(*lo, t);
}

// mld_poly_invntt_tomont's butterfly on four pairs: lo + hi, and
// zeta*(lo - hi).
static inline void butterfly_inverse(lanes *lo, lanes *hi, lanes zeta) {
    lanes t = *lo;
    *lo = vaddq_s32(t, *hi);
    *hi = montgomery_multiply(vsubq_s32(t, *hi), zeta);
}

// The forward layers of span 2 and 1 on the 16 coefficients of blocks
// first to first + 3, four coefficients each. After the transpose, lane i
// of each vector holds block first + i, and vector k its coefficient k.
// mld_poly_ntt reads twiddle 64 + b for block b's layer of span 2, and
// 128 + 2b and 129 + 2b for its two pairs of span 1.
static void forward_last_layers(int32_t *w, unsigned first) {
    lanes v[4] = {vld1q_s32(w), vld1q_s32(w + 4), vld1q_s32(w + 8), vld1q_s32(w + 12)};
    transpose(v);
    unsigned b = first;
    lanes span2 = zetas_at(64 + b, 65 + b, 66 + b, 67 + b, 0);
    butterfly(&v[0], &v[2], span2);
    butterfly(&v[1], &v[3], span2);
    lanes span1_low = zetas_at(128 + 2 * b, 130 + 2 * b, 132 + 2 * b, 134 + 2 * b, 0);
    lanes span1_high = zetas_at(129 + 2 * b, 131 + 2 * b, 133 + 2 * b, 135 + 2 * b, 0);
    butterfly(&v[0], &v[1], span1_low);
    butterfly(&v[2], &v[3], span1_high);
    transpose(v);
    for (size_t k = 0; k < 4; k++) {
        vst1q_s32(w + 4 * k, v[k]);
    }
}

// mld_poly_ntt: the reduction, the layers of span 128 down to 4 on four
// consecutive coefficients at a time, and the last two layers on four
// blocks at a time. Each layer reads the twiddles the loop reads, in the
// same order.
void mld_vector_ntt(mld_poly *p) {
    int32_t *w = p->coeffs;
    reduce_poly(w);
    unsigned m = 0;
    for (unsigned len = 128; len >= 4; len >>= 1) {
        for (unsigned start = 0; start < MLD_N; start += 2 * len) {
            m++;
            lanes zeta = vdupq_n_s32(MLD_ZETAS[m]);
            for (unsigned j = start; j < start + len; j += 4) {
                lanes lo = vld1q_s32(w + j);
                lanes hi = vld1q_s32(w + j + len);
                butterfly(&lo, &hi, zeta);
                vst1q_s32(w + j, lo);
                vst1q_s32(w + j + len, hi);
            }
        }
    }
    for (size_t block = 0; block < MLD_N / 4; block += 4) {
        forward_last_layers(w + 4 * block, (unsigned)block);
    }
}

// The inverse layers of span 1 and 2 on the 16 coefficients of blocks
// first to first + 3, transposed as in forward_last_layers. The loop's
// twiddle index runs down from 256: the layer of span 1 reads 255 - 2b and
// 254 - 2b for block b's two pairs, and the layer of span 2 reads 127 - b.
// Each twiddle is negated, as the loop negates it.
static void inverse_first_layers(int32_t *w, unsigned first) {
    lanes v[4] = {vld1q_s32(w), vld1q_s32(w + 4), vld1q_s32(w + 8), vld1q_s32(w + 12)};
    transpose(v);
    unsigned b = first;
    lanes span1_low = zetas_at(255 - 2 * b, 253 - 2 * b, 251 - 2 * b, 249 - 2 * b, 1);
    lanes span1_high = zetas_at(254 - 2 * b, 252 - 2 * b, 250 - 2 * b, 248 - 2 * b, 1);
    butterfly_inverse(&v[0], &v[1], span1_low);
    butterfly_inverse(&v[2], &v[3], span1_high);
    lanes span2 = zetas_at(127 - b, 126 - b, 125 - b, 124 - b, 1);
    butterfly_inverse(&v[0], &v[2], span2);
    butterfly_inverse(&v[1], &v[3], span2);
    transpose(v);
    for (size_t k = 0; k < 4; k++) {
        vst1q_s32(w + 4 * k, v[k]);
    }
}

// mld_poly_invntt_tomont: the reduction, the first two layers on four
// blocks at a time, the layers of span 4 up to 128 on four consecutive
// coefficients at a time, and the multiply by 41978 = 2^64 / 256 mod q.
void mld_vector_invntt_tomont(mld_poly *p) {
    int32_t *w = p->coeffs;
    reduce_poly(w);
    for (size_t block = 0; block < MLD_N / 4; block += 4) {
        inverse_first_layers(w + 4 * block, (unsigned)block);
    }
    unsigned m = MLD_N / 4;
    for (unsigned len = 4; len < MLD_N; len <<= 1) {
        for (unsigned start = 0; start < MLD_N; start += 2 * len) {
            m--;
            lanes zeta = vdupq_n_s32(-MLD_ZETAS[m]);
            for (unsigned j = start; j < start + len; j += 4) {
                lanes lo = vld1q_s32(w + j);
                lanes hi = vld1q_s32(w + j + len);
                butterfly_inverse(&lo, &hi, zeta);
                vst1q_s32(w + j, lo);
                vst1q_s32(w + j + len, hi);
            }
        }
    }
    lanes factor = vdupq_n_s32(41978);
    for (unsigned j = 0; j < MLD_N; j += 4) {
        vst1q_s32(w + j, montgomery_multiply(vld1q_s32(w + j), factor));
    }
}

// Each group of four reads a, b and acc before it writes, so r or acc may
// be a or b.
void mld_vector_pointwise(mld_poly *r, const mld_poly *a, const mld_poly *b) {
    for (unsigned i = 0; i < MLD_N; i += 4) {
        lanes x = reduce32(vld1q_s32(a->coeffs + i));
        lanes y = reduce32(vld1q_s32(b->coeffs + i));
        vst1q_s32(r->coeffs + i, montgomery_multiply(x, y));
    }
}

void mld_vector_pointwise_acc(mld_poly *acc, const mld_poly *a, const mld_poly *b) {
    for (unsigned i = 0; i < MLD_N; i += 4) {
        lanes x = reduce32(vld1q_s32(a->coeffs + i));
        lanes y = reduce32(vld1q_s32(b->coeffs + i));
        lanes sum = reduce32(vld1q_s32(acc->coeffs + i));
        vst1q_s32(acc->coeffs + i, vaddq_s32(sum, montgomery_multiply(x, y)));
    }
}

#else // __ARM_NEON: the AVX2 arm for x86-64 (docs/decisions.md 174)

#include <immintrin.h>

// Every function from here to the pop below carries the target attribute
// that turns AVX2 on, and no function outside it does, as in
// keccak_avx2.c. So the rest of the object runs on any x86-64 CPU, and
// mld_vector_runs calls this arm only for a session whose ch_cfg.cpu holds
// CH_CPU_AVX2.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx2")
#endif

// Eight int32 coefficients in one AVX2 register. Each operation below
// works on the eight lanes at once, with no branch and no memory access
// that depends on a lane's value.
typedef __m256i lanes;

static inline lanes load(const int32_t *from) {
    return _mm256_loadu_si256((const __m256i *)(const void *)from);
}

static inline void store(int32_t *to, lanes v) {
    _mm256_storeu_si256((__m256i *)(void *)to, v);
}

// mld_montgomery_reduce(a * b) in each lane, for every int32 a and b.
// VPMULDQ multiplies the low 32 bits of each 64-bit lane as signed values
// to a 64-bit product. So one VPMULDQ gives ab for the even lanes, and one
// more after a shift by 32 gives it for the odd lanes. ab is exact, and
// |ab| <= 2^62. VPMULLD keeps the low 32 bits of a product, and the low 32
// bits of ab times q^-1 are t, the scalar's t, as bits. VPMULDQ then gives
// tq exactly. |tq| < 2^31 * q < 2^54, so the 64-bit difference ab - tq
// does not overflow. Its low 32 bits are zero, so its high 32 bits, read
// as int32, are (ab - tq) / 2^32, the value of the scalar shift. That
// value is under 2^30 + q in absolute value, so it fits in 32 bits. The
// blend puts the even lanes' high halves, shifted down, beside the odd
// lanes' high halves, which are in place.
static inline lanes montgomery_multiply(lanes a, lanes b) {
    const lanes q = _mm256_set1_epi32(MLD_Q);
    const lanes qinv = _mm256_set1_epi32((int32_t)MLD_QINV);
    lanes even = _mm256_mul_epi32(a, b);
    lanes odd = _mm256_mul_epi32(_mm256_srli_epi64(a, 32), _mm256_srli_epi64(b, 32));
    lanes t_even = _mm256_mullo_epi32(even, qinv);
    lanes t_odd = _mm256_mullo_epi32(odd, qinv);
    even = _mm256_sub_epi64(even, _mm256_mul_epi32(t_even, q));
    odd = _mm256_sub_epi64(odd, _mm256_mul_epi32(t_odd, q));
    return _mm256_blend_epi32(_mm256_srli_epi64(even, 32), odd, 0xAA);
}

// mld_reduce32(a) in each lane, as the NEON arm computes it: t is a >> 23
// plus bit 22 of a, which is (a + 2^22) >> 23 in 64 bits, and no sum can
// overflow. |t| <= 256, so VPMULLD gives t*q exactly, and a - t*q fits in
// 32 bits.
static inline lanes reduce32(lanes a) {
    lanes bit22 = _mm256_and_si256(_mm256_srli_epi32(a, 22), _mm256_set1_epi32(1));
    lanes t = _mm256_add_epi32(_mm256_srai_epi32(a, 23), bit22);
    return _mm256_sub_epi32(a, _mm256_mullo_epi32(t, _mm256_set1_epi32(MLD_Q)));
}

// mld_poly_reduce: mld_reduce32 on every coefficient.
static void reduce_poly(int32_t w[MLD_N]) {
    for (unsigned i = 0; i < MLD_N; i += 8) {
        store(w + i, reduce32(load(w + i)));
    }
}

// mld_poly_ntt's butterfly on eight pairs: lo + zeta*hi and lo - zeta*hi.
static inline void butterfly(lanes *lo, lanes *hi, lanes zeta) {
    lanes t = montgomery_multiply(*hi, zeta);
    *hi = _mm256_sub_epi32(*lo, t);
    *lo = _mm256_add_epi32(*lo, t);
}

// mld_poly_invntt_tomont's butterfly on eight pairs: lo + hi, and
// zeta*(lo - hi).
static inline void butterfly_inverse(lanes *lo, lanes *hi, lanes zeta) {
    lanes t = *lo;
    *lo = _mm256_add_epi32(t, *hi);
    *hi = montgomery_multiply(_mm256_sub_epi32(t, *hi), zeta);
}

// The last three layers, and the first three of the inverse, pair
// coefficients 4, 2 and 1 apart, inside one register. So those layers take
// 16 coefficients c0 to c15 in two registers, a and b, and move them with
// three exchanges. Each exchange cuts both registers into parts of one
// size. In each pair of parts, a = (x0, x1) and b = (y0, y1) become
// (x0, y0) and (x1, y1), so each exchange done twice gives back its input.
//
//   - exchange_halves, on 128-bit parts (VPERM2I128), takes c0..c7 and
//     c8..c15 to a = c0-c3 c8-c11 and b = c4-c7 c12-c15: lane i of a and
//     lane i of b are 4 apart.
//   - exchange_pairs, on 64-bit parts (VPUNPCKLQDQ and VPUNPCKHQDQ), then
//     gives a = c0 c1 c4 c5 c8 c9 c12 c13 and b = c2 c3 c6 c7 c10 c11 c14
//     c15: 2 apart.
//   - exchange_words, on 32-bit parts (shifts by 32 and VPBLENDD), then
//     gives a = c0 c2 c4 c6 c8 c10 c12 c14 and b = c1 c3 ... c15: 1 apart.
//
// The same three in the other order put c0 to c15 back in place.
static inline void exchange_halves(lanes *a, lanes *b) {
    lanes first = _mm256_permute2x128_si256(*a, *b, 0x20);
    *b = _mm256_permute2x128_si256(*a, *b, 0x31);
    *a = first;
}

static inline void exchange_pairs(lanes *a, lanes *b) {
    lanes first = _mm256_unpacklo_epi64(*a, *b);
    *b = _mm256_unpackhi_epi64(*a, *b);
    *a = first;
}

static inline void exchange_words(lanes *a, lanes *b) {
    lanes first = _mm256_blend_epi32(*a, _mm256_slli_epi64(*b, 32), 0xAA);
    *b = _mm256_blend_epi32(_mm256_srli_epi64(*a, 32), *b, 0xAA);
    *a = first;
}

// Lane i takes MLD_ZETAS[at + order[i]], negated when negate is 1. VPERMD
// moves the eight entries from at. at and order are the loops' indices,
// which are public, and at + 7 is at most 255.
static inline lanes zetas_at(unsigned at, lanes order, int negate) {
    lanes z = _mm256_permutevar8x32_epi32(load(&MLD_ZETAS[at]), order);
    return negate ? _mm256_sub_epi32(_mm256_setzero_si256(), z) : z;
}

// The forward layers of span 4, 2 and 1 on the 16 coefficients of block k,
// at w = 16k. mld_poly_ntt reads twiddle 32 + 2k for c0..c7's layer of
// span 4 and 33 + 2k for c8..c15's. It reads 64 + 4k to 67 + 4k for the
// four groups of span 2, and 128 + 8k to 135 + 8k for the eight pairs of
// span 1, which are in lane order after exchange_words.
static void forward_last_layers(int32_t *w, unsigned k) {
    lanes a = load(w);
    lanes b = load(w + 8);
    exchange_halves(&a, &b);
    butterfly(&a, &b, zetas_at(32 + 2 * k, _mm256_setr_epi32(0, 0, 0, 0, 1, 1, 1, 1), 0));
    exchange_pairs(&a, &b);
    butterfly(&a, &b, zetas_at(64 + 4 * k, _mm256_setr_epi32(0, 0, 1, 1, 2, 2, 3, 3), 0));
    exchange_words(&a, &b);
    butterfly(&a, &b, load(&MLD_ZETAS[128 + 8 * k]));
    exchange_words(&a, &b);
    exchange_pairs(&a, &b);
    exchange_halves(&a, &b);
    store(w, a);
    store(w + 8, b);
}

// mld_poly_ntt: the reduction, the layers of span 128 down to 8 on eight
// consecutive coefficients at a time, and the last three layers on 16
// coefficients at a time. Each layer reads the twiddles the loop reads.
void mld_vector_ntt(mld_poly *p) {
    int32_t *w = p->coeffs;
    reduce_poly(w);
    unsigned m = 0;
    for (unsigned len = 128; len >= 8; len >>= 1) {
        for (unsigned start = 0; start < MLD_N; start += 2 * len) {
            m++;
            lanes zeta = _mm256_set1_epi32(MLD_ZETAS[m]);
            for (unsigned j = start; j < start + len; j += 8) {
                lanes lo = load(w + j);
                lanes hi = load(w + j + len);
                butterfly(&lo, &hi, zeta);
                store(w + j, lo);
                store(w + j + len, hi);
            }
        }
    }
    for (unsigned k = 0; k < MLD_N / 16; k++) {
        forward_last_layers(w + 16 * k, k);
    }
    // The signer's lanes hold s1, y or c here. VZEROALL writes zero to ymm0
    // to ymm15, as at the end of each entry below (docs/decisions.md 129).
    _mm256_zeroall();
}

// The inverse layers of span 1, 2 and 4 on the 16 coefficients of block k,
// moved as in forward_last_layers. The loop's twiddle index runs down from
// 256. The layer of span 1 reads 255 - 8k down to 248 - 8k for the eight
// pairs, the layer of span 2 reads 127 - 4k down to 124 - 4k, and the
// layer of span 4 reads 63 - 2k and 62 - 2k. Each twiddle is negated, as
// the loop negates it.
static void inverse_first_layers(int32_t *w, unsigned k) {
    lanes a = load(w);
    lanes b = load(w + 8);
    exchange_halves(&a, &b);
    exchange_pairs(&a, &b);
    exchange_words(&a, &b);
    butterfly_inverse(&a, &b, zetas_at(248 - 8 * k, _mm256_setr_epi32(7, 6, 5, 4, 3, 2, 1, 0), 1));
    exchange_words(&a, &b);
    butterfly_inverse(&a, &b, zetas_at(120 - 4 * k, _mm256_setr_epi32(7, 7, 6, 6, 5, 5, 4, 4), 1));
    exchange_pairs(&a, &b);
    butterfly_inverse(&a, &b, zetas_at(56 - 2 * k, _mm256_setr_epi32(7, 7, 7, 7, 6, 6, 6, 6), 1));
    exchange_halves(&a, &b);
    store(w, a);
    store(w + 8, b);
}

// mld_poly_invntt_tomont: the reduction, the first three layers on 16
// coefficients at a time, the layers of span 8 up to 128 on eight
// consecutive coefficients at a time, and the multiply by 41978.
void mld_vector_invntt_tomont(mld_poly *p) {
    int32_t *w = p->coeffs;
    reduce_poly(w);
    for (unsigned k = 0; k < MLD_N / 16; k++) {
        inverse_first_layers(w + 16 * k, k);
    }
    unsigned m = MLD_N / 8;
    for (unsigned len = 8; len < MLD_N; len <<= 1) {
        for (unsigned start = 0; start < MLD_N; start += 2 * len) {
            m--;
            lanes zeta = _mm256_set1_epi32(-MLD_ZETAS[m]);
            for (unsigned j = start; j < start + len; j += 8) {
                lanes lo = load(w + j);
                lanes hi = load(w + j + len);
                butterfly_inverse(&lo, &hi, zeta);
                store(w + j, lo);
                store(w + j + len, hi);
            }
        }
    }
    lanes factor = _mm256_set1_epi32(41978);
    for (unsigned j = 0; j < MLD_N; j += 8) {
        store(w + j, montgomery_multiply(load(w + j), factor));
    }
    _mm256_zeroall();
}

// Each group of eight reads a, b and acc before it writes, so r or acc may
// be a or b.
void mld_vector_pointwise(mld_poly *r, const mld_poly *a, const mld_poly *b) {
    for (unsigned i = 0; i < MLD_N; i += 8) {
        lanes x = reduce32(load(a->coeffs + i));
        lanes y = reduce32(load(b->coeffs + i));
        store(r->coeffs + i, montgomery_multiply(x, y));
    }
    _mm256_zeroall();
}

void mld_vector_pointwise_acc(mld_poly *acc, const mld_poly *a, const mld_poly *b) {
    for (unsigned i = 0; i < MLD_N; i += 8) {
        lanes x = reduce32(load(a->coeffs + i));
        lanes y = reduce32(load(b->coeffs + i));
        lanes sum = reduce32(load(acc->coeffs + i));
        store(acc->coeffs + i, _mm256_add_epi32(sum, montgomery_multiply(x, y)));
    }
    _mm256_zeroall();
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // __ARM_NEON

#endif // MLD_VECTOR
