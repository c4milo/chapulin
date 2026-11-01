#include "mldsa_vector.h"

// The whole file compiles only in an arm64 host object (mldsa_vector.h).
#if MLD_VECTOR

#include <arm_neon.h>

#include "mldsa_zetas.h"

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

#endif // MLD_VECTOR
