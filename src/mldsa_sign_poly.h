// The constant-time ring arithmetic of ML-DSA-87 signing (FIPS 204
// sections 7.5 and 7.6, Appendix A), private to the signer's files
// (docs/decisions.md 159). mldsa_poly.c computes the same transforms for
// the verifier on public values, with the native widening multiply. Here
// every operand may be a secret: s1, s2, t0, y and the products with c.
// So every widening product goes through ct.h's ct_widemul_s, and no
// function here branches on a coefficient or indexes memory with one.
//
// A polynomial is mldsa_poly.h's mld_poly. As in mldsa_poly.h, every
// function takes every int32_t value in every coefficient: each one
// reduces its inputs before it adds or multiplies them. The coefficient
// functions sit in this header, so that a harness can replace each one
// with its contract (proof/mldsa_sign_stubs.h).
#ifndef CH_MLDSA_SIGN_POLY_H
#define CH_MLDSA_SIGN_POLY_H

#include <stdint.h>

#include "cpu_cfg.h"
#include "ct.h"
#include "mldsa_poly.h"
#include "mldsa_vector.h"

// A value congruent to a mod q, with |result| <= 6291200, for every int32_t
// a: a minus round(a / 2^23) times q. t is at most 256 in absolute value,
// and the difference fits int32_t, so the product and the difference run on
// uint32_t, where they wrap, and no widening multiply runs.
static inline int32_t mlds_reduce32(int32_t a) {
    int32_t t = (int32_t)(((int64_t)a + (1 << 22)) >> 23);
    return (int32_t)((uint32_t)a - (uint32_t)t * (uint32_t)MLD_Q);
}

// a * 2^-32 mod q for |a| at most 2^31 * q, under q in absolute value. The
// low 32 bits of a * q^-1 are a 32-bit product, and t * q is ct_widemul_s's.
static inline int32_t mlds_montgomery_reduce(int64_t a) {
    int32_t t = (int32_t)((uint32_t)(uint64_t)a * MLD_QINV);
    return (int32_t)((a - ct_widemul_s(t, MLD_Q)) >> 32);
}

// zeta * a * 2^-32 mod q, for |zeta| <= (q - 1) / 2 and every int32_t a.
static inline int32_t mlds_mul_zeta(int32_t zeta, int32_t a) {
    return mlds_montgomery_reduce(ct_widemul_s(zeta, a));
}

// a * b * 2^-32 mod q, under q in absolute value, for every int32_t a and b.
static inline int32_t mlds_mul_reduced(int32_t a, int32_t b) {
    return mlds_montgomery_reduce(ct_widemul_s(mlds_reduce32(a), mlds_reduce32(b)));
}

// a mod q in [0, q), for every int32_t a. The reduced value lies in
// (-q, q), and the mask of its sign adds q to a negative one.
static inline int32_t mlds_freeze(int32_t a) {
    int32_t r = mlds_reduce32(a);
    return r + ((r >> 31) & MLD_Q);
}

// a mod+- q in [-(q - 1) / 2, (q - 1) / 2], for every int32_t a.
static inline int32_t mlds_center(int32_t a) {
    int32_t r = mlds_freeze(a);
    return r - ((((MLD_Q - 1) / 2) - r) >> 31 & MLD_Q);
}

// FIPS 204 Algorithm 41, NTT, as mld_poly_ntt computes it: the input is
// reduced first, and the output stays under 2^27 in absolute value.
void mlds_poly_ntt(mld_poly *p);

// FIPS 204 Algorithm 42, NTT^-1, times 2^32, as mld_poly_invntt_tomont
// computes it. The output is under q in absolute value.
void mlds_poly_invntt_tomont(mld_poly *p);

// r = a o b * 2^-32 (FIPS 204 Algorithm 45, MultiplyNTT). r may be a or b.
void mlds_poly_pointwise(mld_poly *r, const mld_poly *a, const mld_poly *b);

// acc = acc + a o b * 2^-32, with acc reduced before the sum. acc may be a
// or b. The sum is under 6291200 + q, below 2^24.
void mlds_poly_pointwise_acc(mld_poly *acc, const mld_poly *a, const mld_poly *b);

// r = NTT^-1(a_hat o b_hat), each coefficient in [-(q - 1) / 2, (q - 1) / 2].
// For a_hat = NTT(c) and b_hat = NTT(s) this is the product c * s in R_q.
// r may be a_hat or b_hat.
void mlds_poly_product(mld_poly *r, const mld_poly *a_hat, const mld_poly *b_hat);

// p = NTT^-1(p), each coefficient in [0, q): the row of A * v after its sum.
void mlds_poly_invntt_freeze(mld_poly *p);

#if MLD_VECTOR
// mlds_center on each coefficient of p: each in [-(q - 1) / 2, (q - 1) / 2].
void mlds_poly_center(mld_poly *p);

// mlds_freeze on each coefficient of p: each in [0, q).
void mlds_poly_freeze(mld_poly *p);
#endif

// The dispatchers the signer's steps call, with the session's ch_cfg.cpu
// first (docs/decisions.md 172 and 174). Each computes what the mlds_poly_
// function of its name computes. In a host object, for a cpu that holds
// CH_CPU_CONSTANT_TIME_MULTIPLY, and on x86-64 CH_CPU_AVX2 beside it, it
// runs mldsa_vector.c's lanes, whose 32x32 products the multiply bit
// covers. For every other cpu, and in every other object, it runs the
// loops above on ct.h's 16x16 pieces. That is one branch per call, on cpu,
// which the caller chose and which is not secret. A call that holds no cpu
// passes 0, which names no lanes.
static inline int mlds_lanes_run(uint32_t cpu) {
    return mld_vector_runs(cpu, 1);
}

static inline void mlds_ntt(uint32_t cpu, mld_poly *p) {
#if MLD_VECTOR
    if (mlds_lanes_run(cpu)) {
        mld_vector_ntt(p);
        return;
    }
#else
    (void)cpu;
#endif
    mlds_poly_ntt(p);
}

static inline void mlds_pointwise(uint32_t cpu, mld_poly *r, const mld_poly *a, const mld_poly *b) {
#if MLD_VECTOR
    if (mlds_lanes_run(cpu)) {
        mld_vector_pointwise(r, a, b);
        return;
    }
#else
    (void)cpu;
#endif
    mlds_poly_pointwise(r, a, b);
}

static inline void mlds_pointwise_acc(uint32_t cpu, mld_poly *acc, const mld_poly *a,
                                      const mld_poly *b) {
#if MLD_VECTOR
    if (mlds_lanes_run(cpu)) {
        mld_vector_pointwise_acc(acc, a, b);
        return;
    }
#else
    (void)cpu;
#endif
    mlds_poly_pointwise_acc(acc, a, b);
}

static inline void mlds_product(uint32_t cpu, mld_poly *r, const mld_poly *a_hat,
                                const mld_poly *b_hat) {
#if MLD_VECTOR
    if (mlds_lanes_run(cpu)) {
        mld_vector_pointwise(r, a_hat, b_hat);
        mld_vector_invntt_tomont(r);
        mlds_poly_center(r);
        return;
    }
#else
    (void)cpu;
#endif
    mlds_poly_product(r, a_hat, b_hat);
}

static inline void mlds_invntt_freeze(uint32_t cpu, mld_poly *p) {
#if MLD_VECTOR
    if (mlds_lanes_run(cpu)) {
        mld_vector_invntt_tomont(p);
        mlds_poly_freeze(p);
        return;
    }
#else
    (void)cpu;
#endif
    mlds_poly_invntt_freeze(p);
}

#endif
