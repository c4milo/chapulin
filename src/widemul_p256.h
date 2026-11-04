// The dispatchers of widemul.h for P-256: the six point operations, the two scalar operations
// modulo the group order, and on x86-64 the choice of p256_adx.h's field. widemul.h includes this
// file at its end, and no other file includes it. The answers it reads are widemul_answer.h's.
// The rules are widemul.h's, and the file sits apart only to keep widemul.h under 500 lines.
#ifndef CH_WIDEMUL_P256_H
#define CH_WIDEMUL_P256_H

#include <stddef.h>
#include <stdint.h>

#include "p256_adx.h"
#include "p256_point.h"
#include "p256_scalar.h"
#include "p256_wide_mul.h"
#include "p256_wide_point.h"
#include "p256_wide_scalar.h"
#include "p256_wide_wipe.h"
#include "widemul_answer.h"

#ifdef CH_CPU_RUNTIME

#if defined(__x86_64__) || defined(CH_P256_ADX_MODEL)
// The dispatchers below hold p256_adx.h's field where it exists: on x86-64, and on any host in
// the model build, CH_P256_ADX_MODEL, so bin/p256_adx_model_test runs the dispatch over the
// model. arm64 has no such field, and there no bit picks here.
#define WIDEMUL_P256_ADX 1

// Whether a P-256 scalar multiplication, point decode, affine conversion or curve check under
// the answer widemul, in a session whose ch_cfg.cpu is cpu, runs p256_adx.h's field: under
// WIDEMUL_CONSTANT_TIME, whose statement covers MULX's 64x64->128 products, where cpu holds
// CH_CPU_BMI2_ADX, which says the CPU has BMI2 and ADX. The bit states no timing
// (docs/decisions.md 171).
static inline int widemul_p256_adx(uint32_t cpu, uint8_t widemul) {
    return widemul_native(widemul) && (cpu & CH_CPU_BMI2_ADX) != 0;
}
#endif

static inline void widemul_p256_point_mul(uint32_t cpu, uint8_t widemul, p256_point *o,
                                          const p256_scalar *k, const p256_point *p) {
#ifdef WIDEMUL_P256_ADX
    if (widemul_p256_adx(cpu, widemul)) {
        p256_adx_mul(o, k, p);
        p256_wide_wipe_below();
        return;
    }
#else
    (void)cpu;
#endif
    if (widemul_native(widemul)) {
        p256_wide_mul(o, k, p);
        p256_wide_wipe_below();
        return;
    }
    p256_point_mul(o, k, p);
}

static inline void widemul_p256_point_base_mul(uint32_t cpu, uint8_t widemul, p256_point *o,
                                               const p256_scalar *k) {
#ifdef WIDEMUL_P256_ADX
    if (widemul_p256_adx(cpu, widemul)) {
        p256_adx_base_mul(o, k);
        p256_wide_wipe_below();
        return;
    }
#else
    (void)cpu;
#endif
    if (widemul_native(widemul)) {
        p256_wide_base_mul(o, k);
        p256_wide_wipe_below();
        return;
    }
    p256_point_base_mul(o, k);
}

static inline uint32_t widemul_p256_point_from_bytes(uint32_t cpu, uint8_t widemul, p256_point *o,
                                                     const uint8_t in[P256_POINT_LEN]) {
#ifdef WIDEMUL_P256_ADX
    if (widemul_p256_adx(cpu, widemul)) {
        return p256_adx_point_from_bytes(o, in);
    }
#else
    (void)cpu;
#endif
    if (widemul_native(widemul)) {
        return p256_wide_point_from_bytes(o, in);
    }
    return p256_point_from_bytes(o, in);
}

static inline uint32_t widemul_p256_point_affine(uint32_t cpu, uint8_t widemul,
                                                 uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN],
                                                 const p256_point *a) {
#ifdef WIDEMUL_P256_ADX
    if (widemul_p256_adx(cpu, widemul)) {
        uint32_t finite = p256_adx_point_affine(x, y, a);
        p256_wide_wipe_below();
        return finite;
    }
#else
    (void)cpu;
#endif
    if (widemul_native(widemul)) {
        uint32_t finite = p256_wide_point_affine(x, y, a);
        p256_wide_wipe_below();
        return finite;
    }
    return p256_point_affine(x, y, a);
}

static inline uint32_t widemul_p256_point_on_curve(uint32_t cpu, uint8_t widemul,
                                                   const uint8_t x[P256_FE_LEN],
                                                   const uint8_t y[P256_FE_LEN]) {
#ifdef WIDEMUL_P256_ADX
    if (widemul_p256_adx(cpu, widemul)) {
        uint32_t on_curve = p256_adx_point_on_curve(x, y);
        p256_wide_wipe_below();
        return on_curve;
    }
#else
    (void)cpu;
#endif
    if (widemul_native(widemul)) {
        uint32_t on_curve = p256_wide_point_on_curve(x, y);
        p256_wide_wipe_below();
        return on_curve;
    }
    return p256_point_on_curve(x, y);
}

static inline uint32_t widemul_p256_point_affine_x(uint32_t cpu, uint8_t widemul,
                                                   uint8_t out[P256_FE_LEN], const p256_point *a) {
#ifdef WIDEMUL_P256_ADX
    if (widemul_p256_adx(cpu, widemul)) {
        uint32_t finite = p256_adx_point_affine(out, NULL, a);
        p256_wide_wipe_below();
        return finite;
    }
#else
    (void)cpu;
#endif
    if (widemul_native(widemul)) {
        uint32_t finite = p256_wide_point_affine(out, NULL, a);
        p256_wide_wipe_below();
        return finite;
    }
    return p256_point_affine_x(out, a);
}

static inline void widemul_p256_scalar_mul(uint8_t widemul, p256_scalar *o, const p256_scalar *a,
                                           const p256_scalar *b) {
    if (widemul_native(widemul)) {
        p256_wide_scalar_mul(o, a, b);
        p256_wide_wipe_below();
        return;
    }
    p256_scalar_mul(o, a, b);
}

static inline void widemul_p256_scalar_inverse(uint8_t widemul, p256_scalar *o,
                                               const p256_scalar *a) {
    if (widemul_native(widemul)) {
        p256_wide_scalar_inverse(o, a);
        p256_wide_wipe_below();
        return;
    }
    p256_scalar_inverse(o, a);
}

#else // !CH_CPU_RUNTIME

// A device object holds one P-256 field, so no dispatcher reads cpu or widemul.
static inline void widemul_p256_point_mul(uint32_t cpu, uint8_t widemul, p256_point *o,
                                          const p256_scalar *k, const p256_point *p) {
    (void)cpu;
    (void)widemul;
    p256_point_mul(o, k, p);
}

static inline void widemul_p256_point_base_mul(uint32_t cpu, uint8_t widemul, p256_point *o,
                                               const p256_scalar *k) {
    (void)cpu;
    (void)widemul;
    p256_point_base_mul(o, k);
}

static inline uint32_t widemul_p256_point_from_bytes(uint32_t cpu, uint8_t widemul, p256_point *o,
                                                     const uint8_t in[P256_POINT_LEN]) {
    (void)cpu;
    (void)widemul;
    return p256_point_from_bytes(o, in);
}

static inline uint32_t widemul_p256_point_affine(uint32_t cpu, uint8_t widemul,
                                                 uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN],
                                                 const p256_point *a) {
    (void)cpu;
    (void)widemul;
    return p256_point_affine(x, y, a);
}

static inline uint32_t widemul_p256_point_on_curve(uint32_t cpu, uint8_t widemul,
                                                   const uint8_t x[P256_FE_LEN],
                                                   const uint8_t y[P256_FE_LEN]) {
    (void)cpu;
    (void)widemul;
    return p256_point_on_curve(x, y);
}

static inline uint32_t widemul_p256_point_affine_x(uint32_t cpu, uint8_t widemul,
                                                   uint8_t out[P256_FE_LEN], const p256_point *a) {
    (void)cpu;
    (void)widemul;
    return p256_point_affine_x(out, a);
}

static inline void widemul_p256_scalar_mul(uint8_t widemul, p256_scalar *o, const p256_scalar *a,
                                           const p256_scalar *b) {
    (void)widemul;
    p256_scalar_mul(o, a, b);
}

static inline void widemul_p256_scalar_inverse(uint8_t widemul, p256_scalar *o,
                                               const p256_scalar *a) {
    (void)widemul;
    p256_scalar_inverse(o, a);
}

#endif // CH_CPU_RUNTIME

#endif
