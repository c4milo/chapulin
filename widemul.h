// The one place an operation built on ct.h's widening multiply chooses the multiply it runs
// (docs/decisions.md 87 and 89, https://github.com/c4milo/chapulin/issues/186).
//
// Seven files multiply through ct.h: poly1305.c, poly1305_vector.c, x25519.c, mlkem_poly.c,
// p256_field.c, p256_scalar.c and rsa_sign.c. Each entry of theirs that runs the multiply,
// called from outside them, has a dispatcher below, named for it with the widemul_ prefix. The
// dispatcher's first argument is the answer the operation runs under, a WIDEMUL_ value below.
// Every caller outside those files calls the dispatcher and passes on the answer it was
// handed; a session passes its own, widemul_answer. An entry that multiplies nothing, such as
// poly1305_init or p256_fe_add, is called under its own name.
//
// A device object holds one multiply and compiles each file once, so each dispatcher calls that
// copy and reads no answer. A host object (-DCH_CPU_RUNTIME, cpu_cfg.h) holds each operation
// twice. poly1305.c, mlkem_poly.c, p256_field.c, p256_scalar.c and rsa_sign.c compile under their
// own names on the decomposition, as a WIDEMUL=decomposed device object compiles them, and again
// as <file>_native.c on the native multiply, with every name widemul_native.h lists ending in
// _native. poly1305_vector.c compiles as its native copy alone. x25519.c compiles under its own
// names alone, and X25519's second copy is x25519_wide.c, the radix-2^51 field on the 64x64->128
// multiply (x25519_wide.h). The dispatchers run the native copy, and for X25519 the wide field,
// for WIDEMUL_CONSTANT_TIME, and the file under its
// own names for every other byte. That is one branch per call, on the answer, which the caller's
// ch_cfg.cpu chose and which is not secret: never one per product, and through no function
// pointer. Poly1305 takes one per update and one per final, P-256 one per field or scalar
// multiply.
#ifndef CH_WIDEMUL_H
#define CH_WIDEMUL_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "ct.h"
#include "mlkem_poly.h"
#include "p256_field.h"
#include "p256_scalar.h"
#include "poly1305.h"
#include "rsa_sign.h"
#include "x25519.h"
#include "x25519_wide.h"

// The two answers an operation built on the multiply runs under. WIDEMUL_CONSTANT_TIME says the
// multiply runs in constant time on this CPU, in the mode the session's thread runs in, and takes
// the native multiply, 32x32->64 and 64x64->128 alike. WIDEMUL_NOT_STATED says nothing states
// that, and takes ct.h's 16x16
// decomposition. A host object's session runs under the first when its caller set
// CH_CPU_CONSTANT_TIME_MULTIPLY in ch_cfg.cpu, and under the second when it did not
// (widemul_answer). A device object runs every operation under the one its build states,
// WIDEMUL_BUILD_ANSWER.
#define WIDEMUL_CONSTANT_TIME 1
#define WIDEMUL_NOT_STATED 2

#ifdef CH_CPU_RUNTIME

// The answer a description of the CPU gives: WIDEMUL_CONSTANT_TIME when cpu, a session's
// ch_cfg.cpu, holds CH_CPU_CONSTANT_TIME_MULTIPLY, and WIDEMUL_NOT_STATED when it does not. A
// wiped record direction's 0 gives the second.
static inline uint8_t widemul_of_cpu(uint32_t cpu) {
    return (cpu & CH_CPU_CONSTANT_TIME_MULTIPLY) != 0 ? WIDEMUL_CONSTANT_TIME : WIDEMUL_NOT_STATED;
}

// The answer the operations of a session configured by cfg run under: the one its ch_cfg.cpu
// gives. Every init call and ch_srv_check have accepted the value by then (cpu_bits_ok, cpu.h).
static inline uint8_t widemul_answer(const ch_cfg *cfg) {
    return widemul_of_cpu(cfg->cpu);
}

// Whether an operation under the answer widemul runs the native copy: for
// WIDEMUL_CONSTANT_TIME alone, so every other byte takes the decomposition.
static inline int widemul_native(uint8_t widemul) {
    return widemul == WIDEMUL_CONSTANT_TIME;
}

static inline void widemul_poly1305_update(uint8_t widemul, poly1305 *p, const uint8_t *in,
                                           size_t n) {
    if (widemul_native(widemul)) {
        poly1305_update_native(p, in, n);
        return;
    }
    poly1305_update(p, in, n);
}

static inline void widemul_poly1305_final(uint8_t widemul, poly1305 *p, uint8_t tag[POLY1305_TAG]) {
    if (widemul_native(widemul)) {
        poly1305_final_native(p, tag);
        return;
    }
    poly1305_final(p, tag);
}

static inline int widemul_x25519(uint8_t widemul, uint8_t out[X25519_LEN],
                                 const uint8_t scalar[X25519_LEN],
                                 const uint8_t point[X25519_LEN]) {
    if (widemul_native(widemul)) {
        return x25519_wide(out, scalar, point);
    }
    return x25519(out, scalar, point);
}

static inline void widemul_x25519_base(uint8_t widemul, uint8_t out[X25519_LEN],
                                       const uint8_t scalar[X25519_LEN]) {
    if (widemul_native(widemul)) {
        x25519_wide_base(out, scalar);
        return;
    }
    x25519_base(out, scalar);
}

static inline void widemul_mlk_polyvec_compress(uint8_t widemul,
                                                uint8_t out[MLK_POLYVEC_COMP_BYTES],
                                                const mlk_polyvec *v) {
    if (widemul_native(widemul)) {
        mlk_polyvec_compress_native(out, v);
        return;
    }
    mlk_polyvec_compress(out, v);
}

static inline void widemul_mlk_poly_compress(uint8_t widemul, uint8_t out[MLK_POLY_COMP_BYTES],
                                             const mlk_poly *p) {
    if (widemul_native(widemul)) {
        mlk_poly_compress_native(out, p);
        return;
    }
    mlk_poly_compress(out, p);
}

static inline void widemul_mlk_poly_tomsg(uint8_t widemul, uint8_t msg[32], const mlk_poly *p) {
    if (widemul_native(widemul)) {
        mlk_poly_tomsg_native(msg, p);
        return;
    }
    mlk_poly_tomsg(msg, p);
}

static inline void widemul_p256_fe_mul(uint8_t widemul, p256_fe *o, const p256_fe *a,
                                       const p256_fe *b) {
    if (widemul_native(widemul)) {
        p256_fe_mul_native(o, a, b);
        return;
    }
    p256_fe_mul(o, a, b);
}

static inline void widemul_p256_fe_sqr(uint8_t widemul, p256_fe *o, const p256_fe *a) {
    if (widemul_native(widemul)) {
        p256_fe_sqr_native(o, a);
        return;
    }
    p256_fe_sqr(o, a);
}

static inline void widemul_p256_fe_to_mont(uint8_t widemul, p256_fe *o, const p256_fe *a) {
    if (widemul_native(widemul)) {
        p256_fe_to_mont_native(o, a);
        return;
    }
    p256_fe_to_mont(o, a);
}

static inline void widemul_p256_fe_from_mont(uint8_t widemul, p256_fe *o, const p256_fe *a) {
    if (widemul_native(widemul)) {
        p256_fe_from_mont_native(o, a);
        return;
    }
    p256_fe_from_mont(o, a);
}

static inline void widemul_p256_fe_inv(uint8_t widemul, p256_fe *o, const p256_fe *a) {
    if (widemul_native(widemul)) {
        p256_fe_inv_native(o, a);
        return;
    }
    p256_fe_inv(o, a);
}

static inline void widemul_p256_scalar_mul(uint8_t widemul, p256_scalar *o, const p256_scalar *a,
                                           const p256_scalar *b) {
    if (widemul_native(widemul)) {
        p256_scalar_mul_native(o, a, b);
        return;
    }
    p256_scalar_mul(o, a, b);
}

static inline void widemul_p256_scalar_inverse(uint8_t widemul, p256_scalar *o,
                                               const p256_scalar *a) {
    if (widemul_native(widemul)) {
        p256_scalar_inverse_native(o, a);
        return;
    }
    p256_scalar_inverse(o, a);
}

static inline int widemul_rsa_pss_sign(uint8_t widemul, const ch_rsa_priv *k,
                                       const uint8_t msg_hash[32],
                                       const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig,
                                       size_t cap, size_t *sig_len) {
    if (widemul_native(widemul)) {
        return rsa_pss_sign_native(k, msg_hash, salt, sig, cap, sig_len);
    }
    return rsa_pss_sign(k, msg_hash, salt, sig, cap, sig_len);
}

static inline void widemul_rsa_sp1(uint8_t widemul, const ch_rsa_priv *k, const uint8_t *em,
                                   uint8_t *sig) {
    if (widemul_native(widemul)) {
        rsa_sp1_native(k, em, sig);
        return;
    }
    rsa_sp1(k, em, sig);
}

#else // !CH_CPU_RUNTIME

// The answer every operation of a device object runs under: the one its build states, which
// ct.h reads from CH_NATIVE_WIDEMUL and CH_CT_WIDEMUL.
#ifdef CH_WIDEMUL_NATIVE
#define WIDEMUL_BUILD_ANSWER WIDEMUL_CONSTANT_TIME
#else
#define WIDEMUL_BUILD_ANSWER WIDEMUL_NOT_STATED
#endif

// The answer the operations of a session configured by cfg run under: the build's.
static inline uint8_t widemul_answer(const ch_cfg *cfg) {
    (void)cfg;
    return WIDEMUL_BUILD_ANSWER;
}

static inline void widemul_poly1305_update(uint8_t widemul, poly1305 *p, const uint8_t *in,
                                           size_t n) {
    (void)widemul;
    poly1305_update(p, in, n);
}

static inline void widemul_poly1305_final(uint8_t widemul, poly1305 *p, uint8_t tag[POLY1305_TAG]) {
    (void)widemul;
    poly1305_final(p, tag);
}

static inline int widemul_x25519(uint8_t widemul, uint8_t out[X25519_LEN],
                                 const uint8_t scalar[X25519_LEN],
                                 const uint8_t point[X25519_LEN]) {
    (void)widemul;
    return x25519(out, scalar, point);
}

static inline void widemul_x25519_base(uint8_t widemul, uint8_t out[X25519_LEN],
                                       const uint8_t scalar[X25519_LEN]) {
    (void)widemul;
    x25519_base(out, scalar);
}

static inline void widemul_mlk_polyvec_compress(uint8_t widemul,
                                                uint8_t out[MLK_POLYVEC_COMP_BYTES],
                                                const mlk_polyvec *v) {
    (void)widemul;
    mlk_polyvec_compress(out, v);
}

static inline void widemul_mlk_poly_compress(uint8_t widemul, uint8_t out[MLK_POLY_COMP_BYTES],
                                             const mlk_poly *p) {
    (void)widemul;
    mlk_poly_compress(out, p);
}

static inline void widemul_mlk_poly_tomsg(uint8_t widemul, uint8_t msg[32], const mlk_poly *p) {
    (void)widemul;
    mlk_poly_tomsg(msg, p);
}

static inline void widemul_p256_fe_mul(uint8_t widemul, p256_fe *o, const p256_fe *a,
                                       const p256_fe *b) {
    (void)widemul;
    p256_fe_mul(o, a, b);
}

static inline void widemul_p256_fe_sqr(uint8_t widemul, p256_fe *o, const p256_fe *a) {
    (void)widemul;
    p256_fe_sqr(o, a);
}

static inline void widemul_p256_fe_to_mont(uint8_t widemul, p256_fe *o, const p256_fe *a) {
    (void)widemul;
    p256_fe_to_mont(o, a);
}

static inline void widemul_p256_fe_from_mont(uint8_t widemul, p256_fe *o, const p256_fe *a) {
    (void)widemul;
    p256_fe_from_mont(o, a);
}

static inline void widemul_p256_fe_inv(uint8_t widemul, p256_fe *o, const p256_fe *a) {
    (void)widemul;
    p256_fe_inv(o, a);
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

static inline int widemul_rsa_pss_sign(uint8_t widemul, const ch_rsa_priv *k,
                                       const uint8_t msg_hash[32],
                                       const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig,
                                       size_t cap, size_t *sig_len) {
    (void)widemul;
    return rsa_pss_sign(k, msg_hash, salt, sig, cap, sig_len);
}

static inline void widemul_rsa_sp1(uint8_t widemul, const ch_rsa_priv *k, const uint8_t *em,
                                   uint8_t *sig) {
    (void)widemul;
    rsa_sp1(k, em, sig);
}

#endif // CH_CPU_RUNTIME

#endif
