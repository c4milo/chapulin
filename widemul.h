// The one place an operation built on ct.h's widening multiply chooses the multiply it runs
// (https://github.com/c4milo/chapulin/issues/186).
//
// Seven files multiply through ct.h: poly1305.c, poly1305_vector.c, x25519.c, mlkem_poly.c,
// p256_field.c, p256_scalar.c and rsa_sign.c. Each entry of theirs that reaches the multiply has
// a dispatcher below, named for it with the widemul_ prefix. The dispatcher's first argument is
// the answer the operation runs under, a CH_WIDEMUL_ value (cpu_cfg.h). Every caller outside the
// seven files calls the dispatcher and passes on the answer it was handed. An entry that
// multiplies nothing, such as poly1305_init or p256_fe_add, is called under its own name.
//
// An object that holds one multiply compiles each file once, so each dispatcher calls that copy
// and reads no answer.
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

// The answer every operation of an object that holds one multiply runs under: the one its
// build states, which ct.h reads from CH_NATIVE_WIDEMUL and CH_CT_WIDEMUL.
#ifdef CH_WIDEMUL_NATIVE
#define WIDEMUL_BUILD_ANSWER CH_WIDEMUL_CONSTANT_TIME
#else
#define WIDEMUL_BUILD_ANSWER CH_WIDEMUL_NOT_STATED
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

#endif
