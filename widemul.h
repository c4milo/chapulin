// The one place an operation built on ct.h's widening multiply chooses the multiply it runs
// (docs/decisions.md 87, 89 and 94, https://github.com/c4milo/chapulin/issues/186).
//
// Seven files multiply through ct.h: poly1305.c, poly1305_vector.c, x25519.c, mlkem_poly.c,
// p256_field.c, p256_scalar.c and rsa_sign.c. Each entry of theirs that runs the multiply,
// called from outside them, has a dispatcher below, named for it with the widemul_ prefix. For
// P-256 the entries are p256_scalar.c's two and the five of p256_point.c, the one file that
// calls p256_field.c. The dispatcher's first argument is the answer the operation runs under, a
// WIDEMUL_ value below. Every caller outside those files calls the dispatcher and passes on the
// answer it was handed; a session passes its own, widemul_answer. An entry that multiplies
// nothing, such as poly1305_init or p256_scalar_add, is called under its own name.
//
// A device object holds one multiply and compiles each file once, so each dispatcher calls that
// copy and reads no answer. A host object (-DCH_CPU_RUNTIME, cpu_cfg.h) holds each operation
// twice. poly1305.c and mlkem_poly.c compile under their own names on the decomposition, as a
// WIDEMUL=decomposed device object compiles them, and again as <file>_native.c on the native
// multiply, with every name widemul_native.h lists ending in _native. poly1305_vector.c
// compiles as its native copy alone. x25519.c, p256_field.c, p256_scalar.c, p256_point.c and
// rsa_sign.c compile under their own names alone, and their second copies are other files on
// the 64x64->128 multiply: x25519_wide.c, the radix-2^51 field (x25519_wide.h), for P-256 the
// four words of 64 bits in p256_wide_field.c and p256_wide_scalar.c, under p256_wide_point.c
// and p256_wide_mul.c, and for RSA signing rsa_sign64.c, the Chinese remainder theorem over
// 64-bit words (rsa_sign64.h). The dispatchers run the native copy, and for X25519, P-256 and
// RSA signing those files, for WIDEMUL_CONSTANT_TIME, and the file under its own names for
// every other byte. That is one branch per call, on the answer, which the caller's ch_cfg.cpu
// chose and which is not secret: never one per product, and through no function pointer.
// Poly1305 takes one per update and one per final, P-256 one per scalar multiplication, point
// decode, affine conversion and product modulo the group order, and RSA one per signature and
// one per key test.
#ifndef CH_WIDEMUL_H
#define CH_WIDEMUL_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "ct.h"
#include "mlkem_poly.h"
#include "p256_point.h"
#include "p256_scalar.h"
#include "p256_wide_mul.h"
#include "p256_wide_point.h"
#include "p256_wide_scalar.h"
#include "p256_wide_wipe.h"
#include "poly1305.h"
#include "rsa_sign.h"
#include "rsa_sign64.h"
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

#ifdef __x86_64__
// Whether a Poly1305 update under the answer widemul, in a session whose ch_cfg.cpu is cpu, runs
// poly1305_ifma.c's kernel: under WIDEMUL_CONSTANT_TIME, whose statement covers the kernel's
// widening multiply, AVX-512 IFMA's 52-bit products, where cpu holds CH_CPU_AVX512_IFMA, which
// says the CPU has AVX-512F and AVX-512 IFMA. The bit states no timing (docs/decisions.md 121).
static inline int widemul_poly1305_ifma(uint32_t cpu, uint8_t widemul) {
    return widemul_native(widemul) && (cpu & CH_CPU_AVX512_IFMA) != 0;
}

// Whether a Poly1305 update under the answer widemul, in a session whose ch_cfg.cpu is cpu, runs
// poly1305_avx2.c's kernel: under WIDEMUL_CONSTANT_TIME, whose statement covers the kernel's
// widening multiply, where cpu holds CH_CPU_AVX2, which says the CPU has AVX2. The bit states no
// timing (docs/decisions.md 110). widemul_poly1305_update_cpu asks widemul_poly1305_ifma first.
static inline int widemul_poly1305_avx2(uint32_t cpu, uint8_t widemul) {
    return widemul_native(widemul) && (cpu & CH_CPU_AVX2) != 0;
}
#endif

// widemul_poly1305_update with the session's ch_cfg.cpu first, for an update that may be long: a
// record's or a packet's ciphertext. On x86-64, where widemul_poly1305_ifma says so, it runs
// poly1305_update_ifma_native, whose long updates take the AVX-512 IFMA kernel, and where
// widemul_poly1305_avx2 says so, poly1305_update_avx2_native, whose long updates take the AVX2
// kernel; every other call runs widemul_poly1305_update. A caller that holds no description of the
// CPU passes 0, which names no kernel.
static inline void widemul_poly1305_update_cpu(uint32_t cpu, uint8_t widemul, poly1305 *p,
                                               const uint8_t *in, size_t n) {
#ifdef __x86_64__
    if (widemul_poly1305_ifma(cpu, widemul)) {
        poly1305_update_ifma_native(p, in, n);
        return;
    }
    if (widemul_poly1305_avx2(cpu, widemul)) {
        poly1305_update_avx2_native(p, in, n);
        return;
    }
#else
    // arm64 has one vector Poly1305, so no bit picks here.
    (void)cpu;
#endif
    widemul_poly1305_update(widemul, p, in, n);
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

static inline void widemul_p256_point_mul(uint8_t widemul, p256_point *o, const p256_scalar *k,
                                          const p256_point *p) {
    if (widemul_native(widemul)) {
        p256_wide_mul(o, k, p);
        p256_wide_wipe_below();
        return;
    }
    p256_point_mul(o, k, p);
}

static inline void widemul_p256_point_base_mul(uint8_t widemul, p256_point *o,
                                               const p256_scalar *k) {
    if (widemul_native(widemul)) {
        p256_wide_base_mul(o, k);
        p256_wide_wipe_below();
        return;
    }
    p256_point_base_mul(o, k);
}

static inline uint32_t widemul_p256_point_from_bytes(uint8_t widemul, p256_point *o,
                                                     const uint8_t in[P256_POINT_LEN]) {
    if (widemul_native(widemul)) {
        return p256_wide_point_from_bytes(o, in);
    }
    return p256_point_from_bytes(o, in);
}

static inline uint32_t widemul_p256_point_affine(uint8_t widemul, uint8_t x[P256_FE_LEN],
                                                 uint8_t y[P256_FE_LEN], const p256_point *a) {
    if (widemul_native(widemul)) {
        uint32_t finite = p256_wide_point_affine(x, y, a);
        p256_wide_wipe_below();
        return finite;
    }
    return p256_point_affine(x, y, a);
}

static inline uint32_t widemul_p256_point_affine_x(uint8_t widemul, uint8_t out[P256_FE_LEN],
                                                   const p256_point *a) {
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

// An RSA-PSS signature under the answer widemul, in a session whose
// ch_cfg.cpu is cpu, which the 64-bit signer reads: on x86-64 a value
// with CH_CPU_AVX512_IFMA runs its exponentiations on AVX-512 IFMA, whose
// 52-bit products the multiply bit's statement covers (rsa_sign64.h,
// docs/decisions.md 120). The ladder takes no value.
static inline int widemul_rsa_pss_sign_cpu(uint32_t cpu, uint8_t widemul, const ch_rsa_priv *k,
                                           const uint8_t msg_hash[32],
                                           const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig,
                                           size_t cap, size_t *sig_len) {
    if (widemul_native(widemul)) {
        return rsa_sign64_pss(cpu, k, msg_hash, salt, sig, cap, sig_len);
    }
    return rsa_pss_sign(k, msg_hash, salt, sig, cap, sig_len);
}

// The private operation: 1 when sig was written. The 64-bit signer
// returns 0 for a signature that failed its check (rsa_sign64.h), and the
// ladder has no check to fail. cpu is read as above.
static inline int widemul_rsa_sp1_cpu(uint32_t cpu, uint8_t widemul, const ch_rsa_priv *k,
                                      const uint8_t *em, uint8_t *sig) {
    if (widemul_native(widemul)) {
        return rsa_sign64_sp1(cpu, k, em, sig);
    }
    rsa_sp1(k, em, sig);
    return 1;
}

// The key test of the signer the answer picks: the 64-bit signer's reads
// the primes, which only a session that states its multiply may multiply.
static inline int widemul_rsa_pss_sign_key_ok(uint8_t widemul, const ch_rsa_priv *k) {
    if (widemul_native(widemul)) {
        return rsa_sign64_key_ok(k);
    }
    return rsa_pss_sign_key_ok(k);
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

// A device object holds one Poly1305 loop and no kernel, so it never reads cpu.
static inline void widemul_poly1305_update_cpu(uint32_t cpu, uint8_t widemul, poly1305 *p,
                                               const uint8_t *in, size_t n) {
    (void)cpu;
    (void)widemul;
    poly1305_update(p, in, n);
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

static inline void widemul_p256_point_mul(uint8_t widemul, p256_point *o, const p256_scalar *k,
                                          const p256_point *p) {
    (void)widemul;
    p256_point_mul(o, k, p);
}

static inline void widemul_p256_point_base_mul(uint8_t widemul, p256_point *o,
                                               const p256_scalar *k) {
    (void)widemul;
    p256_point_base_mul(o, k);
}

static inline uint32_t widemul_p256_point_from_bytes(uint8_t widemul, p256_point *o,
                                                     const uint8_t in[P256_POINT_LEN]) {
    (void)widemul;
    return p256_point_from_bytes(o, in);
}

static inline uint32_t widemul_p256_point_affine(uint8_t widemul, uint8_t x[P256_FE_LEN],
                                                 uint8_t y[P256_FE_LEN], const p256_point *a) {
    (void)widemul;
    return p256_point_affine(x, y, a);
}

static inline uint32_t widemul_p256_point_affine_x(uint8_t widemul, uint8_t out[P256_FE_LEN],
                                                   const p256_point *a) {
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

static inline int widemul_rsa_pss_sign_cpu(uint32_t cpu, uint8_t widemul, const ch_rsa_priv *k,
                                           const uint8_t msg_hash[32],
                                           const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig,
                                           size_t cap, size_t *sig_len) {
    (void)cpu;
    (void)widemul;
    return rsa_pss_sign(k, msg_hash, salt, sig, cap, sig_len);
}

static inline int widemul_rsa_sp1_cpu(uint32_t cpu, uint8_t widemul, const ch_rsa_priv *k,
                                      const uint8_t *em, uint8_t *sig) {
    (void)cpu;
    (void)widemul;
    rsa_sp1(k, em, sig);
    return 1;
}

static inline int widemul_rsa_pss_sign_key_ok(uint8_t widemul, const ch_rsa_priv *k) {
    (void)widemul;
    return rsa_pss_sign_key_ok(k);
}

#endif // CH_CPU_RUNTIME

#endif
