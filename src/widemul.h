// The one place an operation built on ct.h's widening multiply chooses the multiply it runs
// (docs/decisions.md 87, 89 and 94, https://github.com/c4milo/chapulin/issues/186).
//
// Seven files multiply through ct.h: poly1305.c, poly1305_vector.c, x25519.c, mlkem_poly.c,
// p256_field.c, p256_scalar.c and rsa_sign.c. Each entry of theirs that runs the multiply,
// called from outside them, has a dispatcher below, named for it with the widemul_ prefix. For
// P-256 the entries are p256_scalar.c's two and the five of p256_point.c, the one file that
// calls p256_field.c, and their dispatchers sit in widemul_p256.h, which this file includes at
// its end. A dispatcher's first argument is the answer the operation runs under, a WIDEMUL_
// value below, or a P-256 point dispatcher's second, after the session's ch_cfg.cpu. Every caller
// outside those files calls the dispatcher and passes on the answer it was handed; a session passes
// its own, widemul_answer. An entry that multiplies nothing, such as poly1305_init or
// p256_scalar_add, is called under its own name.
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
// one per key test. On x86-64 an X25519 shared secret and a P-256 point operation take one more,
// on cpu, for x25519_adx.c and p256_adx.h's field (docs/decisions.md 165 and 171).
#ifndef CH_WIDEMUL_H
#define CH_WIDEMUL_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "ct.h"
#include "mlkem_poly.h"
#include "poly1305.h"
#include "rsa_sign.h"
#include "rsa_sign64.h"
#include "widemul_answer.h"
#include "x25519.h"
#include "x25519_adx.h"
#include "x25519_wide.h"

#ifdef CH_CPU_RUNTIME

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

// widemul_x25519 with the session's ch_cfg.cpu first, for a shared secret. On x86-64, under
// WIDEMUL_CONSTANT_TIME, whose statement covers MULX's 64x64->128 products, where cpu holds
// CH_CPU_BMI2_ADX, which says the CPU has BMI2 and ADX, it runs x25519_adx.c's field of four
// 64-bit words. The bit states no timing (docs/decisions.md 165). Every other call runs
// widemul_x25519.
static inline int widemul_x25519_cpu(uint32_t cpu, uint8_t widemul, uint8_t out[X25519_LEN],
                                     const uint8_t scalar[X25519_LEN],
                                     const uint8_t point[X25519_LEN]) {
#ifdef __x86_64__
    if (widemul_native(widemul) && (cpu & CH_CPU_BMI2_ADX) != 0) {
        return x25519_adx(out, scalar, point);
    }
#else
    // arm64 has no such field, so no bit picks here.
    (void)cpu;
#endif
    return widemul_x25519(widemul, out, scalar, point);
}

static inline void widemul_x25519_base(uint8_t widemul, uint8_t out[X25519_LEN],
                                       const uint8_t scalar[X25519_LEN]) {
    if (widemul_native(widemul)) {
        x25519_wide_base(out, scalar);
        return;
    }
    x25519_base(out, scalar);
}

static inline void widemul_mlk_poly_compress_du(uint8_t widemul, uint8_t *out, const mlk_poly *p,
                                                unsigned rank) {
    if (widemul_native(widemul)) {
        mlk_poly_compress_du_native(out, p, rank);
        return;
    }
    mlk_poly_compress_du(out, p, rank);
}

static inline void widemul_mlk_poly_compress(uint8_t widemul, uint8_t *out, const mlk_poly *p,
                                             unsigned rank) {
    if (widemul_native(widemul)) {
        mlk_poly_compress_native(out, p, rank);
        return;
    }
    mlk_poly_compress(out, p, rank);
}

static inline void widemul_mlk_poly_tomsg(uint8_t widemul, uint8_t msg[32], const mlk_poly *p) {
    if (widemul_native(widemul)) {
        mlk_poly_tomsg_native(msg, p);
        return;
    }
    mlk_poly_tomsg(msg, p);
}

// An RSA-PSS signature under the answer widemul, in a session whose
// ch_cfg.cpu is cpu, which the 64-bit signer reads: on x86-64 a value
// with CH_CPU_AVX512_IFMA runs its exponentiations on AVX-512 IFMA, whose
// 52-bit products the multiply bit's statement covers (rsa_sign64.h,
// docs/decisions.md 120). The ladder takes no value.
static inline int widemul_rsa_pss_sign_cpu(uint32_t cpu, uint8_t widemul, const ch_rsa_priv *k,
                                           const uint8_t msg_hash[32],
                                           const uint8_t salt[RSA_PSS_SALT_LEN],
                                           const uint8_t blind[RSA_BLIND_LEN], uint8_t *sig,
                                           size_t cap, size_t *sig_len) {
    if (widemul_native(widemul)) {
        // The 64-bit signer reads no blind: its exponents run by the CRT,
        // which docs/decisions.md 186 leaves unblinded.
        (void)blind;
        return rsa_sign64_pss(cpu, k, msg_hash, salt, sig, cap, sig_len);
    }
    return rsa_pss_sign(k, msg_hash, salt, blind, sig, cap, sig_len);
}

// The private operation: 1 when sig was written. The 64-bit signer
// returns 0 for a signature that failed its check (rsa_sign64.h), and the
// ladder has no check to fail. cpu is read as above.
static inline int widemul_rsa_sp1_cpu(uint32_t cpu, uint8_t widemul, const ch_rsa_priv *k,
                                      const uint8_t *em, const uint8_t blind[RSA_BLIND_LEN],
                                      uint8_t *sig) {
    if (widemul_native(widemul)) {
        (void)blind;
        return rsa_sign64_sp1(cpu, k, em, sig);
    }
    rsa_sp1(k, em, blind, sig);
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

static inline int widemul_x25519_cpu(uint32_t cpu, uint8_t widemul, uint8_t out[X25519_LEN],
                                     const uint8_t scalar[X25519_LEN],
                                     const uint8_t point[X25519_LEN]) {
    (void)cpu;
    (void)widemul;
    return x25519(out, scalar, point);
}

static inline void widemul_x25519_base(uint8_t widemul, uint8_t out[X25519_LEN],
                                       const uint8_t scalar[X25519_LEN]) {
    (void)widemul;
    x25519_base(out, scalar);
}

static inline void widemul_mlk_poly_compress_du(uint8_t widemul, uint8_t *out, const mlk_poly *p,
                                                unsigned rank) {
    (void)widemul;
    mlk_poly_compress_du(out, p, rank);
}

static inline void widemul_mlk_poly_compress(uint8_t widemul, uint8_t *out, const mlk_poly *p,
                                             unsigned rank) {
    (void)widemul;
    mlk_poly_compress(out, p, rank);
}

static inline void widemul_mlk_poly_tomsg(uint8_t widemul, uint8_t msg[32], const mlk_poly *p) {
    (void)widemul;
    mlk_poly_tomsg(msg, p);
}

static inline int widemul_rsa_pss_sign_cpu(uint32_t cpu, uint8_t widemul, const ch_rsa_priv *k,
                                           const uint8_t msg_hash[32],
                                           const uint8_t salt[RSA_PSS_SALT_LEN],
                                           const uint8_t blind[RSA_BLIND_LEN], uint8_t *sig,
                                           size_t cap, size_t *sig_len) {
    (void)cpu;
    (void)widemul;
    return rsa_pss_sign(k, msg_hash, salt, blind, sig, cap, sig_len);
}

static inline int widemul_rsa_sp1_cpu(uint32_t cpu, uint8_t widemul, const ch_rsa_priv *k,
                                      const uint8_t *em, const uint8_t blind[RSA_BLIND_LEN],
                                      uint8_t *sig) {
    (void)cpu;
    (void)widemul;
    rsa_sp1(k, em, blind, sig);
    return 1;
}

static inline int widemul_rsa_pss_sign_key_ok(uint8_t widemul, const ch_rsa_priv *k) {
    (void)widemul;
    return rsa_pss_sign_key_ok(k);
}

#endif // CH_CPU_RUNTIME

// The P-256 dispatchers (widemul_p256.h).
#include "widemul_p256.h"

#endif
