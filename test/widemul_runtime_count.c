// The names widemul.h's dispatchers call in a host object, each
// defined as a count and a call to the entry test/widemul_count_names.h
// renamed (test/widemul_runtime_count.h). An entry under its own name
// counts into widemul_decomposed_calls, and one ending in _native, one of
// the wide X25519 field's two, one of the wide P-256 files' six, or one of
// the 64-bit RSA signer's three, into
// widemul_native_calls.
#include "widemul_runtime_count.h"

#include "poly1305_avx2.h"
#include "poly1305_ifma.h"
#include "poly1305_vector.h"
#include "widemul.h"

unsigned long widemul_decomposed_calls;
unsigned long widemul_native_calls;
unsigned long widemul_vector_calls;

// The declarations the module headers gave these under the names the
// library calls, restated under the second names the count units define
// them by.
void poly1305_update_decomposed_counted(poly1305 *p, const uint8_t *in, size_t n);
void poly1305_final_decomposed_counted(poly1305 *p, uint8_t tag[POLY1305_TAG]);
int x25519_decomposed_counted(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
                              const uint8_t point[X25519_LEN]);
void x25519_base_decomposed_counted(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]);
void mlk_polyvec_compress_decomposed_counted(uint8_t out[MLK_POLYVEC_COMP_BYTES],
                                             const mlk_polyvec *v);
void mlk_poly_compress_decomposed_counted(uint8_t out[MLK_POLY_COMP_BYTES], const mlk_poly *p);
void mlk_poly_tomsg_decomposed_counted(uint8_t msg[32], const mlk_poly *p);
void p256_point_mul_decomposed_counted(p256_point *o, const p256_scalar *k, const p256_point *p);
void p256_point_base_mul_decomposed_counted(p256_point *o, const p256_scalar *k);
uint32_t p256_point_from_bytes_decomposed_counted(p256_point *o, const uint8_t in[P256_POINT_LEN]);
uint32_t p256_point_affine_decomposed_counted(uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN],
                                              const p256_point *a);
uint32_t p256_point_affine_x_decomposed_counted(uint8_t out[P256_FE_LEN], const p256_point *a);
void p256_scalar_mul_decomposed_counted(p256_scalar *o, const p256_scalar *a, const p256_scalar *b);
void p256_scalar_inverse_decomposed_counted(p256_scalar *o, const p256_scalar *a);
int rsa_pss_sign_decomposed_counted(const ch_rsa_priv *k, const uint8_t msg_hash[32],
                                    const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig, size_t cap,
                                    size_t *sig_len);
void rsa_sp1_decomposed_counted(const ch_rsa_priv *k, const uint8_t *em, uint8_t *sig);

void poly1305_update_native_counted(poly1305 *p, const uint8_t *in, size_t n);
void poly1305_final_native_counted(poly1305 *p, uint8_t tag[POLY1305_TAG]);
int x25519_wide_counted(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
                        const uint8_t point[X25519_LEN]);
void x25519_wide_base_counted(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]);
void mlk_polyvec_compress_native_counted(uint8_t out[MLK_POLYVEC_COMP_BYTES], const mlk_polyvec *v);
void mlk_poly_compress_native_counted(uint8_t out[MLK_POLY_COMP_BYTES], const mlk_poly *p);
void mlk_poly_tomsg_native_counted(uint8_t msg[32], const mlk_poly *p);
void p256_wide_mul_counted(p256_point *o, const p256_scalar *k, const p256_point *p);
void p256_wide_base_mul_counted(p256_point *o, const p256_scalar *k);
uint32_t p256_wide_point_from_bytes_counted(p256_point *o, const uint8_t in[P256_POINT_LEN]);
uint32_t p256_wide_point_affine_counted(uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN],
                                        const p256_point *a);
void p256_wide_scalar_mul_counted(p256_scalar *o, const p256_scalar *a, const p256_scalar *b);
void p256_wide_scalar_inverse_counted(p256_scalar *o, const p256_scalar *a);
int rsa_sign64_pss_counted(uint32_t cpu, const ch_rsa_priv *k, const uint8_t msg_hash[32],
                           const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig, size_t cap,
                           size_t *sig_len);
int rsa_sign64_sp1_counted(uint32_t cpu, const ch_rsa_priv *k, const uint8_t *em, uint8_t *sig);
int rsa_sign64_key_ok_counted(const ch_rsa_priv *k);

void poly1305_update(poly1305 *p, const uint8_t *in, size_t n) {
    widemul_decomposed_calls++;
    poly1305_update_decomposed_counted(p, in, n);
}

void poly1305_final(poly1305 *p, uint8_t tag[POLY1305_TAG]) {
    widemul_decomposed_calls++;
    poly1305_final_decomposed_counted(p, tag);
}

int x25519(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
           const uint8_t point[X25519_LEN]) {
    widemul_decomposed_calls++;
    return x25519_decomposed_counted(out, scalar, point);
}

void x25519_base(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]) {
    widemul_decomposed_calls++;
    x25519_base_decomposed_counted(out, scalar);
}

void mlk_polyvec_compress(uint8_t out[MLK_POLYVEC_COMP_BYTES], const mlk_polyvec *v) {
    widemul_decomposed_calls++;
    mlk_polyvec_compress_decomposed_counted(out, v);
}

void mlk_poly_compress(uint8_t out[MLK_POLY_COMP_BYTES], const mlk_poly *p) {
    widemul_decomposed_calls++;
    mlk_poly_compress_decomposed_counted(out, p);
}

void mlk_poly_tomsg(uint8_t msg[32], const mlk_poly *p) {
    widemul_decomposed_calls++;
    mlk_poly_tomsg_decomposed_counted(msg, p);
}

void p256_point_mul(p256_point *o, const p256_scalar *k, const p256_point *p) {
    widemul_decomposed_calls++;
    p256_point_mul_decomposed_counted(o, k, p);
}

void p256_point_base_mul(p256_point *o, const p256_scalar *k) {
    widemul_decomposed_calls++;
    p256_point_base_mul_decomposed_counted(o, k);
}

uint32_t p256_point_from_bytes(p256_point *o, const uint8_t in[P256_POINT_LEN]) {
    widemul_decomposed_calls++;
    return p256_point_from_bytes_decomposed_counted(o, in);
}

uint32_t p256_point_affine(uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN], const p256_point *a) {
    widemul_decomposed_calls++;
    return p256_point_affine_decomposed_counted(x, y, a);
}

uint32_t p256_point_affine_x(uint8_t out[P256_FE_LEN], const p256_point *a) {
    widemul_decomposed_calls++;
    return p256_point_affine_x_decomposed_counted(out, a);
}

void p256_scalar_mul(p256_scalar *o, const p256_scalar *a, const p256_scalar *b) {
    widemul_decomposed_calls++;
    p256_scalar_mul_decomposed_counted(o, a, b);
}

void p256_scalar_inverse(p256_scalar *o, const p256_scalar *a) {
    widemul_decomposed_calls++;
    p256_scalar_inverse_decomposed_counted(o, a);
}

int rsa_pss_sign(const ch_rsa_priv *k, const uint8_t msg_hash[32],
                 const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig, size_t cap, size_t *sig_len) {
    widemul_decomposed_calls++;
    return rsa_pss_sign_decomposed_counted(k, msg_hash, salt, sig, cap, sig_len);
}

void rsa_sp1(const ch_rsa_priv *k, const uint8_t *em, uint8_t *sig) {
    widemul_decomposed_calls++;
    rsa_sp1_decomposed_counted(k, em, sig);
}

void poly1305_update_native(poly1305 *p, const uint8_t *in, size_t n) {
    widemul_native_calls++;
    poly1305_update_native_counted(p, in, n);
}

void poly1305_final_native(poly1305 *p, uint8_t tag[POLY1305_TAG]) {
    widemul_native_calls++;
    poly1305_final_native_counted(p, tag);
}

int x25519_wide(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
                const uint8_t point[X25519_LEN]) {
    widemul_native_calls++;
    return x25519_wide_counted(out, scalar, point);
}

void x25519_wide_base(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]) {
    widemul_native_calls++;
    x25519_wide_base_counted(out, scalar);
}

void mlk_polyvec_compress_native(uint8_t out[MLK_POLYVEC_COMP_BYTES], const mlk_polyvec *v) {
    widemul_native_calls++;
    mlk_polyvec_compress_native_counted(out, v);
}

void mlk_poly_compress_native(uint8_t out[MLK_POLY_COMP_BYTES], const mlk_poly *p) {
    widemul_native_calls++;
    mlk_poly_compress_native_counted(out, p);
}

void mlk_poly_tomsg_native(uint8_t msg[32], const mlk_poly *p) {
    widemul_native_calls++;
    mlk_poly_tomsg_native_counted(msg, p);
}

void p256_wide_mul(p256_point *o, const p256_scalar *k, const p256_point *p) {
    widemul_native_calls++;
    p256_wide_mul_counted(o, k, p);
}

void p256_wide_base_mul(p256_point *o, const p256_scalar *k) {
    widemul_native_calls++;
    p256_wide_base_mul_counted(o, k);
}

uint32_t p256_wide_point_from_bytes(p256_point *o, const uint8_t in[P256_POINT_LEN]) {
    widemul_native_calls++;
    return p256_wide_point_from_bytes_counted(o, in);
}

uint32_t p256_wide_point_affine(uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN],
                                const p256_point *a) {
    widemul_native_calls++;
    return p256_wide_point_affine_counted(x, y, a);
}

void p256_wide_scalar_mul(p256_scalar *o, const p256_scalar *a, const p256_scalar *b) {
    widemul_native_calls++;
    p256_wide_scalar_mul_counted(o, a, b);
}

void p256_wide_scalar_inverse(p256_scalar *o, const p256_scalar *a) {
    widemul_native_calls++;
    p256_wide_scalar_inverse_counted(o, a);
}

int rsa_sign64_pss(uint32_t cpu, const ch_rsa_priv *k, const uint8_t msg_hash[32],
                   const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig, size_t cap,
                   size_t *sig_len) {
    widemul_native_calls++;
    return rsa_sign64_pss_counted(cpu, k, msg_hash, salt, sig, cap, sig_len);
}

int rsa_sign64_sp1(uint32_t cpu, const ch_rsa_priv *k, const uint8_t *em, uint8_t *sig) {
    widemul_native_calls++;
    return rsa_sign64_sp1_counted(cpu, k, em, sig);
}

int rsa_sign64_key_ok(const ch_rsa_priv *k) {
    widemul_native_calls++;
    return rsa_sign64_key_ok_counted(k);
}

// poly1305_native.c's block loop calls the vector path under the name
// poly1305_vector.h declares for a host object.
void poly1305_vector_blocks_native_counted(poly1305 *p, const uint8_t *m, size_t n);

void poly1305_vector_blocks_native(poly1305 *p, const uint8_t *m, size_t n) {
    widemul_vector_calls++;
    poly1305_vector_blocks_native_counted(p, m, n);
}

#ifdef __x86_64__
// The native copy's AVX2 update, which widemul.h's
// widemul_poly1305_update_cpu calls, and the AVX2 kernel's entry, which
// that update's block loop calls under the name poly1305_avx2.h declares
// for an x86-64 host object (docs/decisions.md 110). The kernel is a
// vector path, so its calls count with the 128-bit path's.
void poly1305_update_avx2_native_counted(poly1305 *p, const uint8_t *in, size_t n);
void poly1305_avx2_blocks_native_counted(poly1305 *p, const uint8_t *m, size_t n);

void poly1305_update_avx2_native(poly1305 *p, const uint8_t *in, size_t n) {
    widemul_native_calls++;
    poly1305_update_avx2_native_counted(p, in, n);
}

void poly1305_avx2_blocks_native(poly1305 *p, const uint8_t *m, size_t n) {
    widemul_vector_calls++;
    poly1305_avx2_blocks_native_counted(p, m, n);
}

// The native copy's IFMA update and the AVX-512 IFMA kernel's entry, the
// same way. test/aead_avx512_count.c defines the kernel's second name as a
// call to the 128-bit path, so these binaries run no AVX-512 instruction.
void poly1305_update_ifma_native_counted(poly1305 *p, const uint8_t *in, size_t n);
void poly1305_ifma_blocks_native_counted(poly1305 *p, const uint8_t *m, size_t n);

void poly1305_update_ifma_native(poly1305 *p, const uint8_t *in, size_t n) {
    widemul_native_calls++;
    poly1305_update_ifma_native_counted(p, in, n);
}

void poly1305_ifma_blocks_native(poly1305 *p, const uint8_t *m, size_t n) {
    widemul_vector_calls++;
    poly1305_ifma_blocks_native_counted(p, m, n);
}
#endif
