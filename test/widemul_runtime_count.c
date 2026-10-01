// The names widemul.h's dispatchers call in a WIDEMUL=runtime object, each
// defined as a count and a call to the entry test/widemul_count_names.h
// renamed (test/widemul_runtime_count.h). An entry under its own name
// counts into widemul_decomposed_calls and one ending in _native into
// widemul_native_calls.
#include "widemul_runtime_count.h"

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
void p256_fe_mul_decomposed_counted(p256_fe *o, const p256_fe *a, const p256_fe *b);
void p256_fe_sqr_decomposed_counted(p256_fe *o, const p256_fe *a);
void p256_fe_to_mont_decomposed_counted(p256_fe *o, const p256_fe *a);
void p256_fe_from_mont_decomposed_counted(p256_fe *o, const p256_fe *a);
void p256_fe_inv_decomposed_counted(p256_fe *o, const p256_fe *a);
void p256_scalar_mul_decomposed_counted(p256_scalar *o, const p256_scalar *a, const p256_scalar *b);
void p256_scalar_inverse_decomposed_counted(p256_scalar *o, const p256_scalar *a);
int rsa_pss_sign_decomposed_counted(const ch_rsa_priv *k, const uint8_t msg_hash[32],
                                    const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig, size_t cap,
                                    size_t *sig_len);
void rsa_sp1_decomposed_counted(const ch_rsa_priv *k, const uint8_t *em, uint8_t *sig);

void poly1305_update_native_counted(poly1305 *p, const uint8_t *in, size_t n);
void poly1305_final_native_counted(poly1305 *p, uint8_t tag[POLY1305_TAG]);
int x25519_native_counted(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
                          const uint8_t point[X25519_LEN]);
void x25519_base_native_counted(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]);
void mlk_polyvec_compress_native_counted(uint8_t out[MLK_POLYVEC_COMP_BYTES], const mlk_polyvec *v);
void mlk_poly_compress_native_counted(uint8_t out[MLK_POLY_COMP_BYTES], const mlk_poly *p);
void mlk_poly_tomsg_native_counted(uint8_t msg[32], const mlk_poly *p);
void p256_fe_mul_native_counted(p256_fe *o, const p256_fe *a, const p256_fe *b);
void p256_fe_sqr_native_counted(p256_fe *o, const p256_fe *a);
void p256_fe_to_mont_native_counted(p256_fe *o, const p256_fe *a);
void p256_fe_from_mont_native_counted(p256_fe *o, const p256_fe *a);
void p256_fe_inv_native_counted(p256_fe *o, const p256_fe *a);
void p256_scalar_mul_native_counted(p256_scalar *o, const p256_scalar *a, const p256_scalar *b);
void p256_scalar_inverse_native_counted(p256_scalar *o, const p256_scalar *a);
int rsa_pss_sign_native_counted(const ch_rsa_priv *k, const uint8_t msg_hash[32],
                                const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig, size_t cap,
                                size_t *sig_len);
void rsa_sp1_native_counted(const ch_rsa_priv *k, const uint8_t *em, uint8_t *sig);

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

void p256_fe_mul(p256_fe *o, const p256_fe *a, const p256_fe *b) {
    widemul_decomposed_calls++;
    p256_fe_mul_decomposed_counted(o, a, b);
}

void p256_fe_sqr(p256_fe *o, const p256_fe *a) {
    widemul_decomposed_calls++;
    p256_fe_sqr_decomposed_counted(o, a);
}

void p256_fe_to_mont(p256_fe *o, const p256_fe *a) {
    widemul_decomposed_calls++;
    p256_fe_to_mont_decomposed_counted(o, a);
}

void p256_fe_from_mont(p256_fe *o, const p256_fe *a) {
    widemul_decomposed_calls++;
    p256_fe_from_mont_decomposed_counted(o, a);
}

void p256_fe_inv(p256_fe *o, const p256_fe *a) {
    widemul_decomposed_calls++;
    p256_fe_inv_decomposed_counted(o, a);
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

int x25519_native(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
                  const uint8_t point[X25519_LEN]) {
    widemul_native_calls++;
    return x25519_native_counted(out, scalar, point);
}

void x25519_base_native(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]) {
    widemul_native_calls++;
    x25519_base_native_counted(out, scalar);
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

void p256_fe_mul_native(p256_fe *o, const p256_fe *a, const p256_fe *b) {
    widemul_native_calls++;
    p256_fe_mul_native_counted(o, a, b);
}

void p256_fe_sqr_native(p256_fe *o, const p256_fe *a) {
    widemul_native_calls++;
    p256_fe_sqr_native_counted(o, a);
}

void p256_fe_to_mont_native(p256_fe *o, const p256_fe *a) {
    widemul_native_calls++;
    p256_fe_to_mont_native_counted(o, a);
}

void p256_fe_from_mont_native(p256_fe *o, const p256_fe *a) {
    widemul_native_calls++;
    p256_fe_from_mont_native_counted(o, a);
}

void p256_fe_inv_native(p256_fe *o, const p256_fe *a) {
    widemul_native_calls++;
    p256_fe_inv_native_counted(o, a);
}

void p256_scalar_mul_native(p256_scalar *o, const p256_scalar *a, const p256_scalar *b) {
    widemul_native_calls++;
    p256_scalar_mul_native_counted(o, a, b);
}

void p256_scalar_inverse_native(p256_scalar *o, const p256_scalar *a) {
    widemul_native_calls++;
    p256_scalar_inverse_native_counted(o, a);
}

int rsa_pss_sign_native(const ch_rsa_priv *k, const uint8_t msg_hash[32],
                        const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig, size_t cap,
                        size_t *sig_len) {
    widemul_native_calls++;
    return rsa_pss_sign_native_counted(k, msg_hash, salt, sig, cap, sig_len);
}

void rsa_sp1_native(const ch_rsa_priv *k, const uint8_t *em, uint8_t *sig) {
    widemul_native_calls++;
    rsa_sp1_native_counted(k, em, sig);
}

#ifdef CH_CHACHA_VECTOR
// poly1305_native.c's block loop calls the vector path under the name
// poly1305_vector.h declares for a WIDEMUL=runtime object.
void poly1305_vector_blocks_native_counted(poly1305 *p, const uint8_t *m, size_t n);

void poly1305_vector_blocks_native(poly1305 *p, const uint8_t *m, size_t n) {
    widemul_vector_calls++;
    poly1305_vector_blocks_native_counted(p, m, n);
}
#endif
