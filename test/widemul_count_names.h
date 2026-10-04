// The second names bin/widemul_runtime_test gives the entries widemul.h
// dispatches to, for the test/widemul_count_*.c units that compile the
// files built on ct.h's widening multiply once more
// (test/widemul_runtime_count.h). A unit that includes widemul_native.h
// first compiles the native copy, and its entries end in _native_counted;
// any other compiles the files under their own names, and its entries end
// in _decomposed_counted. test/widemul_runtime_count.c defines the names
// the library calls, each as a count and a call to the second name.
// x25519.c has no native copy: X25519's second copy is x25519_wide.c,
// which test/widemul_count_wide.c compiles under second names of its own.
//
// Every other name the files define keeps the name the library gives it,
// widemul_native.h's in a native unit, so a call from one entry to
// another, as rsa_pss_sign's to rsa_sp1, stays inside the copy and is not
// counted twice.
#ifndef CH_TEST_WIDEMUL_COUNT_NAMES_H
#define CH_TEST_WIDEMUL_COUNT_NAMES_H

#ifdef CH_WIDEMUL_NATIVE_COPY
#undef poly1305_update
#undef poly1305_final
#undef mlk_polyvec_compress
#undef mlk_poly_compress
#undef mlk_poly_tomsg
#undef p256_fe_mul
#undef p256_fe_sqr
#undef p256_fe_to_mont
#undef p256_fe_from_mont
#undef p256_fe_inv
#undef p256_scalar_mul
#undef p256_scalar_inverse
#undef rsa_pss_sign
#undef rsa_sp1
#define poly1305_update poly1305_update_native_counted
#define poly1305_final poly1305_final_native_counted
#define mlk_polyvec_compress mlk_polyvec_compress_native_counted
#define mlk_poly_compress mlk_poly_compress_native_counted
#define mlk_poly_tomsg mlk_poly_tomsg_native_counted
#define p256_fe_mul p256_fe_mul_native_counted
#define p256_fe_sqr p256_fe_sqr_native_counted
#define p256_fe_to_mont p256_fe_to_mont_native_counted
#define p256_fe_from_mont p256_fe_from_mont_native_counted
#define p256_fe_inv p256_fe_inv_native_counted
#define p256_scalar_mul p256_scalar_mul_native_counted
#define p256_scalar_inverse p256_scalar_inverse_native_counted
#define rsa_pss_sign rsa_pss_sign_native_counted
#define rsa_sp1 rsa_sp1_native_counted
#else
#define poly1305_update poly1305_update_decomposed_counted
#define poly1305_final poly1305_final_decomposed_counted
#define x25519 x25519_decomposed_counted
#define x25519_base x25519_base_decomposed_counted
#define mlk_polyvec_compress mlk_polyvec_compress_decomposed_counted
#define mlk_poly_compress mlk_poly_compress_decomposed_counted
#define mlk_poly_tomsg mlk_poly_tomsg_decomposed_counted
#define p256_fe_mul p256_fe_mul_decomposed_counted
#define p256_fe_sqr p256_fe_sqr_decomposed_counted
#define p256_fe_to_mont p256_fe_to_mont_decomposed_counted
#define p256_fe_from_mont p256_fe_from_mont_decomposed_counted
#define p256_fe_inv p256_fe_inv_decomposed_counted
#define p256_scalar_mul p256_scalar_mul_decomposed_counted
#define p256_scalar_inverse p256_scalar_inverse_decomposed_counted
#define rsa_pss_sign rsa_pss_sign_decomposed_counted
#define rsa_sp1 rsa_sp1_decomposed_counted
#endif

#endif
