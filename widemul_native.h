// The native copy of a file built on ct.h's widening multiply, for a host object
// (-DCH_CPU_RUNTIME). Each <file>_native.c includes this header and then <file>.c, so the copy is
// the same source text as the file under its own names, compiled once more.
//
// CH_WIDEMUL_NATIVE_COPY makes ct.h take the native multiply in this translation unit alone,
// and ct.h refuses it outside a host object. The renames below give every function
// and constant the copied files define outside their own translation unit a second name, the
// first with _native after it, so the two copies define no name twice. They rename the
// declarations each file's header gives as well as its definitions, and a call from one of the
// copied files to another, as poly1305.c's call to poly1305_vector_blocks, calls the native
// copy of the callee. widemul.h's dispatchers call the _native entries for the answer
// WIDEMUL_CONSTANT_TIME alone. x25519.c, p256_field.c, p256_scalar.c and rsa_sign.c are not
// copied: their second copies in a host object are x25519_wide.c's field (x25519_wide.h), the
// wide P-256 files (p256_wide_field.h) and rsa_sign64.c's words (rsa_sign64.h).
//
// Every name the copied files define outside their unit is here. A name left out is defined by
// both copies, and the link of the object refuses it.
#ifndef CH_WIDEMUL_NATIVE_H
#define CH_WIDEMUL_NATIVE_H

#define CH_WIDEMUL_NATIVE_COPY 1

// poly1305.c, and poly1305_vector.c, poly1305_avx2.c and poly1305_ifma.c, which a host object
// holds in its native copy alone, because the vector paths run on the native multiply
// (docs/decisions.md 83 and 110). poly1305_update_avx2, poly1305_avx2_blocks,
// poly1305_update_ifma and poly1305_ifma_blocks exist in an x86-64 object alone.
#define poly1305_init poly1305_init_native
#define poly1305_update poly1305_update_native
#define poly1305_update_avx2 poly1305_update_avx2_native
#define poly1305_final poly1305_final_native
#define poly1305_vector_blocks poly1305_vector_blocks_native
#define poly1305_avx2_blocks poly1305_avx2_blocks_native
#define poly1305_update_ifma poly1305_update_ifma_native
#define poly1305_ifma_blocks poly1305_ifma_blocks_native

// mlkem_poly.c.
#define mlk_poly_reduce mlk_poly_reduce_native
#define mlk_poly_tomont mlk_poly_tomont_native
#define mlk_poly_add mlk_poly_add_native
#define mlk_poly_sub mlk_poly_sub_native
#define mlk_poly_ntt mlk_poly_ntt_native
#define mlk_poly_invntt mlk_poly_invntt_native
#define mlk_poly_basemul mlk_poly_basemul_native
#define mlk_poly_tobytes mlk_poly_tobytes_native
#define mlk_poly_frombytes mlk_poly_frombytes_native
#define mlk_polyvec_compress mlk_polyvec_compress_native
#define mlk_polyvec_decompress mlk_polyvec_decompress_native
#define mlk_poly_compress mlk_poly_compress_native
#define mlk_poly_decompress mlk_poly_decompress_native
#define mlk_poly_frommsg mlk_poly_frommsg_native
#define mlk_poly_tomsg mlk_poly_tomsg_native
#define mlk_sample_ntt mlk_sample_ntt_native
#define mlk_sample_cbd mlk_sample_cbd_native

#endif
