// The copies of the files that call Keccak, for an arm64 host object's sessions on the CPU's
// SHA-3 instructions (-DCH_CPU_RUNTIME, docs/decisions.md 99). sha3_hw.c, mlkem_poly_hw.c and
// mlkem_hw.c each include this header and then their file, so a copy is the same source text
// as the file under its own names, compiled once more, as hash_hw.h's copies are for SHA-2.
//
// The renames below do two things. They send a copy's SHA-3 and SHAKE calls to sha3_hw.c's
// entries, which run Keccak-f[1600] on EOR3, RAX1, XAR and BCAX, where the file under its own
// names calls sha3.c's portable code. And they give every function the copied files define
// outside their own translation unit a second name, the first with _hw after it, so the two
// copies define no name twice. They rename the declarations each file's header gives as well
// as its definitions, and a call from mlkem.c to mlkem_poly.c calls the copy of the callee.
// The entries that end mlkem.h call the _hw names for a session whose ch_cfg.cpu holds
// CH_CPU_CONSTANT_TIME_SHA3, and the file under its own names for any other.
//
// A copy takes its multiply as the file under its own names does: mlkem_poly_hw.c is on ct.h's
// decomposition, and the three calls widemul.h sends to mlkem_poly_native.c still go there,
// because these renames do not match a _native name.
//
// Every name the copied files define outside their unit is here. A name left out is defined by
// both copies, and the link of the object refuses it. sha3.h and mlkem.h read CH_KECCAK_HW_H:
// a copy takes their declarations of the _hw names and none of their entries, whose two arms
// the renames would send to one path.
#ifndef CH_KECCAK_HW_H
#define CH_KECCAK_HW_H

#ifndef CH_CPU_RUNTIME
#error "a copy on the SHA-3 instructions belongs to a host object (docs/decisions.md 99)"
#endif

// sha3.c.
#define sha3_256 sha3_256_hw
#define sha3_512 sha3_512_hw
#define shake128_init shake128_init_hw
#define shake256_init shake256_init_hw
#define shake_absorb shake_absorb_hw
#define shake_squeeze shake_squeeze_hw

// mlkem_poly.c.
#define mlk_poly_reduce mlk_poly_reduce_hw
#define mlk_poly_tomont mlk_poly_tomont_hw
#define mlk_poly_add mlk_poly_add_hw
#define mlk_poly_sub mlk_poly_sub_hw
#define mlk_poly_ntt mlk_poly_ntt_hw
#define mlk_poly_invntt mlk_poly_invntt_hw
#define mlk_poly_basemul mlk_poly_basemul_hw
#define mlk_poly_tobytes mlk_poly_tobytes_hw
#define mlk_poly_frombytes mlk_poly_frombytes_hw
#define mlk_polyvec_compress mlk_polyvec_compress_hw
#define mlk_polyvec_decompress mlk_polyvec_decompress_hw
#define mlk_poly_compress mlk_poly_compress_hw
#define mlk_poly_decompress mlk_poly_decompress_hw
#define mlk_poly_frommsg mlk_poly_frommsg_hw
#define mlk_poly_tomsg mlk_poly_tomsg_hw
#define mlk_sample_ntt mlk_sample_ntt_hw
#define mlk_sample_cbd mlk_sample_cbd_hw

// mlkem.c.
#define mlkem_keygen_dk mlkem_keygen_dk_hw
#define mlkem_keygen_derand mlkem_keygen_derand_hw
#define mlkem_encaps_derand mlkem_encaps_derand_hw
#define mlkem_decaps mlkem_decaps_hw

#endif
