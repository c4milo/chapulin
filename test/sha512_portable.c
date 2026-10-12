// sha512.c's second arm, the reference, in a host test binary.
// bin/sha2_equiv_test compiles every unit under -DCH_CPU_RUNTIME, as a host
// object is compiled, so sha512.c beside this unit is the arm that
// compresses on sha512_compress_blocks.c. This unit takes the define away
// and compiles the other arm, the one a device object runs over
// sha512_compress.c, under second names, so one binary holds both
// (docs/decisions.md 127).
//
// Each #define rewrites both a definition in sha512.c and the declaration
// it reads from sha512.h, because it is in effect before that header is
// read. test/p256_verify_portable.c is the same construction for P-256.
// The two calls that write an initial value take a second name too:
// sha512.c defines them above both arms, so this unit defines them again.
#undef CH_CPU_RUNTIME
#define sha512_init sha512_init_portable
#define sha384_init sha384_init_portable
#define sha512_update sha512_update_portable
#define sha512_final sha512_final_portable
#define sha384_final sha384_final_portable
#define sha512_of sha512_of_portable
#define sha384_of sha384_of_portable

#include "sha512.c"
