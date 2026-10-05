// p256.c's 32-bit arithmetic, the reference, under a second name, so one
// binary can hold both arms of that file. bin/p256_verify_equiv_test and
// bin/p256_equiv_test compile every unit under -DCH_CPU_RUNTIME, as a
// host object is compiled, so p256.c beside this unit is the arm that
// calls p256_wide_verify.c. This unit takes the define away and compiles
// the other arm, the one a device object runs.
//
// The #define rewrites both the definition in p256.c and the declaration
// it reads from p256.h, because it is in effect before that header is
// read. test/rsa_equiv_portable.c is the same construction for RSA's
// public operation.
#undef CH_CPU_RUNTIME
#define p256_ecdsa_verify p256_ecdsa_verify_portable

#include "p256.c"
