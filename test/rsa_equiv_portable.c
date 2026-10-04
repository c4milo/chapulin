// rsa_mont.c's 32-bit arithmetic, the reference, under a second name, so
// one binary can hold both arms of that file. bin/rsa_equiv_test compiles
// every unit under -DCH_CPU_RUNTIME, as a host object is compiled, so
// rsa_mont.c beside it is the arm that calls rsa_mont64.c. This unit
// takes the define away and compiles the other arm, the one a device
// object runs.
//
// The #define rewrites both the definition in rsa_mont.c and the
// declaration it reads from rsa.h, because it is in effect before that
// header is read. test/aes_equiv_soft.c is the same construction for the
// AES table.
#undef CH_CPU_RUNTIME
#define rsa_vp1 rsa_vp1_portable

#include "rsa_mont.c"
