// The decomposition variant of the x25519_mul proof: the same harness
// with ct_widemul_s resolved to the 16x16 decomposition firmware ships,
// not the native (int64_t)a * b arm that run.sh's -DCH_NATIVE_WIDEMUL
// selects. CH_CT_WIDEMUL wins over that define (ct.h), as it does in
// ctwidemul_harness.c. So the product contract proof/x25519_stubs.h
// states -- operands under 2^18 multiply to a value under 2^36 -- is
// proven on the multiply that runs on the target, with every check on
// (https://github.com/c4milo/chapulin/issues/145). A proof name is one
// launch line, so the variant gets its own file, the x509der_ecdsa
// precedent.
#define CH_CT_WIDEMUL 1
#include "x25519_mul_harness.c"
