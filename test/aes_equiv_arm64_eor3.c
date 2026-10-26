// gcm_arm64_eor3.c's whole seal and open, for bin/aes_equiv_test's
// test/aes_equiv_gcm.h, under the defines test/aes_equiv_arm64.c
// states, in a translation unit apart from that copy, whose file-local
// names this one shares. On a target other than arm64 they compile to
// nothing.
#define CH_CPU_RUNTIME 1
#define CH_AES_256_TEST 1
#include "gcm_arm64_eor3.c"
