// gcm_arm64.c's whole seal and open, for bin/aes_equiv_test's
// test/aes_equiv_gcm.h. CH_CPU_RUNTIME is defined here rather than on
// the compile line, as test/aes_equiv_hw.c defines it, and CH_AES_256_TEST
// turns on AES-256, which a -DCH_SUITE_AES_GCM build runs. The entries take
// a translation unit apart from gcm_hw.c, whose file-local names they
// share. On a target other than arm64 they compile to nothing.
#define CH_CPU_RUNTIME 1
#define CH_AES_256_TEST 1
#include "gcm_arm64.c"
