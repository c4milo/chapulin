// gcm_vaes.c's kernels, for bin/aes_equiv_test. CH_CPU_RUNTIME is defined
// here rather than on the compile line, as test/aes_equiv_hw.c defines it, and
// the kernels take a translation unit apart from aes_hw.c and gcm_hw.c,
// whose file-local names they share. On a target other than x86-64 they
// compile to nothing.
#define CH_CPU_RUNTIME 1
#include "gcm_vaes.c"
