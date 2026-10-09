// avx512_wipe.h's one call. A kernel that runs secrets through 512-bit
// registers leaves them there when it returns: the compiler clears no
// register on return, and VZEROUPPER and VZEROALL leave zmm16 to zmm31. C
// names no register, so this file holds the one block of assembly: an EVEX
// VPXORD of an xmm register clears the whole 512-bit register, and KXORW
// clears a mask register. k0 is not written: no instruction takes it as a
// mask, so no kernel leaves anything in it.
#include "avx512_wipe.h"

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
__attribute__((target("avx512f"))) void avx512_wipe_registers(void) {
    __asm__ volatile("vpxord %%xmm0, %%xmm0, %%xmm0\n\t"
                     "vpxord %%xmm1, %%xmm1, %%xmm1\n\t"
                     "vpxord %%xmm2, %%xmm2, %%xmm2\n\t"
                     "vpxord %%xmm3, %%xmm3, %%xmm3\n\t"
                     "vpxord %%xmm4, %%xmm4, %%xmm4\n\t"
                     "vpxord %%xmm5, %%xmm5, %%xmm5\n\t"
                     "vpxord %%xmm6, %%xmm6, %%xmm6\n\t"
                     "vpxord %%xmm7, %%xmm7, %%xmm7\n\t"
                     "vpxord %%xmm8, %%xmm8, %%xmm8\n\t"
                     "vpxord %%xmm9, %%xmm9, %%xmm9\n\t"
                     "vpxord %%xmm10, %%xmm10, %%xmm10\n\t"
                     "vpxord %%xmm11, %%xmm11, %%xmm11\n\t"
                     "vpxord %%xmm12, %%xmm12, %%xmm12\n\t"
                     "vpxord %%xmm13, %%xmm13, %%xmm13\n\t"
                     "vpxord %%xmm14, %%xmm14, %%xmm14\n\t"
                     "vpxord %%xmm15, %%xmm15, %%xmm15\n\t"
                     "vpxord %%xmm16, %%xmm16, %%xmm16\n\t"
                     "vpxord %%xmm17, %%xmm17, %%xmm17\n\t"
                     "vpxord %%xmm18, %%xmm18, %%xmm18\n\t"
                     "vpxord %%xmm19, %%xmm19, %%xmm19\n\t"
                     "vpxord %%xmm20, %%xmm20, %%xmm20\n\t"
                     "vpxord %%xmm21, %%xmm21, %%xmm21\n\t"
                     "vpxord %%xmm22, %%xmm22, %%xmm22\n\t"
                     "vpxord %%xmm23, %%xmm23, %%xmm23\n\t"
                     "vpxord %%xmm24, %%xmm24, %%xmm24\n\t"
                     "vpxord %%xmm25, %%xmm25, %%xmm25\n\t"
                     "vpxord %%xmm26, %%xmm26, %%xmm26\n\t"
                     "vpxord %%xmm27, %%xmm27, %%xmm27\n\t"
                     "vpxord %%xmm28, %%xmm28, %%xmm28\n\t"
                     "vpxord %%xmm29, %%xmm29, %%xmm29\n\t"
                     "vpxord %%xmm30, %%xmm30, %%xmm30\n\t"
                     "vpxord %%xmm31, %%xmm31, %%xmm31\n\t"
                     "kxorw %%k1, %%k1, %%k1\n\t"
                     "kxorw %%k2, %%k2, %%k2\n\t"
                     "kxorw %%k3, %%k3, %%k3\n\t"
                     "kxorw %%k4, %%k4, %%k4\n\t"
                     "kxorw %%k5, %%k5, %%k5\n\t"
                     "kxorw %%k6, %%k6, %%k6\n\t"
                     "kxorw %%k7, %%k7, %%k7\n\t"
                     :
                     :
                     : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8",
                       "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "xmm16",
                       "xmm17", "xmm18", "xmm19", "xmm20", "xmm21", "xmm22", "xmm23", "xmm24",
                       "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31", "k1", "k2",
                       "k3", "k4", "k5", "k6", "k7");
}
#endif
