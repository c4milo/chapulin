// Zeros every vector register and the mask registers k1 to k7 of an x86-64
// CPU with AVX-512F, after a kernel that ran secrets through them.
#ifndef CH_AVX512_WIPE_H
#define CH_AVX512_WIPE_H

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
// Runs only where the session's ch_cfg.cpu holds CH_CPU_AVX512_IFMA, which
// says the CPU has AVX-512F: on a CPU without it the first instruction
// faults.
void avx512_wipe_registers(void);
#endif

#endif
