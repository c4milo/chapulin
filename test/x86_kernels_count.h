// The calls bin/x86_kernels_test counts into an x86-64 host object's
// kernels (docs/decisions.md 89, 90 and 107): chacha20_avx2.c's
// chacha20_avx2_xor, gcm_vaes.c's three entries, and the three session
// calls of mlkem_avx2.c. test/x86_kernels_count.c defines the seven, each
// as a count and a call to the entry it stands beside, which computes the
// same bytes, and the binary links that file in place of the kernel
// sources. So the
// library's sources run unchanged, no instruction of a kernel runs, and
// the test reads which calls the library sent to a kernel, on any x86-64
// CPU.
//
// The names are this test's alone, as test/aes_runtime_count.h's are.
#ifndef CH_TEST_X86_KERNELS_COUNT_H
#define CH_TEST_X86_KERNELS_COUNT_H

// Calls to chacha20_avx2_xor.
extern unsigned long x86_avx2_calls;
// Calls to gcm_seal_passes_vaes, gcm_open_passes_vaes and
// gcm_counter_blocks_vaes.
extern unsigned long x86_vaes_seal_calls;
extern unsigned long x86_vaes_open_calls;
extern unsigned long x86_vaes_counter_calls;
// Calls to the three session calls of mlkem_avx2.c, ML-KEM's copy for the
// four-way Keccak (docs/decisions.md 107): mlkem_keygen_dk_avx2,
// mlkem_encaps_derand_avx2 and mlkem_decaps_avx2.
extern unsigned long x86_mlkem_keygen_calls;
extern unsigned long x86_mlkem_encaps_calls;
extern unsigned long x86_mlkem_decaps_calls;

#endif
