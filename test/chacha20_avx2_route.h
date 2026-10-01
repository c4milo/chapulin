// Test and bench code only. A build that force-includes this header
// (-include) runs every chacha20_xor call on chacha20_avx2.c's AVX2
// kernel, whatever chacha20.c's use_avx2 answers: the header renames
// chacha20_vector_xor, the 128-bit path chacha20.c calls, to the kernel.
// Such a build links chacha20_avx2.c and not chacha20_vector.c, and links
// test/x86_kernels_route.c, which stops it before main on a CPU without
// AVX2. That is how the unit vectors, Wycheproof and the record bench run
// on the kernel while use_avx2 still answers 0 (docs/decisions.md 90).
#ifndef CH_TEST_CHACHA20_AVX2_ROUTE_H
#define CH_TEST_CHACHA20_AVX2_ROUTE_H

#define TEST_ROUTE_AVX2
#define chacha20_vector_xor chacha20_avx2_xor

#endif
