// Linked into each test or bench build that routes the library's calls to
// an x86-64 kernel (test/chacha20_avx2_route.h, test/gcm_vaes_route.h),
// whose route headers are force-included here too. Before main it checks
// that this CPU has the instructions those kernels run. On a CPU that
// lacks one, the binary prints SKIP and exits 0, or fails when
// CH_REQUIRE_X86_KERNELS is 1 (test/x86_kernels_cpu.h). The Makefile
// builds such binaries for x86-64 alone, so on any other target this file
// holds nothing to run.
#include <stdio.h>

#include "x86_kernels_cpu.h"

#ifdef __x86_64__
// Whether this CPU runs every kernel the build routes its calls to.
static int routed_instructions_present(void) {
#if defined(TEST_ROUTE_AVX2) && defined(TEST_ROUTE_VAES)
    return x86_cpu_has_avx2() && x86_cpu_has_vaes();
#elif defined(TEST_ROUTE_VAES)
    return x86_cpu_has_vaes();
#else
    return x86_cpu_has_avx2();
#endif
}

__attribute__((constructor)) static void require_routed_instructions(void) {
    if (routed_instructions_present()) {
        return;
    }
    if (x86_kernels_required()) {
        (void)fprintf(stderr,
                      "x86 kernels: this CPU lacks the instructions the routed kernels run, "
                      "and CH_REQUIRE_X86_KERNELS is 1\n");
        exit(1);
    }
    printf("SKIP: this CPU lacks the instructions the routed x86-64 kernels run\n");
    exit(0);
}
#endif
