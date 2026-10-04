// bin/ghash_equiv_test's cases on gcm_vaes.c's 256-bit kernels, which an
// x86-64 host object holds beside gcm_hw.c's 128-bit loops
// (docs/decisions.md 90). Included by test/ghash_equiv_test.c only, after
// test/ghash_equiv_residue.h: it runs that file's AEAD cases and that
// header's residue checks, and uses the failure count both use.
#ifndef CH_GHASH_EQUIV_VAES_H
#define CH_GHASH_EQUIV_VAES_H
#ifdef __x86_64__

#include "gcm_vaes.h"
#include "x86_kernels_cpu.h"

// The AEAD cases and the residue checks once more on gcm_vaes.c's kernels,
// where this CPU runs them. The cases run under a schedule whose
// description of the CPU names VAES beside the AES bit, which is how gcm.c
// picks the kernels for a session, and the residue checks call the
// kernels' seal and open. Under CH_REQUIRE_X86_KERNELS a CPU without the
// instructions counts as a failure.
static void run_on_vaes(void) {
    if (!x86_cpu_has_vaes()) {
        if (x86_kernels_required()) {
            (void)fprintf(stderr, "ghash equivalence: this CPU lacks VAES or VPCLMULQDQ, and "
                                  "CH_REQUIRE_X86_KERNELS is 1\n");
            failures++;
            return;
        }
        printf("ghash equivalence: SKIP the VAES kernels: this CPU lacks VAES or VPCLMULQDQ\n");
        return;
    }
    aead_cpu = CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_VAES;
    run_aead();
    aead_cpu = 0;
    residue_seal_passes = gcm_seal_passes_vaes;
    residue_open_passes = gcm_open_passes_vaes;
    run_residue();
}

#endif // __x86_64__
#endif
