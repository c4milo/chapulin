// bin/ghash_equiv_test's cases on gcm_arm64_eor3.c's copy of the whole
// seal and open, which an arm64 host object holds beside gcm_arm64.c's and
// runs for a session whose ch_cfg.cpu holds CH_CPU_CONSTANT_TIME_SHA3
// (docs/decisions.md 158). Included by test/ghash_equiv_test.c only, after
// test/ghash_equiv_residue.h: it runs that file's AEAD cases and that
// header's residue checks, and uses the failure count both use.
#ifndef CH_GHASH_EQUIV_EOR3_H
#define CH_GHASH_EQUIV_EOR3_H
#ifdef __aarch64__

#include "gcm_arm64.h"
#include "hash_instructions_cpu.h"

// The AEAD cases and the residue checks once more on the EOR3 copy, where
// this CPU has FEAT_SHA3. The cases run under a schedule whose description
// of the CPU names the SHA-3 bit beside the AES bit, which is how gcm.c
// picks the copy for a session, and the residue checks call its seal and
// open. Under CH_REQUIRE_HASH_INSTRUCTIONS a CPU without FEAT_SHA3 counts
// as a failure.
static void run_on_eor3(void) {
    if (!cpu_has_sha3_instructions()) {
        if (hash_instructions_required()) {
            (void)fprintf(stderr, "ghash equivalence: this CPU lacks FEAT_SHA3, and "
                                  "CH_REQUIRE_HASH_INSTRUCTIONS is 1\n");
            failures++;
            return;
        }
        printf("ghash equivalence: SKIP the EOR3 passes: this CPU lacks FEAT_SHA3\n");
        return;
    }
    aead_cpu = CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_SHA3;
    run_aead();
    aead_cpu = 0;
    residue_seal_aead = gcm_seal_arm64_eor3;
    residue_open_aead = gcm_open_arm64_eor3;
    run_residue();
}

#else
// Another target holds no such copy.
static void run_on_eor3(void) {
}
#endif // __aarch64__
#endif
