// The two Wycheproof ML-DSA-87 suites alone, over the vectors
// test/gen_wycheproof.py writes to bin/wycheproof_vectors.h
// (docs/decisions.md 154). test/wycheproof_test.c runs the same suites
// beside every other one on each host lane. The Cortex-M3 lane's 4 MB
// image cannot hold every suite at once, so that lane builds
// wycheproof_test.c with -DWYCHEPROOF_NO_MLDSA and runs this binary
// beside it (test/platforms.mk).
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "mldsa.h"
#include "test_cpu.h"
#include "wycheproof_vectors.h"

static int failures;

static void fail(const char *suite, uint32_t tc, const char *what) {
    printf("FAIL %s tc%" PRIu32 ": %s\n", suite, tc, what);
    failures++;
}

static void check_verdict(const char *suite, uint32_t tc, int ok, int valid) {
    if (ok != valid) {
        fail(suite, tc, ok ? "invalid signature accepted" : "valid rejected");
    }
}

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

#include "wycheproof_mldsa.h"

// A host binary takes the ch_cfg.cpu value it runs under as its one
// argument (test/test_cpu.h); every other binary takes none.
int main(int argc, char **argv) {
    test_take_cpu(argc, argv);
    printf("wycheproof vectors at commit %s\n", WYCHEPROOF_COMMIT);
    run_mldsa_verify();
    run_mldsa_signatures();
    if (failures) {
        printf("wycheproof mldsa-87: %d FAILURES\n", failures);
        return 1;
    }
    printf("wycheproof mldsa-87: all suites passed\n");
    return 0;
}
