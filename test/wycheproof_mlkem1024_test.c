// The three Wycheproof ML-KEM-1024 suites against mlkem.c built under
// -DCH_MLKEM_1024, over the vectors test/gen_wycheproof.py writes to
// bin/wycheproof_mlkem1024_vectors.h from the pinned checkout
// (docs/decisions.md 150). One object holds one ML-KEM parameter set, so
// this binary runs apart from wycheproof_test.c, and the runners are the
// ones that binary runs at ML-KEM-768 (test/wycheproof_mlkem.h).
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "mlkem.h"
#include "test_widemul.h"
#include "wycheproof_mlkem1024_vectors.h"

#ifndef CH_MLKEM_1024
#error "wycheproof_mlkem1024_test builds with -DCH_MLKEM_1024"
#endif

static int failures;

static void fail(const char *suite, uint32_t tc, const char *what) {
    printf("FAIL %s tc%" PRIu32 ": %s\n", suite, tc, what);
    failures++;
}

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

#include "wycheproof_mlkem.h"

// A host binary takes the ch_cfg.cpu value it runs under as its one
// argument (test/test_cpu.h); every other binary takes none.
int main(int argc, char **argv) {
    test_take_cpu(argc, argv);
    printf("wycheproof vectors at commit %s\n", WYCHEPROOF_COMMIT);
    run_mlkem_keygen();
    run_mlkem_encaps();
    run_mlkem_full();
    if (failures) {
        printf("wycheproof mlkem-1024: %d FAILURES\n", failures);
        return 1;
    }
    printf("wycheproof mlkem-1024: all %d cases passed\n", WP_MLKEM1024_CASES_TOTAL);
    return 0;
}
