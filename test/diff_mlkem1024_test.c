// ML-KEM-1024's arm of the differential oracle: the ML-KEM rows of
// test/diff_mlkem.h, run against the same Lean spec process test/diff_test.c
// drives, over mlkem.c built under -DCH_MLKEM_1024 (docs/decisions.md 150).
// The rows then ask the oracle's mlkem1024_ commands, which run
// spec/lean/Spec/MlKem.lean at its ml1024 parameter set.
//
// Its own main rather than a second build of test/diff_test.c, because the
// parameter set changes nothing else that binary compares: every other row
// would run the same code twice.
//
// Under -DCH_MLKEM_TWO_RANKS it is bin/diff_mlkem_two_ranks, over an object
// that runs both ranks (docs/decisions.md 177): each round runs the rows at
// rank 4 and then at rank 3, so the two-rank code meets the spec at both.
//
// The rows draw fresh random inputs on every call, so each is run four
// times.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rand.h"
#include "test_random.h"

#include "diff_driver.h"

#ifndef CH_MLKEM_1024
#error "test/diff_mlkem1024_test.c diffs ML-KEM-1024: build it with -DCH_MLKEM_1024"
#endif

#include "diff_mlkem.h"

#ifdef CH_MLKEM_TWO_RANKS
#define DIFF_LABEL "diff mlkem two ranks"
#else
#define DIFF_LABEL "diff mlkem-1024"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf(DIFF_LABEL ": seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    for (int round = 0; round < 4; round++) {
        diff_mlkem_keygen(MLKEM_RANK_1024);
        diff_mlkem_encaps(MLKEM_RANK_1024);
        diff_mlkem_decaps(MLKEM_RANK_1024);
#ifdef CH_MLKEM_TWO_RANKS
        diff_mlkem_keygen(MLKEM_RANK_768);
        diff_mlkem_encaps(MLKEM_RANK_768);
        diff_mlkem_decaps(MLKEM_RANK_768);
#endif
    }
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf(DIFF_LABEL ": %ld comparisons, C == spec\n", comparisons);
    return 0;
}
