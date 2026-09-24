// The X25519=wide arm of the differential oracle: the x25519 rows of
// test/diff_x25519.h, run against the same Lean spec process test/diff_test.c
// drives, over x25519_wide.c. The Makefile builds it with -DCH_X25519_WIDE,
// so x25519() answers from the radix-2^51 field here and from the 16-limb
// field in bin/diff.
//
// Its own main rather than a second build of test/diff_test.c, because the
// field changes nothing else that binary compares: every other row would
// run the same code twice. spec/lean/Spec/X25519.lean computes over Nat
// with a reduction mod p after every operation, so it states no limb
// representation and serves both fields unchanged.
//
// The rows draw fresh random inputs on every call, so each is run ten times:
// 1,000 scalar multiplications of a random point and 500 of the base point.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rand.h"
#include "test_random.h"

#include "diff_driver.h"

#include "diff_x25519.h"

// A build without the define would diff the 16-limb field a second time and
// report success for the wrong field.
#ifndef CH_X25519_WIDE
#error "test/diff_x25519_test.c diffs X25519=wide: build it with -DCH_X25519_WIDE"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff x25519 wide: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    for (int round = 0; round < 10; round++) {
        diff_x25519();
        diff_x25519_base();
    }
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff x25519 wide: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
