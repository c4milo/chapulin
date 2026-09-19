// The TRANSPORT=quic arm of the differential oracle: the same Lean spec
// process test/diff_test.c drives, over the modules only a
// -DCH_TRANSPORT_QUIC build compiles.
//
// Its own main rather than rows in test/diff_test.c, for the reason that
// file's own binary has: test/diff_test.c calls rec_seal and reads the
// TLS layout of ch_cfg, and a -DCH_TRANSPORT_QUIC build compiles
// neither. docs/quic.md records the same split for test/unit_test.c and
// bin/quic_test. The driver plumbing is shared: test/diff_driver.h holds
// the PRNG, the hex codecs and the pipe protocol, and both mains include
// it.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rand.h"
#include "test_random.h"

#include "diff_driver.h"

#include "diff_aes.h"

#include "diff_gcm.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/.lake/build/bin/diffspec";
    (void)printf("diff quic: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    diff_aes128();
    diff_quic_initial_keys();
    diff_aes128gcm_seal();
    diff_aes128gcm_open();
    diff_ghash();
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff quic: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
