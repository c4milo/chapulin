// Differential oracle: drives the Lean executable spec (built as
// spec/.lake/build/bin/diffspec) over a blocking pipe line protocol and
// compares every C crypto module against it on deterministic
// pseudo-random inputs. Any divergence prints the request and both
// answers, then fails the build.
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rand.h"
#include "test_random.h"

// Driver plumbing (PRNG, hex, spec pipe) and every primitive's section
// live in sibling headers of this, the only translation unit.
#include "diff_driver.h"
#include "diff_hash.h"
#include "diff_hsparse.h"
#include "diff_p256.h"
#include "diff_record.h"
#include "diff_rsa.h"
#include "diff_x25519.h"
#include "diff_x509.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/.lake/build/bin/diffspec";
    (void)printf("diff: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    diff_sha256();
    diff_hmac();
    diff_hkdf_extract();
    diff_hkdf_expand();
    diff_expand_label();
    diff_schedule();
    diff_chacha20();
    diff_poly1305();
    diff_aead_seal();
    diff_aead_open();
    diff_rec_seal();
    diff_rec_open();
    diff_traffic_update();
    diff_x25519();
    diff_x25519_base();
    diff_p256();
    diff_rsa();
    diff_x509();
    diff_hs_server_hello();
    diff_hs_encrypted_exts();
    diff_hs_certificate();
    diff_hs_certificate_verify();
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
