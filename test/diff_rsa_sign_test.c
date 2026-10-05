// The RSA signers' arm of the differential oracle: RSASSA-PSS signatures
// by the same Lean spec process test/diff_test.c drives, against both
// signers a host object holds. The spec signs a random digest under a
// random salt with a key of test/rsa_sign_vectors.h, and each C signer
// must write the same bytes: a PSS signature is a function of the key,
// the digest and the salt. The Makefile builds this as a host object's
// sources, with -DCH_CPU_RUNTIME, so rsa_sign64_pss is the signer on
// 64-bit limbs, which signs by the Chinese remainder theorem from the
// key's primes, and rsa_pss_sign is the ladder on the decomposition, the
// code a device object runs.
//
// Its own main rather than rows of test/diff_test.c, because bin/diff is
// built as a device object's sources and holds no 64-bit signer.
// spec/lean/Spec/Rsa.lean computes RSASP1 over Nat as m^d mod n, so it
// states no limb width and no route to that power, and serves both
// signers unchanged: the spec takes n and d alone, and the 64-bit signer
// must give its bytes from p, q, dp, dq and qinv.
//
// The ladder takes 60 ms and more for a signature, so it signs the first
// row of each key, and the 64-bit signer signs every row.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rsa_sign.h"
#include "rsa_sign_key.h"

#include "diff_driver.h"

// A build without the define declares no 64-bit signer, so it could only
// diff the ladder and report success for the wrong one.
#ifndef CH_CPU_RUNTIME
#error "test/diff_rsa_sign_test.c diffs the 64-bit RSA signer: build it with -DCH_CPU_RUNTIME"
#endif
#include "rsa_sign64.h"

#define DIFF_RSA_SIGN_ROWS 4

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// One key: static, because ch_rsa_priv is a kilobyte and more.
static ch_rsa_priv key;

// The spec's signature over hash and salt under key, as n_len bytes.
static void spec_sign(const uint8_t hash[32], const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig) {
    static char cmd[4 * CH_RSA_MODULUS_MAX + 256];
    static char n_hex[2 * CH_RSA_MODULUS_MAX + 1];
    static char d_hex[2 * CH_RSA_MODULUS_MAX + 1];
    static char sig_hex[2 * CH_RSA_MODULUS_MAX + 2];
    char hash_hex[65];
    char salt_hex[2 * RSA_PSS_SALT_LEN + 1];
    (void)hex_encode(n_hex, key.n, key.n_len);
    (void)hex_encode(d_hex, key.d, key.n_len);
    (void)hex_encode(hash_hex, hash, 32);
    (void)hex_encode(salt_hex, salt, RSA_PSS_SALT_LEN);
    (void)snprintf(cmd, sizeof cmd, "rsa_sign %s %s 65537 %s %s", n_hex, d_hex, salt_hex, hash_hex);
    query(cmd, sig_hex, sizeof sig_hex);
    if (strlen(sig_hex) != 2 * key.n_len || !hex_decode(sig, sig_hex, key.n_len)) {
        die("rsa_sign: malformed spec response");
    }
}

// One C signer's bytes against the spec's.
static void compare(const char *signer, int signed_ok, const uint8_t *got, size_t got_len,
                    const uint8_t *want) {
    if (!signed_ok || got_len != key.n_len || memcmp(got, want, key.n_len) != 0) {
        (void)fprintf(stderr, "diff: rsa_sign: %s differs from the spec at %zu bytes\n", signer,
                      key.n_len);
        exit(1);
    }
    comparisons++;
}

static void diff_key(const test_rsa_sign_key *from) {
    test_rsa_sign_key_load(&key, from);
    for (int row = 0; row < DIFF_RSA_SIGN_ROWS; row++) {
        uint8_t hash[32];
        uint8_t salt[RSA_PSS_SALT_LEN];
        static uint8_t want[CH_RSA_MODULUS_MAX];
        static uint8_t got[CH_RSA_MODULUS_MAX];
        size_t got_len = 0;
        rng_fill(hash, sizeof hash);
        rng_fill(salt, sizeof salt);
        // rsa_pss_sign asserts on an all-zero salt, which a draw gives
        // once in 2^256.
        salt[0] |= 1;
        spec_sign(hash, salt, want);

        int signed_ok = rsa_sign64_pss(&key, hash, salt, got, sizeof got, &got_len);
        compare("the 64-bit signer", signed_ok, got, got_len, want);
        if (row == 0) {
            got_len = 0;
            signed_ok = rsa_pss_sign(&key, hash, salt, got, sizeof got, &got_len);
            compare("the ladder", signed_ok, got, got_len, want);
        }
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff rsa sign: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    static const test_rsa_sign_key keys[] = {TEST_RSA_SIGN_KEY(2048), TEST_RSA_SIGN_KEY(2112),
                                             TEST_RSA_SIGN_KEY(3072), TEST_RSA_SIGN_KEY(4096)};
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        diff_key(&keys[i]);
    }
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff rsa sign: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
