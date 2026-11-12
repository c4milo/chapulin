// The DNSSEC Ed25519 check (algorithm 15) against every case of
// Wycheproof's ed25519_test.json, through the public calls a validator
// makes: ch_dnssec_hash_init with the key and the signature, an update
// with the message, ch_dnssec_hash_final, then ch_dnssec_verify. A valid
// case must verify and an invalid one must not. A case that Wycheproof
// leaves to the implementation has a small-order key or a key outside the
// subgroup of prime order, and must not verify either
// (test/gen_wycheproof_ed25519.py, docs/decisions.md 227). The header is
// bin/wycheproof_ed25519_vectors.h, which make wycheproof writes.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>

#include "ch_assert.h"
#include "dnssec.h"
#include "wycheproof_ed25519_vectors.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// CH_OK when the public calls accept the case, and the first refusal
// otherwise.
static int check(size_t i) {
    ch_dnssec_hash h;
    int rc = ch_dnssec_hash_init(&h, CH_DNSSEC_ALG_ED25519, wp_ed25519[i].key, 32,
                                 wp_ed25519[i].sig, wp_ed25519[i].sig_len);
    if (rc != CH_OK) {
        return rc;
    }
    ch_dnssec_hash_update(&h, wp_ed25519[i].msg, wp_ed25519[i].msg_len);
    uint8_t digest[CH_DNSSEC_DIGEST_MAX];
    size_t n = ch_dnssec_hash_final(&h, digest);
    return ch_dnssec_verify(CH_DNSSEC_ALG_ED25519, wp_ed25519[i].key, 32, digest, n,
                            wp_ed25519[i].sig, wp_ed25519[i].sig_len);
}

int main(void) {
    size_t count = sizeof wp_ed25519 / sizeof wp_ed25519[0];
    size_t failures = 0;
    size_t valid = 0;
    size_t left = 0;
    for (size_t i = 0; i < count; i++) {
        int ok = check(i) == CH_OK;
        int want = wp_ed25519[i].kind == 1;
        valid += (size_t)want;
        left += (size_t)(wp_ed25519[i].kind == 2);
        if (ok != want) {
            printf("FAIL Wycheproof Ed25519 tcId %d: %s\n", wp_ed25519[i].tc_id,
                   want ? "a valid signature was refused"
                        : "a signature that must not verify did");
            failures++;
        }
    }
    if (failures != 0) {
        return 1;
    }
    printf("Wycheproof Ed25519: %zu cases, %zu valid, %zu invalid and %zu left to the "
           "implementation, which the key's order refuses; every verdict matches\n",
           count, valid, count - valid - left, left);
    return 0;
}
