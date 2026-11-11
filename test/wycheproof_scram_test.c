// ch_hmac_sha256 and ch_pbkdf2_hmac_sha256 against Wycheproof: every
// case of hmac_sha256_test.json and of pbkdf2_hmacsha256_test.json. A
// valid tag must be the first bytes of the tag the call writes, and an
// invalid one must not. ch_ct_compare makes each compare, as a caller's
// does. The header is bin/wycheproof_scram_vectors.h, which make
// wycheproof writes.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>

#include "ch_assert.h"
#include "scram.h"
#include "wycheproof_scram_vectors.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#define COUNT(a) (sizeof(a) / sizeof(a)[0])

// The longest key a PBKDF2 case derives here.
#define KEY_ROOM 128

int main(void) {
    size_t failures = 0;
    size_t valid = 0;
    for (size_t i = 0; i < COUNT(wp_hmac); i++) {
        uint8_t tag[CH_SHA256_LEN];
        ch_hmac_sha256(wp_hmac[i].key, wp_hmac[i].key_len, wp_hmac[i].msg, wp_hmac[i].msg_len,
                       tag);
        // A tag of another length than the group's is no tag of the group.
        int accepted = wp_hmac[i].tag_len == wp_hmac[i].tag_size &&
                       ch_ct_compare(tag, wp_hmac[i].tag, wp_hmac[i].tag_size) == CH_OK;
        valid += (size_t)wp_hmac[i].valid;
        if (accepted != wp_hmac[i].valid) {
            printf("FAIL Wycheproof HMAC-SHA-256 tcId %d: %s\n", wp_hmac[i].tc_id,
                   wp_hmac[i].valid ? "a valid tag was refused" : "an invalid tag was accepted");
            failures++;
        }
    }
    for (size_t i = 0; i < COUNT(wp_pbkdf2); i++) {
        uint8_t key[KEY_ROOM];
        if (wp_pbkdf2[i].key_len > sizeof key) {
            printf("FAIL Wycheproof PBKDF2 tcId %d: a key of %zu bytes\n", wp_pbkdf2[i].tc_id,
                   wp_pbkdf2[i].key_len);
            return 1;
        }
        int rc = ch_pbkdf2_hmac_sha256(wp_pbkdf2[i].password, wp_pbkdf2[i].password_len,
                                       wp_pbkdf2[i].salt, wp_pbkdf2[i].salt_len,
                                       wp_pbkdf2[i].iteration_count, key, wp_pbkdf2[i].key_len);
        if (rc != CH_OK || ch_ct_compare(key, wp_pbkdf2[i].key, wp_pbkdf2[i].key_len) != CH_OK) {
            printf("FAIL Wycheproof PBKDF2-HMAC-SHA-256 tcId %d\n", wp_pbkdf2[i].tc_id);
            failures++;
        }
    }
    if (failures != 0) {
        return 1;
    }
    printf("Wycheproof SCRAM parts: %zu HMAC-SHA-256 cases, %zu valid and %zu invalid, and %zu "
           "PBKDF2-HMAC-SHA-256 keys; every one matches\n",
           COUNT(wp_hmac), valid, COUNT(wp_hmac) - valid, COUNT(wp_pbkdf2));
    return 0;
}
