// ch_hmac, ch_hkdf_extract and ch_hkdf_expand against Wycheproof: every
// case of the HMAC and HKDF suites over SHA-256, SHA-384 and SHA-512
// (test/gen_wycheproof_hash.py, docs/decisions.md 246), under
// CH_CPU_PROBED and under the bits this CPU has of the hash instructions
// and kernels (test/hash_host_cpu.h). A valid tag must be the first bytes
// of the tag the call writes, and an invalid one must not. A valid HKDF
// case must give its output, and an invalid one, which asks for more than
// 255 blocks, must be refused. The header is bin/wycheproof_hash_vectors.h,
// which make wycheproof writes.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "hash.h"
#include "hash_host_cpu.h"
#include "wycheproof_hash_vectors.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#define COUNT(a) (sizeof(a) / sizeof(a)[0])

// The longest output a case asks for: 255 blocks of SHA-512, and one more
// byte for a case past them.
#define OKM_ROOM (CH_HKDF_EXPAND_LEN_MAX(CH_SHA512_LEN) + 1)

static size_t digest_len(uint8_t algorithm) {
    if (algorithm == CH_HASH_ALGORITHM_SHA256) {
        return CH_SHA256_LEN;
    }
    return algorithm == CH_HASH_ALGORITHM_SHA384 ? CH_SHA384_LEN : CH_SHA512_LEN;
}

static size_t hmac_failures(uint32_t cpu) {
    size_t failures = 0;
    for (size_t i = 0; i < COUNT(wp_hmac); i++) {
        uint8_t tag[CH_SHA512_LEN];
        size_t tag_len = digest_len(wp_hmac[i].algorithm);
        int rc = ch_hmac(cpu, wp_hmac[i].algorithm, wp_hmac[i].key, wp_hmac[i].key_len,
                         wp_hmac[i].msg, wp_hmac[i].msg_len, tag, tag_len);
        // A tag of another length than the group's is no tag of the group.
        int accepted = rc == CH_OK && wp_hmac[i].tag_len == wp_hmac[i].tag_size &&
                       memcmp(tag, wp_hmac[i].tag, wp_hmac[i].tag_size) == 0;
        if (accepted != wp_hmac[i].valid) {
            printf("FAIL Wycheproof HMAC algorithm %d tcId %d under 0x%x: %s\n",
                   wp_hmac[i].algorithm, wp_hmac[i].tc_id, (unsigned)cpu,
                   wp_hmac[i].valid ? "a valid tag was refused" : "an invalid tag was accepted");
            failures++;
        }
    }
    return failures;
}

static size_t hkdf_failures(uint32_t cpu) {
    static uint8_t okm[OKM_ROOM];
    size_t failures = 0;
    for (size_t i = 0; i < COUNT(wp_hkdf); i++) {
        uint8_t prk[CH_SHA512_LEN];
        size_t prk_len = digest_len(wp_hkdf[i].algorithm);
        int rc = ch_hkdf_extract(cpu, wp_hkdf[i].algorithm, wp_hkdf[i].salt, wp_hkdf[i].salt_len,
                                 wp_hkdf[i].ikm, wp_hkdf[i].ikm_len, prk, prk_len);
        if (rc == CH_OK && wp_hkdf[i].size <= sizeof okm) {
            rc = ch_hkdf_expand(cpu, wp_hkdf[i].algorithm, prk, prk_len, wp_hkdf[i].info,
                                wp_hkdf[i].info_len, okm, wp_hkdf[i].size);
        }
        int accepted = rc == CH_OK && wp_hkdf[i].okm_len == wp_hkdf[i].size &&
                       memcmp(okm, wp_hkdf[i].okm, wp_hkdf[i].size) == 0;
        if (accepted != wp_hkdf[i].valid) {
            printf("FAIL Wycheproof HKDF algorithm %d tcId %d under 0x%x: %s\n",
                   wp_hkdf[i].algorithm, wp_hkdf[i].tc_id, (unsigned)cpu,
                   wp_hkdf[i].valid ? "a valid case failed" : "an invalid case was taken");
            failures++;
        }
    }
    return failures;
}

int main(void) {
    uint32_t host = hash_host_cpu();
    size_t failures = hmac_failures(CH_CPU_PROBED) + hkdf_failures(CH_CPU_PROBED) +
                      hmac_failures(host) + hkdf_failures(host);
    if (failures != 0) {
        return 1;
    }
    printf("Wycheproof hash: %zu HMAC and %zu HKDF cases over SHA-256, SHA-384 and SHA-512, under "
           "CH_CPU_PROBED and under 0x%x; every one matches\n",
           COUNT(wp_hmac), COUNT(wp_hkdf), (unsigned)host);
    return 0;
}
