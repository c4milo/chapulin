// bin/x86_kernels_test's RSA rows. test/x86_kernels_test.c alone includes
// this file, on x86-64, after it defines CHECK and failures.
//
// rsa.c's and rsa_pkcs1.c's entries that take a session's ch_cfg.cpu run
// the public operation through rsa_mont.c's rsa_vp1_cpu, which hands it to
// rsa_ifma.c's rsa_ifma_public where the value holds CH_CPU_AVX512_IFMA
// and the modulus is one that call takes: at least RSA_IFMA_WORDS_MIN
// words, its top bit set, and odd. The entries that take no value run
// rsa_mont64.c. test/rsa_ifma_count.c counts each call to
// rsa_ifma_public and computes its bytes on rsa_mont64.c from the
// 2^(104n) mod m the call passed, so these rows also fail where
// rsa_vp1_cpu computed that power of two wrongly: a wrong count of steps
// at RSA-2048 and RSA-3072, and a wrong start bit at RSA-3072 alone
// (check_rsa_moduli).
#ifndef CH_TEST_X86_KERNELS_RSA_H
#define CH_TEST_X86_KERNELS_RSA_H

#include <stdio.h>
#include <string.h>

#include "rsa.h"
#include "rsa_ifma_count.h"
#include "rsa_ifma_sign_count.h"
#include "rsa_pkcs1.h"
#include "rsa_pkcs1_vectors.h"
#include "rsa_sign.h"
#include "rsa_sign_key.h"
#include "sha256.h"
#include "widemul.h"

// What a value names, written here apart from rsa_mont.c's use_ifma so
// that a wrong predicate fails a row.
static unsigned long names_ifma(uint32_t cpu) {
    return (cpu & CH_CPU_AVX512_IFMA) != 0 ? 1 : 0;
}

// Whether the calls into rsa_ifma_public since the last look are these,
// and resets them.
static int rsa_ifma_calls_are(unsigned long calls) {
    int same = rsa_ifma_public_calls == calls;
    if (!same) {
        (void)fprintf(stderr, "calls: rsa_ifma_public %lu; want %lu\n", rsa_ifma_public_calls,
                      calls);
    }
    rsa_ifma_public_calls = 0;
    return same;
}

// The two verifiers over test/rsa_pkcs1_vectors.h's RSA-2048 key, which
// has a PKCS#1 v1.5 signature and a PSS one over the same digest. Each
// entry that takes a value runs the kernel once where the value names it
// and gives the plain entry's answer, a refusal of the other scheme's
// signature included. A signature at the modulus is refused before the
// public operation, so it runs no kernel.
static void check_rsa_verifiers(uint32_t cpu) {
    const uint8_t *digest = rsa2048_sha256_digest;
    const uint8_t *pss = rsa2048_sha256_pss_sig;
    const uint8_t *pkcs1 = rsa2048_sha256_sig;
    size_t len = sizeof n2048;
    rsa_ifma_public_calls = 0;
    CHECK(rsa_pss_verify(n2048, len, digest, pss, len) == 1);
    CHECK(rsa_pkcs1_verify(n2048, len, digest, SHA256_LEN, pkcs1, len) == 1);
    CHECK(rsa_ifma_calls_are(0));
    CHECK(rsa_pss_verify_cpu(cpu, n2048, len, digest, pss, len) == 1);
    CHECK(rsa_ifma_calls_are(names_ifma(cpu)));
    CHECK(rsa_pkcs1_verify_cpu(cpu, n2048, len, digest, SHA256_LEN, pkcs1, len) == 1);
    CHECK(rsa_ifma_calls_are(names_ifma(cpu)));
    CHECK(rsa_pss_verify_cpu(cpu, n2048, len, digest, pkcs1, len) == 0);
    CHECK(rsa_pkcs1_verify_cpu(cpu, n2048, len, digest, SHA256_LEN, pss, len) == 0);
    CHECK(rsa_ifma_calls_are(2 * names_ifma(cpu)));
    CHECK(rsa_pss_verify_cpu(cpu, n2048, len, digest, n2048, len) == 0);
    CHECK(rsa_pkcs1_verify_cpu(cpu, n2048, len, digest, SHA256_LEN, n2048, len) == 0);
    CHECK(rsa_ifma_calls_are(0));
}

// rsa_vp1_cpu over two moduli the kernel takes, that key's and
// test/rsa_pkcs1_vectors.h's RSA-3072 one, and over three moduli made from
// the RSA-2048 one that it does not take, each one condition short: an
// even one, one whose top bit is clear, and one of 31 words. Each gives
// rsa_vp1's bytes for the base 2, which is below all five.
//
// The RSA-3072 row is the one that fails where rsa_mont.c's
// power_of_two_mod starts at the wrong bit of its top word. At RSA-2048
// the exponent it takes is 104n = 4160, a multiple of 64, so it starts at
// bit 0 of that word, and a start bit that ignores the exponent gives the
// same power of two. At RSA-3072 the exponent is 6240, which is 32 past a
// multiple of 64.
static void check_rsa_moduli(uint32_t cpu) {
    uint8_t even[sizeof n2048];
    uint8_t top_clear[sizeof n2048];
    uint8_t short_n[sizeof n2048 - 8];
    memcpy(even, n2048, sizeof even);
    even[sizeof even - 1] &= 0xfe;
    memcpy(top_clear, n2048, sizeof top_clear);
    top_clear[0] &= 0x7f;
    memcpy(short_n, n2048, sizeof short_n);
    short_n[sizeof short_n - 1] |= 1;
    const struct {
        const uint8_t *n;
        size_t n_len;
        unsigned long kernel_calls;
    } rows[] = {
        {n2048,     sizeof n2048,     names_ifma(cpu)},
        {n3072,     sizeof n3072,     names_ifma(cpu)},
        {even,      sizeof even,      0              },
        {top_clear, sizeof top_clear, 0              },
        {short_n,   sizeof short_n,   0              },
    };
    uint8_t two[sizeof n3072] = {0};
    two[sizeof two - 1] = 2;
    rsa_ifma_public_calls = 0;
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        const uint8_t *base = two + sizeof two - rows[i].n_len;
        uint8_t want[sizeof n3072];
        uint8_t got[sizeof n3072];
        rsa_vp1(rows[i].n, rows[i].n_len, base, want);
        CHECK(rsa_ifma_calls_are(0));
        rsa_vp1_cpu(cpu, rows[i].n, rows[i].n_len, base, got);
        CHECK(rsa_ifma_calls_are(rows[i].kernel_calls));
        CHECK(memcmp(got, want, rows[i].n_len) == 0);
    }
}

// What a value names for a signature, written apart from rsa_sign64.c's
// use_ifma: the exponentiations and the check on AVX-512 IFMA where it
// holds CH_CPU_AVX512_IFMA and CH_CPU_CONSTANT_TIME_MULTIPLY both.
static unsigned long names_ifma_signer(uint32_t cpu) {
    uint32_t both = CH_CPU_AVX512_IFMA | CH_CPU_CONSTANT_TIME_MULTIPLY;
    return (cpu & both) == both ? 1 : 0;
}

static void reset_signer_calls(void) {
    rsa_ifma_sign_pair_calls = 0;
    rsa_ifma_public_calls = 0;
    rsa_ifma_sign_wipe_calls = 0;
    avx512_wipe_calls = 0;
}

// Whether a signature's calls since the last reset are these: each
// kernel kernel_calls times, and each of the two wipes after each of
// them. Resets them.
static int signer_calls_are(unsigned long kernel_calls) {
    int same = rsa_ifma_sign_pair_calls == kernel_calls && rsa_ifma_public_calls == kernel_calls &&
               rsa_ifma_sign_wipe_calls == 2 * kernel_calls &&
               avx512_wipe_calls == 2 * kernel_calls;
    if (!same) {
        (void)fprintf(stderr,
                      "calls: rsa_ifma_sign_power_pair %lu, rsa_ifma_public %lu, "
                      "rsa_ifma_sign_wipe_below %lu, avx512_wipe_registers %lu; want %lu, %lu, "
                      "%lu, %lu\n",
                      rsa_ifma_sign_pair_calls, rsa_ifma_public_calls, rsa_ifma_sign_wipe_calls,
                      avx512_wipe_calls, kernel_calls, kernel_calls, 2 * kernel_calls,
                      2 * kernel_calls);
    }
    reset_signer_calls();
    return same;
}

// The signer through widemul.h's entry a server signs through, under the
// answer the value gives and the value itself, over
// test/rsa_sign_vectors.h's RSA-2048 key: the bytes of rsa_sign.c's
// ladder, which a value without the multiply bit runs, and the kernels
// with their wipes exactly where the value names them
// (docs/decisions.md 120). test/rsa_ifma_sign_count.c and
// test/rsa_ifma_count.c write the bytes the kernels write, on
// rsa_mont64.c, so the bytes hold wherever the calls go.
static void check_rsa_signer(uint32_t cpu) {
    static const test_rsa_sign_key from = TEST_RSA_SIGN_KEY(2048);
    static ch_rsa_priv key;
    static uint8_t want[CH_RSA_MODULUS_MAX];
    static size_t want_len;
    static const uint8_t digest[SHA256_LEN] = {0x5a, 0x01};
    static const uint8_t salt[RSA_PSS_SALT_LEN] = {0xa5, 0x02};
    if (want_len == 0) {
        test_rsa_sign_key_load(&key, &from);
        CHECK(rsa_pss_sign(&key, digest, salt, want, sizeof want, &want_len) == 1);
    }
    uint8_t sig[CH_RSA_MODULUS_MAX];
    size_t sig_len = 0;
    reset_signer_calls();
    CHECK(widemul_rsa_pss_sign_cpu(cpu, widemul_of_cpu(cpu), &key, digest, salt, sig, sizeof sig,
                                   &sig_len) == 1);
    CHECK(signer_calls_are(names_ifma_signer(cpu)));
    CHECK(sig_len == want_len && memcmp(sig, want, want_len) == 0);
}

#endif
