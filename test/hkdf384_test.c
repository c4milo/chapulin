// The SHA-384 half of the key schedule against published values: RFC 4231
// for HMAC-SHA-384, through hmac_sha384 and through the hmac dispatcher at
// SHA384_LEN, and a TLS 1.3 handshake under TLS_AES_256_GCM_SHA384 for
// ks_early, ks_handshake and the "key" and "iv" labels at the SHA-384 hash
// length. The dispatcher is also run at SHA256_LEN against RFC 4231's
// SHA-256 answer, so a dispatch that swapped the two hashes fails here.
//
// No RFC prints a SHA-384 TLS 1.3 trace: RFC 8448 runs
// TLS_AES_128_GCM_SHA256 throughout. The handshake values below are from
// The Illustrated TLS 1.3 Connection (tls13.xargs.org), which negotiates
// TLS_AES_256_GCM_SHA384 over x25519 and prints every secret, and
// Python's hmac module reproduces each of them from the two inputs it
// prints, the x25519 shared secret and the ClientHello..ServerHello hash.
// The Wycheproof HMAC-SHA-384 and HKDF-SHA-384 suites run in
// test/wycheproof_test.c.
//
// Its own binary built with -DCH_HASH_SHA384, so it runs on every host,
// with or without the AES instructions a suite build needs.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "hkdf.h"
#include "keysched.h"
#include "sha512.h"

#ifndef CH_HASH_SHA384
#error "test/hkdf384_test.c runs the SHA-384 key schedule: build it with -DCH_HASH_SHA384"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

static uint8_t nibble(char c) {
    if (c >= '0' && c <= '9') {
        return (uint8_t)(c - '0');
    }
    return (uint8_t)(c - 'a' + 10);
}

static size_t unhex(const char *hex, uint8_t *out) {
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    }
    return n;
}

static int eq_hex(const uint8_t *got, size_t n, const char *hex) {
    uint8_t want[SHA384_LEN];
    return unhex(hex, want) == n && memcmp(got, want, n) == 0;
}

// RFC 4231 §4.2 to §4.8, HMAC-SHA-384. Case 5 truncates the output to 128
// bits, which no caller here does, so it is left out.
static void test_rfc4231_sha384(void) {
    static const char big_key_data[] = "This is a test using a larger than block-size key and a "
                                       "larger than block-size data. The key needs to be hashed "
                                       "before being used by the HMAC algorithm.";
    uint8_t key[131];
    uint8_t data[160];
    uint8_t out[SHA384_LEN];

    memset(key, 0x0b, 20);
    hmac_sha384(key, 20, (const uint8_t *)"Hi There", 8, out);
    CHECK(eq_hex(out, sizeof out,
                 "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
                 "faea9ea9076ede7f4af152e8b2fa9cb6"));

    hmac(SHA384_LEN, (const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?",
         28, out);
    CHECK(eq_hex(out, sizeof out,
                 "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e"
                 "8e2240ca5e69e2c78b3239ecfab21649"));

    memset(key, 0xaa, 20);
    memset(data, 0xdd, 50);
    hmac(SHA384_LEN, key, 20, data, 50, out);
    CHECK(eq_hex(out, sizeof out,
                 "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b"
                 "2a5ab39dc13814b94e3ab6e101a34f27"));

    for (size_t i = 0; i < 25; i++) {
        key[i] = (uint8_t)(i + 1);
    }
    memset(data, 0xcd, 50);
    hmac(SHA384_LEN, key, 25, data, 50, out);
    CHECK(eq_hex(out, sizeof out,
                 "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e"
                 "6801dd23c4a7d679ccf8a386c674cffb"));

    // Cases 6 and 7: a key longer than SHA-384's 128-byte block, which
    // HMAC hashes first (RFC 2104 §2).
    memset(key, 0xaa, sizeof key);
    hmac(SHA384_LEN, key, sizeof key,
         (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54, out);
    CHECK(eq_hex(out, sizeof out,
                 "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6"
                 "0c2ef6ab4030fe8296248df163f44952"));
    hmac(SHA384_LEN, key, sizeof key, (const uint8_t *)big_key_data, strlen(big_key_data), out);
    CHECK(eq_hex(out, sizeof out,
                 "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5"
                 "a678cc31e799176d3860e6110c46523e"));
}

// The dispatcher at SHA256_LEN is HMAC-SHA-256: RFC 4231 §4.3's answer for
// the same "Jefe" input, 32 bytes.
static void test_dispatch_sha256(void) {
    uint8_t out[SHA256_LEN];
    hmac(SHA256_LEN, (const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?",
         28, out);
    CHECK(eq_hex(out, sizeof out,
                 "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
}

// The Illustrated TLS 1.3 Connection's key schedule under
// TLS_AES_256_GCM_SHA384: the early secret of no PSK, the handshake
// secret from the x25519 shared secret, both handshake traffic secrets
// over the ClientHello..ServerHello hash, and the key and IV each one
// gives at the suite's lengths, 32 and 12.
static void test_sha384_schedule(void) {
    static const uint8_t no_psk[SHA384_LEN] = {0};
    uint8_t early[SHA384_LEN];
    uint8_t binder_key[SHA384_LEN];
    ks_early(SHA384_LEN, no_psk, sizeof no_psk, 0, early, binder_key);
    CHECK(eq_hex(early, sizeof early,
                 "7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e7169"
                 "71f9362f2c2fe2a76bfd78dfec4ea9b5"));

    uint8_t shared[32];
    CHECK(unhex("df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624", shared) ==
          sizeof shared);
    uint8_t hello_hash[SHA384_LEN];
    CHECK(unhex("e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4"
                "f4d34555112077f16e079019d5a845bd",
                hello_hash) == sizeof hello_hash);
    uint8_t handshake_secret[SHA384_LEN];
    uint8_t c_hs[SHA384_LEN];
    uint8_t s_hs[SHA384_LEN];
    ks_handshake(SHA384_LEN, early, shared, sizeof shared, hello_hash, handshake_secret, c_hs,
                 s_hs);
    CHECK(eq_hex(handshake_secret, sizeof handshake_secret,
                 "bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c92"
                 "9078d2caa0936231c38d1725f179d299"));
    CHECK(eq_hex(c_hs, sizeof c_hs,
                 "db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42"
                 "ae184501972f8d30c4a3e4a3693d0ef0"));
    CHECK(eq_hex(s_hs, sizeof s_hs,
                 "23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a"
                 "68f481f2b019f9403a3051908a5d1622"));

    uint8_t key[32];
    uint8_t iv[12];
    hkdf_expand_label(SHA384_LEN, s_hs, "key", NULL, 0, key, sizeof key);
    hkdf_expand_label(SHA384_LEN, s_hs, "iv", NULL, 0, iv, sizeof iv);
    CHECK(eq_hex(key, sizeof key,
                 "9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f"));
    CHECK(eq_hex(iv, sizeof iv, "9563bc8b590f671f488d2da3"));
    hkdf_expand_label(SHA384_LEN, c_hs, "key", NULL, 0, key, sizeof key);
    hkdf_expand_label(SHA384_LEN, c_hs, "iv", NULL, 0, iv, sizeof iv);
    CHECK(eq_hex(key, sizeof key,
                 "1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69"));
    CHECK(eq_hex(iv, sizeof iv, "4256d2e0e88babdd05eb2f27"));
}

int main(void) {
    test_rfc4231_sha384();
    test_dispatch_sha256();
    test_sha384_schedule();
    if (failures == 0) {
        (void)printf("hkdf384: RFC 4231 HMAC-SHA-384 and a TLS_AES_256_GCM_SHA384 key schedule "
                     "agree\n");
    }
    return failures != 0;
}
