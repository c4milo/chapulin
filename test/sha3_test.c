// SHA-3 and SHAKE against the published FIPS 202 example values, plus the
// streaming contract: split absorbs and split squeezes produce the one-shot
// stream. Its own binary because nothing in the packaged object calls SHA-3
// yet (https://github.com/c4milo/chapulin/issues/21); the module stays
// testable without the rest of the stack, the way drbg_test and rsa_test do.
#include <stdio.h>
#include <string.h>

#include "sha3.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

// NIST FIPS 202 example values: the empty message and "abc" for the
// fixed-length digests, the empty message and the 1600-bit message of
// repeated 0xa3 for the XOFs (first 32 output bytes).
static void test_vectors(void) {
    static const uint8_t sha3_256_empty[] = {0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
                                             0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
                                             0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
                                             0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a};
    static const uint8_t sha3_256_abc[] = {0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
                                           0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
                                           0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
                                           0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32};
    static const uint8_t sha3_512_empty[] = {
        0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc, 0x18,
        0x5a, 0x75, 0x6e, 0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1,
        0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6, 0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9,
        0x4c, 0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58, 0xf5, 0x00, 0x19, 0x9d,
        0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26};
    static const uint8_t sha3_512_abc[] = {
        0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, 0x56, 0x93, 0xcd, 0x92, 0x4b,
        0x6b, 0x09, 0x6e, 0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d, 0x88, 0x4f,
        0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e, 0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3,
        0xc9, 0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40, 0x57, 0x34, 0x0b, 0x4c,
        0xf4, 0x08, 0xd5, 0xa5, 0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0};
    static const uint8_t shake128_empty[] = {0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
                                             0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
                                             0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
                                             0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26};
    static const uint8_t shake256_empty[] = {0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
                                             0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
                                             0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
                                             0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f};
    static const uint8_t shake128_a3[] = {0x13, 0x1a, 0xb8, 0xd2, 0xb5, 0x94, 0x94, 0x6b,
                                          0x9c, 0x81, 0x33, 0x3f, 0x9b, 0xb6, 0xe0, 0xce,
                                          0x75, 0xc3, 0xb9, 0x31, 0x04, 0xfa, 0x34, 0x69,
                                          0xd3, 0x91, 0x74, 0x57, 0x38, 0x5d, 0xa0, 0x37};
    static const uint8_t shake256_a3[] = {0xcd, 0x8a, 0x92, 0x0e, 0xd1, 0x41, 0xaa, 0x04,
                                          0x07, 0xa2, 0x2d, 0x59, 0x28, 0x86, 0x52, 0xe9,
                                          0xd9, 0xf1, 0xa7, 0xee, 0x0c, 0x1e, 0x7c, 0x1c,
                                          0xa6, 0x99, 0x42, 0x4d, 0xa8, 0x4a, 0x90, 0x4d};

    uint8_t d32[SHA3_256_LEN];
    uint8_t d64[SHA3_512_LEN];
    sha3_256((const uint8_t *)"", 0, d32);
    CHECK(memcmp(d32, sha3_256_empty, sizeof d32) == 0);
    sha3_256((const uint8_t *)"abc", 3, d32);
    CHECK(memcmp(d32, sha3_256_abc, sizeof d32) == 0);
    sha3_512((const uint8_t *)"", 0, d64);
    CHECK(memcmp(d64, sha3_512_empty, sizeof d64) == 0);
    sha3_512((const uint8_t *)"abc", 3, d64);
    CHECK(memcmp(d64, sha3_512_abc, sizeof d64) == 0);

    uint8_t a3[200];
    memset(a3, 0xa3, sizeof a3);
    uint8_t xof[32];
    shake s;
    shake128_init(&s);
    shake_squeeze(&s, xof, sizeof xof);
    CHECK(memcmp(xof, shake128_empty, sizeof xof) == 0);
    shake256_init(&s);
    shake_squeeze(&s, xof, sizeof xof);
    CHECK(memcmp(xof, shake256_empty, sizeof xof) == 0);
    shake128_init(&s);
    shake_absorb(&s, a3, sizeof a3);
    shake_squeeze(&s, xof, sizeof xof);
    CHECK(memcmp(xof, shake128_a3, sizeof xof) == 0);
    shake256_init(&s);
    shake_absorb(&s, a3, sizeof a3);
    shake_squeeze(&s, xof, sizeof xof);
    CHECK(memcmp(xof, shake256_a3, sizeof xof) == 0);
}

// The streaming contract from sha3.h: absorbing in pieces and squeezing
// in pieces produce the same stream as one absorb and one squeeze. The
// splits sit on and around the rate so both refill paths run.
static void test_streaming(void) {
    uint8_t msg[300];
    for (size_t i = 0; i < sizeof msg; i++) {
        msg[i] = (uint8_t)(i * 31 + 5);
    }
    uint8_t whole[400];
    shake s;
    shake128_init(&s);
    shake_absorb(&s, msg, sizeof msg);
    shake_squeeze(&s, whole, sizeof whole);

    static const size_t absorb_splits[] = {0, 1, 167, 168, 169, 299};
    for (size_t i = 0; i < sizeof absorb_splits / sizeof absorb_splits[0]; i++) {
        size_t at = absorb_splits[i];
        uint8_t out[400];
        shake128_init(&s);
        shake_absorb(&s, msg, at);
        shake_absorb(&s, msg + at, sizeof msg - at);
        shake_squeeze(&s, out, sizeof out);
        CHECK(memcmp(out, whole, sizeof out) == 0);
    }

    static const size_t squeeze_splits[] = {1, 167, 168, 169, 399};
    for (size_t i = 0; i < sizeof squeeze_splits / sizeof squeeze_splits[0]; i++) {
        size_t at = squeeze_splits[i];
        uint8_t out[400];
        shake128_init(&s);
        shake_absorb(&s, msg, sizeof msg);
        shake_squeeze(&s, out, at);
        shake_squeeze(&s, out + at, sizeof out - at);
        CHECK(memcmp(out, whole, sizeof out) == 0);
    }
}

int main(void) {
    test_vectors();
    test_streaming();
    if (failures == 0) {
        (void)printf("sha3: all tests passed\n");
    }
    return failures != 0;
}
