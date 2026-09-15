// SHA-512 and SHA-384 against the FIPS 180-4 example values and RFC 6234
// §8.5, plus the streaming contract: a message delivered in two pieces
// hashes as one piece does. Its own binary because nothing in the raw
// or ca object calls SHA-512; the module stays testable without the rest
// of the stack, the way sha3_test does.
//
// Every expected value below was produced by `printf '%s' msg | openssl
// dgst -sha384` (or -sha512) with OpenSSL 3.6.4, and the standard's
// own examples — "abc", the 896-bit message, the empty string — match
// FIPS 180-4 appendix C and D. The 111, 112 and 113 byte messages sit
// on the padding boundary of the 128-byte block: 111 leaves room for
// the 0x80 and the 16-byte length in the same block, 112 forces a
// second block, 113 fills part of it. 127, 128 and 129 do the same for
// the block itself.
#include <stdio.h>
#include <string.h>

#include "sha512.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

static unsigned nibble(char c) {
    return c <= '9' ? (unsigned)(c - '0') : (unsigned)(c - 'a' + 10);
}

static void unhex(const char *hex, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    }
}

static void check_sha512(const uint8_t *msg, size_t n, const char *want_hex) {
    uint8_t want[SHA512_LEN];
    unhex(want_hex, want, sizeof want);
    uint8_t got[SHA512_LEN];
    sha512_of(msg, n, got);
    CHECK(memcmp(got, want, sizeof got) == 0);
}

static void check_sha384(const uint8_t *msg, size_t n, const char *want_hex) {
    uint8_t want[SHA384_LEN];
    unhex(want_hex, want, sizeof want);
    uint8_t got[SHA384_LEN];
    sha384_of(msg, n, got);
    CHECK(memcmp(got, want, sizeof got) == 0);
}

static const char msg_448[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static const char msg_896[] =
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnop"
    "jklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

static void test_sha512_vectors(void) {
    check_sha512((const uint8_t *)"", 0,
                 "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                 "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    check_sha512((const uint8_t *)"abc", 3,
                 "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                 "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    check_sha512((const uint8_t *)msg_448, sizeof msg_448 - 1,
                 "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
                 "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
    check_sha512((const uint8_t *)msg_896, sizeof msg_896 - 1,
                 "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                 "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");

    uint8_t a[129];
    memset(a, 'a', sizeof a);
    check_sha512(a, 111,
                 "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff4"
                 "8404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2");
    check_sha512(a, 112,
                 "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1"
                 "ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca");
    check_sha512(a, 113,
                 "55ddd8ac210a6e18ba1ee055af84c966e0dbff091c43580ae1be703bdb85da31acf6948c"
                 "f5bd90c55a20e5450f22fb89bd8d0085e39f85a86cc46abbca75e24d");
    check_sha512(a, 127,
                 "828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91bab50a51e0"
                 "88769a5c1eff4782ace147dce3642554199876374291f5d921629502");
    check_sha512(a, 128,
                 "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807e"
                 "d300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321");
    check_sha512(a, 129,
                 "4f681e0bd53cda4b5a2041cc8a06f2eabde44fb16c951fbd5b87702f07aeab611565b19c"
                 "47fde30587177ebb852e3971bbd8d3fd30da18d71037dfbd98420429");
}

static void test_sha384_vectors(void) {
    check_sha384((const uint8_t *)"", 0,
                 "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
                 "274edebfe76f65fbd51ad2f14898b95b");
    check_sha384((const uint8_t *)"abc", 3,
                 "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                 "8086072ba1e7cc2358baeca134c825a7");
    check_sha384((const uint8_t *)msg_448, sizeof msg_448 - 1,
                 "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6"
                 "b0455a8520bc4e6f5fe95b1fe3c8452b");
    check_sha384((const uint8_t *)msg_896, sizeof msg_896 - 1,
                 "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
                 "fcc7c71a557e2db966c3e9fa91746039");

    uint8_t a[129];
    memset(a, 'a', sizeof a);
    check_sha384(a, 111,
                 "3c37955051cb5c3026f94d551d5b5e2ac38d572ae4e07172085fed81f8466b8f"
                 "90dc23a8ffcdea0b8d8e58e8fdacc80a");
    check_sha384(a, 112,
                 "187d4e07cb306103c69967bf544d0dfbe9042577599c73c330abc0cb64c61236"
                 "d5ed565ee19119d8c31779a38f791fcd");
    check_sha384(a, 113,
                 "1d6bed01626682961b50da078a6b1da707c1da0c8a0a3226f159235bd45ed724"
                 "a0622fa6f39fd70007a6c72a5cda43ae");
    check_sha384(a, 127,
                 "9bd06b1763c2cf7aef40e795dc65bc96d59c41b537f3ad72ebdefd485476b571"
                 "7c1aeb37c327fe9c1831b12b9efd08ae");
    check_sha384(a, 128,
                 "edb12730a366098b3b2beac75a3bef1b0969b15c48e2163c23d96994f8d1bef7"
                 "60c7e27f3c464d3829f56c0d53808b0b");
    check_sha384(a, 129,
                 "39b6f5a7b0e781dbc419f72e49b30eaac10f2c98c4403bc610da31067fd1b48f"
                 "324138c8615d2b496d08d73d5e865326");

    // RFC 6234 §8.5 test 3: one million 'a', fed a thousand at a time so
    // the multi-block path of update runs on every call.
    sha512 s;
    sha384_init(&s);
    uint8_t chunk[1000];
    memset(chunk, 'a', sizeof chunk);
    for (int i = 0; i < 1000; i++) {
        sha512_update(&s, chunk, sizeof chunk);
    }
    uint8_t got[SHA384_LEN];
    sha384_final(&s, got);
    uint8_t want[SHA384_LEN];
    unhex("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b"
          "07b8b3dc38ecc4ebae97ddd87f3d8985",
          want, sizeof want);
    CHECK(memcmp(got, want, sizeof got) == 0);
}

// The streaming contract from sha512.h: two updates produce the digest
// one update does. The splits sit on and around the padding boundary
// (112) and the block boundary (128), so every refill path runs, and
// the whole-message and empty-first-piece cases bracket them.
static void test_streaming(void) {
    uint8_t msg[300];
    for (size_t i = 0; i < sizeof msg; i++) {
        msg[i] = (uint8_t)(i * 31 + 5);
    }
    uint8_t whole512[SHA512_LEN];
    sha512_of(msg, sizeof msg, whole512);
    uint8_t whole384[SHA384_LEN];
    sha384_of(msg, sizeof msg, whole384);

    static const size_t splits[] = {0, 1, 111, 112, 113, 127, 128, 129, 299, 300};
    for (size_t i = 0; i < sizeof splits / sizeof splits[0]; i++) {
        size_t at = splits[i];
        sha512 s;
        uint8_t out512[SHA512_LEN];
        sha512_init(&s);
        sha512_update(&s, msg, at);
        sha512_update(&s, msg + at, sizeof msg - at);
        sha512_final(&s, out512);
        CHECK(memcmp(out512, whole512, sizeof out512) == 0);

        uint8_t out384[SHA384_LEN];
        sha384_init(&s);
        sha512_update(&s, msg, at);
        sha512_update(&s, msg + at, sizeof msg - at);
        sha384_final(&s, out384);
        CHECK(memcmp(out384, whole384, sizeof out384) == 0);
    }
}

int main(void) {
    test_sha512_vectors();
    test_sha384_vectors();
    test_streaming();
    if (failures == 0) {
        (void)printf("sha512: all tests passed\n");
    }
    return failures != 0;
}
