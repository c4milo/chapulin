// ECDSA P-384/SHA-384 verify against RFC 6979 A.2.6, three openssl
// signatures, the mutations and out-of-range scalars that must be
// refused, and the strict-DER length boundary. Its own binary because
// only the TRUST=webpki object calls P-384; the module stays testable
// without the rest of the stack, the way sha3_test and rsa_test do.
//
// Every vector below was checked with openssl 3.6.4 before it was
// embedded. The RFC's private key d became a PEM key through a SEC 1
// ECPrivateKey DER wrapper (`openssl ec -inform DER -out key.pem`), the
// public point is what `openssl ec -in key.pem -text -noout` prints for
// it, and every signature passed
//   openssl pkeyutl -verify -pubin -inkey pub.pem -in msg.dgst
//       -sigfile msg.sig -pkeyopt digest:sha384
// (one command line; wrapped here because a backslash at the end of a
// comment line continues the comment) where msg.dgst is
// `openssl dgst -sha384 -binary` of the message. The three fresh
// signatures are
//   openssl pkeyutl -sign -inkey key.pem -in msg.dgst
//       -pkeyopt digest:sha384 -out msg.sig
// over 64 random bytes (`openssl rand 64`), and the boundary signature
// is the same recipe over 32 random bytes, repeated until both scalars
// needed a leading zero.
#include <stdio.h>
#include <string.h>

#include "p384.h"
#include "sha512.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

// Decodes hex into out; returns byte count. Test-only, trusts its input.
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

// RFC 6979 A.2.6: the public key for
// d = 6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8
//     96d5724e4c70a825f872c9ea60d2edf5.
static const char *const PUB_HEX = "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c6"
                                   "4def8f0ea9055866064a254515480bc13"
                                   "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db"
                                   "1288b231c3ae0d4fe7344fd2533264720";

// The largest possible SEQUENCE body: 2*(2+49) bytes.
#define DER_BODY_MAX 102

// Verify a message under the RFC key: the digest is SHA-384 of msg and
// must equal dgst_hex, and sig_hex must verify against it.
static void check_signature(const uint8_t *pub, const uint8_t *msg, size_t msg_len,
                            const char *dgst_hex, const char *sig_hex) {
    uint8_t hash[SHA384_LEN];
    uint8_t want[SHA384_LEN];
    uint8_t sig[128];
    sha384_of(msg, msg_len, hash);
    unhex(dgst_hex, want);
    CHECK(memcmp(hash, want, sizeof hash) == 0);
    size_t n = unhex(sig_hex, sig);
    CHECK(p384_ecdsa_verify(pub, hash, sig, n) == 1);
}

// RFC 6979 A.2.6, "sample" and "test" with SHA-384.
static void test_rfc6979(const uint8_t *pub) {
    check_signature(
        pub, (const uint8_t *)"sample", 6,
        "9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890e"
        "fee42c77b1ee25fe",
        "306602310094edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a6"
        "48152e44acf96e36dd1e80fabe4602310099ef4aeb15f178cea1fe40db2603138f130e740a1962"
        "4526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8");
    check_signature(
        pub, (const uint8_t *)"test", 4,
        "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d1"
        "96047dfedf17a0a9",
        "30660231008203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb0542"
        "a7f0812998da8f1dd3ca3cf023db023100ddd0760448d42d8a43af45af836fce4de8be06b485e9"
        "b61b827c2f13173923e06a739f040649a667bf3b828246baa5a5");
}

// Rejections, each a one-bit or one-byte mutation of the "sample" vector.
static void test_mutations(const uint8_t *pub_ok) {
    uint8_t pub[P384_PUB_LEN];
    uint8_t hash[SHA384_LEN];
    uint8_t sig[128];
    memcpy(pub, pub_ok, sizeof pub);
    unhex("9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890efee42c77"
          "b1ee25fe",
          hash);
    size_t n = unhex("306602310094edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81"
                     "a648152e44acf96e36dd1e80fabe4602310099ef4aeb15f178cea1fe40db2603138f130e740a"
                     "19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8",
                     sig);
    CHECK(p384_ecdsa_verify(pub, hash, sig, n) == 1);

    hash[0] ^= 0x01;
    CHECK(p384_ecdsa_verify(pub, hash, sig, n) == 0); // flipped hash bit
    hash[0] ^= 0x01;
    sig[6] ^= 0x01;
    CHECK(p384_ecdsa_verify(pub, hash, sig, n) == 0); // flipped r byte
    sig[6] ^= 0x01;
    sig[n - 1] ^= 0x01;
    CHECK(p384_ecdsa_verify(pub, hash, sig, n) == 0); // flipped s byte
    sig[n - 1] ^= 0x01;
    pub[1] ^= 0x01;
    CHECK(p384_ecdsa_verify(pub, hash, sig, n) == 0); // pub off the curve
    pub[1] ^= 0x01;
    CHECK(p384_ecdsa_verify(pub, hash, sig, n - 1) == 0); // truncated DER
    sig[n] = 0x00;
    CHECK(p384_ecdsa_verify(pub, hash, sig, n + 1) == 0); // trailing garbage

    // x == p: out of the field, whatever y says.
    unhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000"
          "ffffffff",
          pub);
    CHECK(p384_ecdsa_verify(pub, hash, sig, n) == 0);
}

// Out-of-range scalars: r or s of 0 or n, the other scalar kept from
// the "sample" vector where a live one is needed.
static void test_scalar_range(const uint8_t *pub) {
    uint8_t hash[SHA384_LEN];
    uint8_t bad[128];
    unhex("9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890efee42c77"
          "b1ee25fe",
          hash);
    size_t bad_len = unhex("3036020100"
                           "02310099ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a9"
                           "4fa329c145786e679e7b82c71a38628ac8",
                           bad);
    CHECK(p384_ecdsa_verify(pub, hash, bad, bad_len) == 0); // r = 0
    bad_len = unhex("303602310094edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a6"
                    "48152e44acf96e36dd1e80fabe46"
                    "020100",
                    bad);
    CHECK(p384_ecdsa_verify(pub, hash, bad, bad_len) == 0); // s = 0
    bad_len = unhex("3066023100ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a"
                    "0db248b0a77aecec196accc52973"
                    "02310099ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c1"
                    "45786e679e7b82c71a38628ac8",
                    bad);
    CHECK(p384_ecdsa_verify(pub, hash, bad, bad_len) == 0); // r = n
    bad_len = unhex("306602310094edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a6"
                    "48152e44acf96e36dd1e80fabe46"
                    "023100ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0d"
                    "b248b0a77aecec196accc52973",
                    bad);
    CHECK(p384_ecdsa_verify(pub, hash, bad, bad_len) == 0); // s = n
}

// The DER length boundary. A signature whose r and s both carry a
// leading zero fills the largest SEQUENCE body, 102 bytes, and
// verifies; the same body declared one byte longer (103) is refused,
// as is the same body under a long-form length, at the SEQUENCE and at
// an INTEGER.
static void test_der_boundary(const uint8_t *pub) {
    uint8_t hash[SHA384_LEN];
    uint8_t sig[128];
    uint8_t body[DER_BODY_MAX];
    unhex("5b1b0c40d3802a72599f0183f4e6ecbd7de3e14a62b0aeffe610f741951ce488526175eb15cbbddcab016dad"
          "41b46457",
          hash);
    size_t body_len =
        unhex("023100ba9c0aa208d47b95abc54100de38e5979d827a381a40bae422d0a55174bf84b75676429c8234"
              "558e0ed657a05525b894023100c6bb0065dcd6e3b9121e7b50c74ed4723414ee5828e0f905cd3615ce"
              "9b587558e4ffab677b364761678da7f37e80345f",
              body);
    CHECK(body_len == DER_BODY_MAX);

    sig[0] = 0x30;
    sig[1] = DER_BODY_MAX;
    memcpy(sig + 2, body, body_len);
    CHECK(p384_ecdsa_verify(pub, hash, sig, 2 + body_len) == 1); // 102: the last valid length

    sig[1] = DER_BODY_MAX + 1;
    sig[2 + body_len] = 0x00;
    CHECK(p384_ecdsa_verify(pub, hash, sig, 3 + body_len) == 0); // 103: the first invalid one

    sig[1] = 0x81; // long form for a length under 128: non-minimal
    sig[2] = DER_BODY_MAX;
    memcpy(sig + 3, body, body_len);
    CHECK(p384_ecdsa_verify(pub, hash, sig, 3 + body_len) == 0);

    sig[1] = DER_BODY_MAX + 1; // the first INTEGER under a long-form length
    sig[2] = 0x02;
    sig[3] = 0x81;
    sig[4] = 0x31;
    memcpy(sig + 5, body + 2, body_len - 2);
    CHECK(p384_ecdsa_verify(pub, hash, sig, 3 + body_len) == 0);
}

// Three openssl signatures over random 64-byte messages.
static void test_openssl(const uint8_t *pub) {
    uint8_t msg[64];
    size_t msg_len =
        unhex("4bded3a739ad7a9a65c357ccc6c92045a5f4b3c0f19a6ae0f46d2b7f00e777f017efe8caddc"
              "74d82b889d43d5643fa91acf7ca65ddcc068440d235cf8ff6415f",
              msg);
    check_signature(
        pub, msg, msg_len,
        "647d66124a030e6a5bec0f3da60e7cfd8036168e5f6f4916e66c14b6f79ac20e0608f401840a7eab"
        "41b4da470b7494f7",
        "3065023100d052e07302e6d12d192e6f60bfb5dd3b2cdcc928904f3b8baea8eadabb8366517b5d"
        "d05255f6e360b122b5488db4337d023005560b9e7bd10d4e6fc78efb37919a849455f231d3b4e2"
        "33414a58af013997e2a0859bee7306e60080d7559f368c4bb5");
    msg_len =
        unhex("eb395c74611a0676858c17cfd45973c776648b12f046f8a5ada7aaff47a01ff4f3fddec1f051a003"
              "7879aa0053c677010f7af396ee27d0dcd58d0cbc619809ed",
              msg);
    check_signature(
        pub, msg, msg_len,
        "a36034b84ef835145f770aa288ecee4997d5c1966c5d45c82a13062da2870bad1fd543286765dacf"
        "7f37365ab02c30a7",
        "3065023100e4f0c42809030fba18a8460430e59d90a642959418f6b676e02ae0b5213097b0376d"
        "a397cf3862851e10c819e04a263e02302b958356708f96f17884e52be1711a62ec849b7b07c049"
        "b12373c00597f0ede5e5515007948ba4211f1d1ef5cffed59d");
    msg_len =
        unhex("a59af539ea1d5c342d4046290a16334d4b1eedaf7ae5541227dffb91c79689a1abea44297144258b"
              "ef37d01300e04deca5f5e554c6cdc430d8eccffa6e44bda0",
              msg);
    check_signature(
        pub, msg, msg_len,
        "2bfa17fdd1f55f93b43ea04b7855440508bdd1c036d8ee8443fa9e18deaf828004c832da04e8a027"
        "278d7f8af6352bf0",
        "30660231008c825512ae6a60d187958f25e5b2b3f647bec75ed26ff36b4760d9dc7dc3ecacbef5"
        "7ecebb3fe98ca0a407f4c283899b023100d2c78ee2d43e745d93340260ac8641ace91d280fb29c"
        "6a4db06b6bed6c2ec005b98afa8b588655f49e316b888cf7219b");
}

int main(void) {
    uint8_t pub[P384_PUB_LEN];
    CHECK(unhex(PUB_HEX, pub) == sizeof pub);
    test_rfc6979(pub);
    test_mutations(pub);
    test_scalar_range(pub);
    test_der_boundary(pub);
    test_openssl(pub);
    if (failures == 0) {
        (void)printf("p384: all tests passed\n");
    }
    return failures != 0;
}
