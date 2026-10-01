// RFC 8439's block function vector (§2.3.2) and its Appendix A.2 and A.5
// vectors, which run ChaCha20 over up to 375 bytes: long enough to run
// the CHACHA=vector path over a whole group of four blocks and a partial
// one, a whole pass and a partial one on SSE2 and one pass with both its
// groups on NEON, where test_chacha20's 114 bytes run a partial group
// alone.
// Appendix A.3's Poly1305 vectors follow, the longest of which reach the
// CHACHA=vector Poly1305. bin/unit runs them on chacha20.c's and
// poly1305.c's portable loops and bin/unit_chacha_vector on
// chacha20_vector.c and poly1305_vector.c. Included by test/unit_test.c
// only, after its CHECK macro, unhex and eq_hex.
//
// The RFC's plaintexts are prose, so the table holds each one's SHA-256,
// computed from the RFC's hex dump, and not its 127 to 375 bytes. The
// published ciphertext must decrypt to bytes with that digest, and those
// bytes must encrypt back to the ciphertext.
#ifndef CH_RFC8439_TESTS_H
#define CH_RFC8439_TESTS_H

#include "aead.h"
#include "chacha20.h"
#include "poly1305.h"
#include "sha256.h"
#include "test_widemul.h"

// The largest ciphertext below, A.2's second vector.
#define RFC8439_MAX 375

typedef struct {
    const char *name;
    const char *key;
    const char *nonce;
    uint32_t counter;
    const char *ciphertext;
    const char *plaintext_sha256;
} rfc8439_cipher_vector;

// Appendix A.2, test vector 2: 375 bytes from block counter 1, one group
// of four blocks and 119 bytes more.
static const rfc8439_cipher_vector rfc8439_a2_vector_2 = {
    .name = "A.2 vector 2",
    .key = "0000000000000000000000000000000000000000000000000000000000000001",
    .nonce = "000000000000000000000002",
    .counter = 1,
    .ciphertext = "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec"
                  "2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d"
                  "4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950"
                  "42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85a"
                  "d00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259d"
                  "c4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b"
                  "0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6c"
                  "cc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0b"
                  "c39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f"
                  "5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e6"
                  "98ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab"
                  "7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
    .plaintext_sha256 = "5ee1f64124afd5f77454793c076903a582acac70e77d70ae39657cedceb6f5de",
};

// Appendix A.2, test vector 3: 127 bytes from block counter 42.
static const rfc8439_cipher_vector rfc8439_a2_vector_3 = {
    .name = "A.2 vector 3",
    .key = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
    .nonce = "000000000000000000000002",
    .counter = 42,
    .ciphertext = "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf"
                  "166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb"
                  "f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77"
                  "04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
    .plaintext_sha256 = "9cc921a47ff6db0f8ec35ad72e60a2871cfb233e083783a664de0237c3b70599",
};

// Appendix A.5: 265 bytes of AEAD ciphertext, one group of four blocks and
// 9 bytes more once counter 0 has given the Poly1305 key.
static const char rfc8439_aead_key[] =
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";
static const char rfc8439_aead_nonce[] = "000000000102030405060708";
static const char rfc8439_aead_aad[] = "f33388860000000000004e91";
static const char rfc8439_aead_ciphertext[] =
    "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
    "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
    "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
    "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
    "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
    "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
    "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
    "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
    "a6ad5cb4022b02709b";
static const char rfc8439_aead_tag[] = "eead9d67890cbb22392336fea1851f38";
static const char rfc8439_aead_plaintext_sha256[] =
    "686ff73f1610b08cd80f98a321bba01dca634c41bad02ebd166661fc4ca1757c";

// Each A.2 vector three ways: into a separate buffer, in place, and into a
// buffer 5 bytes below the input, as rec_open decrypts over its header.
static void test_rfc8439_cipher(const rfc8439_cipher_vector *v) {
    uint8_t key[CHACHA20_KEY];
    uint8_t nonce[CHACHA20_NONCE];
    uint8_t ct[RFC8439_MAX];
    uint8_t pt[RFC8439_MAX];
    uint8_t shifted[5 + RFC8439_MAX];
    uint8_t digest[SHA256_LEN];
    int failures_before = failures;
    unhex(v->key, key);
    unhex(v->nonce, nonce);
    size_t n = unhex(v->ciphertext, ct);
    chacha20_xor(key, nonce, v->counter, ct, pt, n);
    sha256_of(pt, n, digest);
    CHECK(eq_hex(digest, v->plaintext_sha256));
    chacha20_xor(key, nonce, v->counter, pt, pt, n);
    CHECK(eq_hex(pt, v->ciphertext));
    memcpy(shifted + 5, ct, n);
    chacha20_xor(key, nonce, v->counter, shifted + 5, shifted, n);
    sha256_of(shifted, n, digest);
    CHECK(eq_hex(digest, v->plaintext_sha256));
    if (failures != failures_before) {
        (void)fprintf(stderr, "rfc8439: the checks above ran on %s\n", v->name);
    }
}

static void test_rfc8439_appendix(void) {
    // §2.3.2: the block function, and the same 64 bytes as keystream.
    static const char block[] = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                                "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";
    uint8_t key[CHACHA20_KEY];
    uint8_t nonce[CHACHA20_NONCE];
    uint8_t out[CHACHA20_BLOCK];
    unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key);
    unhex("000000090000004a00000000", nonce);
    chacha20_block(key, nonce, 1, out);
    CHECK(eq_hex(out, block));
    memset(out, 0, sizeof out);
    chacha20_xor(key, nonce, 1, out, out, sizeof out);
    CHECK(eq_hex(out, block));

    test_rfc8439_cipher(&rfc8439_a2_vector_2);
    test_rfc8439_cipher(&rfc8439_a2_vector_3);

    // A.5: the tag verifies, the plaintext has the RFC's digest, and
    // sealing it again gives the same ciphertext and tag.
    uint8_t aad[12];
    uint8_t ct[RFC8439_MAX];
    uint8_t pt[RFC8439_MAX];
    uint8_t tag[AEAD_TAG];
    uint8_t digest[SHA256_LEN];
    unhex(rfc8439_aead_key, key);
    unhex(rfc8439_aead_nonce, nonce);
    unhex(rfc8439_aead_aad, aad);
    unhex(rfc8439_aead_tag, tag);
    size_t n = unhex(rfc8439_aead_ciphertext, ct);
    CHECK(aead_open(TEST_WIDEMUL, key, nonce, aad, sizeof aad, ct, n, tag, pt) == 1);
    sha256_of(pt, n, digest);
    CHECK(eq_hex(digest, rfc8439_aead_plaintext_sha256));
    aead_seal(TEST_WIDEMUL, key, nonce, aad, sizeof aad, pt, n, pt, tag);
    CHECK(eq_hex(pt, rfc8439_aead_ciphertext));
    CHECK(eq_hex(tag, rfc8439_aead_tag));
}

// Appendix A.3's eleven Poly1305 vectors. Vectors 2 and 3 authenticate
// A.2 vector 2's 375-byte plaintext and vector 4 A.2 vector 3's 127
// bytes, so each of those names the cipher vector whose ciphertext
// decrypts to its message; the other eight hold their message in hex.
// Vectors 2 and 3 hold 368 bytes of whole blocks, enough for the
// CHACHA=vector Poly1305 in bin/unit_chacha_vector, and vectors 5 to 11
// meet the final reduction's edge cases in both builds.
typedef struct {
    const char *name;
    const char *key; // r, then s
    const rfc8439_cipher_vector *plaintext_of;
    const char *message;
    const char *tag;
} rfc8439_poly1305_vector;

static const rfc8439_poly1305_vector rfc8439_a3_vector_1 = {
    .name = "A.3 vector 1",
    .key = "0000000000000000000000000000000000000000000000000000000000000000",
    .message = "0000000000000000000000000000000000000000000000000000000000000000"
               "0000000000000000000000000000000000000000000000000000000000000000",
    .tag = "00000000000000000000000000000000",
};

static const rfc8439_poly1305_vector rfc8439_a3_vector_2 = {
    .name = "A.3 vector 2",
    .key = "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
    .plaintext_of = &rfc8439_a2_vector_2,
    .tag = "36e5f6b5c5e06070f0efca96227a863e",
};

static const rfc8439_poly1305_vector rfc8439_a3_vector_3 = {
    .name = "A.3 vector 3",
    .key = "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
    .plaintext_of = &rfc8439_a2_vector_2,
    .tag = "f3477e7cd95417af89a6b8794c310cf0",
};

static const rfc8439_poly1305_vector rfc8439_a3_vector_4 = {
    .name = "A.3 vector 4",
    .key = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
    .plaintext_of = &rfc8439_a2_vector_3,
    .tag = "4541669a7eaaee61e708dc7cbcc5eb62",
};

static const rfc8439_poly1305_vector rfc8439_a3_vector_5 = {
    .name = "A.3 vector 5",
    .key = "0200000000000000000000000000000000000000000000000000000000000000",
    .message = "ffffffffffffffffffffffffffffffff",
    .tag = "03000000000000000000000000000000",
};

static const rfc8439_poly1305_vector rfc8439_a3_vector_6 = {
    .name = "A.3 vector 6",
    .key = "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
    .message = "02000000000000000000000000000000",
    .tag = "03000000000000000000000000000000",
};

static const rfc8439_poly1305_vector rfc8439_a3_vector_7 = {
    .name = "A.3 vector 7",
    .key = "0100000000000000000000000000000000000000000000000000000000000000",
    .message = "ffffffffffffffffffffffffffffffff"
               "f0ffffffffffffffffffffffffffffff"
               "11000000000000000000000000000000",
    .tag = "05000000000000000000000000000000",
};

static const rfc8439_poly1305_vector rfc8439_a3_vector_8 = {
    .name = "A.3 vector 8",
    .key = "0100000000000000000000000000000000000000000000000000000000000000",
    .message = "ffffffffffffffffffffffffffffffff"
               "fbfefefefefefefefefefefefefefefe"
               "01010101010101010101010101010101",
    .tag = "00000000000000000000000000000000",
};

static const rfc8439_poly1305_vector rfc8439_a3_vector_9 = {
    .name = "A.3 vector 9",
    .key = "0200000000000000000000000000000000000000000000000000000000000000",
    .message = "fdffffffffffffffffffffffffffffff",
    .tag = "faffffffffffffffffffffffffffffff",
};

static const rfc8439_poly1305_vector rfc8439_a3_vector_10 = {
    .name = "A.3 vector 10",
    .key = "0100000000000000040000000000000000000000000000000000000000000000",
    .message = "e33594d7505e43b90000000000000000"
               "3394d7505e4379cd0100000000000000"
               "00000000000000000000000000000000"
               "01000000000000000000000000000000",
    .tag = "14000000000000005500000000000000",
};

static const rfc8439_poly1305_vector rfc8439_a3_vector_11 = {
    .name = "A.3 vector 11",
    .key = "0100000000000000040000000000000000000000000000000000000000000000",
    .message = "e33594d7505e43b90000000000000000"
               "3394d7505e4379cd0100000000000000"
               "00000000000000000000000000000000",
    .tag = "13000000000000000000000000000000",
};

static const rfc8439_poly1305_vector *const rfc8439_a3_vectors[] = {
    &rfc8439_a3_vector_1, &rfc8439_a3_vector_2,  &rfc8439_a3_vector_3,  &rfc8439_a3_vector_4,
    &rfc8439_a3_vector_5, &rfc8439_a3_vector_6,  &rfc8439_a3_vector_7,  &rfc8439_a3_vector_8,
    &rfc8439_a3_vector_9, &rfc8439_a3_vector_10, &rfc8439_a3_vector_11,
};

// Each A.3 vector in one update, and in two cut 7 bytes in, so a partial
// block waits in the context when the rest of the message arrives.
static void test_rfc8439_poly1305(void) {
    uint8_t key[POLY1305_KEY];
    uint8_t message[RFC8439_MAX];
    uint8_t tag[POLY1305_TAG];
    for (size_t i = 0; i < sizeof rfc8439_a3_vectors / sizeof rfc8439_a3_vectors[0]; i++) {
        const rfc8439_poly1305_vector *v = rfc8439_a3_vectors[i];
        int failures_before = failures;
        unhex(v->key, key);
        size_t n;
        if (v->plaintext_of != NULL) {
            uint8_t cipher_key[CHACHA20_KEY];
            uint8_t nonce[CHACHA20_NONCE];
            unhex(v->plaintext_of->key, cipher_key);
            unhex(v->plaintext_of->nonce, nonce);
            n = unhex(v->plaintext_of->ciphertext, message);
            chacha20_xor(cipher_key, nonce, v->plaintext_of->counter, message, message, n);
        } else {
            n = unhex(v->message, message);
        }
        poly1305 p;
        poly1305_init(&p, key);
        widemul_poly1305_update(TEST_WIDEMUL, &p, message, n);
        widemul_poly1305_final(TEST_WIDEMUL, &p, tag);
        CHECK(eq_hex(tag, v->tag));
        size_t cut = n < 7 ? n : 7;
        poly1305_init(&p, key);
        widemul_poly1305_update(TEST_WIDEMUL, &p, message, cut);
        widemul_poly1305_update(TEST_WIDEMUL, &p, message + cut, n - cut);
        widemul_poly1305_final(TEST_WIDEMUL, &p, tag);
        CHECK(eq_hex(tag, v->tag));
        if (failures != failures_before) {
            (void)fprintf(stderr, "rfc8439: the checks above ran on %s\n", v->name);
        }
    }
}

#endif
