// Unit tests: RFC vectors for every primitive. FIPS 180-4 / RFC 4231 /
// RFC 5869 / RFC 8439 / RFC 7748, including the iterated x25519 vectors
// that catch carry-chain bugs single vectors miss.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aead.h"
#include "buf.h"
#include "ch_assert.h"
#include "chacha20.h"
#include "ct.h"
#include "handshake.h"
#include "hkdf.h"
#include "p256.h"
#include "poly1305.h"
#include "rand.h"
#include "record.h"
#include "sha256.h"
#include "testrand.h"
#include "tls.h"
#include "x25519.h"

static int failures = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

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

static int eq_hex(const uint8_t *got, const char *hex) {
    uint8_t want[512];
    size_t n = unhex(hex, want);
    return memcmp(got, want, n) == 0;
}

static void test_sha256(void) {
    uint8_t d[SHA256_LEN];
    sha256_of((const uint8_t *)"", 0, d);
    CHECK(eq_hex(d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    sha256_of((const uint8_t *)"abc", 3, d);
    CHECK(eq_hex(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256_of((const uint8_t *)two, strlen(two), d);
    CHECK(eq_hex(d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    // Streaming across odd boundaries must match one-shot.
    sha256 s;
    sha256_init(&s);
    for (size_t i = 0; i < strlen(two); i++) {
        sha256_update(&s, (const uint8_t *)two + i, 1);
    }
    uint8_t d2[SHA256_LEN];
    sha256_final(&s, d2);
    CHECK(memcmp(d, d2, SHA256_LEN) == 0);
}

static void test_hmac_hkdf(void) {
    // RFC 4231 case 1 and case 2 (short key).
    uint8_t key[131];
    uint8_t out[SHA256_LEN];
    memset(key, 0x0b, 20);
    hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, out);
    CHECK(eq_hex(out, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28,
                out);
    CHECK(eq_hex(out, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    // RFC 4231 case 6: 131-byte key forces the hash-the-key path.
    memset(key, 0xaa, 131);
    hmac_sha256(key, 131, (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First",
                54, out);
    CHECK(eq_hex(out, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));

    // RFC 5869 case 1.
    uint8_t ikm[22];
    uint8_t salt[13];
    uint8_t info[10];
    uint8_t prk[SHA256_LEN];
    uint8_t okm[42];
    memset(ikm, 0x0b, sizeof ikm);
    unhex("000102030405060708090a0b0c", salt);
    unhex("f0f1f2f3f4f5f6f7f8f9", info);
    hkdf_extract(salt, sizeof salt, ikm, sizeof ikm, prk);
    CHECK(eq_hex(prk, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
    hkdf_expand(prk, info, sizeof info, okm, sizeof okm);
    CHECK(eq_hex(okm, "3cb25f25faacd57a90434f64d0362f2a"
                      "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                      "34007208d5b887185865"));
}

static void test_chacha20(void) {
    // RFC 8439 §2.4.2.
    uint8_t key[CHACHA20_KEY];
    uint8_t nonce[CHACHA20_NONCE];
    uint8_t ct[128];
    unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key);
    unhex("000000000000004a00000000", nonce);
    const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you "
                     "only one tip for the future, sunscreen would be it.";
    chacha20_xor(key, nonce, 1, (const uint8_t *)pt, ct, strlen(pt));
    CHECK(eq_hex(ct, "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
                     "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
                     "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
                     "5af90bbf74a35be6b40b8eedf2785e42874d"));
    // Round-trip in place.
    chacha20_xor(key, nonce, 1, ct, ct, strlen(pt));
    CHECK(memcmp(ct, pt, strlen(pt)) == 0);
}

static void test_poly1305(void) {
    // RFC 8439 §2.5.2.
    uint8_t key[POLY1305_KEY];
    uint8_t tag[POLY1305_TAG];
    unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", key);
    const char *msg = "Cryptographic Forum Research Group";
    poly1305 p;
    poly1305_init(&p, key);
    poly1305_update(&p, (const uint8_t *)msg, strlen(msg));
    poly1305_final(&p, tag);
    CHECK(eq_hex(tag, "a8061dc1305136c6c22b8baf0c0127a9"));
    // Same message, byte-at-a-time.
    poly1305_init(&p, key);
    for (size_t i = 0; i < strlen(msg); i++) {
        poly1305_update(&p, (const uint8_t *)msg + i, 1);
    }
    poly1305_final(&p, tag);
    CHECK(eq_hex(tag, "a8061dc1305136c6c22b8baf0c0127a9"));
}

static void test_aead(void) {
    // RFC 8439 §2.8.2.
    uint8_t key[AEAD_KEY];
    uint8_t nonce[AEAD_NONCE];
    uint8_t aad[12];
    uint8_t ct[128];
    uint8_t tag[AEAD_TAG];
    uint8_t back[128];
    unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key);
    unhex("070000004041424344454647", nonce);
    unhex("50515253c0c1c2c3c4c5c6c7", aad);
    const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you "
                     "only one tip for the future, sunscreen would be it.";
    aead_seal(key, nonce, aad, sizeof aad, (const uint8_t *)pt, strlen(pt), ct, tag);
    CHECK(eq_hex(ct, "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                     "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                     "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                     "3ff4def08e4b7a9de576d26586cec64b6116"));
    CHECK(eq_hex(tag, "1ae10b594f09e26a7e902ecbd0600691"));
    CHECK(aead_open(key, nonce, aad, sizeof aad, ct, strlen(pt), tag, back) == 1);
    CHECK(memcmp(back, pt, strlen(pt)) == 0);
    // Backward-overlap decrypt (pt 5 bytes below ct), as rec_open does it.
    uint8_t framed[5 + 128];
    aead_seal(key, nonce, aad, sizeof aad, (const uint8_t *)pt, strlen(pt), framed + 5, tag);
    CHECK(aead_open(key, nonce, aad, sizeof aad, framed + 5, strlen(pt), tag, framed) == 1);
    CHECK(memcmp(framed, pt, strlen(pt)) == 0);
    // Any flipped bit anywhere must fail closed.
    tag[3] ^= 1;
    CHECK(aead_open(key, nonce, aad, sizeof aad, ct, strlen(pt), tag, back) == 0);
    tag[3] ^= 1;
    ct[17] ^= 0x80;
    CHECK(aead_open(key, nonce, aad, sizeof aad, ct, strlen(pt), tag, back) == 0);
}

static void test_x25519(void) {
    uint8_t k[X25519_LEN];
    uint8_t u[X25519_LEN];
    uint8_t out[X25519_LEN];
    // RFC 7748 §5.2 vectors.
    unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", k);
    unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u);
    CHECK(x25519(out, k, u) == 1);
    CHECK(eq_hex(out, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
    unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", k);
    unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", u);
    CHECK(x25519(out, k, u) == 1);
    CHECK(eq_hex(out, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));

    // §5.2 iterated: k = result, u = old k; 1,000 rounds.
    unhex("0900000000000000000000000000000000000000000000000000000000000000", k);
    memcpy(u, k, X25519_LEN);
    for (int i = 0; i < 1000; i++) {
        uint8_t next[X25519_LEN];
        (void)x25519(next, k, u);
        memcpy(u, k, X25519_LEN);
        memcpy(k, next, X25519_LEN);
        if (i == 0) {
            CHECK(eq_hex(k, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));
        }
    }
    CHECK(eq_hex(k, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));

    // §6.1 Diffie-Hellman: both directions agree and match the vector.
    uint8_t apriv[32];
    uint8_t apub[32];
    uint8_t bpriv[32];
    uint8_t bpub[32];
    uint8_t s1[32];
    uint8_t s2[32];
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", apriv);
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bpriv);
    x25519_base(apub, apriv);
    CHECK(eq_hex(apub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    x25519_base(bpub, bpriv);
    CHECK(eq_hex(bpub, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    CHECK(x25519(s1, apriv, bpub) == 1);
    CHECK(x25519(s2, bpriv, apub) == 1);
    CHECK(memcmp(s1, s2, 32) == 0);
    CHECK(eq_hex(s1, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));

    // All-zero point (low order) must be rejected.
    uint8_t zero[X25519_LEN] = {0};
    CHECK(x25519(out, apriv, zero) == 0);
}

static void test_ct(void) {
    uint8_t a[7] = {1, 2, 3, 4, 5, 6, 7};
    uint8_t b[7] = {1, 2, 3, 4, 5, 6, 7};
    CHECK(ct_memeq(a, b, 7) == 1);
    b[6] = 8;
    CHECK(ct_memeq(a, b, 7) == 0);
    CHECK(ct_memeq(a, b, 0) == 1);
    ct_wipe(a, sizeof a);
    const uint8_t z[7] = {0};
    CHECK(memcmp(a, z, 7) == 0);
}

static void test_buf(void) {
    uint8_t mem[8];
    wbuf w;
    wb_init(&w, mem, sizeof mem);
    wb_u8(&w, 1);
    size_t mark = wb_mark(&w, 2);
    wb_u24(&w, 0x020304);
    wb_patch16(&w, mark);
    CHECK(!w.err && w.len == 6);
    CHECK(mem[1] == 0 && mem[2] == 3); // patched length = 3 bytes after mark
    wb_bytes(&w, mem, 3);              // overruns: 6 + 3 > 8
    CHECK(w.err);

    rbuf r;
    rb_init(&r, mem, 6);
    CHECK(rb_u8(&r) == 1 && rb_u16(&r) == 3 && rb_u24(&r) == 0x020304);
    CHECK(rb_left(&r) == 0 && !r.err);
    (void)rb_u8(&r);
    CHECK(r.err && rb_left(&r) == 0);
}

static void test_record(void) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    rec_dir tx;
    rec_dir rx;
    rec_dir_init(&tx, secret);
    rec_dir_init(&rx, secret);

    const char *msg = "matando sapos desde 2026";
    uint8_t rec[128];
    uint8_t pt[128];
    for (int i = 0; i < 3; i++) { // sequence numbers must track
        size_t record_len = 0;
        CHECK(rec_seal(&tx, REC_APPDATA, (const uint8_t *)msg, strlen(msg), rec, sizeof rec,
                       &record_len) == 0);
        size_t pt_len = 0;
        uint8_t type = 0;
        CHECK(rec_open(&rx, rec, record_len, pt, sizeof pt, &pt_len, &type) == 0);
        CHECK(type == REC_APPDATA && pt_len == strlen(msg) && memcmp(pt, msg, pt_len) == 0);
    }
    // Tampered record must fail, and a KeyUpdate rekey must still track.
    size_t record_len = 0;
    CHECK(rec_seal(&tx, REC_APPDATA, (const uint8_t *)msg, strlen(msg), rec, sizeof rec,
                   &record_len) == 0);
    rec[REC_HDR] ^= 1;
    size_t pt_len = 0;
    uint8_t type = 0;
    CHECK(rec_open(&rx, rec, record_len, pt, sizeof pt, &pt_len, &type) == -1);
    uint8_t s2[SHA256_LEN];
    memcpy(s2, secret, sizeof s2);
    rec_dir_update(secret, &tx);
    rec_dir_update(s2, &rx);
    CHECK(memcmp(secret, s2, sizeof s2) == 0);
    CHECK(rec_seal(&tx, REC_ALERT, (const uint8_t *)"\1\0", 2, rec, sizeof rec, &record_len) == 0);
    CHECK(rec_open(&rx, rec, record_len, pt, sizeof pt, &pt_len, &type) == 0);
    CHECK(type == REC_ALERT && pt_len == 2);
}

#include "rfc8448_tests.h"
#include "session_tests.h"

int main(void) {
    test_ct();
    test_sha256();
    test_hmac_hkdf();
    test_chacha20();
    test_poly1305();
    test_aead();
    test_x25519();
    test_p256();
    test_buf();
    test_record();
    test_rfc8448_1rtt();
    test_rfc8448_binder();
    test_rfc8448_hrr();
    test_seq_exhaustion();
    test_post_handshake();
    test_connect_cfg();
    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("unit: all tests passed\n");
    return 0;
}
