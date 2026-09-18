// webpki_read_spki against openssl's SubjectPublicKeyInfo encodings of
// the corpus keys, the negatives test/gen_webpki_sigalg_vectors.py
// derives from them, and the exact boundaries webpki.h states: the
// modulus length check and its step, the pad octet, the oddness, the
// exponent, the point form and length, and no byte after the last
// field of each container. Its own binary, out of the raw and ca
// objects, the way sha512_test and p384_test are.
//
// The Makefile builds it with -DCH_TRUST_WEBPKI, so rsa.h's
// CH_RSA_MODULUS_MAX is 512: the RSA-4096 SPKI is the last accepted
// size and one more value byte is the first refused. The test adapts
// to the bound, as rsa_pkcs1_test does, so a build at the device bound
// of 384 expects the RSA-4096 SPKI refused.
#include <stdio.h>
#include <string.h>

#include "buf.h"
#include "rsa.h"
#include "webpki.h"
#include "webpki_sigalg_vectors.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

_Static_assert(CH_RSA_MODULUS_MAX == 384 || CH_RSA_MODULUS_MAX == 512,
               "webpki_spki_test knows the device bound and the webpki bound");

// 1 when this binary's bound admits an RSA-4096 modulus.
static const int wide = CH_RSA_MODULUS_MAX >= 512;

// The largest SPKI this test builds: a 520-byte modulus with its pad,
// headers and exponent, and room for one trailing byte.
#define BUILD_MAX 600

// One read over exactly n bytes. Returns the verdict and fills out.
static int read_spki(const uint8_t *der, size_t n, webpki_spki *out, size_t *left) {
    rbuf r;
    rb_init(&r, der, n);
    memset(out, 0, sizeof *out);
    int ok = webpki_read_spki(&r, out);
    *left = rb_left(&r);
    return ok;
}

// A DER tag and minimal length, as x509_emit_header writes them.
static void put_header(wbuf *w, uint8_t tag, size_t len) {
    wb_u8(w, tag);
    if (len >= 0x100) {
        wb_u8(w, 0x82);
        wb_u16(w, (uint16_t)len);
    } else if (len >= 0x80) {
        wb_u8(w, 0x81);
        wb_u8(w, (uint8_t)len);
    } else {
        wb_u8(w, (uint8_t)len);
    }
}

static size_t header_len(size_t len) {
    if (len >= 0x100) {
        return 4;
    }
    if (len >= 0x80) {
        return 3;
    }
    return 2;
}

static const uint8_t algid_rsa[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};
static const uint8_t algid_p256[] = {0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
                                     0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
                                     0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
static const uint8_t algid_p384[] = {0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
                                     0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};

// The container a builder ends with one extra 0x00 byte. The byte is
// always the last byte of the encoding. The lengths of the named
// container and of every container around it count the byte.
enum extra_byte {
    EXTRA_NONE,
    EXTRA_IN_RSA_KEY,    // RSAPublicKey, after the exponent
    EXTRA_IN_BIT_STRING, // the BIT STRING, after RSAPublicKey or the point
    EXTRA_IN_SPKI,       // the SPKI SEQUENCE, after the BIT STRING
};

// An RSA SPKI around a modulus of value_len bytes: the top byte is top,
// the last is low, every byte between is 0x5a, and pad says whether the
// INTEGER carries a 0x00 octet before the value. extra names the
// container that ends with one extra byte. Returns the length.
static size_t build_rsa(uint8_t *out, size_t value_len, uint8_t top, uint8_t low, int pad,
                        enum extra_byte extra) {
    static const uint8_t exponent[] = {0x02, 0x03, 0x01, 0x00, 0x01};
    size_t integer_len = value_len + (pad ? 1 : 0);
    size_t key_len = header_len(integer_len) + integer_len + sizeof exponent +
                     (extra == EXTRA_IN_RSA_KEY ? 1 : 0);
    size_t bits_len = 1 + header_len(key_len) + key_len + (extra == EXTRA_IN_BIT_STRING ? 1 : 0);
    size_t body_len =
        sizeof algid_rsa + header_len(bits_len) + bits_len + (extra == EXTRA_IN_SPKI ? 1 : 0);
    wbuf w;
    wb_init(&w, out, BUILD_MAX);
    put_header(&w, 0x30, body_len);
    wb_bytes(&w, algid_rsa, sizeof algid_rsa);
    put_header(&w, 0x03, bits_len);
    wb_u8(&w, 0x00);
    put_header(&w, 0x30, key_len);
    put_header(&w, 0x02, integer_len);
    if (pad) {
        wb_u8(&w, 0x00);
    }
    wb_u8(&w, top);
    for (size_t i = 2; i < value_len; i++) {
        wb_u8(&w, 0x5a);
    }
    wb_u8(&w, low);
    wb_bytes(&w, exponent, sizeof exponent);
    if (extra != EXTRA_NONE) {
        wb_u8(&w, 0x00);
    }
    CHECK(!w.err);
    return w.len;
}

// An EC SPKI under algid around a point of marker then point_len bytes.
// extra names the container that ends with one extra byte; an EC key
// has no RSAPublicKey, so EXTRA_IN_RSA_KEY is not a shape it builds.
static size_t build_ec(uint8_t *out, const uint8_t *algid, size_t algid_len, uint8_t marker,
                       size_t point_len, enum extra_byte extra) {
    CHECK(extra != EXTRA_IN_RSA_KEY);
    size_t bits_len = 2 + point_len + (extra == EXTRA_IN_BIT_STRING ? 1 : 0);
    wbuf w;
    wb_init(&w, out, BUILD_MAX);
    put_header(&w, 0x30,
               algid_len + header_len(bits_len) + bits_len + (extra == EXTRA_IN_SPKI ? 1 : 0));
    wb_bytes(&w, algid, algid_len);
    put_header(&w, 0x03, bits_len);
    wb_u8(&w, 0x00);
    wb_u8(&w, marker);
    for (size_t i = 0; i < point_len; i++) {
        wb_u8(&w, (uint8_t)(i + 1));
    }
    if (extra != EXTRA_NONE) {
        wb_u8(&w, 0x00);
    }
    CHECK(!w.err);
    return w.len;
}

// openssl's encodings of the four admitted keys: accepted, the key a
// slice of the input at the algorithm's length, the reader past the
// SPKI and no further.
static void test_admitted_keys(void) {
    static const struct {
        const uint8_t *der;
        size_t len;
        uint8_t alg;
        size_t key_len;
    } keys[] = {
        {webpki_spki_rsa2048, sizeof webpki_spki_rsa2048, WEBPKI_KEY_RSA,  256},
        {webpki_spki_rsa4096, sizeof webpki_spki_rsa4096, WEBPKI_KEY_RSA,  512},
        {webpki_spki_p256,    sizeof webpki_spki_p256,    WEBPKI_KEY_P256, 64 },
        {webpki_spki_p384,    sizeof webpki_spki_p384,    WEBPKI_KEY_P384, 96 },
    };
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        webpki_spki out;
        size_t left = 0;
        if (keys[i].key_len > CH_RSA_MODULUS_MAX) {
            CHECK(!wide && read_spki(keys[i].der, keys[i].len, &out, &left) == 0);
            continue;
        }
        CHECK(read_spki(keys[i].der, keys[i].len, &out, &left) == 1);
        CHECK(out.alg == keys[i].alg);
        CHECK(out.key_len == keys[i].key_len);
        // The key ends where the SPKI ends, except for RSA's exponent.
        size_t tail = keys[i].alg == WEBPKI_KEY_RSA ? 5 : 0;
        CHECK(out.key == keys[i].der + keys[i].len - tail - keys[i].key_len);
        CHECK(left == 0);

        // A byte after the SPKI is the next field's, left unread.
        uint8_t longer[BUILD_MAX];
        memcpy(longer, keys[i].der, keys[i].len);
        longer[keys[i].len] = 0xaa;
        CHECK(read_spki(longer, keys[i].len + 1, &out, &left) == 1);
        CHECK(left == 1);

        // Every truncation is refused.
        for (size_t n = 0; n < keys[i].len; n++) {
            CHECK(read_spki(keys[i].der, n, &out, &left) == 0);
        }
    }
}

// Every negative the generator wrote, one rule each.
static void test_refused_keys(void) {
    static const struct {
        const uint8_t *der;
        size_t len;
    } refused[] = {
        {webpki_spki_rsa1024,          sizeof webpki_spki_rsa1024         },
        {webpki_spki_rsa_exponent3,    sizeof webpki_spki_rsa_exponent3   },
        {webpki_spki_rsa_even_modulus, sizeof webpki_spki_rsa_even_modulus},
        {webpki_spki_rsa4104,          sizeof webpki_spki_rsa4104         },
        {webpki_spki_rsa_missing_pad,  sizeof webpki_spki_rsa_missing_pad },
        {webpki_spki_rsa_unneeded_pad, sizeof webpki_spki_rsa_unneeded_pad},
        {webpki_spki_p256_compressed,  sizeof webpki_spki_p256_compressed },
        {webpki_spki_p256_under_p384,  sizeof webpki_spki_p256_under_p384 },
        {webpki_spki_p384_under_p256,  sizeof webpki_spki_p384_under_p256 },
    };
    for (size_t i = 0; i < sizeof refused / sizeof refused[0]; i++) {
        webpki_spki out;
        size_t left = 0;
        CHECK(read_spki(refused[i].der, refused[i].len, &out, &left) == 0);
    }
}

// The modulus size check at its edges: 256 bytes is the first accepted,
// CH_RSA_MODULUS_MAX the last, and every length between that is not a
// multiple of 8 is refused.
static void test_modulus_boundaries(void) {
    static const struct {
        size_t value_len;
        int accepted;
    } sizes[] = {
        {248,                    0},
        {255,                    0},
        {256,                    1},
        {257,                    0},
        {260,                    0},
        {264,                    1},
        {CH_RSA_MODULUS_MAX - 8, 1},
        {CH_RSA_MODULUS_MAX - 1, 0},
        {CH_RSA_MODULUS_MAX,     1},
        {CH_RSA_MODULUS_MAX + 1, 0},
        {CH_RSA_MODULUS_MAX + 8, 0},
    };
    uint8_t der[BUILD_MAX];
    webpki_spki out;
    size_t left = 0;
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        size_t n = build_rsa(der, sizes[i].value_len, 0xc1, 0x0b, 1, EXTRA_NONE);
        CHECK(read_spki(der, n, &out, &left) == sizes[i].accepted);
        if (sizes[i].accepted) {
            CHECK(out.alg == WEBPKI_KEY_RSA && out.key_len == sizes[i].value_len);
        }
    }
    // The top bit: 0x80 needs the pad and is accepted; 0x7f under a pad
    // is an unneeded pad; 0x80 with no pad reads as negative.
    size_t n = build_rsa(der, 256, 0x80, 0x01, 1, EXTRA_NONE);
    CHECK(read_spki(der, n, &out, &left) == 1);
    n = build_rsa(der, 256, 0x7f, 0x01, 1, EXTRA_NONE);
    CHECK(read_spki(der, n, &out, &left) == 0);
    n = build_rsa(der, 256, 0x80, 0x01, 0, EXTRA_NONE);
    CHECK(read_spki(der, n, &out, &left) == 0);
    // Oddness: the low bit set is accepted, clear is refused.
    n = build_rsa(der, CH_RSA_MODULUS_MAX, 0xff, 0xff, 1, EXTRA_NONE);
    CHECK(read_spki(der, n, &out, &left) == 1);
    n = build_rsa(der, CH_RSA_MODULUS_MAX, 0xff, 0xfe, 1, EXTRA_NONE);
    CHECK(read_spki(der, n, &out, &left) == 0);
}

// Each container ends at its last field. The encoding without the extra
// byte is accepted, and one extra byte at the end of RSAPublicKey, of
// the BIT STRING or of the SPKI SEQUENCE is refused, at the shortest
// and the longest admitted modulus and under both curves. Every
// enclosing length counts the byte, so only the fill rule refuses it.
static void test_exact_fill(void) {
    static const enum extra_byte rsa_refused[] = {EXTRA_IN_RSA_KEY, EXTRA_IN_BIT_STRING,
                                                  EXTRA_IN_SPKI};
    static const enum extra_byte ec_refused[] = {EXTRA_IN_BIT_STRING, EXTRA_IN_SPKI};
    static const size_t value_lens[] = {256, CH_RSA_MODULUS_MAX};
    uint8_t der[BUILD_MAX];
    webpki_spki out;
    size_t left = 0;
    for (size_t i = 0; i < sizeof value_lens / sizeof value_lens[0]; i++) {
        size_t n = build_rsa(der, value_lens[i], 0xc1, 0x0b, 1, EXTRA_NONE);
        CHECK(read_spki(der, n, &out, &left) == 1 && left == 0);
        for (size_t j = 0; j < sizeof rsa_refused / sizeof rsa_refused[0]; j++) {
            n = build_rsa(der, value_lens[i], 0xc1, 0x0b, 1, rsa_refused[j]);
            CHECK(read_spki(der, n, &out, &left) == 0);
        }
    }
    static const struct {
        const uint8_t *algid;
        size_t algid_len;
        size_t point_len;
    } curves[] = {
        {algid_p256, sizeof algid_p256, 64},
        {algid_p384, sizeof algid_p384, 96},
    };
    for (size_t i = 0; i < sizeof curves / sizeof curves[0]; i++) {
        size_t n = build_ec(der, curves[i].algid, curves[i].algid_len, 0x04, curves[i].point_len,
                            EXTRA_NONE);
        CHECK(read_spki(der, n, &out, &left) == 1 && left == 0);
        for (size_t j = 0; j < sizeof ec_refused / sizeof ec_refused[0]; j++) {
            n = build_ec(der, curves[i].algid, curves[i].algid_len, 0x04, curves[i].point_len,
                         ec_refused[j]);
            CHECK(read_spki(der, n, &out, &left) == 0);
        }
    }
}

// The point form and length under each curve: 0x04 then exactly two
// coordinates; the compressed markers, the hybrid ones and one byte
// short or long are refused.
static void test_point_boundaries(void) {
    static const struct {
        const uint8_t *algid;
        size_t algid_len;
        uint8_t alg;
        size_t point_len;
    } curves[] = {
        {algid_p256, sizeof algid_p256, WEBPKI_KEY_P256, 64},
        {algid_p384, sizeof algid_p384, WEBPKI_KEY_P384, 96},
    };
    uint8_t der[BUILD_MAX];
    webpki_spki out;
    size_t left = 0;
    for (size_t i = 0; i < 2; i++) {
        size_t len = curves[i].point_len;
        size_t n = build_ec(der, curves[i].algid, curves[i].algid_len, 0x04, len, EXTRA_NONE);
        CHECK(read_spki(der, n, &out, &left) == 1);
        CHECK(out.alg == curves[i].alg && out.key_len == len);
        for (uint8_t marker = 0; marker < 8; marker++) {
            if (marker != 0x04) {
                n = build_ec(der, curves[i].algid, curves[i].algid_len, marker, len, EXTRA_NONE);
                CHECK(read_spki(der, n, &out, &left) == 0);
            }
        }
        n = build_ec(der, curves[i].algid, curves[i].algid_len, 0x04, len - 1, EXTRA_NONE);
        CHECK(read_spki(der, n, &out, &left) == 0);
        n = build_ec(der, curves[i].algid, curves[i].algid_len, 0x04, len + 1, EXTRA_NONE);
        CHECK(read_spki(der, n, &out, &left) == 0);
        // The other curve's length under this curve's identifier.
        n = build_ec(der, curves[i].algid, curves[i].algid_len, 0x04, curves[1 - i].point_len,
                     EXTRA_NONE);
        CHECK(read_spki(der, n, &out, &left) == 0);
    }
}

// One bit flipped at pos in der, whose unflipped read gave base. A flip
// inside the key bytes is accepted with the same algorithm and key
// position, except the two modulus bits webpki_read_spki reads: the top bit of
// the first value byte (the pad would be unneeded) and the low bit of
// the last (the modulus would be even). A flip anywhere else is refused.
static void check_bit_flip(const uint8_t *der, size_t len, const webpki_spki *base, size_t pos,
                           unsigned bit) {
    size_t key_start = (size_t)(base->key - der);
    size_t key_end = key_start + base->key_len;
    uint8_t flipped[BUILD_MAX];
    memcpy(flipped, der, len);
    flipped[pos] ^= (uint8_t)(1U << bit);
    int in_key = pos >= key_start && pos < key_end;
    int gate_bit = base->alg == WEBPKI_KEY_RSA &&
                   ((pos == key_start && bit == 7) || (pos == key_end - 1 && bit == 0));
    webpki_spki out;
    size_t left = 0;
    int ok = read_spki(flipped, len, &out, &left);
    CHECK(ok == (in_key && !gate_bit));
    if (ok) {
        CHECK(out.alg == base->alg && out.key == flipped + key_start &&
              out.key_len == base->key_len);
    }
}

// Every single-bit flip of each admitted encoding, so no byte of the
// encoding outside the key is free.
static void test_bit_flips(void) {
    static const struct {
        const uint8_t *der;
        size_t len;
    } keys[] = {
        {webpki_spki_rsa2048, sizeof webpki_spki_rsa2048},
        {webpki_spki_rsa4096, sizeof webpki_spki_rsa4096},
        {webpki_spki_p256,    sizeof webpki_spki_p256   },
        {webpki_spki_p384,    sizeof webpki_spki_p384   },
    };
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        webpki_spki base;
        size_t left = 0;
        if (read_spki(keys[i].der, keys[i].len, &base, &left) == 0) {
            CHECK(!wide && keys[i].der == webpki_spki_rsa4096);
            continue;
        }
        for (size_t pos = 0; pos < keys[i].len; pos++) {
            for (unsigned bit = 0; bit < 8; bit++) {
                check_bit_flip(keys[i].der, keys[i].len, &base, pos, bit);
            }
        }
    }
}

int main(void) {
    test_admitted_keys();
    test_refused_keys();
    test_modulus_boundaries();
    test_exact_fill();
    test_point_boundaries();
    test_bit_flips();
    if (failures != 0) {
        (void)fprintf(stderr, "webpki_spki_test: %d failures\n", failures);
        return 1;
    }
    (void)printf("webpki_spki_test: ok\n");
    return 0;
}
