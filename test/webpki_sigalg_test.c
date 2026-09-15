// webpki_read_sigalg and webpki_verify against openssl. The reader over
// the four AlgorithmIdentifiers openssl writes, every one-byte change
// of them, and the SHA-1, RSA-PSS and parameter-variant encodings it
// must refuse. The verify over openssl signatures for every admitted
// algorithm under every key that can sign with it, including P-256
// with SHA-384 (the digest cut) and P-384 with SHA-256 (the pad), and
// over each change that must break a signature: a TBS byte, a
// signature byte, the signature length, the algorithm family, the
// hash, the signer, the TBS length cap, and a signature over the wrong
// end of the digest. Last, a key that is not on its curve, under a
// signature only the curve check refuses.
// test/gen_webpki_sigalg_vectors.py produced the vectors and quotes
// every openssl command.
//
// The Makefile builds it with -DCH_TRUST_WEBPKI, so rsa.h's
// CH_RSA_MODULUS_MAX is 512 and the RSA-4096 rows verify. The test
// adapts to the bound, as rsa_pkcs1_test does: at the device bound of
// 384 it expects webpki_read_spki to refuse the RSA-4096 key instead.
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
               "webpki_sigalg_test knows the device bound and the webpki bound");

// 1 when this binary's bound admits the RSA-4096 rows.
static const int wide = CH_RSA_MODULUS_MAX >= 512;

// 1 when the key spki holds is one this binary's bound admits. At the
// device bound the RSA-4096 key is refused, which is checked here.
static int row_admitted(const uint8_t *spki, size_t spki_len) {
    if (spki != webpki_spki_rsa4096 || wide) {
        return 1;
    }
    rbuf r;
    rb_init(&r, spki, spki_len);
    webpki_spki refused;
    CHECK(webpki_read_spki(&r, &refused) == 0);
    return 0;
}

// The largest signature in the vectors: RSA-4096's 512 bytes, plus one.
#define SIG_BUF 520
// The largest TBS content in the vectors, plus one.
#define TBS_BUF 3080

typedef struct {
    const uint8_t *der;
    size_t len;
    uint8_t sigalg;
} admitted_sigalg;

static const admitted_sigalg admitted[] = {
    {webpki_sigalg_rsa_sha256,   sizeof webpki_sigalg_rsa_sha256,   WEBPKI_SIG_RSA_SHA256  },
    {webpki_sigalg_rsa_sha384,   sizeof webpki_sigalg_rsa_sha384,   WEBPKI_SIG_RSA_SHA384  },
    {webpki_sigalg_ecdsa_sha256, sizeof webpki_sigalg_ecdsa_sha256, WEBPKI_SIG_ECDSA_SHA256},
    {webpki_sigalg_ecdsa_sha384, sizeof webpki_sigalg_ecdsa_sha384, WEBPKI_SIG_ECDSA_SHA384},
};
#define ADMITTED_COUNT (sizeof admitted / sizeof admitted[0])

// One read over exactly n bytes: the verdict, the value and what is left.
static int read_sigalg(const uint8_t *der, size_t n, uint8_t *sigalg, size_t *left) {
    rbuf r;
    rb_init(&r, der, n);
    *sigalg = 0;
    int ok = webpki_read_sigalg(&r, sigalg);
    *left = rb_left(&r);
    return ok;
}

// The admitted index whose encoding equals der[0..n), or ADMITTED_COUNT.
static size_t admitted_index(const uint8_t *der, size_t n) {
    for (size_t i = 0; i < ADMITTED_COUNT; i++) {
        if (admitted[i].len == n && memcmp(admitted[i].der, der, n) == 0) {
            return i;
        }
    }
    return ADMITTED_COUNT;
}

static void test_read_sigalg(void) {
    uint8_t sigalg = 0;
    size_t left = 0;
    uint8_t buf[32];
    for (size_t i = 0; i < ADMITTED_COUNT; i++) {
        CHECK(read_sigalg(admitted[i].der, admitted[i].len, &sigalg, &left) == 1);
        CHECK(sigalg == admitted[i].sigalg && left == 0);
        // The next field's byte is left for the caller.
        memcpy(buf, admitted[i].der, admitted[i].len);
        buf[admitted[i].len] = 0x03;
        CHECK(read_sigalg(buf, admitted[i].len + 1, &sigalg, &left) == 1);
        CHECK(sigalg == admitted[i].sigalg && left == 1);
        for (size_t n = 0; n < admitted[i].len; n++) {
            CHECK(read_sigalg(admitted[i].der, n, &sigalg, &left) == 0);
        }
        // Every one-byte change is refused, unless it lands on another
        // admitted encoding: the two RSA identifiers differ in one byte,
        // and so do the two ECDSA ones.
        for (size_t pos = 0; pos < admitted[i].len; pos++) {
            for (unsigned delta = 1; delta < 256; delta++) {
                memcpy(buf, admitted[i].der, admitted[i].len);
                buf[pos] ^= (uint8_t)delta;
                size_t other = admitted_index(buf, admitted[i].len);
                int ok = read_sigalg(buf, admitted[i].len, &sigalg, &left);
                CHECK(ok == (other < ADMITTED_COUNT));
                if (ok) {
                    CHECK(other != i && sigalg == admitted[other].sigalg);
                }
            }
        }
    }
    static const struct {
        const uint8_t *der;
        size_t len;
    } refused[] = {
        {webpki_sigalg_rsa_sha1,          sizeof webpki_sigalg_rsa_sha1         },
        {webpki_sigalg_ecdsa_sha1,        sizeof webpki_sigalg_ecdsa_sha1       },
        {webpki_sigalg_rsa_pss_sha256,    sizeof webpki_sigalg_rsa_pss_sha256   },
        {webpki_sigalg_ecdsa_sha256_null, sizeof webpki_sigalg_ecdsa_sha256_null},
        {webpki_sigalg_rsa_sha256_absent, sizeof webpki_sigalg_rsa_sha256_absent},
    };
    for (size_t i = 0; i < sizeof refused / sizeof refused[0]; i++) {
        CHECK(read_sigalg(refused[i].der, refused[i].len, &sigalg, &left) == 0);
    }
}

// The certificate and signer one vector row describes.
static void load_row(const webpki_signature_vector *v, webpki_cert *cert, webpki_spki *signer) {
    memset(cert, 0, sizeof *cert);
    cert->tbs = v->tbs;
    cert->tbs_len = v->tbs_len;
    cert->sigalg = v->sigalg;
    cert->sig = v->sig;
    cert->sig_len = v->sig_len;
    rbuf r;
    rb_init(&r, v->spki, v->spki_len);
    CHECK(webpki_read_spki(&r, signer) == 1);
}

// The same family's other hash, and the other family's same hash.
static uint8_t other_hash(uint8_t sigalg) {
    static const uint8_t swap[5] = {0, WEBPKI_SIG_RSA_SHA384, WEBPKI_SIG_RSA_SHA256,
                                    WEBPKI_SIG_ECDSA_SHA384, WEBPKI_SIG_ECDSA_SHA256};
    return swap[sigalg];
}

static uint8_t other_family(uint8_t sigalg) {
    static const uint8_t swap[5] = {0, WEBPKI_SIG_ECDSA_SHA256, WEBPKI_SIG_ECDSA_SHA384,
                                    WEBPKI_SIG_RSA_SHA256, WEBPKI_SIG_RSA_SHA384};
    return swap[sigalg];
}

// The accept path for every row, then each change that must break it.
static void test_verify_rows(void) {
    size_t count = sizeof webpki_signature_vectors / sizeof webpki_signature_vectors[0];
    for (size_t i = 0; i < count; i++) {
        const webpki_signature_vector *v = &webpki_signature_vectors[i];
        if (!row_admitted(v->spki, v->spki_len)) {
            continue;
        }
        webpki_cert cert;
        webpki_spki signer;
        load_row(v, &cert, &signer);
        CHECK(webpki_verify(&cert, &signer) == 1);

        uint8_t tbs[TBS_BUF];
        uint8_t sig[SIG_BUF];
        const size_t flip_at[3] = {0, v->tbs_len / 2, v->tbs_len - 1};
        for (size_t j = 0; j < 3; j++) {
            memcpy(tbs, v->tbs, v->tbs_len);
            tbs[flip_at[j]] ^= 0x01;
            cert.tbs = tbs;
            CHECK(webpki_verify(&cert, &signer) == 0);
        }
        cert.tbs = v->tbs;

        const size_t sig_flip_at[2] = {v->sig_len / 2, v->sig_len - 1};
        for (size_t j = 0; j < 2; j++) {
            memcpy(sig, v->sig, v->sig_len);
            sig[sig_flip_at[j]] ^= 0x01;
            cert.sig = sig;
            CHECK(webpki_verify(&cert, &signer) == 0);
        }
        // One byte short, and one zero byte long: for RSA both are a
        // sig_len other than n_len, for ECDSA a broken DER frame.
        memcpy(sig, v->sig, v->sig_len);
        sig[v->sig_len] = 0x00;
        cert.sig = sig;
        cert.sig_len = v->sig_len - 1;
        CHECK(webpki_verify(&cert, &signer) == 0);
        cert.sig_len = v->sig_len + 1;
        CHECK(webpki_verify(&cert, &signer) == 0);
        cert.sig = v->sig;
        cert.sig_len = v->sig_len;

        cert.sigalg = other_hash(v->sigalg);
        CHECK(webpki_verify(&cert, &signer) == 0);
        cert.sigalg = other_family(v->sigalg);
        CHECK(webpki_verify(&cert, &signer) == 0);
        for (unsigned bad = 0; bad < 256; bad++) {
            if (bad < WEBPKI_SIG_RSA_SHA256 || bad > WEBPKI_SIG_ECDSA_SHA384) {
                cert.sigalg = (uint8_t)bad;
                CHECK(webpki_verify(&cert, &signer) == 0);
            }
        }
        cert.sigalg = v->sigalg;
        CHECK(webpki_verify(&cert, &signer) == 1);
    }
}

// A signature under one key never verifies under another: every row
// against every other row's signer, same algorithm kept.
static void test_wrong_signer(void) {
    size_t count = sizeof webpki_signature_vectors / sizeof webpki_signature_vectors[0];
    for (size_t i = 0; i < count; i++) {
        for (size_t j = 0; j < count; j++) {
            const webpki_signature_vector *a = &webpki_signature_vectors[i];
            const webpki_signature_vector *b = &webpki_signature_vectors[j];
            if (a->spki == b->spki || !row_admitted(a->spki, a->spki_len) ||
                !row_admitted(b->spki, b->spki_len)) {
                continue;
            }
            webpki_cert cert;
            webpki_cert unused;
            webpki_spki signer;
            webpki_spki other;
            load_row(a, &cert, &signer);
            load_row(b, &unused, &other);
            CHECK(webpki_verify(&cert, &other) == 0);
        }
    }
}

static void verify_one(const uint8_t *spki, size_t spki_len, uint8_t sigalg, const uint8_t *tbs,
                       size_t tbs_len, const uint8_t *sig, size_t sig_len, int expected) {
    webpki_signature_vector v = {"", spki, spki_len, sigalg, tbs, tbs_len, sig, sig_len};
    webpki_cert cert;
    webpki_spki signer;
    load_row(&v, &cert, &signer);
    CHECK(webpki_verify(&cert, &signer) == expected);
}

// An EC key whose length is the other curve's, and a key of no
// algorithm, over the valid P-256 row.
static void test_signer_shape(void) {
    webpki_signature_vector v = {"",
                                 webpki_spki_p256,
                                 sizeof webpki_spki_p256,
                                 WEBPKI_SIG_ECDSA_SHA256,
                                 webpki_tbs_p256_sha256,
                                 sizeof webpki_tbs_p256_sha256,
                                 webpki_sig_p256_sha256,
                                 sizeof webpki_sig_p256_sha256};
    webpki_cert cert;
    webpki_spki signer;
    load_row(&v, &cert, &signer);
    CHECK(webpki_verify(&cert, &signer) == 1);
    signer.key_len = 96;
    CHECK(webpki_verify(&cert, &signer) == 0);
    signer.alg = WEBPKI_KEY_P384;
    signer.key_len = 64;
    CHECK(webpki_verify(&cert, &signer) == 0);
    signer.alg = 0;
    CHECK(webpki_verify(&cert, &signer) == 0);
}

// The TBS cap: CH_WEBPKI_CERT_MAX bytes is hashed and verifies, one
// more is refused though openssl signed it just the same.
static void test_tbs_cap(void) {
    CHECK(sizeof webpki_tbs_p256_sha256_cert_max == CH_WEBPKI_CERT_MAX);
    CHECK(sizeof webpki_tbs_p256_sha256_over_cert_max == CH_WEBPKI_CERT_MAX + 1);
    verify_one(webpki_spki_p256, sizeof webpki_spki_p256, WEBPKI_SIG_ECDSA_SHA256,
               webpki_tbs_p256_sha256_cert_max, sizeof webpki_tbs_p256_sha256_cert_max,
               webpki_sig_p256_sha256_cert_max, sizeof webpki_sig_p256_sha256_cert_max, 1);
    verify_one(webpki_spki_p256, sizeof webpki_spki_p256, WEBPKI_SIG_ECDSA_SHA256,
               webpki_tbs_p256_sha256_over_cert_max, sizeof webpki_tbs_p256_sha256_over_cert_max,
               webpki_sig_p256_sha256_over_cert_max, sizeof webpki_sig_p256_sha256_over_cert_max,
               0);
}

// FIPS 186-4 §6.4 names the leftmost bits. A P-256 signature over the
// rightmost 32 bytes of the SHA-384 digest, and a P-384 signature over
// the SHA-256 digest with its zeros on the right, are both refused.
static void test_wrong_end_of_digest(void) {
    verify_one(webpki_spki_p256, sizeof webpki_spki_p256, WEBPKI_SIG_ECDSA_SHA384,
               webpki_tbs_p256_sha384, sizeof webpki_tbs_p256_sha384,
               webpki_sig_p256_sha384_rightmost, sizeof webpki_sig_p256_sha384_rightmost, 0);
    verify_one(webpki_spki_p384, sizeof webpki_spki_p384, WEBPKI_SIG_ECDSA_SHA256,
               webpki_tbs_p384_sha256, sizeof webpki_tbs_p384_sha256,
               webpki_sig_p384_sha256_right_padded, sizeof webpki_sig_p384_sha256_right_padded, 0);
}

// The point (1, 0) is on neither curve. Each forged signature
// satisfies the ECDSA verification equation under it:
// test/webpki_off_curve.py states the construction and checks it.
// webpki_read_spki accepts both keys, because it reads only the
// point's form. webpki_verify refuses all four signatures, and the
// curve equation in p256_ecdsa_verify and p384_ecdsa_verify is the only
// check that refuses them.
static void test_off_curve_key(void) {
    static const struct {
        const uint8_t *spki;
        size_t spki_len;
        uint8_t sigalg;
        const uint8_t *tbs;
        size_t tbs_len;
        const uint8_t *sig;
        size_t sig_len;
    } rows[] = {
        {webpki_spki_p256_off_curve, sizeof webpki_spki_p256_off_curve, WEBPKI_SIG_ECDSA_SHA256,
         webpki_tbs_p256_sha256, sizeof webpki_tbs_p256_sha256, webpki_sig_p256_sha256_off_curve,
         sizeof webpki_sig_p256_sha256_off_curve},
        {webpki_spki_p256_off_curve, sizeof webpki_spki_p256_off_curve, WEBPKI_SIG_ECDSA_SHA384,
         webpki_tbs_p256_sha384, sizeof webpki_tbs_p256_sha384, webpki_sig_p256_sha384_off_curve,
         sizeof webpki_sig_p256_sha384_off_curve},
        {webpki_spki_p384_off_curve, sizeof webpki_spki_p384_off_curve, WEBPKI_SIG_ECDSA_SHA256,
         webpki_tbs_p384_sha256, sizeof webpki_tbs_p384_sha256, webpki_sig_p384_sha256_off_curve,
         sizeof webpki_sig_p384_sha256_off_curve},
        {webpki_spki_p384_off_curve, sizeof webpki_spki_p384_off_curve, WEBPKI_SIG_ECDSA_SHA384,
         webpki_tbs_p384_sha384, sizeof webpki_tbs_p384_sha384, webpki_sig_p384_sha384_off_curve,
         sizeof webpki_sig_p384_sha384_off_curve},
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        verify_one(rows[i].spki, rows[i].spki_len, rows[i].sigalg, rows[i].tbs, rows[i].tbs_len,
                   rows[i].sig, rows[i].sig_len, 0);
    }
}

int main(void) {
    test_read_sigalg();
    test_verify_rows();
    test_wrong_signer();
    test_signer_shape();
    test_tbs_cap();
    test_wrong_end_of_digest();
    test_off_curve_key();
    if (failures != 0) {
        (void)fprintf(stderr, "webpki_sigalg_test: %d failures\n", failures);
        return 1;
    }
    (void)printf("webpki_sigalg_test: ok\n");
    return 0;
}
