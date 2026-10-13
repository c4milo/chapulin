// The PEM calls (pem_files.h) against real files and at
// their exact boundaries.
//
// The real files are test/gen_pem_fixtures.py's:
//  - the corpus r2 chain, as openssl x509 writes it;
//  - its leaf's key as openssl genpkey (PKCS #8), openssl ec (SEC 1) and
//    openssl ecparam (EC PARAMETERS above SEC 1) wrote it;
//  - a fresh key, as `openssl ecparam -genkey` writes it;
//  - keys that the call refuses;
//  - a CA bundle in curl's cacert.pem layout, over the five captured
//    public roots and the corpus root_p384.
// Each decoded value is compared with webpki_corpus.h's, which a second
// generator extracted with openssl. The decoded anchors verify the r2
// chain and a captured public chain through webpki_verify_chain.
//
// Each limit has an exact pair: the last value it admits and the first
// it refuses. The limits are these:
//  - the caller's DER room and entries for a chain and a bundle;
//  - a chain's 255 certificates;
//  - the key file's text, and the scalar at 1 to n - 1. The chain cases are in
// test/pem_files_chain_tests.h, the bundle cases in
// test/pem_files_bundle_tests.h, and the key cases in
// test/pem_files_key_tests.h. The EC PARAMETERS and cpu cases are in
// test/pem_files_parameters_tests.h.
//
// The Makefile builds it as a ROLE=both TRUST=webpki device object
// (bin/pem_files_test). It builds it again as the host object, over the
// copies of the multiply's files that count calls (bin/pem_files_host).
// Those are the two shapes that the three calls are packaged in.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "pem.h"
#include "pem_armor.h"
#include "pem_blocks.h"
#include "pem_files.h"
#include "pem_files_der.h"
#include "pem_fixtures.h"
#include "webpki.h"
#include "webpki_corpus.h"
#include "x509_pem.h"

#ifdef TEST_WIDEMUL_COUNTED
#include "widemul_runtime_count.h"
#endif

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

// The certificates of a corpus Certificate message, leaf first.
typedef struct {
    const uint8_t *cert[4];
    size_t len[4];
    size_t count;
} corpus_entries;

static corpus_entries entries_of(const uint8_t *message, size_t message_len) {
    corpus_entries e;
    memset(&e, 0, sizeof e);
    rbuf r;
    rb_init(&r, message, message_len);
    rb_skip(&r, 8); // msg_type, length, empty context, list length
    while (rb_left(&r) > 0 && e.count < 4) {
        e.len[e.count] = rb_u24(&r);
        e.cert[e.count] = rb_bytes(&r, e.len[e.count]);
        (void)rb_u16(&r);
        e.count++;
    }
    CHECK(!r.err && rb_left(&r) == 0);
    return e;
}

static const uint8_t *text(const char *s) {
    return (const uint8_t *)s;
}

// Where want first appears in the n bytes at hay, or n.
static size_t find(const uint8_t *hay, size_t n, const char *want) {
    size_t want_len = strlen(want);
    for (size_t i = 0; i + want_len <= n; i++) {
        if (memcmp(hay + i, want, want_len) == 0) {
            return i;
        }
    }
    return n;
}

static int same(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len) {
    return a_len == b_len && memcmp(a, b, a_len) == 0;
}

// The rooms this test places. The calls take any size; these are the
// sizes the cases need. A chain's default rooms are the sizes the Interop
// Runner's chain of nine fits, 12,288 bytes and twelve entries. The large
// rooms hold 300 entries, past a system bundle's 150 roots and past the
// 255 certificates a chain holds.
#define TEST_CHAIN_DER 12288
#define TEST_CHAIN_ENTRIES 12
#define TEST_ROOM (256 * 1024)
#define TEST_ENTRIES 300
static uint8_t chain_der[TEST_ROOM];
static ch_cert chain[TEST_ENTRIES];
static uint8_t bundle_der[TEST_ROOM];
static ch_trust_anchor anchors[TEST_ENTRIES];
// Room for the largest file a case builds: a bundle of TEST_ENTRIES roots.
static uint8_t file[1024 * 1024];

// A chain call with a DER room of der_len bytes and chain_max entries.
static int chain_in(const uint8_t *pem, size_t n, size_t der_len, size_t chain_max,
                    uint8_t *count) {
    *count = 0x5a;
    return ch_chain_from_pem(pem, n, chain_der, der_len, chain, chain_max, count);
}

static int chain_of(const uint8_t *pem, size_t n, uint8_t *count) {
    return chain_in(pem, n, TEST_CHAIN_DER, TEST_CHAIN_ENTRIES, count);
}

// A bundle call with a DER room of der_len bytes and anchor_max entries.
static int anchors_in(const uint8_t *pem, size_t n, size_t der_len, size_t anchor_max,
                      size_t *count) {
    *count = 0x5a;
    return ch_anchors_from_pem(pem, n, bundle_der, der_len, anchors, anchor_max, count);
}

static int anchors_of(const uint8_t *pem, size_t n, size_t *count) {
    return anchors_in(pem, n, sizeof bundle_der, TEST_ENTRIES, count);
}

// A file of count copies of block, separated by sep, in file. Returns 0
// when the file would outgrow its buffer.
static size_t repeat_block(const uint8_t *block, size_t block_len, size_t count, const char *sep) {
    size_t n = 0;
    for (size_t i = 0; i < count; i++) {
        size_t sep_len = i != 0 ? strlen(sep) : 0;
        if (n + sep_len + block_len > sizeof file) {
            return 0;
        }
        memcpy(file + n, sep, sep_len);
        n += sep_len;
        memcpy(file + n, block, block_len);
        n += block_len;
    }
    return n;
}

// A certificate of exactly want bytes of the corpus leaf's key, armored
// into file at offset at. Returns the text's length, or 0.
static size_t cert_block_at(size_t at, size_t want) {
    static uint8_t der[PFD_CERT_MAX];
    size_t pad = pfd_pad_for(want, webpki_corpus_server_pub);
    pfd_cert_shape shape = {1, 0, pad, 0};
    if (pad == 0 || pfd_cert(der, sizeof der, webpki_corpus_server_pub, shape) != want) {
        return 0;
    }
    return pem_armor(der, want, 64, "\n", file + at);
}

#include "pem_files_bundle_tests.h"
#include "pem_files_chain_tests.h"
#include "pem_files_key_tests.h"
#include "pem_files_parameters_tests.h"

// The r2 chain file decodes to the corpus r2 message's two certificates,
// leaf first.
static void test_chain_file(void) {
    corpus_entries r2 = entries_of(webpki_corpus_message_r2, sizeof webpki_corpus_message_r2);
    uint8_t count = 0;
    CHECK(chain_of(pem_fixture_r2_chain, sizeof pem_fixture_r2_chain, &count) == CH_OK);
    CHECK(count == 2 && r2.count == 2);
    for (size_t i = 0; i < 2 && i < count; i++) {
        CHECK(same(chain[i].der, chain[i].len, r2.cert[i], r2.len[i]));
    }
}

// The outer fields that x509_pem_read_subject_key reads. A version 1
// certificate and one with an issuerUniqueID read. A byte after the TBS
// fields or after the certificate is refused.
static void test_certificate_framing(void) {
    static uint8_t der[512];
    const uint8_t *point = webpki_corpus_server_pub;
    const uint8_t *name = NULL;
    const uint8_t *spki = NULL;
    size_t name_len = 0;
    size_t spki_len = 0;
    const struct {
        pfd_cert_shape shape;
        int ok;
    } rows[] = {
        {{1, 0, 0, 0}, 1},
        {{0, 0, 0, 0}, 1},
        {{1, 1, 8, 0}, 1},
        {{0, 1, 0, 0}, 1},
        {{1, 0, 8, 1}, 0},
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        size_t n = pfd_cert(der, sizeof der, point, rows[i].shape);
        int ok = x509_pem_read_subject_key(der, n, &name, &name_len, &spki, &spki_len);
        CHECK(ok == rows[i].ok);
        if (ok) {
            CHECK(same(name, name_len, pfd_name, sizeof pfd_name));
            CHECK(x509_pem_spki_is_p256(spki, spki_len, point));
        }
    }
    size_t n = pfd_cert(der, sizeof der - 1, point, rows[0].shape);
    der[1] = (uint8_t)(der[1] + 1); // the Certificate SEQUENCE claims one byte more
    der[n] = 0x00;
    CHECK(!x509_pem_read_subject_key(der, n + 1, &name, &name_len, &spki, &spki_len));
    // The Certificate SEQUENCE claims one or two bytes fewer than the
    // certificate holds, and the fields inside it still read to the end. A
    // version 1 certificate is short enough that its length is one byte,
    // so the shorter length is still canonical DER.
    for (uint8_t short_by = 1; short_by <= 2; short_by++) {
        n = pfd_cert(der, sizeof der, point, rows[1].shape);
        CHECK(n != 0 && der[1] < 0x80 &&
              x509_pem_read_subject_key(der, n, &name, &name_len, &spki, &spki_len));
        der[1] = (uint8_t)(der[1] - short_by);
        CHECK(!x509_pem_read_subject_key(der, n, &name, &name_len, &spki, &spki_len));
    }
}

// The key cases, once under each cpu value this object takes. That is 0
// in a device object. In a host object it is CH_CPU_PROBED with the
// multiply bit, and without it.
static void key_cases(void) {
    test_key_files();
    test_key_refusals();
    test_key_grammar();
    test_key_fields();
    test_scalar_range();
    test_key_text_cap();
    test_key_parameters();
    test_genkey_file();
    test_key_wipes();
}

int main(void) {
    test_chain_file();
    test_bundle_file();
    test_full_bundle();
#ifdef CH_CPU_RUNTIME
    key_cpu = CH_CPU_PROBED;
    key_cases();
    key_cpu = CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY;
    key_cases();
#else
    key_cases();
#endif
    test_key_cpu();
    test_chain_counts();
    test_chain_room();
    test_chain_framing();
    test_chain_long_text();
    test_chain_grammar();
    test_bundle_counts();
    test_bundle_room();
    test_bundle_grammar();
    test_bundle_first_lines();
    test_certificate_framing();
    if (failures != 0) {
        (void)fprintf(stderr, "pem_files_test: %d failures\n", failures);
        return 1;
    }
    (void)printf("pem_files_test: a chain, a PKCS #8 and a SEC 1 key, a key under its EC "
                 "PARAMETERS and a CA bundle decode from real files, the anchors verify their "
                 "chains, and every limit holds at its boundary\n");
    return 0;
}
