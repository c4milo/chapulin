// The TRUST=webpki certificate parser (webpki_cert.c) and extension
// walk (webpki_ext.c) over every certificate the corpus header carries
// and over hand-built mutants of one minted certificate.
//
// The corpus half reads each row's RFC 9846 §4.4.2 Certificate message
// and parses every entry, the leaf with is_ca = 0 and each later entry
// with is_ca = 1. A row whose rule belongs to this parser must fail at
// its one broken entry with ALERT_UNSUPPORTED_CERTIFICATE, and every
// other entry, including those of the rows whose rule belongs to the
// walk, the clock or the hostname, must parse. The four captured public
// chains must parse whole. The mutant half is test/webpki_cert_mutants.h.
//
// Its own binary, built with -DCH_TRUST_WEBPKI so the RSA-4096 keys in
// the captures pass webpki_read_spki's modulus gate, as they do in the
// webpki object.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "buf.h"
#include "handshake_message.h"
#include "webpki.h"
#include "webpki_corpus.h"
#include "x509_mutate.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

// One Certificate message's entries, as pointers into the message.
typedef struct {
    const uint8_t *cert[CH_WEBPKI_FLIGHT_ENTRIES];
    size_t cert_len[CH_WEBPKI_FLIGHT_ENTRIES];
    size_t count;
} flight;

#define HANDSHAKE_CERTIFICATE 11
#define HANDSHAKE_HEADER_LEN 4 // msg_type, u24 length
#define LIST_HEADER_LEN 4      // u8 context length, u24 list length

// msg_type 11, u24 length, an empty certificate_request_context, a u24
// list length, then each CertificateEntry: u24 length, the certificate,
// an empty u16 extensions vector. Returns 1 when the message has exactly
// that shape with at most CH_WEBPKI_FLIGHT_ENTRIES entries.
static int read_flight(const uint8_t *message, size_t message_len, flight *f) {
    rbuf r;
    rb_init(&r, message, message_len);
    f->count = 0;
    uint8_t msg_type = rb_u8(&r);
    size_t body_len = rb_u24(&r);
    if (r.err || msg_type != HANDSHAKE_CERTIFICATE || body_len != rb_left(&r)) {
        return 0;
    }
    uint8_t context_len = rb_u8(&r);
    size_t list_len = rb_u24(&r);
    if (r.err || context_len != 0 || list_len != rb_left(&r)) {
        return 0;
    }
    while (rb_left(&r) > 0) {
        if (f->count == CH_WEBPKI_FLIGHT_ENTRIES) {
            return 0;
        }
        size_t cert_len = rb_u24(&r);
        const uint8_t *cert = rb_bytes(&r, cert_len);
        uint16_t extensions_len = rb_u16(&r);
        if (cert == NULL || r.err || extensions_len != 0) {
            return 0;
        }
        f->cert[f->count] = cert;
        f->cert_len[f->count] = cert_len;
        f->count++;
    }
    return 1;
}

// Framing the entries again with put_entry reproduces the message's
// list byte for byte, so read_flight dropped and invented nothing.
static void check_reframed(const flight *f, const uint8_t *message, size_t message_len) {
    static uint8_t entry[CH_WEBPKI_CERT_MAX + 5];
    size_t at = HANDSHAKE_HEADER_LEN + LIST_HEADER_LEN;
    for (size_t i = 0; i < f->count; i++) {
        if (f->cert_len[i] > CH_WEBPKI_CERT_MAX) {
            (void)fprintf(stderr, "FAIL entry %zu is over CH_WEBPKI_CERT_MAX\n", i);
            failures++;
            return;
        }
        size_t n = put_entry(entry, f->cert[i], f->cert_len[i]);
        CHECK(at + n <= message_len && memcmp(message + at, entry, n) == 0);
        at += n;
    }
    CHECK(at == message_len);
}

// 1 when [inner, inner + inner_len) lies inside [outer, outer + outer_len).
static int inside(const uint8_t *outer, size_t outer_len, const uint8_t *inner, size_t inner_len) {
    return inner != NULL && inner >= outer && inner_len <= outer_len &&
           (size_t)(inner - outer) <= outer_len - inner_len;
}

// What every accepted certificate satisfies, whatever its bytes.
static void check_accepted(const webpki_cert *c, const uint8_t *cert, size_t cert_len, int is_ca) {
    CHECK(inside(cert, cert_len, c->tbs, c->tbs_len));
    CHECK(inside(c->tbs, c->tbs_len, c->issuer, c->issuer_len) && c->issuer[0] == 0x30);
    CHECK(inside(c->tbs, c->tbs_len, c->subject, c->subject_len) && c->subject[0] == 0x30);
    CHECK(inside(c->tbs, c->tbs_len, c->spki.key, c->spki.key_len));
    CHECK(inside(cert, cert_len, c->sig, c->sig_len) && c->sig_len > 0);
    CHECK(c->sigalg >= WEBPKI_SIG_RSA_SHA256 && c->sigalg <= WEBPKI_SIG_ECDSA_SHA384);
    CHECK(c->not_before <= c->not_after);
    CHECK(c->san == NULL ? c->san_len == 0 : inside(c->tbs, c->tbs_len, c->san, c->san_len));
    CHECK(c->is_ca == (is_ca != 0));
    if (is_ca) {
        uint8_t required = WEBPKI_EXT_KEY_USAGE | WEBPKI_EXT_BASIC_CONSTRAINTS;
        CHECK((c->seen & required) == required);
        CHECK(c->path_len >= -1);
    } else {
        uint8_t required = WEBPKI_EXT_KEY_USAGE | WEBPKI_EXT_EXT_KEY_USAGE | WEBPKI_EXT_SAN;
        CHECK((c->seen & required) == required && c->san != NULL);
        CHECK(c->path_len == -1);
    }
}

// The corpus rows whose rule is this parser's, and the entry that
// breaks it: the leaf, or the intermediate for the two issuer rules.
typedef struct {
    const char *name;
    size_t entry;
} refused_row;

static const refused_row refused_rows[] = {
    {"no_subject_alt_name",            0},
    {"key_usage_no_digital_signature", 0},
    {"no_server_auth_eku",             0},
    {"leaf_asserts_ca",                0},
    {"sha1_signature",                 0},
    {"rsa_1024_leaf",                  0},
    {"critical_name_constraints",      1},
    {"intermediate_not_ca",            1},
};
#define REFUSED_ROW_COUNT (sizeof refused_rows / sizeof refused_rows[0])
#define NO_ENTRY CH_WEBPKI_FLIGHT_ENTRIES

static size_t refused_entry(const char *name) {
    for (size_t i = 0; i < REFUSED_ROW_COUNT; i++) {
        if (strcmp(refused_rows[i].name, name) == 0) {
            return refused_rows[i].entry;
        }
    }
    return NO_ENTRY;
}

// Parses entry i of a row's flight into *c and requires the verdict the
// row names for it. Returns 1 when the entry was accepted.
static int check_entry(const webpki_corpus_chain *row, const flight *f, size_t i, size_t refused_at,
                       webpki_cert *c) {
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    int rc = webpki_parse_certificate(f->cert[i], f->cert_len[i], i > 0, c, &alert);
    if (i == refused_at) {
        CHECK(rc == CH_EPROTO && alert == ALERT_UNSUPPORTED_CERTIFICATE);
        return 0;
    }
    if (rc != CH_OK || alert != ALERT_BAD_CERTIFICATE) {
        (void)fprintf(stderr, "FAIL %s entry %zu: rc %d alert %u\n", row->name, i, rc, alert);
        failures++;
        return 0;
    }
    check_accepted(c, f->cert[i], f->cert_len[i], i > 0);
    return 1;
}

// Parses every entry of one row, the leaf with is_ca = 0 and each later
// entry with is_ca = 1. In a row where every entry parses, each
// certificate's issuer Name is the next entry's subject Name, byte for
// byte, except in the row built to break that: so the Name pointers
// cover the whole TLV and no more. Returns the number of entries refused.
static size_t check_row(const webpki_corpus_chain *row, flight *f) {
    CHECK(read_flight(row->message, row->message_len, f));
    check_reframed(f, row->message, row->message_len);
    size_t refused_at = refused_entry(row->name);
    int names_chain = refused_at == NO_ENTRY && strcmp(row->name, "issuer_name_mismatch") != 0;
    size_t accepted = 0;
    webpki_cert previous;
    memset(&previous, 0, sizeof previous);
    for (size_t i = 0; i < f->count; i++) {
        webpki_cert c;
        memset(&c, 0, sizeof c);
        accepted += (size_t)check_entry(row, f, i, refused_at, &c);
        if (names_chain && i > 0) {
            CHECK(previous.issuer_len == c.subject_len &&
                  memcmp(previous.issuer, c.subject, c.subject_len) == 0);
        }
        previous = c;
    }
    return f->count - accepted;
}

// Entry index of a row, parsed under its arm; a refusal is a failure.
static webpki_cert parse_entry(const webpki_corpus_chain *row, size_t index) {
    flight f;
    webpki_cert c;
    memset(&c, 0, sizeof c);
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    if (!read_flight(row->message, row->message_len, &f) || index >= f.count ||
        webpki_parse_certificate(f.cert[index], f.cert_len[index], index > 0, &c, &alert) !=
            CH_OK) {
        (void)fprintf(stderr, "FAIL %s entry %zu does not parse\n", row->name, index);
        failures++;
    }
    return c;
}

static void test_corpus(void) {
    size_t refused = 0;
    size_t entries = 0;
    for (size_t i = 0; i < sizeof webpki_corpus_chains / sizeof webpki_corpus_chains[0]; i++) {
        flight f;
        refused += check_row(&webpki_corpus_chains[i], &f);
        entries += f.count;
    }
    CHECK(refused == REFUSED_ROW_COUNT);
    CHECK(entries == 75); // every entry of the 30 corpus chains
}

static const uint8_t leaf_host[] = "s3.example.test";

// The fields the minted chains pin: the aws leaf's RSA-2048 key and
// dates, the SAN value that names the corpus host, and the
// pathLenConstraint of each issuer shape.
static void test_corpus_fields(void) {
    const webpki_corpus_chain *aws = &webpki_corpus_chains[0];
    const webpki_corpus_chain *r2 = &webpki_corpus_chains[2];
    const webpki_corpus_chain *letsencrypt = &webpki_corpus_chains[3];
    webpki_cert c = parse_entry(aws, 0);
    CHECK(c.spki.alg == WEBPKI_KEY_RSA && c.spki.key_len == 256);
    CHECK(c.sigalg == WEBPKI_SIG_RSA_SHA256);
    CHECK(c.not_before == UINT64_C(20260101000000) && c.not_after == UINT64_C(20261231235959));
    // 30 11 82 0f "s3.example.test"
    CHECK(c.san_len == 2 + 2 + sizeof leaf_host - 1);
    CHECK(c.san != NULL && memcmp(c.san + 4, leaf_host, sizeof leaf_host - 1) == 0);
    c = parse_entry(aws, 1);
    CHECK(c.not_before == UINT64_C(20250101000000) && c.not_after == UINT64_C(20401231235959));
    CHECK(c.path_len == 0 && parse_entry(aws, 2).path_len == -1);
    c = parse_entry(r2, 0);
    CHECK(c.spki.alg == WEBPKI_KEY_P256 && c.spki.key_len == 64);
    CHECK(c.sigalg == WEBPKI_SIG_ECDSA_SHA256);
    CHECK(parse_entry(r2, 1).sigalg == WEBPKI_SIG_ECDSA_SHA384);
    c = parse_entry(letsencrypt, 1);
    CHECK(c.spki.alg == WEBPKI_KEY_P384 && c.spki.key_len == 96 && c.path_len == 0);
    CHECK(parse_entry(letsencrypt, 2).path_len == 1);
    CHECK(parse_entry(letsencrypt, 3).path_len == -1);
}

// docs/webpki.md fact 4: the S3 leaf carries ten extensions and a
// subjectAltName over the ca profile's 256-byte cap.
static void test_captures(void) {
    size_t entries = 0;
    for (size_t i = 0; i < sizeof webpki_capture_chains / sizeof webpki_capture_chains[0]; i++) {
        flight f;
        CHECK(check_row(&webpki_capture_chains[i], &f) == 0);
        entries += f.count;
    }
    CHECK(entries == 16);
    const webpki_corpus_chain *s3 = &webpki_capture_chains[0];
    flight f;
    CHECK(strcmp(s3->name, "s3.amazonaws.com") == 0);
    CHECK(read_flight(s3->message, s3->message_len, &f) && f.count == 3);
    CHECK(ext_count(f.cert[0], f.cert_len[0]) == 10);
    webpki_cert c = parse_entry(s3, 0);
    CHECK(c.san_len == 640 && c.spki.alg == WEBPKI_KEY_RSA);
}

#include "webpki_cert_mutants.h"
#include "webpki_ext_mutants.h"

int main(void) {
    test_corpus();
    test_corpus_fields();
    test_captures();
    test_mutants();
    test_extension_mutants();
    if (failures == 0) {
        (void)printf("webpki_cert: all tests passed\n");
    }
    return failures != 0;
}
