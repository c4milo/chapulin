// The TRUST=webpki chain walk (webpki.c) over every fixture in
// test/webpki_corpus.h, and over lists this file reframes from those
// fixtures to reach the bounds no minted chain reaches.
//
// The corpus half drives each row through webpki_verify_chain with that
// row's anchors, hostname and now_seconds, and requires the row's
// recorded verdict: CH_OK for the 11 positive rows and the 4 positive
// captures, and for each negative row the return code and the alert
// webpki.h names for its rule. The bounds half reframes corpus entries
// into new CertificateEntry lists: a trailing entry of junk, an entry
// one byte over CH_WEBPKI_CERT_MAX, a fifth entry, a chain that would
// need a fourth certificate, and a non-empty per-entry extensions
// vector on the leaf's entry and on a trailing one.
// test/webpki_chain_path.h checks the path the walk reports.
//
// Its own binary, built with -DCH_TRUST_WEBPKI: ch_cfg carries the
// anchors, the hostname and the clock only there, and the RSA-4096 keys
// in the captures pass webpki_read_spki's modulus size check only there.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "buf.h"
#include "handshake_message.h"
#include "webpki.h"
#include "webpki_corpus.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

#define HANDSHAKE_CERTIFICATE 11
// Entries this file frames into one list, two over the flight cap so
// the refused side of that boundary fits.
#define TEST_ENTRIES_MAX ((size_t)6)
#define TEST_LIST_MAX (TEST_ENTRIES_MAX * (CH_WEBPKI_CERT_MAX + 5))

// The verdict one rule reaches: what webpki_verify_chain returns and
// the alert it leaves behind. "ok" keeps the caller's seed.
typedef struct {
    const char *rule;
    int rc;
    uint8_t alert;
} verdict;

// Every value webpki_corpus_chain.expected takes, and the row of
// webpki.h's alert table that names its answer.
static const verdict verdicts[] = {
    {"ok",                             CH_OK,     ALERT_BAD_CERTIFICATE        },
    // now_seconds outside a validity
    {"expired",                        CH_EAUTH,  ALERT_CERTIFICATE_EXPIRED    },
    {"not_yet_valid",                  CH_EAUTH,  ALERT_CERTIFICATE_EXPIRED    },
    // no dNSName matches the hostname
    {"hostname_mismatch",              CH_EAUTH,  ALERT_BAD_CERTIFICATE        },
    {"wildcard_two_labels",            CH_EAUTH,  ALERT_BAD_CERTIFICATE        },
    {"wildcard_public_suffix",         CH_EAUTH,  ALERT_BAD_CERTIFICATE        },
    // a recognized off-profile fact in one certificate
    {"no_subject_alt_name",            CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE},
    {"key_usage_no_digital_signature", CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE},
    {"no_server_auth_eku",             CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE},
    {"leaf_asserts_ca",                CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE},
    {"sha1_signature",                 CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE},
    {"rsa_1024_leaf",                  CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE},
    {"critical_name_constraints",      CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE},
    {"intermediate_not_ca",            CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE},
    // the walk's own off-profile facts
    {"path_len_exceeded",              CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE},
    {"issuer_name_mismatch",           CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE},
    // a signature that fails under its issuer
    {"corrupt_signature",              CH_EAUTH,  ALERT_BAD_CERTIFICATE        },
    // the entries run out before an anchor verifies
    {"anchor_key_mismatch",            CH_EAUTH,  ALERT_UNKNOWN_CA             },
};
#define VERDICT_COUNT (sizeof verdicts / sizeof verdicts[0])

static const verdict *verdict_for(const char *rule) {
    for (size_t i = 0; i < VERDICT_COUNT; i++) {
        if (strcmp(verdicts[i].rule, rule) == 0) {
            return &verdicts[i];
        }
    }
    (void)fprintf(stderr, "FAIL no verdict for rule %s\n", rule);
    failures++;
    return &verdicts[0];
}

// One Certificate message's entries, as pointers into the message.
typedef struct {
    const uint8_t *cert[TEST_ENTRIES_MAX];
    size_t cert_len[TEST_ENTRIES_MAX];
    size_t count;
} entries;

// The CertificateEntry list of a corpus row's Certificate message:
// msg_type 11, a u24 body length, an empty certificate_request_context
// and a u24 list length, then the list itself, which is what
// webpki_verify_chain takes.
static int row_list(const webpki_corpus_chain *row, const uint8_t **list, size_t *list_len) {
    rbuf r;
    rb_init(&r, row->message, row->message_len);
    uint8_t msg_type = rb_u8(&r);
    size_t body_len = rb_u24(&r);
    uint8_t context_len = rb_u8(&r);
    size_t len = rb_u24(&r);
    if (r.err || msg_type != HANDSHAKE_CERTIFICATE || body_len != row->message_len - 4 ||
        context_len != 0 || len != rb_left(&r)) {
        return 0;
    }
    *list = rb_bytes(&r, len);
    *list_len = len;
    return *list != NULL;
}

// Splits a list into its entries, so this file can frame them again.
static int split_list(const uint8_t *list, size_t list_len, entries *out) {
    rbuf r;
    rb_init(&r, list, list_len);
    out->count = 0;
    while (rb_left(&r) > 0 && out->count < TEST_ENTRIES_MAX) {
        size_t cert_len = rb_u24(&r);
        const uint8_t *cert = rb_bytes(&r, cert_len);
        if (cert == NULL || rb_u16(&r) != 0 || r.err) {
            return 0;
        }
        out->cert[out->count] = cert;
        out->cert_len[out->count] = cert_len;
        out->count++;
    }
    return rb_left(&r) == 0;
}

// The entries of a row, or a failure the caller reports.
static entries row_entries(const webpki_corpus_chain *row) {
    entries e;
    const uint8_t *list = NULL;
    size_t list_len = 0;
    memset(&e, 0, sizeof e);
    if (!row_list(row, &list, &list_len) || !split_list(list, list_len, &e)) {
        (void)fprintf(stderr, "FAIL %s does not frame\n", row->name);
        failures++;
    }
    return e;
}

// Frames entries into a CertificateEntry list: each is a u24 length,
// the certificate, and an empty u16 per-entry extensions vector.
static size_t frame_list(uint8_t *out, const entries *e) {
    wbuf w;
    wb_init(&w, out, TEST_LIST_MAX);
    for (size_t i = 0; i < e->count; i++) {
        wb_u24(&w, (uint32_t)e->cert_len[i]);
        wb_bytes(&w, e->cert[i], e->cert_len[i]);
        wb_u16(&w, 0);
    }
    CHECK(!w.err);
    return w.len;
}

// A row's configuration: its anchors, its hostname and its clock. The
// anchors are copied into ch_trust_anchor, which holds the same four
// fields the corpus header declares for itself.
static void row_cfg(const webpki_corpus_chain *row, ch_trust_anchor *anchors, ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    CHECK(row->anchor_count <= CH_WEBPKI_ANCHOR_MAX);
    for (size_t i = 0; i < row->anchor_count; i++) {
        anchors[i].name = row->anchors[i].name;
        anchors[i].name_len = row->anchors[i].name_len;
        anchors[i].spki = row->anchors[i].spki;
        anchors[i].spki_len = row->anchors[i].spki_len;
    }
    cfg->anchors = anchors;
    cfg->anchor_count = row->anchor_count;
    cfg->hostname = (const uint8_t *)row->hostname;
    cfg->hostname_len = strlen(row->hostname);
    cfg->now_seconds = row->now_seconds;
}

// One walk over a list, under a row's configuration. Returns the return
// code and writes the alert the walk left, seeded as hsa_server_auth
// seeds it.
static int walk(const webpki_corpus_chain *row, const uint8_t *list, size_t list_len,
                webpki_leaf_info *leaf, uint8_t *alert) {
    ch_trust_anchor anchors[CH_WEBPKI_ANCHOR_MAX];
    ch_cfg cfg;
    row_cfg(row, anchors, &cfg);
    memset(leaf, 0, sizeof *leaf);
    *alert = ALERT_BAD_CERTIFICATE;
    return webpki_verify_chain(list, list_len, &cfg, leaf, alert);
}

// One corpus row: the walk over its own message must reach the verdict
// its rule names, and an accepted chain must carry a leaf key out.
static void check_row(const webpki_corpus_chain *row) {
    const uint8_t *list = NULL;
    size_t list_len = 0;
    if (!row_list(row, &list, &list_len)) {
        (void)fprintf(stderr, "FAIL %s does not frame\n", row->name);
        failures++;
        return;
    }
    webpki_leaf_info leaf;
    uint8_t alert = 0;
    int rc = walk(row, list, list_len, &leaf, &alert);
    const verdict *want = verdict_for(row->expected);
    if (rc != want->rc || alert != want->alert) {
        (void)fprintf(stderr, "FAIL %s (%s): rc %d alert %u, want rc %d alert %u\n", row->name,
                      row->expected, rc, alert, want->rc, want->alert);
        failures++;
        return;
    }
    if (rc == CH_OK) {
        CHECK(leaf.alg >= WEBPKI_KEY_RSA && leaf.alg <= WEBPKI_KEY_P384);
        CHECK(leaf.key_len > 0 && leaf.key_len <= CH_WEBPKI_KEY_MAX);
    }
}

static void test_corpus(void) {
    for (size_t i = 0; i < sizeof webpki_corpus_chains / sizeof webpki_corpus_chains[0]; i++) {
        check_row(&webpki_corpus_chains[i]);
    }
    for (size_t i = 0; i < sizeof webpki_capture_chains / sizeof webpki_capture_chains[0]; i++) {
        check_row(&webpki_capture_chains[i]);
    }
}

// Row indexes this file names. The corpus order is
// gen_webpki_corpus.py's, and each check below asserts the name it
// expects, so a reordered corpus fails here rather than testing
// something else.
#define ROW_AWS 0
#define ROW_R2 2
#define ROW_LETSENCRYPT 3
#define ROW_ISSUER_NOT_AFTER_BOUNDARY 23
#define ROW_ISSUER_EXPIRED 24
#define ROW_ISSUER_NOT_BEFORE_BOUNDARY 25
#define ROW_ISSUER_NOT_YET_VALID 26
#define ROW_REKEYED_INTERMEDIATE 27
#define ROW_ANCHOR_KEY_MISMATCH 28

static const webpki_corpus_chain *row_named(size_t index, const char *name) {
    const webpki_corpus_chain *row = &webpki_corpus_chains[index];
    CHECK(strcmp(row->name, name) == 0);
    return row;
}

// The key the walk copies out is the leaf's own, not an issuer's.
static void test_leaf_key(void) {
    const webpki_corpus_chain *aws = row_named(ROW_AWS, "aws");
    const webpki_corpus_chain *r2 = row_named(ROW_R2, "r2");
    const webpki_corpus_chain *letsencrypt = row_named(ROW_LETSENCRYPT, "letsencrypt");
    const uint8_t *list = NULL;
    size_t list_len = 0;
    webpki_leaf_info leaf;
    uint8_t alert = 0;
    CHECK(row_list(aws, &list, &list_len));
    CHECK(walk(aws, list, list_len, &leaf, &alert) == CH_OK);
    CHECK(leaf.alg == WEBPKI_KEY_RSA && leaf.key_len == 256);
    // The leaf's modulus, not the RSA-2048 intermediate's: the first
    // entry's key bytes are the ones copied.
    entries e = row_entries(aws);
    CHECK(e.count == 3);
    CHECK(leaf.key[0] != 0 && (leaf.key[leaf.key_len - 1] & 1) == 1);
    CHECK(row_list(r2, &list, &list_len));
    CHECK(walk(r2, list, list_len, &leaf, &alert) == CH_OK);
    CHECK(leaf.alg == WEBPKI_KEY_P256 && leaf.key_len == 64);
    CHECK(row_list(letsencrypt, &list, &list_len));
    CHECK(walk(letsencrypt, list, list_len, &leaf, &alert) == CH_OK);
    CHECK(leaf.alg == WEBPKI_KEY_P256 && leaf.key_len == 64);
}

// docs/webpki.md, "Validity": both ends are inclusive, so now_seconds
// equal to notAfter is valid and one second later is not, and the same
// pair holds at notBefore. The four corpus rows are the same aws chain
// at four clocks one second apart in two places.
static void test_validity_boundaries(void) {
    const webpki_corpus_chain *aws = row_named(ROW_AWS, "aws");
    const webpki_corpus_chain *after_ok = row_named(6, "not_after_boundary");
    const webpki_corpus_chain *after_bad = row_named(8, "expired");
    const webpki_corpus_chain *before_ok = row_named(7, "not_before_boundary");
    const webpki_corpus_chain *before_bad = row_named(9, "not_yet_valid");
    CHECK(after_ok->message == aws->message && before_ok->message == aws->message);
    CHECK(after_bad->now_seconds == after_ok->now_seconds + 1);
    CHECK(before_ok->now_seconds == before_bad->now_seconds + 1);
    CHECK(strcmp(after_ok->expected, "ok") == 0 && strcmp(before_ok->expected, "ok") == 0);
    CHECK(strcmp(after_bad->expected, "expired") == 0);
    CHECK(strcmp(before_bad->expected, "not_yet_valid") == 0);
}

// The same four clocks against an issuer's validity (step 6d of
// docs/webpki.md, "The chain walk"): the corpus's short intermediate is
// valid over a window inside its leaf's, so at each of these clocks the
// leaf is valid and only the intermediate's verdict moves. The rows are
// one chain at four clocks one second apart in two places, the
// intermediate's own two boundaries.
static void test_issuer_validity_boundaries(void) {
    const webpki_corpus_chain *after_ok =
        row_named(ROW_ISSUER_NOT_AFTER_BOUNDARY, "issuer_not_after_boundary");
    const webpki_corpus_chain *after_bad = row_named(ROW_ISSUER_EXPIRED, "issuer_expired");
    const webpki_corpus_chain *before_ok =
        row_named(ROW_ISSUER_NOT_BEFORE_BOUNDARY, "issuer_not_before_boundary");
    const webpki_corpus_chain *before_bad =
        row_named(ROW_ISSUER_NOT_YET_VALID, "issuer_not_yet_valid");
    CHECK(after_ok->message == after_bad->message && before_ok->message == after_ok->message &&
          before_bad->message == after_ok->message);
    CHECK(after_bad->now_seconds == after_ok->now_seconds + 1);
    CHECK(before_ok->now_seconds == before_bad->now_seconds + 1);
    CHECK(strcmp(after_ok->expected, "ok") == 0 && strcmp(before_ok->expected, "ok") == 0);
    CHECK(strcmp(after_bad->expected, "expired") == 0);
    CHECK(strcmp(before_bad->expected, "not_yet_valid") == 0);
    entries e = row_entries(after_ok);
    webpki_cert leaf;
    webpki_cert issuer;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    CHECK(e.count == 2);
    CHECK(webpki_parse_certificate(e.cert[0], e.cert_len[0], 0, &leaf, &alert) == CH_OK);
    CHECK(webpki_parse_certificate(e.cert[1], e.cert_len[1], 1, &issuer, &alert) == CH_OK);
    CHECK(leaf.not_before < webpki_pack_seconds(before_bad->now_seconds));
    CHECK(webpki_pack_seconds(after_bad->now_seconds) < leaf.not_after);
    CHECK(issuer.not_before == webpki_pack_seconds(before_ok->now_seconds));
    CHECK(issuer.not_after == webpki_pack_seconds(after_ok->now_seconds));
}

// RFC 5280 §6.1.4 (l), as docs/webpki.md's "Decisions" records it: a
// self-issued certificate does not count against a pathLenConstraint.
// The rekeyed_intermediate row is the aws leaf under the intermediate's
// new key, whose certificate is self-issued under the old key, then the
// old key's certificate at pathLenConstraint 0; the walk accepts it. A
// walk that counted the self-issued certificate would refuse it.
static void test_rekeyed_intermediate(void) {
    const webpki_corpus_chain *row = row_named(ROW_REKEYED_INTERMEDIATE, "rekeyed_intermediate");
    entries e = row_entries(row);
    webpki_cert rekey;
    webpki_cert old;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    CHECK(e.count == 3 && strcmp(row->expected, "ok") == 0);
    CHECK(webpki_parse_certificate(e.cert[1], e.cert_len[1], 1, &rekey, &alert) == CH_OK);
    CHECK(webpki_parse_certificate(e.cert[2], e.cert_len[2], 1, &old, &alert) == CH_OK);
    CHECK(rekey.subject_len == rekey.issuer_len &&
          memcmp(rekey.subject, rekey.issuer, rekey.subject_len) == 0);
    CHECK(rekey.path_len == 0 && old.path_len == 0);
}

// A walk over a list this file framed, under a row's configuration.
static int walk_framed(const webpki_corpus_chain *row, const entries *e, uint8_t *alert) {
    static uint8_t list[TEST_LIST_MAX];
    webpki_leaf_info leaf;
    size_t list_len = frame_list(list, e);
    return walk(row, list, list_len, &leaf, alert);
}

// Bytes no certificate parser accepts: a SEQUENCE header claiming more
// content than follows.
static const uint8_t invalid_der[] = {0x30, 0x7f, 0x00, 0x00};

// docs/webpki.md, "The chain walk": entries after the terminating
// certificate are ignored, not read. The aws walk stops at entry 1, so
// entry 2 may be anything a CertificateEntry can frame.
static void test_trailing_entry_unread(void) {
    const webpki_corpus_chain *aws = row_named(ROW_AWS, "aws");
    entries e = row_entries(aws);
    CHECK(e.count == 3);
    uint8_t alert = 0;
    e.cert[2] = invalid_der;
    e.cert_len[2] = sizeof invalid_der;
    CHECK(walk_framed(aws, &e, &alert) == CH_OK);
}

// CH_WEBPKI_CERT_MAX bounds every entry, read or not. A trailing entry
// at the cap is framed and never parsed; one byte more refuses the
// message before any certificate is parsed.
static void test_entry_size_boundary(void) {
    static uint8_t junk[CH_WEBPKI_CERT_MAX + 1];
    const webpki_corpus_chain *aws = row_named(ROW_AWS, "aws");
    entries e = row_entries(aws);
    CHECK(e.count == 3);
    uint8_t alert = 0;
    memset(junk, 0xff, sizeof junk);
    e.cert[2] = junk;
    e.cert_len[2] = CH_WEBPKI_CERT_MAX;
    CHECK(walk_framed(aws, &e, &alert) == CH_OK);
    e.cert_len[2] = CH_WEBPKI_CERT_MAX + 1;
    alert = 0;
    CHECK(walk_framed(aws, &e, &alert) == CH_EPROTO && alert == ALERT_BAD_CERTIFICATE);
}

// CH_WEBPKI_FLIGHT_ENTRIES bounds the list. The letsencrypt row sends
// exactly four entries and is accepted; a fifth refuses the message.
static void test_flight_entries_boundary(void) {
    const webpki_corpus_chain *letsencrypt = row_named(ROW_LETSENCRYPT, "letsencrypt");
    entries e = row_entries(letsencrypt);
    CHECK(e.count == CH_WEBPKI_FLIGHT_ENTRIES);
    uint8_t alert = 0;
    CHECK(walk_framed(letsencrypt, &e, &alert) == CH_OK);
    e.cert[e.count] = invalid_der;
    e.cert_len[e.count] = sizeof invalid_der;
    e.count++;
    alert = 0;
    CHECK(walk_framed(letsencrypt, &e, &alert) == CH_EPROTO && alert == ALERT_BAD_CERTIFICATE);
}

// CH_WEBPKI_CHAIN_MAX bounds the certificates the walk reads and
// verifies. The letsencrypt chain needs exactly three of them — the
// leaf and two intermediates — before its anchor verifies, and is
// accepted. Under an anchor that names none of those three issuers the
// walk stops at the third certificate with unknown_ca, and the fourth
// entry stays unread: invalid DER there does not change the verdict.
static void test_chain_max_boundary(void) {
    const webpki_corpus_chain *letsencrypt = row_named(ROW_LETSENCRYPT, "letsencrypt");
    const webpki_corpus_chain *aws = row_named(ROW_AWS, "aws");
    const uint8_t *list = NULL;
    size_t list_len = 0;
    webpki_leaf_info leaf;
    uint8_t alert = 0;
    CHECK(row_list(letsencrypt, &list, &list_len));
    CHECK(walk(letsencrypt, list, list_len, &leaf, &alert) == CH_OK);
    // aws's anchor is the RSA root, whose Name no letsencrypt issuer
    // carries, so no anchor ends the walk before the cap does.
    webpki_corpus_chain capped = *letsencrypt;
    capped.anchors = aws->anchors;
    capped.anchor_count = aws->anchor_count;
    alert = 0;
    CHECK(walk(&capped, list, list_len, &leaf, &alert) == CH_EAUTH && alert == ALERT_UNKNOWN_CA);
    entries e = row_entries(letsencrypt);
    CHECK(e.count == 4);
    e.cert[3] = invalid_der;
    e.cert_len[3] = sizeof invalid_der;
    alert = 0;
    CHECK(walk_framed(&capped, &e, &alert) == CH_EAUTH && alert == ALERT_UNKNOWN_CA);
}

// Framing the list itself: an empty list is refused with
// bad_certificate before any certificate is parsed, and a non-empty
// per-entry extensions vector with unsupported_extension, on the leaf's
// entry and on a trailing entry the walk never parses alike
// (docs/webpki.md, "Decisions"). The aws walk stops at entry 1, so
// entry 2 is a trailing one.
static void test_list_framing(void) {
    const webpki_corpus_chain *aws = row_named(ROW_AWS, "aws");
    entries e = row_entries(aws);
    CHECK(e.count == 3);
    webpki_leaf_info leaf;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    static const uint8_t empty[1] = {0};
    CHECK(walk(aws, empty, 0, &leaf, &alert) == CH_EPROTO && alert == ALERT_BAD_CERTIFICATE);
    static uint8_t list[TEST_LIST_MAX];
    size_t list_len = frame_list(list, &e);
    // An entry's extensions vector is the two bytes after its u24
    // length and its certificate.
    size_t leaf_extensions = 3 + e.cert_len[0];
    size_t trailing_extensions = list_len - 2;
    list[leaf_extensions + 1] = 1;
    alert = 0;
    CHECK(walk(aws, list, list_len, &leaf, &alert) == CH_EPROTO &&
          alert == ALERT_UNSUPPORTED_EXTENSION);
    list[leaf_extensions + 1] = 0;
    list[trailing_extensions + 1] = 1;
    alert = 0;
    CHECK(walk(aws, list, list_len, &leaf, &alert) == CH_EPROTO &&
          alert == ALERT_UNSUPPORTED_EXTENSION);
    list[trailing_extensions + 1] = 0;
    alert = 0;
    CHECK(walk(aws, list, list_len, &leaf, &alert) == CH_OK);
}

#include "webpki_chain_path.h"

int main(void) {
    test_corpus();
    test_leaf_key();
    test_validity_boundaries();
    test_issuer_validity_boundaries();
    test_rekeyed_intermediate();
    test_trailing_entry_unread();
    test_entry_size_boundary();
    test_flight_entries_boundary();
    test_chain_max_boundary();
    test_anchor_name_alone();
    test_list_framing();
    test_path_outputs();
    test_anchor_index();
    if (failures == 0) {
        (void)printf("webpki_chain: all tests passed\n");
    }
    return failures != 0;
}
