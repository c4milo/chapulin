// The TRUST=webpki CertificateVerify arm of handshake_auth.c: the rule
// that binds the signature scheme to the leaf key's family, the SHA-384
// signed content ecdsa_secp384r1_sha384 names, and the verifier each
// family's key goes to.
//
// The test drives hsa_server_auth directly over a mock transport that
// answers with plaintext handshake records, which is what the reader
// takes before the handshake keys are up. The flight is one corpus
// chain's Certificate message and one CertificateVerify from
// test/webpki_auth_vectors.h. Because the Certificate message is the
// whole transcript at that point, every signature in that header is over
// a hash this file recomputes and compares, so a corpus and a vector
// header that drifted apart fail by name.
//
// Three verdicts, each with both sides of its boundary: an accepted row
// per key family, the same signature under a scheme that family cannot
// produce, and a signature over the content hashed the other way.
// test/webpki_auth_pins.h drives the same flight under SPKI pins: RFC
// 7250 raw public keys, and chains a pin must name a key on.
// test/webpki_leaf_pins.h drives it under pins alone, where a pin must
// name the leaf's key.
//
// Its own binary, built with -DCH_TRUST_WEBPKI over the sources that
// object packages: ch_cfg carries the anchors, the hostname and the
// clock only there.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "handshake_auth.h"
#include "handshake_message.h"
#include "record.h"
#include "session.h"
#include "sha256.h"
#include "test_random.h"
#include "webpki.h"
#include "webpki_auth_vectors.h"
#include "webpki_corpus.h"

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

// The flight the mock answers with: two handshake messages, each in one
// plaintext record. The Certificate message is the largest thing here,
// and CH_MIN_RXBUF is the buffer the mode demands for it.
#define FLIGHT_MAX (2 * (CH_MIN_RXBUF + REC_HDR))
// The CertificateVerify message: a header, a scheme, a length and an
// RSA-2048 signature fit with room to spare.
#define VERIFY_MSG_MAX 1024

typedef struct {
    uint8_t queue[FLIGHT_MAX];
    size_t len;
    size_t off;
} mock_source;

static int mock_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return 0; // hsa_server_auth sends nothing; the alert is the caller's job
}

static int mock_recv(void *io, uint8_t *p, size_t n) {
    mock_source *s = io;
    size_t left = s->len - s->off;
    if (left == 0) {
        return -1;
    }
    size_t take = n < left ? n : left;
    memcpy(p, s->queue + s->off, take);
    s->off += take;
    return (int)take;
}

// One handshake message as one plaintext record.
static void push_message(mock_source *s, const uint8_t *msg, size_t n) {
    wbuf w;
    wb_init(&w, s->queue + s->len, sizeof s->queue - s->len);
    wb_u8(&w, REC_HANDSHAKE);
    wb_u16(&w, 0x0303);
    wb_u16(&w, (uint16_t)n);
    wb_bytes(&w, msg, n);
    CHECK(!w.err);
    s->len += w.len;
}

// The CertificateVerify message of RFC 9846 section 4.5.2: the scheme,
// then the signature as opaque signature<0..2^16-1>.
static size_t build_certificate_verify(uint8_t *out, size_t cap, uint16_t scheme,
                                       const uint8_t *sig, size_t sig_len) {
    wbuf w;
    wb_init(&w, out, cap);
    wb_u8(&w, HS_CERTIFICATE_VERIFY);
    size_t body = wb_mark(&w, 3);
    wb_u16(&w, scheme);
    wb_u16(&w, (uint16_t)sig_len);
    wb_bytes(&w, sig, sig_len);
    wb_patch24(&w, body);
    CHECK(!w.err);
    return w.len;
}

// The corpus row a vector signs. A name no row carries is a header the
// generator wrote against another corpus.
static const webpki_corpus_chain *chain_named(const char *name) {
    for (size_t i = 0; i < sizeof webpki_corpus_chains / sizeof webpki_corpus_chains[0]; i++) {
        if (strcmp(webpki_corpus_chains[i].name, name) == 0) {
            return &webpki_corpus_chains[i];
        }
    }
    (void)fprintf(stderr, "FAIL no corpus chain named %s\n", name);
    failures++;
    return NULL;
}

// A row's configuration: its anchors, its hostname and its clock, as
// test/webpki_chain_test.c builds them.
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

// The verdict a row's expected name stands for: what hsa_server_auth
// returns and the alert it leaves behind. An accepted row leaves the
// alert it staged for a decode error, which no peer ever sees, so only
// the refusals name one.
typedef struct {
    const char *expected;
    int rc;
    uint8_t alert;
} verdict;

static const verdict verdicts[] = {
    {"ok",            CH_OK,    0                      },
    {"wrong_scheme",  CH_EAUTH, ALERT_ILLEGAL_PARAMETER},
    {"bad_signature", CH_EAUTH, ALERT_DECRYPT_ERROR    },
};
#define VERDICT_COUNT (sizeof verdicts / sizeof verdicts[0])

static const verdict *verdict_for(const char *expected) {
    for (size_t i = 0; i < VERDICT_COUNT; i++) {
        if (strcmp(verdicts[i].expected, expected) == 0) {
            return &verdicts[i];
        }
    }
    (void)fprintf(stderr, "FAIL no verdict for %s\n", expected);
    failures++;
    return &verdicts[0];
}

// The leaf key family RFC 9846 section 4.5.2 binds each scheme to, which
// an accepted row must have walked out of the chain.
static uint8_t scheme_family(uint16_t scheme) {
    if (scheme == SIGALG_ECDSA_P256_SHA256) {
        return WEBPKI_KEY_P256;
    }
    if (scheme == SIGALG_ECDSA_P384_SHA384) {
        return WEBPKI_KEY_P384;
    }
    return WEBPKI_KEY_RSA;
}

static uint8_t rxbuf[CH_MIN_RXBUF];
static mock_source source;

// One flight through hsa_server_auth, from a session that has hashed
// nothing yet: a Certificate message, then a CertificateVerify under
// scheme carrying sig. t->cfg holds the trust configuration and
// t->server_cert_type the type the EncryptedExtensions selected; this
// adds the buffer and the mock transport. Returns what hsa_server_auth
// returns, with the handshake state left in h and the CertificateVerify
// message in verify_msg.
static int run_flight(ch_tls *t, handshake_state *h, const uint8_t *message, size_t message_len,
                      uint16_t scheme, const uint8_t *sig, size_t sig_len, uint8_t *verify_msg,
                      size_t *verify_len) {
    *verify_len = build_certificate_verify(verify_msg, VERIFY_MSG_MAX, scheme, sig, sig_len);
    memset(&source, 0, sizeof source);
    push_message(&source, message, message_len);
    push_message(&source, verify_msg, *verify_len);
    t->cfg.buf = rxbuf;
    t->cfg.buf_len = CH_MIN_RXBUF;
    t->cfg.send = mock_send;
    t->cfg.recv = mock_recv;
    t->cfg.io = &source;
    transcript_init(&t->transcript);
    memset(h, 0, sizeof *h);
    h->t = t;
    return hsa_server_auth(h);
}

// An accepted CertificateVerify joins the transcript, so the Finished
// that follows covers it: the running hash must be SHA-256 of the two
// messages.
static void check_transcript(const ch_tls *t, const uint8_t *message, size_t message_len,
                             const uint8_t *verify_msg, size_t verify_len) {
    uint8_t after[SHA256_LEN];
    transcript_hash_after(&t->transcript, SHA256_LEN, NULL, 0, after);
    sha256 s;
    sha256_init(&s);
    sha256_update(&s, message, message_len);
    sha256_update(&s, verify_msg, verify_len);
    uint8_t want_hash[SHA256_LEN];
    sha256_final(&s, want_hash);
    CHECK(memcmp(after, want_hash, SHA256_LEN) == 0);
}

// One vector: the chain's Certificate message and the row's
// CertificateVerify through hsa_server_auth.
static void check_vector(const webpki_auth_vector *v) {
    const webpki_corpus_chain *row = chain_named(v->chain);
    if (row == NULL) {
        return;
    }
    // The transcript the signature covers. hsa_server_auth hashes the
    // Certificate message and nothing else before CertificateVerify.
    uint8_t transcript[SHA256_LEN];
    sha256_of(row->message, row->message_len, transcript);
    if (memcmp(transcript, v->transcript, SHA256_LEN) != 0) {
        (void)fprintf(stderr, "FAIL %s: the corpus message is not the one it was signed over\n",
                      v->name);
        failures++;
        return;
    }

    ch_trust_anchor anchors[CH_WEBPKI_ANCHOR_MAX];
    ch_tls t;
    memset(&t, 0, sizeof t);
    row_cfg(row, anchors, &t.cfg);
    handshake_state h;
    uint8_t verify_msg[VERIFY_MSG_MAX];
    size_t verify_len = 0;
    int rc = run_flight(&t, &h, row->message, row->message_len, v->scheme, v->sig, v->sig_len,
                        verify_msg, &verify_len);
    const verdict *want = verdict_for(v->expected);
    if (rc != want->rc || (want->rc != CH_OK && h.alert != want->alert)) {
        (void)fprintf(stderr, "FAIL %s (%s): rc %d alert %u, want rc %d alert %u\n", v->name,
                      v->expected, rc, h.alert, want->rc, want->alert);
        failures++;
        return;
    }
    if (rc != CH_OK) {
        return;
    }
    CHECK(h.leaf.alg == scheme_family(v->scheme));
    check_transcript(&t, row->message, row->message_len, verify_msg, verify_len);
}

// Every vector, and the count of each verdict, so a header that lost its
// accepted rows fails here instead of passing on refusals alone.
static void test_vectors(void) {
    size_t accepted = 0;
    size_t refused = 0;
    for (size_t i = 0; i < sizeof webpki_auth_vectors / sizeof webpki_auth_vectors[0]; i++) {
        const webpki_auth_vector *v = &webpki_auth_vectors[i];
        check_vector(v);
        if (strcmp(v->expected, "ok") == 0) {
            accepted++;
        } else {
            refused++;
        }
    }
    CHECK(accepted == 3); // one per key family the mode admits
    CHECK(refused == 5);
}

// Each accepted row's twin under every other scheme, built here rather
// than signed: the client must refuse the scheme before it looks at the
// signature, so the same bytes stand. This walks the whole binding table
// instead of the rows the vector header samples.
static void test_scheme_table(void) {
    static const uint16_t schemes[3] = {SIGALG_ECDSA_P256_SHA256, SIGALG_RSA_PSS_RSAE_SHA256,
                                        SIGALG_ECDSA_P384_SHA384};
    for (size_t i = 0; i < sizeof webpki_auth_vectors / sizeof webpki_auth_vectors[0]; i++) {
        const webpki_auth_vector *v = &webpki_auth_vectors[i];
        if (strcmp(v->expected, "ok") != 0) {
            continue;
        }
        for (size_t j = 0; j < 3; j++) {
            if (schemes[j] == v->scheme) {
                continue;
            }
            webpki_auth_vector twin = *v;
            twin.scheme = schemes[j];
            twin.expected = "wrong_scheme";
            check_vector(&twin);
        }
    }
}

#include "webpki_auth_pins.h"
// The leaf pin rows read webpki_auth_pins.h's helpers.
#include "webpki_leaf_pins.h"

int main(void) {
    test_vectors();
    test_scheme_table();
    test_raw_keys();
    test_raw_key_framing();
    test_raw_key_bound();
    test_chain_pins();
    test_leaf_pins();
    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("webpki_auth_test: all checks passed\n");
    return 0;
}
