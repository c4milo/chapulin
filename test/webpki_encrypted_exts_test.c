// hsf_read_encrypted_extensions in a TRUST=webpki build: the flight
// handler passes the parser what the ClientHello asked for, and the
// certificate type the server selected lands in ch_tls.server_cert_type,
// where hsa_server_auth reads it to tell a raw public key (RFC 7250) from
// a chain. bin/handshake_strict_webpki holds the parser's own rows; this
// test holds the three things the handler adds:
//  - server_name counts as sent when cfg.hostname_len is not 0, so a
//    pins-only configuration with no hostname refuses the
//    acknowledgement with unsupported_extension;
//  - the certificate types offered are webpki_cert_types_offered's, so a
//    configuration without pins refuses a server_certificate_type with
//    unsupported_extension, and a resumption with pins accepts one,
//    because its hello offered the certificate path beside the ticket
//    (docs/decisions.md 55);
//  - t->server_cert_type is seeded with CH_CERT_TYPE_X509 on every read,
//    and the parser writes the selection into it.
//
// The test drives the handler directly over a mock transport that
// answers with one plaintext handshake record, which is what the record
// reader takes before the handshake keys are up; on the wire this
// message arrives protected, and bin/webpki_session_test runs that path.
// Its own binary, built with -DCH_TRUST_WEBPKI over the sources that
// object packages: ch_cfg carries the pins, the anchors and the hostname
// only there.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "handshake_flight.h"
#include "handshake_message.h"
#include "record.h"
#include "session.h"
#include "sha256.h"
#include "test_random.h"

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

// The one record the mock answers with.
typedef struct {
    uint8_t queue[128];
    size_t len;
    size_t off;
} mock_source;

static int mock_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return 0; // the handler sends nothing; the alert is the caller's job
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

// The configuration shapes a row runs under. Every shape names the
// fields webpki_cert_types_offered and the handler read; nothing here
// passes ch_connect, which holds the rules on how they combine.
typedef enum {
    PINS_AND_ANCHORS, // offers the raw key and X.509, sends server_name
    PINS_ONLY,        // offers the raw key alone, sends no server_name
    ANCHORS_ONLY,     // offers no certificate type, sends server_name
    RESUMPTION,       // pins and anchors with a PSK: offers both types too
} cfg_shape;

static const uint8_t pins[1][SHA256_LEN] = {{0x5a}};
static const uint8_t anchor_der[] = {0x30, 0x00};
static const ch_trust_anchor anchors[1] = {
    {anchor_der, sizeof anchor_der, anchor_der, sizeof anchor_der}
};
static const uint8_t host[] = {'d', 'n', 's', '.', 't', 'e', 's', 't'};
static const uint8_t ticket_psk[SHA256_LEN] = {0x01};
static const uint8_t ticket_id[4] = {0x02};
static uint8_t rxbuf[CH_MIN_RXBUF];
static mock_source source;

static void shape_cfg(ch_cfg *cfg, cfg_shape shape) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = rxbuf;
    cfg->buf_len = sizeof rxbuf;
    cfg->send = mock_send;
    cfg->recv = mock_recv;
    cfg->io = &source;
    if (shape != ANCHORS_ONLY) {
        cfg->spki_pins = (const uint8_t *)pins;
        cfg->spki_pin_count = 1;
    }
    if (shape != PINS_ONLY) {
        cfg->anchors = anchors;
        cfg->anchor_count = 1;
        cfg->hostname = host;
        cfg->hostname_len = sizeof host;
    }
    if (shape == RESUMPTION) {
        cfg->psk = ticket_psk;
        cfg->psk_len = sizeof ticket_psk;
        cfg->psk_id = ticket_id;
        cfg->psk_id_len = sizeof ticket_id;
    }
}

// One EncryptedExtensions carrying exts, as one plaintext record, read
// by the handler from a session whose server_cert_type holds before.
// Returns the handler's result, with the session's type in *after and
// the alert in *alert.
static int read_row(cfg_shape shape, const uint8_t *exts, size_t n, uint8_t before, uint8_t *after,
                    uint8_t *alert) {
    memset(&source, 0, sizeof source);
    wbuf w;
    wb_init(&w, source.queue, sizeof source.queue);
    wb_u8(&w, REC_HANDSHAKE);
    wb_u16(&w, 0x0303);
    wb_u16(&w, (uint16_t)(4 + 2 + n));
    wb_u8(&w, HS_ENCRYPTED_EXTENSIONS);
    wb_u24(&w, (uint32_t)(2 + n));
    wb_u16(&w, (uint16_t)n);
    if (n > 0) {
        wb_bytes(&w, exts, n);
    }
    CHECK(!w.err);
    source.len = w.len;

    static ch_tls t;
    memset(&t, 0, sizeof t);
    shape_cfg(&t.cfg, shape);
    t.peer_limit = CH_TX_PT;
    t.alpn_selected = CH_ALPN_NONE;
    t.server_cert_type = before;
    transcript_init(&t.transcript);
    handshake_state h;
    memset(&h, 0, sizeof h);
    h.t = &t;
    int rc = hsf_read_encrypted_extensions(&h);
    *after = t.server_cert_type;
    *alert = h.alert;
    return rc;
}

// The extensions a row carries: the empty server_name acknowledgement
// and a server_certificate_type naming each of the two types.
static const uint8_t server_name_ack[] = {0x00, 0x00, 0x00, 0x00};
static const uint8_t select_raw[] = {0x00, 0x14, 0x00, 0x01, CH_CERT_TYPE_RAW_PUBLIC_KEY};
static const uint8_t select_x509[] = {0x00, 0x14, 0x00, 0x01, CH_CERT_TYPE_X509};

// The selection lands in the session, and a message without one leaves
// the X.509 type there, whatever the session held before the read.
static void test_selection_written(void) {
    uint8_t after = 0;
    uint8_t alert = 0;
    CHECK(read_row(PINS_AND_ANCHORS, select_raw, sizeof select_raw, CH_CERT_TYPE_X509, &after,
                   &alert) == CH_OK);
    CHECK(after == CH_CERT_TYPE_RAW_PUBLIC_KEY);
    CHECK(read_row(PINS_AND_ANCHORS, select_x509, sizeof select_x509, CH_CERT_TYPE_RAW_PUBLIC_KEY,
                   &after, &alert) == CH_OK);
    CHECK(after == CH_CERT_TYPE_X509);
    CHECK(read_row(PINS_AND_ANCHORS, NULL, 0, CH_CERT_TYPE_RAW_PUBLIC_KEY, &after, &alert) ==
          CH_OK);
    CHECK(after == CH_CERT_TYPE_X509);
    CHECK(read_row(PINS_ONLY, select_raw, sizeof select_raw, CH_CERT_TYPE_X509, &after, &alert) ==
          CH_OK);
    CHECK(after == CH_CERT_TYPE_RAW_PUBLIC_KEY);
}

// The offer is webpki_cert_types_offered's. Pins alone offer the raw
// key alone, so X.509 is a type the hello did not offer (47); no pins
// offer nothing, so any selection is unrequested (110). A resumption
// offers what the same configuration offers without a ticket, because a
// server that declines the ticket sends a Certificate after all
// (docs/decisions.md 55), so its server may select the raw key.
static void test_offer_passed(void) {
    uint8_t after = 0;
    uint8_t alert = 0;
    CHECK(read_row(PINS_ONLY, select_x509, sizeof select_x509, CH_CERT_TYPE_X509, &after, &alert) ==
          CH_EPROTO);
    CHECK(alert == ALERT_ILLEGAL_PARAMETER && after == CH_CERT_TYPE_X509);
    CHECK(read_row(ANCHORS_ONLY, select_raw, sizeof select_raw, CH_CERT_TYPE_X509, &after,
                   &alert) == CH_EPROTO);
    CHECK(alert == ALERT_UNSUPPORTED_EXTENSION && after == CH_CERT_TYPE_X509);
    CHECK(read_row(RESUMPTION, select_raw, sizeof select_raw, CH_CERT_TYPE_X509, &after, &alert) ==
          CH_OK);
    CHECK(after == CH_CERT_TYPE_RAW_PUBLIC_KEY);
}

// server_name counts as sent when the configuration has a hostname. A
// pins-only configuration without one sent none, so the acknowledgement
// answers nothing (110).
static void test_server_name_sent(void) {
    uint8_t after = 0;
    uint8_t alert = 0;
    CHECK(read_row(ANCHORS_ONLY, server_name_ack, sizeof server_name_ack, CH_CERT_TYPE_X509, &after,
                   &alert) == CH_OK);
    CHECK(read_row(PINS_AND_ANCHORS, server_name_ack, sizeof server_name_ack, CH_CERT_TYPE_X509,
                   &after, &alert) == CH_OK);
    CHECK(read_row(PINS_ONLY, server_name_ack, sizeof server_name_ack, CH_CERT_TYPE_X509, &after,
                   &alert) == CH_EPROTO);
    CHECK(alert == ALERT_UNSUPPORTED_EXTENSION);
}

int main(void) {
    test_selection_written();
    test_offer_passed();
    test_server_name_sent();
    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("webpki_encrypted_exts_test: all checks passed\n");
    return 0;
}
