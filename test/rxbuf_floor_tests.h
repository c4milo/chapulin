// The receive-buffer floor's one promise (cfg.h, CH_MIN_RXBUF): a
// buffer of exactly CH_MIN_RXBUF bytes reassembles the largest
// handshake message the build admits when that message arrives as
// protected records, and a buffer one byte smaller does not.
//
// The message is sealed here the way a server that honours
// record_size_limit seals it: fragments of at most record_size_limit - 1
// plaintext bytes, where handshake.c derives the limit from buf_len,
// each under the client's own read key. It is read back through
// hsr_next_msg with encrypted set, the reader hsa_server_auth takes the
// Certificate message from. At the floor the message fits one record;
// one byte under, it needs two, and the second record does not fit
// beside the first record's plaintext.
//
// Included by test/session_tests.h and test/webpki_session_test.c after
// their CHECK macros; not a standalone translation unit.
#ifndef CH_RXBUF_FLOOR_TESTS_H
#define CH_RXBUF_FLOOR_TESTS_H

#include <string.h>

#include "cfg.h"
#include "handshake_message.h"
#include "handshake_record.h"
#include "record.h"
#include "session.h"

// The largest message the floor reassembles: the buffer minus the
// header, inner content type and tag of the record that completes it.
#define FLOOR_MSG_LEN ((size_t)CH_MIN_RXBUF - REC_OVERHEAD)
// One record at the floor, two one byte under it.
#define FLOOR_WIRE_MAX ((size_t)CH_MIN_RXBUF + (size_t)2 * REC_OVERHEAD)

static uint8_t floor_wire[FLOOR_WIRE_MAX];
static size_t floor_wire_len;
static size_t floor_wire_off;
static uint8_t floor_rxbuf[CH_MIN_RXBUF];
static uint8_t floor_msg[FLOOR_MSG_LEN];

static int floor_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return 0;
}

static int floor_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    size_t left = floor_wire_len - floor_wire_off;
    if (left == 0) {
        return -1;
    }
    size_t take = n < left ? n : left;
    memcpy(p, floor_wire + floor_wire_off, take);
    floor_wire_off += take;
    return (int)take;
}

// Seals floor_msg into floor_wire as the records a server sends under
// the record_size_limit a buf_len-byte buffer advertises.
static void floor_seal(rec_dir *server_write, size_t buf_len) {
    size_t room = buf_len - REC_HDR - AEAD_TAG;
    size_t limit = room > 0x4001 ? 0x4001 : room; // handshake.c, ch_handshake
    size_t content_max = limit - 1;               // RFC 8449 counts the inner content type
    floor_wire_len = 0;
    floor_wire_off = 0;
    for (size_t off = 0; off < sizeof floor_msg;) {
        size_t left = sizeof floor_msg - off;
        size_t take = left < content_max ? left : content_max;
        size_t out_len = 0;
        CHECK(rec_seal(server_write, REC_HANDSHAKE, floor_msg + off, take,
                       floor_wire + floor_wire_len, sizeof floor_wire - floor_wire_len,
                       &out_len) == 0);
        floor_wire_len += out_len;
        off += take;
    }
}

// hsr_next_msg's verdict over a buf_len-byte buffer receiving
// floor_msg, and the message it yielded when the verdict is CH_OK.
static int floor_reassemble(size_t buf_len) {
    uint8_t secret[SHA256_LEN];
    memset(secret, 0x5a, sizeof secret);
    rec_dir server_write;
    rec_dir_init(&server_write, secret);
    floor_seal(&server_write, buf_len);

    static ch_tls t;
    memset(&t, 0, sizeof t);
    t.cfg.buf = floor_rxbuf;
    t.cfg.buf_len = buf_len;
    t.cfg.send = floor_send;
    t.cfg.recv = floor_recv;
    rec_dir_init(&t.rd, secret);
    handshake_state h;
    memset(&h, 0, sizeof h);
    h.t = &t;
    h.encrypted = 1;

    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t raw_len = 0;
    int rc = hsr_next_msg(&h, &type, &raw, &raw_len);
    if (rc == CH_OK) {
        CHECK(type == HS_CERTIFICATE && raw_len == sizeof floor_msg &&
              memcmp(raw, floor_msg, raw_len) == 0);
    }
    return rc;
}

static void test_rxbuf_floor(void) {
    // The trust mode's floor is built from its largest admitted
    // Certificate message (cfg.h): the 8-byte message framing and one
    // entry of the cap + 5 per certificate.
#ifdef CH_TRUST_CA
    CHECK(FLOOR_MSG_LEN == 8 + 2 * ((size_t)CH_X509_MAX + 5));
#endif
#ifdef CH_TRUST_WEBPKI
    CHECK(FLOOR_MSG_LEN == 8 + CH_WEBPKI_FLIGHT_ENTRIES * ((size_t)CH_WEBPKI_CERT_MAX + 5));
#endif
    // A Certificate message of that size: the header says how long it
    // is, and the reader parses nothing else here.
    memset(floor_msg, 0xc5, sizeof floor_msg);
    size_t body_len = sizeof floor_msg - 4;
    floor_msg[0] = HS_CERTIFICATE;
    floor_msg[1] = (uint8_t)(body_len >> 16);
    floor_msg[2] = (uint8_t)(body_len >> 8);
    floor_msg[3] = (uint8_t)body_len;
    CHECK(floor_reassemble(CH_MIN_RXBUF) == CH_OK);
    CHECK(floor_reassemble(CH_MIN_RXBUF - 1) == CH_ECAP);
}

#endif
