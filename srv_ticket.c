// The resumption ticket: seal and open. srv_ticket.h states the layout and
// each rule. Reading goes through the rbuf reader and writing through the
// wbuf writer (buf.h), so no step here does raw buffer arithmetic, and
// auth_seconds moves one byte at a time, so no multi-byte value assumes
// host endianness.
#include "srv_ticket.h"

#ifdef CH_ROLE_SERVER

#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "ct.h"

// RFC 9846 §4.7.1 forbids a ticket_lifetime above 604800 seconds
// (rfc9846.txt:3257-3258), and a lifetime of 0 tells the client to discard
// the ticket at once, so a build that set either would issue tickets no
// client may use. The library builds as C, so the guard always runs.
#ifndef __cplusplus
_Static_assert(SRV_TICKET_LIFETIME >= 1 && SRV_TICKET_LIFETIME <= 604800,
               "a ticket lifetime is 1 to 604800 seconds");
#endif

// The bytes of auth_seconds in the body.
#define SRV_TICKET_INSTANT_LEN 8

// The associated data every ticket is sealed and opened with: its version
// byte, which srv_ticket.h names as the one byte before the nonce.
static const uint8_t ticket_version[1] = {SRV_TICKET_VERSION};

// Writes auth_seconds as SRV_TICKET_INSTANT_LEN bytes, the most
// significant first.
static void write_instant(wbuf *w, uint64_t seconds) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        wb_u8(w, (uint8_t)(seconds >> shift));
    }
}

// Reads the SRV_TICKET_INSTANT_LEN bytes write_instant wrote.
static uint64_t read_instant(rbuf *r) {
    uint64_t seconds = 0;
    for (int i = 0; i < SRV_TICKET_INSTANT_LEN; i++) {
        seconds = (seconds << 8) | rb_u8(r);
    }
    return seconds;
}

// Writes the body srv_ticket.h lays out. The name field is always
// CH_ALPN_NAME_MAX bytes wide, and the bytes past alpn_len are zero, so the
// body's length never depends on the protocol. The caller has held alpn_len
// to CH_ALPN_NAME_MAX.
static void write_body(const srv_ticket_contents *c, uint8_t body[SRV_TICKET_BODY_LEN]) {
    uint8_t name[CH_ALPN_NAME_MAX] = {0};
    memcpy(name, c->alpn, c->alpn_len);
    wbuf b;
    wb_init(&b, body, SRV_TICKET_BODY_LEN);
    write_instant(&b, c->auth_seconds);
    wb_u16(&b, c->suite);
    wb_u8(&b, c->alpn_len);
    wb_bytes(&b, name, sizeof name);
    wb_bytes(&b, c->psk, SHA256_LEN);
    CH_ASSERT(b.err == 0 && b.len == SRV_TICKET_BODY_LEN);
}

size_t srv_ticket_seal(const uint8_t key[SRV_TICKET_KEY_LEN], const uint8_t nonce[AEAD_NONCE],
                       const srv_ticket_contents *c, uint8_t *out, size_t cap) {
    if (cap < SRV_TICKET_LEN || c->alpn_len > CH_ALPN_NAME_MAX) {
        return 0;
    }
    // The body holds the PSK, so it is wiped as soon as it is sealed. The
    // ciphertext and the tag go out in the clear and are not wiped.
    uint8_t body[SRV_TICKET_BODY_LEN];
    write_body(c, body);
    uint8_t ct[SRV_TICKET_BODY_LEN];
    uint8_t tag[AEAD_TAG];
    aead_seal(key, nonce, ticket_version, sizeof ticket_version, body, sizeof body, ct, tag);
    ct_wipe(body, sizeof body);

    wbuf w;
    wb_init(&w, out, cap);
    wb_bytes(&w, ticket_version, sizeof ticket_version);
    wb_bytes(&w, nonce, AEAD_NONCE);
    wb_bytes(&w, ct, sizeof ct);
    wb_bytes(&w, tag, sizeof tag);
    // The cap check above is what keeps the writer inside out.
    CH_ASSERT(w.err == 0 && w.len == SRV_TICKET_LEN);
    return w.len;
}

// Reads the body aead_open released into c. The reads take exactly
// SRV_TICKET_BODY_LEN bytes, so the reader cannot run short, and the assert
// holds it to that. Returns CH_OK, or CH_EAUTH for an alpn_len above
// CH_ALPN_NAME_MAX.
static int read_body(const uint8_t body[SRV_TICKET_BODY_LEN], srv_ticket_contents *c) {
    rbuf r;
    rb_init(&r, body, SRV_TICKET_BODY_LEN);
    c->auth_seconds = read_instant(&r);
    c->suite = rb_u16(&r);
    c->alpn_len = rb_u8(&r);
    const uint8_t *name = rb_bytes(&r, CH_ALPN_NAME_MAX);
    const uint8_t *psk = rb_bytes(&r, SHA256_LEN);
    CH_ASSERT(r.err == 0 && rb_left(&r) == 0);
    if (c->alpn_len > CH_ALPN_NAME_MAX) {
        return CH_EAUTH;
    }
    memcpy(c->alpn, name, CH_ALPN_NAME_MAX);
    memcpy(c->psk, psk, SHA256_LEN);
    return CH_OK;
}

int srv_ticket_open(const uint8_t key[SRV_TICKET_KEY_LEN], const uint8_t *ticket, size_t n,
                    srv_ticket_contents *c) {
    memset(c, 0, sizeof *c);
    // INV-25's exact-fill check, and the two clear-text checks srv_ticket.h
    // promises before the AEAD runs: r.err refuses a ticket shorter than
    // SRV_TICKET_LEN, a byte left over refuses one longer, and the version
    // byte names the layout. The reader is bounded by n, so no answer came
    // from a read past the end.
    rbuf r;
    rb_init(&r, ticket, n);
    uint8_t version = rb_u8(&r);
    const uint8_t *nonce = rb_bytes(&r, AEAD_NONCE);
    const uint8_t *ct = rb_bytes(&r, SRV_TICKET_BODY_LEN);
    const uint8_t *tag = rb_bytes(&r, AEAD_TAG);
    if (r.err || rb_left(&r) != 0 || version != SRV_TICKET_VERSION) {
        return CH_EAUTH;
    }
    // aead_open compares the tag in constant time and releases no byte of
    // body on a mismatch (aead.h).
    uint8_t body[SRV_TICKET_BODY_LEN];
    if (aead_open(key, nonce, ticket_version, sizeof ticket_version, ct, sizeof body, tag, body) ==
        0) {
        return CH_EAUTH;
    }
    int rc = read_body(body, c);
    ct_wipe(body, sizeof body);
    if (rc != CH_OK) {
        ct_wipe(c, sizeof *c);
    }
    return rc;
}

#endif // CH_ROLE_SERVER
