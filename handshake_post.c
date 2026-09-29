// NewSessionTicket and KeyUpdate: the post-handshake messages, parsed
// out of decrypted bytes on a live session. See handshake_post.h for
// why they sit apart from the handshake flight and from tls.c.
#include "handshake_post.h"

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "handshake_message.h"
#include "keysched.h"
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
#include "handshake_record.h"
#include "io.h"
#include "record.h"
#endif
#ifdef CH_TRUST_WEBPKI
// handle_ticket binds every ticket, on either transport.
#include "webpki_ticket.h"
#endif

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
// early_data in a NewSessionTicket (RFC 9846 §4.7.1). It is the one
// extension defined there, and RFC 9001 §4.6.1 gives its
// max_early_data_size a single legal value on this transport.
#define TICKET_EXT_EARLY_DATA 42

// Reads the ticket's extension block rather than skipping it. RFC 9001
// §4.6.1 repurposes early_data's max_early_data_size as the sentinel
// 0xffffffff, which says the server accepts QUIC 0-RTT, and a server
// that does not accept it omits the extension (rfc9001.txt:799-802).
// This client offers no 0-RTT, so both shapes are accepted and neither
// changes what it sends.
//
// Returns CH_OK for a block that parses and carries no other
// max_early_data_size. Returns CH_EPROTO with ALERT_ILLEGAL_PARAMETER
// and 0x0a, PROTOCOL_VIOLATION, for any other value, which §4.6.1 makes
// an unconditional client MUST (rfc9001.txt:808-809), and CH_EPROTO
// with ALERT_DECODE_ERROR for a block that does not parse.
static int read_ticket_extensions(const uint8_t *block, size_t n, uint8_t *alert,
                                  uint64_t *error_code) {
    rbuf e;
    rb_init(&e, block, n);
    while (rb_left(&e) > 0) {
        uint16_t ext = rb_u16(&e);
        size_t ext_len = rb_u16(&e);
        const uint8_t *data = rb_bytes(&e, ext_len);
        if (data == NULL) {
            *alert = ALERT_DECODE_ERROR;
            return CH_EPROTO;
        }
        if (ext != TICKET_EXT_EARLY_DATA) {
            continue;
        }
        rbuf d;
        rb_init(&d, data, ext_len);
        uint32_t hi = rb_u24(&d); // u32 read as u24+u8 to keep the reads sequenced
        uint32_t max_early_data_size = (hi << 8) | rb_u8(&d);
        if (d.err || rb_left(&d) != 0) {
            *alert = ALERT_DECODE_ERROR;
            return CH_EPROTO;
        }
        if (max_early_data_size != 0xffffffffU) {
            *alert = ALERT_ILLEGAL_PARAMETER;
            *error_code = 0x0a;
            return CH_EPROTO;
        }
    }
    // The block's own framing must fill it exactly. A trailing byte that
    // is not a whole extension is a decode error rather than padding,
    // and a header the reader could not finish sets e.err instead.
    if (e.err || rb_left(&e) != 0) {
        *alert = ALERT_DECODE_ERROR;
        return CH_EPROTO;
    }
    return CH_OK;
}
#endif

// One NewSessionTicket: derive the resumption PSK and hand the ticket to
// the application. Tickets we could never present again — nonce too long
// for a KDF context, identity too big for our ClientHello — return CH_OK
// with nothing delivered: those messages decode, this client just cannot
// use them, and a ticket is an optimization. A ticket_lifetime of 0 is
// dropped the same way: RFC 9846 §4.6.1 says such a ticket is to be
// discarded at once (rfc9846.txt:3258-3259), and dropping it here is what
// lets ch_cfg.ticket_lifetime_s read 0 as a lifetime the caller did not
// give (hspost_ticket_age_ok).
//
// A message whose own fields do not fill it does not decode at all, so
// it returns CH_EPROTO with decode_error in *alert, which RFC 9846 §6
// requires for a message that cannot be parsed against its syntax
// (rfc9846.txt:3785-3788), and hspost_read's caller kills the session.
// That is the answer the KeyUpdate arm below gives a body that is not one
// byte long.
//
// The extensions vector closes the message (RFC 9846 §4.7.1). Its
// length is read and its bytes are not: the only extension defined
// there is early_data, and chapulin sends no 0-RTT. Skipping by that
// length is what leaves rb_left below at zero for a whole message and
// above zero for a message that carries anything else.
static int handle_ticket(ch_tls *t, const uint8_t *body, size_t n, uint8_t *alert
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
                         ,
                         uint64_t *error_code
#endif
) {
    rbuf r;
    rb_init(&r, body, n);
    // Every byte starts at zero, so none of the caller's copy holds stack
    // bytes: the PSK array past psk_len included, which a SHA-256 session
    // leaves 16 bytes of in a SUITE=aesgcm build.
    ch_ticket ticket;
    memset(&ticket, 0, sizeof ticket);
    uint32_t hi = rb_u24(&r);                  // u32 fields read as u24+u8 to keep the
    ticket.lifetime_s = (hi << 8) | rb_u8(&r); // reads sequenced
    hi = rb_u24(&r);
    ticket.age_add = (hi << 8) | rb_u8(&r);
    size_t nonce_len = rb_u8(&r);
    const uint8_t *nonce = rb_bytes(&r, nonce_len);
    ticket.identity_len = rb_u16(&r);
    ticket.identity = rb_bytes(&r, ticket.identity_len);
    size_t ext_len = rb_u16(&r);
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    const uint8_t *exts = rb_bytes(&r, ext_len);
    if (exts != NULL) {
        int rc = read_ticket_extensions(exts, ext_len, alert, error_code);
        if (rc != CH_OK) {
            return rc;
        }
    }
#else
    rb_skip(&r, ext_len);
#endif
    if (r.err || rb_left(&r) != 0) {
        *alert = ALERT_DECODE_ERROR;
        return CH_EPROTO;
    }
    if (t->cfg.on_ticket == NULL || ticket.lifetime_s == 0 || nonce_len > SHA256_LEN ||
        ticket.identity_len > CH_TICKET_ID_MAX) {
        return CH_OK;
    }
    ticket.epoch = t->epoch;
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    // The version this connection negotiated, which RFC 9369 section 5
    // makes the ticket's (rfc9369.txt:268-284).
    ticket.quic_version = t->quic_negotiated_version;
#endif
    // The PSK takes the hash of the suite this session ran
    // (rfc9846.txt:3298-3301), and its length says which one.
    ticket.psk_len = tls_hash_len(t);
    ks_res_psk(ticket.psk_len, t->res_master, nonce, nonce_len, ticket.psk);
#ifdef CH_TRUST_WEBPKI
    // Binds the ticket to this session's hostname, anchors and SPKI pins,
    // so no other configuration can present it (webpki_ticket.h).
    webpki_ticket_binding(ticket.psk, ticket.psk_len, t->ticket_config_hash, ticket.binding);
#endif
    t->cfg.on_ticket(t->cfg.io, &ticket);
    ct_wipe(ticket.psk, sizeof ticket.psk);
    return CH_OK;
}

// ticket.h states the contract, and a ROLE=server object compiles no
// client, so it defines no client call. The cast keeps the low 32 bits of
// the age, and C defines a uint32_t sum to wrap modulo 2^32, so the two
// together are RFC 9846 §4.3.11.1's sum modulo 2^32 whatever the age.
#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)
uint32_t ch_ticket_obfuscated_age(const ch_ticket *ticket, uint64_t age_ms) {
    return (uint32_t)age_ms + ticket->age_add;
}
#endif

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
int hspost_take_ticket(ch_tls *t, const uint8_t *body, size_t n, uint8_t *alert,
                       uint64_t *error_code) {
    return handle_ticket(t, body, n, alert, error_code);
}
#endif

#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
int hspost_send_key_update(ch_tls *t) {
    uint8_t msg[5] = {HS_KEY_UPDATE, 0, 0, 1, 0};
    size_t out_len = 0;
    if (rec_seal(&t->wr, REC_HANDSHAKE, msg, sizeof msg, t->tx, sizeof t->tx, &out_len) != 0 ||
        io_send_all(&t->cfg, t->tx, out_len) != CH_OK) {
        return CH_EIO;
    }
    rec_dir_update(t->wr_secret, &t->wr);
    t->send_epochs++;
    return CH_OK;
}

// One KeyUpdate: the read direction always rekeys — receivers are
// forbidden from enforcing the peer's epoch cap (RFC 9846 §4.7.3) — and
// a reply goes out only when requested and while our own epoch count is
// under the cap the same section puts on senders.
static int handle_key_update(ch_tls *t, uint8_t request) {
    rec_dir_update(t->rd_secret, &t->rd);
    if (request != 1 || t->send_epochs >= HSPOST_SEND_EPOCHS_MAX) {
        return CH_OK;
    }
    return hspost_send_key_update(t);
}

// One NewSessionTicket. RFC 9846 §4.7.1 gives the message to the server to
// send (rfc9846.txt:3194-3196), so a client's session takes it and a
// server's refuses it as a message out of the order §4 defines, with the
// unexpected_message the caller set (rfc9846.txt:1054-1058). A ROLE=both
// object holds sessions of both sides, and each server entry marks its
// own (session.h).
static int take_ticket(ch_tls *t, const uint8_t *body, size_t msg_len, uint8_t *alert) {
#ifdef CH_ROLE_SERVER
    if (t->server != 0) {
        return CH_EPROTO;
    }
#endif
    return handle_ticket(t, body, msg_len, alert);
}

// One KeyUpdate of msg_len bytes at body, which ends_input says is the
// last message of its record. Its body is the one request_update byte,
// and a body of another length does not parse, which RFC 9846 §6 answers
// with decode_error (rfc9846.txt:3785-3788).
// request_update has two values, and §4.7.3 ends the connection on any
// other with illegal_parameter (rfc9846.txt:3362-3365). Each writes its
// alert to *alert. A KeyUpdate with bytes after it keeps the
// unexpected_message the caller set. Each refusal comes before the rekey.
static int take_key_update(ch_tls *t, const uint8_t *body, size_t msg_len, int ends_input,
                           uint8_t *alert) {
    if (msg_len != 1) {
        *alert = ALERT_DECODE_ERROR;
        return CH_EPROTO;
    }
    if (body[0] > 1) {
        *alert = ALERT_ILLEGAL_PARAMETER;
        return CH_EPROTO;
    }
    if (!ends_input) {
        return CH_EPROTO;
    }
    return handle_key_update(t, body[0]);
}

// Handles the complete post-handshake messages in pt[0..n) — only
// NewSessionTicket and KeyUpdate exist here — and reports through used
// how many bytes were consumed. A trailing partial message is not an
// error; the caller reassembles across records. A failure that owes
// another alert than the unexpected_message the caller set writes it to
// *alert.
//
// A KeyUpdate changes the read key, so it must end its record (RFC 9846
// §5.1, rfc9846.txt:3464-3470), and one that does not is refused before
// it rekeys or answers. pt[0..n) ends where the newest record ends:
// hspost_read appends a record only while these bytes end in a partial
// message, so every byte after a whole message came from the record that
// holds that message's last byte. A KeyUpdate split across two records
// under one key ends the second, which is legal.
static int handle_post_handshake(ch_tls *t, const uint8_t *pt, size_t n, size_t *used,
                                 uint8_t *alert) {
    size_t off = 0;
    while (n - off >= 4) {
        uint8_t type = pt[off];
        size_t msg_len = ((size_t)pt[off + 1] << 16) | ((size_t)pt[off + 2] << 8) | pt[off + 3];
        if (msg_len > 0x4000 || 4 + msg_len > t->cfg.buf_len) {
            return CH_EPROTO; // could never fit; not a fragment worth waiting for
        }
        if (off + 4 + msg_len > n) {
            break; // partial message, reassembled by the caller
        }
        const uint8_t *body = pt + off + 4;
        int rc = CH_EPROTO; // any other message type
        if (type == HS_NEW_SESSION_TICKET) {
            rc = take_ticket(t, body, msg_len, alert);
        } else if (type == HS_KEY_UPDATE) {
            rc = take_key_update(t, body, msg_len, off + 4 + msg_len == n, alert);
        }
        if (rc != CH_OK) {
            return rc;
        }
        off += 4 + msg_len;
    }
    *used = off;
    return CH_OK;
}

// Opens, in place, the record io_read_record wrote at cfg.buf + fill, of
// record_len bytes with outer type outer, and writes the length of the
// handshake bytes it carries to *n. It is the next fragment of a split
// message, so RFC 9846 §5.1 lets it be nothing else
// (rfc9846.txt:3460-3462): a record that does not open is bad_record_mac,
// an alert record goes to hsr_refuse_alert, which records the peer's
// fatal alert, and any other type keeps the unexpected_message the caller
// set.
static int open_fragment(ch_tls *t, size_t fill, uint8_t outer, size_t record_len, size_t *n,
                         uint8_t *alert) {
    uint8_t *at = t->cfg.buf + fill;
    uint8_t inner_type = 0;
    if (outer != REC_APPDATA ||
        rec_open(&t->rd, at, record_len, at, t->cfg.buf_len - fill, n, &inner_type) != 0) {
        *alert = ALERT_BAD_RECORD_MAC;
        return CH_EAUTH;
    }
    if (inner_type == REC_ALERT) {
        return hsr_refuse_alert(t, at, *n, alert);
    }
    return inner_type == REC_HANDSHAKE ? CH_OK : CH_EPROTO;
}

// Drains a post-handshake handshake message run that starts with pt_len
// plaintext bytes in cfg.buf, pulling further records when a message is
// fragmented across them (RFC 9846 §5.1 allows it, and our own
// record_size_limit forces peers with large tickets into it). Fragments
// of one message cannot be interleaved with other record types
// (open_fragment). A failure writes the alert it owes to *alert where it
// owes another than the unexpected_message hspost_read starts with.
static int drain_run(ch_tls *t, size_t pt_len, uint8_t *alert) {
    uint8_t *buf = t->cfg.buf;
    size_t fill = pt_len;
    // Bounded like ch_read's quiet cap: a fragmented message must make
    // byte progress; an endless stream of empty fragments is an attack.
    for (int quiet = 0; quiet < CH_QUIET_CAP;) {
        size_t used = 0;
        int rc = handle_post_handshake(t, buf, fill, &used, alert);
        if (rc != CH_OK) {
            return rc;
        }
        if (used == fill) {
            return CH_OK;
        }
        memmove(buf, buf + used, fill - used);
        fill -= used;
        uint8_t outer = 0;
        size_t record_len = 0;
        rc = io_read_record(&t->cfg, buf + fill, t->cfg.buf_len - fill, &outer, &record_len);
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
        if (rc == CH_RECORD_AGAIN) {
            // The next fragment has not arrived. The fill bytes stay at
            // the front of cfg.buf, and the next ch_read continues from
            // them (session.h, post_fill).
            t->post_fill = fill;
            return rc;
        }
#endif
        if (rc != CH_OK) {
            return rc;
        }
        size_t n = 0;
        rc = open_fragment(t, fill, outer, record_len, &n, alert);
        if (rc != CH_OK) {
            return rc;
        }
        if (n == 0) {
            quiet++;
        }
        fill += n;
    }
    return CH_EPROTO;
}

int hspost_read(ch_tls *t, size_t pt_len) {
    uint8_t alert = ALERT_UNEXPECTED_MESSAGE;
    int rc = drain_run(t, pt_len, &alert);
    if (rc != CH_OK && rc != CH_RECORD_AGAIN) {
        tlsi_fail(t, alert);
    }
    return rc;
}
#endif // CH_TRANSPORT_QUIC_NONBLOCKING
