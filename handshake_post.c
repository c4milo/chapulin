// NewSessionTicket and KeyUpdate: the post-handshake messages, parsed
// out of decrypted bytes on a live session. See handshake_post.h for
// why they sit apart from the handshake flight and from tls.c.
#include "handshake_post.h"

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "handshake_message.h"
#include "io.h"
#include "keysched.h"
#include "record.h"

// One NewSessionTicket: derive the resumption PSK and hand the ticket to
// the application. Tickets we could never present again — nonce too long
// for a KDF context, identity too big for our ClientHello — are skipped,
// not fatal: a ticket is an optimization.
static void handle_ticket(ch_tls *t, const uint8_t *body, size_t n) {
    rbuf r;
    rb_init(&r, body, n);
    ch_ticket ticket;
    uint32_t hi = rb_u24(&r);                  // u32 fields read as u24+u8 to keep the
    ticket.lifetime_s = (hi << 8) | rb_u8(&r); // reads sequenced
    hi = rb_u24(&r);
    ticket.age_add = (hi << 8) | rb_u8(&r);
    size_t nonce_len = rb_u8(&r);
    const uint8_t *nonce = rb_bytes(&r, nonce_len);
    ticket.identity_len = rb_u16(&r);
    ticket.identity = rb_bytes(&r, ticket.identity_len);
    if (r.err || t->cfg.on_ticket == NULL || nonce_len > SHA256_LEN ||
        ticket.identity_len > CH_TICKET_ID_MAX) {
        return;
    }
    ticket.epoch = t->epoch;
    ks_res_psk(t->res_master, nonce, nonce_len, ticket.psk);
    t->cfg.on_ticket(t->cfg.io, &ticket);
    ct_wipe(ticket.psk, sizeof ticket.psk);
}

// One KeyUpdate: the read direction always rekeys — receivers are
// forbidden from enforcing the peer's epoch cap (RFC 9846 §4.7.3) — and
// a reply goes out only when requested and while our own epoch count is
// under the cap the same section puts on senders.
static int handle_key_update(ch_tls *t, uint8_t request) {
    rec_dir_update(t->rd_secret, &t->rd);
    if (request != 1 || t->send_epochs >= 0xffffffffffffULL) {
        return CH_OK;
    }
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

// Handles the complete post-handshake messages in pt[0..n) — only
// NewSessionTicket and KeyUpdate exist here — and reports through used
// how many bytes were consumed. A trailing partial message is not an
// error; the caller reassembles across records.
static int handle_post_handshake(ch_tls *t, const uint8_t *pt, size_t n, size_t *used) {
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
        if (type == HS_NEW_SESSION_TICKET) {
            handle_ticket(t, body, msg_len);
        } else if (type == HS_KEY_UPDATE && msg_len == 1 && body[0] <= 1) {
            int rc = handle_key_update(t, body[0]);
            if (rc != CH_OK) {
                return rc;
            }
        } else {
            return CH_EPROTO;
        }
        off += 4 + msg_len;
    }
    *used = off;
    return CH_OK;
}

// Drains a post-handshake handshake message run that starts with pt_len
// plaintext bytes in cfg.buf, pulling further records when a message is
// fragmented across them (RFC 9846 §5.1 allows it, and our own
// record_size_limit forces peers with large tickets into it). Fragments
// of one message cannot be interleaved with other record types.
int hspost_read(ch_tls *t, size_t pt_len) {
    uint8_t *buf = t->cfg.buf;
    size_t fill = pt_len;
    // Bounded like ch_read's quiet cap: a fragmented message must make
    // byte progress; an endless stream of empty fragments is an attack.
    for (int quiet = 0; quiet < CH_QUIET_CAP;) {
        size_t used = 0;
        int rc = handle_post_handshake(t, buf, fill, &used);
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
        if (rc != CH_OK) {
            return rc;
        }
        size_t n = 0;
        uint8_t inner_type = 0;
        if (outer != REC_APPDATA || rec_open(&t->rd, buf + fill, record_len, buf + fill,
                                             t->cfg.buf_len - fill, &n, &inner_type) != 0) {
            return CH_EAUTH;
        }
        if (inner_type != REC_HANDSHAKE) {
            return CH_EPROTO;
        }
        if (n == 0) {
            quiet++;
        }
        fill += n;
    }
    return CH_EPROTO;
}
