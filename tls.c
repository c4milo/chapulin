#include "tls.h"

#include "ch_assert.h"

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "handshake.h"
#include "hsmsg.h"
#include "io.h"
#include "keysched.h"

// Loads the stored epoch and checks a resuming ticket against it
// (docs/ca.md). Storage that fails or answers out of range stops
// the connection at config time, not mid-handshake, so revocation
// state stays out of any path a peer can influence. Returns CH_OK
// when no epoch is configured.
static int epoch_init(ch_tls *t, const ch_cfg *cfg, int psk_ok) {
#ifdef CH_TRUST_CA
    // The callbacks come as a pair; one alone is a provisioning
    // mistake, and store is the only way to write the epoch back.
    if ((cfg->epoch_load == NULL) != (cfg->epoch_store == NULL)) {
        return CH_EINVAL;
    }
    if (cfg->epoch_load == NULL) {
        return CH_OK;
    }
    uint32_t stored = 0;
    if (cfg->epoch_load(cfg->epoch_io, &stored) != 0 || stored > CH_EPOCH_MAX) {
        return CH_EINVAL;
    }
    t->epoch = stored;
    // A resumed session presents no certificate, so the ticket's epoch
    // is the only revocation check left: a ticket below the stored
    // epoch was retired by that bump. A ticket epoch over CH_EPOCH_MAX
    // is corrupt ticket storage, so it returns CH_EINVAL, not CH_EAUTH.
    if (!psk_ok || !cfg->resumption) {
        return CH_OK;
    }
    if (cfg->ticket_epoch > CH_EPOCH_MAX) {
        return CH_EINVAL;
    }
    t->epoch_seen = cfg->ticket_epoch;
    if (cfg->ticket_epoch < stored) {
        t->epoch_status = CH_EPOCH_REVOKED;
        return CH_EAUTH;
    }
    // A ticket above the stored epoch means the store lost a bump that
    // an earlier session wrote. The device would again trust the
    // certificates that bump retired. Reported as CH_EPOCH_AHEAD.
    t->epoch_status = cfg->ticket_epoch > stored ? CH_EPOCH_AHEAD : CH_EPOCH_MATCHED;
    return CH_OK;
#else
    // No CA mode here, so nothing enforces an epoch. Reject such a
    // config: unenforced revocation is worse than a failed connect.
    (void)t;
    (void)psk_ok;
    return (cfg->epoch_load != NULL || cfg->epoch_store != NULL) ? CH_EINVAL : CH_OK;
#endif
}

int ch_connect(ch_tls *t, const ch_cfg *cfg) {
    memset(t, 0, sizeof *t);
    t->cfg = *cfg;
    // Exactly one auth mode: a config carrying both a PSK and a pin is a
    // provisioning mistake and gets rejected, not silently resolved. The
    // pin length must match the build's one algorithm — 64 raw P-256
    // bytes under CH_PIN_ECDSA, an RSA-2048..3072 modulus otherwise.
    int psk_ok =
        cfg->psk != NULL && cfg->psk_len > 0 && cfg->psk_id != NULL && cfg->server_pubkey == NULL;
#ifdef CH_PIN_ECDSA
    int pin_len_ok = cfg->server_pubkey_len == 64;
#else
    int pin_len_ok = cfg->server_pubkey_len >= 256 && cfg->server_pubkey_len <= 384 &&
                     cfg->server_pubkey_len % 8 == 0;
#endif
    int pin_ok = cfg->psk == NULL && cfg->server_pubkey != NULL && pin_len_ok;
    // The optional second pin (key rotation) obeys every slot-A rule and
    // never stands alone: pinned mode still requires server_pubkey.
#ifdef CH_PIN_ECDSA
    int pin2_len_ok = cfg->server_pubkey2_len == 64;
#else
    int pin2_len_ok = cfg->server_pubkey2_len >= 256 && cfg->server_pubkey2_len <= 384 &&
                      cfg->server_pubkey2_len % 8 == 0;
#endif
    if (cfg->server_pubkey2 != NULL && (!pin_ok || !pin2_len_ok)) {
        t->state = CH_ST_FAILED;
        return CH_EINVAL;
    }
    if ((!psk_ok && !pin_ok) || cfg->buf == NULL || cfg->send == NULL || cfg->recv == NULL ||
        cfg->buf_len < CH_MIN_RXBUF) {
        t->state = CH_ST_FAILED;
        return CH_EINVAL;
    }
#ifndef CH_PIN_ECDSA
    // Every real modulus is odd (a product of odd primes); an even pin in
    // either slot is provisioning corruption. Rejected here so the failure
    // points at the config — inside the handshake it would surface as
    // CH_EAUTH and read like an attack.
    if ((pin_ok && (cfg->server_pubkey[cfg->server_pubkey_len - 1] & 1) == 0) ||
        (cfg->server_pubkey2 != NULL &&
         (cfg->server_pubkey2[cfg->server_pubkey2_len - 1] & 1) == 0)) {
        t->state = CH_ST_FAILED;
        return CH_EINVAL;
    }
#endif
    int rc = epoch_init(t, cfg, psk_ok);
    if (rc != CH_OK) {
        t->state = CH_ST_FAILED;
        return rc;
    }
    return ch_handshake(t);
}

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
static int pump_post_handshake(ch_tls *t, size_t pt_len) {
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

// Reads and dispatches one record: application data lands in the buffer,
// post-handshake messages are handled, close_notify returns CH_ECLOSED.
static int pump_once(ch_tls *t) {
    uint8_t outer = 0;
    size_t record_len = 0;
    int rc = io_read_record(&t->cfg, t->cfg.buf, t->cfg.buf_len, &outer, &record_len);
    if (rc != CH_OK) {
        tlsi_fail(t, ALERT_DECODE_ERROR);
        return rc;
    }
    if (outer != REC_APPDATA) {
        tlsi_fail(t, ALERT_UNEXPECTED_MESSAGE);
        return CH_EPROTO;
    }
    size_t pt_len = 0;
    uint8_t inner_type = 0;
    if (rec_open(&t->rd, t->cfg.buf, record_len, t->cfg.buf, t->cfg.buf_len, &pt_len,
                 &inner_type) != 0) {
        tlsi_fail(t, ALERT_BAD_RECORD_MAC);
        return CH_EAUTH;
    }
    if (inner_type == REC_APPDATA) {
        t->pt_off = 0;
        t->pt_len = pt_len;
        return CH_OK;
    }
    if (inner_type == REC_HANDSHAKE) {
        rc = pump_post_handshake(t, pt_len);
        if (rc != CH_OK) {
            tlsi_fail(t, rc == CH_EAUTH ? ALERT_BAD_RECORD_MAC : ALERT_UNEXPECTED_MESSAGE);
        }
        return rc;
    }
    if (inner_type == REC_ALERT && pt_len == 2 && t->cfg.buf[1] == ALERT_CLOSE_NOTIFY) {
        t->state = CH_ST_CLOSED;
        ch_close(t);
        return CH_ECLOSED;
    }
    if (inner_type == REC_ALERT && pt_len == 2 && t->cfg.buf[1] == ALERT_USER_CANCELED) {
        // RFC 9846 §6.1: user_canceled precedes a close_notify; keep
        // reading for it. ch_read's quiet cap bounds a hostile stream of
        // these like any other dataless record.
        return CH_OK;
    }
    tlsi_fail(t, ALERT_UNEXPECTED_MESSAGE);
    return CH_EPROTO;
}

int ch_read(ch_tls *t, uint8_t *p, size_t n) {
    // Contract-point guard: no input can set an undefined state; only
    // programmer error or corrupted memory can. TigerStyle-class
    // defense priced at zero per-byte cost (docs/decisions.md).
    CH_ASSERT(t->state <= CH_ST_FAILED);

    if (n == 0) {
        return CH_EINVAL; // 0 is the close sentinel; a zero-byte read is a caller bug
    }
    if (t->state == CH_ST_CLOSED) {
        return 0;
    }
    if (t->state != CH_ST_CONNECTED) {
        return CH_EPROTO;
    }
    // A peer may legally send records that yield no application data
    // (tickets, key updates, empty records), but not an endless stream of
    // them; the cap turns that into a protocol error instead of a spin.
    for (int quiet = 0; quiet < CH_QUIET_CAP; quiet++) {
        if (t->pt_len > t->pt_off) {
            size_t take = t->pt_len - t->pt_off;
            if (take > n) {
                take = n;
            }
            memcpy(p, t->cfg.buf + t->pt_off, take);
            t->pt_off += take;
            return (int)take;
        }
        int rc = pump_once(t);
        if (rc == CH_ECLOSED) {
            return 0;
        }
        if (rc != CH_OK) {
            return rc;
        }
    }
    tlsi_fail(t, ALERT_UNEXPECTED_MESSAGE);
    return CH_EPROTO;
}

int ch_write(ch_tls *t, const uint8_t *p, size_t n) {
    // Contract-point guard: no input can set an undefined state; only
    // programmer error or corrupted memory can. TigerStyle-class
    // defense priced at zero per-byte cost (docs/decisions.md).
    CH_ASSERT(t->state <= CH_ST_FAILED);

    if (t->state != CH_ST_CONNECTED) {
        return CH_EPROTO;
    }
    size_t limit = t->peer_limit < CH_TX_PT ? t->peer_limit : CH_TX_PT;
    while (n > 0) {
        size_t take = n < limit ? n : limit;
        size_t out_len = 0;
        if (rec_seal(&t->wr, REC_APPDATA, p, take, t->tx, sizeof t->tx, &out_len) != 0) {
            tlsi_fail(t, ALERT_INTERNAL_ERROR);
            return CH_ECAP;
        }
        int rc = io_send_all(&t->cfg, t->tx, out_len);
        if (rc != CH_OK) {
            tlsi_fail(t, ALERT_INTERNAL_ERROR);
            return rc;
        }
        p += take;
        n -= take;
    }
    return CH_OK;
}

void ch_close(ch_tls *t) {
    // Contract-point guard: no input can set an undefined state; only
    // programmer error or corrupted memory can. TigerStyle-class
    // defense priced at zero per-byte cost (docs/decisions.md).
    CH_ASSERT(t->state <= CH_ST_FAILED);

    if (t->keys) {
        (void)tlsi_send_alert(t, 1, ALERT_CLOSE_NOTIFY);
    }
    tlsi_wipe(t);
    t->state = CH_ST_CLOSED;
}
