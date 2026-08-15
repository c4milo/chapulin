#include "tls.h"

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "handshake.h"
#include "hsmsg.h"
#include "io.h"
#include "keysched.h"

int ms_connect(ms_tls *t, const ms_cfg *cfg) {
    memset(t, 0, sizeof *t);
    t->cfg = *cfg;
    int psk_ok = cfg->psk != NULL && cfg->psk_len > 0 && cfg->psk_id != NULL;
    int pin_ok = cfg->psk == NULL && cfg->server_pubkey != NULL;
    if ((!psk_ok && !pin_ok) || cfg->buf == NULL || cfg->send == NULL || cfg->recv == NULL ||
        cfg->buf_len < 512) {
        t->state = MS_ST_FAILED;
        return MS_ECAP;
    }
    return ms_handshake(t);
}

// One NewSessionTicket: derive the resumption PSK and hand the ticket to
// the application. Tickets we could never present again — nonce too long
// for a KDF context, identity too big for our ClientHello — are skipped,
// not fatal: a ticket is an optimization.
static void handle_ticket(ms_tls *t, const uint8_t *body, size_t n) {
    rbuf r;
    rb_init(&r, body, n);
    ms_ticket tk;
    uint32_t hi = rb_u24(&r);              // u32 fields read as u24+u8 to keep the
    tk.lifetime_s = (hi << 8) | rb_u8(&r); // reads sequenced
    hi = rb_u24(&r);
    tk.age_add = (hi << 8) | rb_u8(&r);
    size_t noncelen = rb_u8(&r);
    const uint8_t *nonce = rb_bytes(&r, noncelen);
    tk.identity_len = rb_u16(&r);
    tk.identity = rb_bytes(&r, tk.identity_len);
    if (r.err || t->cfg.on_ticket == NULL || noncelen > SHA256_LEN ||
        tk.identity_len > MS_TICKET_ID_MAX) {
        return;
    }
    ks_res_psk(t->res_master, nonce, noncelen, tk.psk);
    t->cfg.on_ticket(t->cfg.io, &tk);
    ct_wipe(tk.psk, sizeof tk.psk);
}

// Handles the complete post-handshake messages in pt[0..n) — only
// NewSessionTicket and KeyUpdate exist here — and reports through used
// how many bytes were consumed. A trailing partial message is not an
// error; the caller reassembles across records.
static int handle_post_hs(ms_tls *t, const uint8_t *pt, size_t n, size_t *used) {
    size_t off = 0;
    while (n - off >= 4) {
        uint8_t type = pt[off];
        size_t mlen = ((size_t)pt[off + 1] << 16) | ((size_t)pt[off + 2] << 8) | pt[off + 3];
        if (mlen > 0x4000 || 4 + mlen > t->cfg.buf_len) {
            return MS_EPROTO; // could never fit; not a fragment worth waiting for
        }
        if (off + 4 + mlen > n) {
            break; // partial message, reassembled by the caller
        }
        const uint8_t *body = pt + off + 4;
        if (type == HS_NEW_SESSION_TICKET) {
            handle_ticket(t, body, mlen);
        } else if (type == HS_KEY_UPDATE && mlen == 1 && body[0] <= 1) {
            rec_dir_update(t->rd_secret, &t->rd);
            if (body[0] == 1) {
                uint8_t msg[5] = {HS_KEY_UPDATE, 0, 0, 1, 0};
                size_t outn = 0;
                if (rec_seal(&t->wr, REC_HANDSHAKE, msg, sizeof msg, t->tx, sizeof t->tx, &outn) !=
                        0 ||
                    io_send_all(&t->cfg, t->tx, outn) != MS_OK) {
                    return MS_EIO;
                }
                rec_dir_update(t->wr_secret, &t->wr);
            }
        } else {
            return MS_EPROTO;
        }
        off += 4 + mlen;
    }
    *used = off;
    return MS_OK;
}

// Drains a post-handshake handshake message run that starts with ptn
// plaintext bytes in cfg.buf, pulling further records when a message is
// fragmented across them (RFC 8446 §5.1 allows it, and our own
// record_size_limit forces peers with large tickets into it). Fragments
// of one message cannot be interleaved with other record types.
static int pump_post_hs(ms_tls *t, size_t ptn) {
    uint8_t *buf = t->cfg.buf;
    size_t fill = ptn;
    // Bounded like ms_read's quiet cap: a fragmented message must make
    // byte progress; an endless stream of empty fragments is an attack.
    for (int quiet = 0; quiet < 32;) {
        size_t used = 0;
        int rc = handle_post_hs(t, buf, fill, &used);
        if (rc != MS_OK) {
            return rc;
        }
        if (used == fill) {
            return MS_OK;
        }
        memmove(buf, buf + used, fill - used);
        fill -= used;
        uint8_t outer = 0;
        size_t reclen = 0;
        rc = io_read_record(&t->cfg, buf + fill, t->cfg.buf_len - fill, &outer, &reclen);
        if (rc != MS_OK) {
            return rc;
        }
        size_t n = 0;
        uint8_t itype = 0;
        if (outer != REC_APPDATA || rec_open(&t->rd, buf + fill, reclen, buf + fill,
                                             t->cfg.buf_len - fill, &n, &itype) != 0) {
            return MS_EAUTH;
        }
        if (itype != REC_HANDSHAKE) {
            return MS_EPROTO;
        }
        if (n == 0) {
            quiet++;
        }
        fill += n;
    }
    return MS_EPROTO;
}

// Reads and dispatches one record: application data lands in the buffer,
// post-handshake messages are handled, close_notify returns MS_ECLOSED.
static int pump_once(ms_tls *t) {
    uint8_t outer = 0;
    size_t reclen = 0;
    int rc = io_read_record(&t->cfg, t->cfg.buf, t->cfg.buf_len, &outer, &reclen);
    if (rc != MS_OK) {
        tlsi_fail(t, ALERT_DECODE_ERROR);
        return rc;
    }
    if (outer != REC_APPDATA) {
        tlsi_fail(t, ALERT_UNEXPECTED_MESSAGE);
        return MS_EPROTO;
    }
    size_t ptn = 0;
    uint8_t itype = 0;
    if (rec_open(&t->rd, t->cfg.buf, reclen, t->cfg.buf, t->cfg.buf_len, &ptn, &itype) != 0) {
        tlsi_fail(t, ALERT_BAD_RECORD_MAC);
        return MS_EAUTH;
    }
    if (itype == REC_APPDATA) {
        t->pt_off = 0;
        t->pt_len = ptn;
        return MS_OK;
    }
    if (itype == REC_HANDSHAKE) {
        rc = pump_post_hs(t, ptn);
        if (rc != MS_OK) {
            tlsi_fail(t, rc == MS_EAUTH ? ALERT_BAD_RECORD_MAC : ALERT_UNEXPECTED_MESSAGE);
        }
        return rc;
    }
    if (itype == REC_ALERT && ptn == 2 && t->cfg.buf[1] == ALERT_CLOSE_NOTIFY) {
        t->state = MS_ST_CLOSED;
        ms_close(t);
        return MS_ECLOSED;
    }
    tlsi_fail(t, ALERT_UNEXPECTED_MESSAGE);
    return MS_EPROTO;
}

int ms_read(ms_tls *t, uint8_t *p, size_t n) {
    if (n == 0) {
        return MS_ECAP; // 0 is the close sentinel; a zero-byte read is a caller bug
    }
    if (t->state == MS_ST_CLOSED) {
        return 0;
    }
    if (t->state != MS_ST_CONNECTED) {
        return MS_EPROTO;
    }
    // A peer may legally send records that yield no application data
    // (tickets, key updates, empty records), but not an endless stream of
    // them; the cap turns that into a protocol error instead of a spin.
    for (int quiet = 0; quiet < 32; quiet++) {
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
        if (rc == MS_ECLOSED) {
            return 0;
        }
        if (rc != MS_OK) {
            return rc;
        }
    }
    tlsi_fail(t, ALERT_UNEXPECTED_MESSAGE);
    return MS_EPROTO;
}

int ms_write(ms_tls *t, const uint8_t *p, size_t n) {
    if (t->state != MS_ST_CONNECTED) {
        return MS_EPROTO;
    }
    size_t lim = t->peer_limit < MS_TX_PT ? t->peer_limit : MS_TX_PT;
    while (n > 0) {
        size_t take = n < lim ? n : lim;
        size_t outn = 0;
        if (rec_seal(&t->wr, REC_APPDATA, p, take, t->tx, sizeof t->tx, &outn) != 0) {
            tlsi_fail(t, ALERT_INTERNAL_ERROR);
            return MS_ECAP;
        }
        int rc = io_send_all(&t->cfg, t->tx, outn);
        if (rc != MS_OK) {
            tlsi_fail(t, ALERT_INTERNAL_ERROR);
            return rc;
        }
        p += take;
        n -= take;
    }
    return MS_OK;
}

void ms_close(ms_tls *t) {
    if (t->keys) {
        (void)tlsi_send_alert(t, 1, ALERT_CLOSE_NOTIFY);
    }
    tlsi_wipe(t);
    t->state = MS_ST_CLOSED;
}
