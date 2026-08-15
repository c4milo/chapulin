#include "tls.h"

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "handshake.h"
#include "hsmsg.h"
#include "io.h"
#include "keysched.h"

int tlsi_send_alert(ms_tls *t, uint8_t level, uint8_t desc) {
    uint8_t body[2] = {level, desc};
    if (t->state == MS_ST_CONNECTED || t->state == MS_ST_CLOSED) {
        size_t n = 0;
        if (rec_seal(&t->wr, REC_ALERT, body, 2, t->tx, sizeof t->tx, &n) != 0) {
            return MS_ECAP;
        }
        return io_send_all(&t->cfg, t->tx, n);
    }
    uint8_t rec[REC_HDR + 2] = {REC_ALERT, 0x03, 0x03, 0, 2, level, desc};
    return io_send_all(&t->cfg, rec, sizeof rec);
}

void tlsi_fail(ms_tls *t, uint8_t desc) {
    (void)tlsi_send_alert(t, 2, desc);
    ct_wipe(&t->rd, sizeof t->rd);
    ct_wipe(&t->wr, sizeof t->wr);
    ct_wipe(t->rd_secret, sizeof t->rd_secret);
    ct_wipe(t->wr_secret, sizeof t->wr_secret);
    ct_wipe(t->res_master, sizeof t->res_master);
    t->pt_off = 0;
    t->pt_len = 0;
    t->state = MS_ST_FAILED;
}

int ms_connect(ms_tls *t, const ms_cfg *cfg) {
    memset(t, 0, sizeof *t);
    t->cfg = *cfg;
    if (cfg->psk == NULL || cfg->psk_len == 0 || cfg->psk_id == NULL || cfg->buf == NULL ||
        cfg->send == NULL || cfg->recv == NULL || cfg->buf_len < 512) {
        t->state = MS_ST_FAILED;
        return MS_ECAP;
    }
    return ms_handshake(t);
}

// One NewSessionTicket: derive the resumption PSK and hand the ticket to
// the application. A nonce too long to be a KDF context is skipped, not
// fatal — the ticket is an optimization.
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
    if (r.err || t->cfg.on_ticket == NULL || noncelen > SHA256_LEN) {
        return;
    }
    ks_res_psk(t->res_master, nonce, noncelen, tk.psk);
    t->cfg.on_ticket(t->cfg.io, &tk);
    ct_wipe(tk.psk, sizeof tk.psk);
}

// Post-handshake handshake messages: NewSessionTicket and KeyUpdate.
static int handle_post_hs(ms_tls *t, const uint8_t *pt, size_t n) {
    rbuf r;
    rb_init(&r, pt, n);
    while (rb_left(&r) > 0) {
        uint8_t type = rb_u8(&r);
        size_t mlen = rb_u24(&r);
        const uint8_t *body = rb_bytes(&r, mlen);
        if (body == NULL) {
            return MS_EPROTO;
        }
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
    }
    return MS_OK;
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
        rc = handle_post_hs(t, t->cfg.buf, ptn);
        if (rc != MS_OK) {
            tlsi_fail(t, ALERT_UNEXPECTED_MESSAGE);
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
    if (t->state == MS_ST_CLOSED) {
        return 0;
    }
    if (t->state != MS_ST_CONNECTED) {
        return MS_EPROTO;
    }
    for (;;) {
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
    if (t->state == MS_ST_CONNECTED || t->state == MS_ST_CLOSED) {
        (void)tlsi_send_alert(t, 1, ALERT_CLOSE_NOTIFY);
    }
    ct_wipe(&t->rd, sizeof t->rd);
    ct_wipe(&t->wr, sizeof t->wr);
    ct_wipe(t->rd_secret, sizeof t->rd_secret);
    ct_wipe(t->wr_secret, sizeof t->wr_secret);
    ct_wipe(t->res_master, sizeof t->res_master);
    t->state = MS_ST_CLOSED;
    t->pt_off = 0;
    t->pt_len = 0;
}
