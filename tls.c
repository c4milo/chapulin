#include "tls.h"

#include "ch_assert.h"

#include <string.h>

#include "handshake.h"
#include "handshake_message.h"
#include "handshake_post.h"
#include "io.h"

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

// Reads and dispatches one record: application data lands in the buffer,
// post-handshake messages are handled, close_notify returns CH_ECLOSED.
static int dispatch_one_record(ch_tls *t) {
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
        rc = hspost_read(t, pt_len);
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
        int rc = dispatch_one_record(t);
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
