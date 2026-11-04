#include "io.h"

#include "handshake_message.h"
#include "record.h"

// send returns the bytes it moved, 1 to n, so a socket that takes part of
// a record gets the rest in the next call. 0, a negative value and a count
// above n are failures, so a send that moves nothing cannot keep the
// session in this loop (cfg.h).
int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    while (n > 0) {
        int sent = cfg->send(cfg->io, p, n);
        if (sent <= 0 || (size_t)sent > n) {
            return CH_EIO;
        }
        p += sent;
        n -= (size_t)sent;
    }
    return CH_OK;
}

static int read_exact(const ch_cfg *cfg, uint8_t *p, size_t n) {
    while (n > 0) {
        int got = cfg->recv(cfg->io, p, n);
        if (got <= 0 || (size_t)got > n) {
            return CH_EIO;
        }
        p += got;
        n -= (size_t)got;
    }
    return CH_OK;
}

// The length check of the header in buf, against rec_body_max and the
// two buffers io.h names: CH_OK for a body io_read_record reads, or the
// result it returns, with the alert io.h states.
static int check_body(const ch_tls *t, const uint8_t *buf, size_t body, size_t cap,
                      uint8_t *alert) {
    if (body > rec_body_max(buf[0])) {
        *alert = ALERT_RECORD_OVERFLOW;
        return CH_EPROTO;
    }
    if (body == 0) {
        return CH_EPROTO;
    }
    if (REC_HDR + body > t->cfg.buf_len) {
        *alert = t->limit_sent ? ALERT_RECORD_OVERFLOW : ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    if (REC_HDR + body > cap) {
        return CH_ECAP;
    }
    return CH_OK;
}

int io_read_record(const ch_tls *t, uint8_t *buf, size_t cap, uint8_t *outer, size_t *record_len,
                   uint8_t *alert) {
    const ch_cfg *cfg = &t->cfg;
    if (cap < REC_HDR) {
        return CH_ECAP;
    }
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
    // A TRANSPORT=tcp-nonblocking caller owns the socket and hands over whole
    // records, so a recv that returns 0 before a record's first byte says
    // no record has arrived yet (tcp_nonblocking.h). The caller runs ch_read
    // again once one has. A 0 after that first byte breaks the whole-record
    // promise, and read_exact fails it with CH_EIO like any short read.
    int got = cfg->recv(cfg->io, buf, REC_HDR);
    if (got == 0) {
        return CH_RECORD_AGAIN;
    }
    if (got < 0 || (size_t)got > REC_HDR) {
        return CH_EIO;
    }
    int rc = read_exact(cfg, buf + got, REC_HDR - (size_t)got);
#else
    int rc = read_exact(cfg, buf, REC_HDR);
#endif
    if (rc != CH_OK) {
        return rc;
    }
    size_t body = ((size_t)buf[3] << 8) | buf[4];
    rc = check_body(t, buf, body, cap, alert);
    if (rc != CH_OK) {
        return rc;
    }
    rc = read_exact(cfg, buf + REC_HDR, body);
    if (rc != CH_OK) {
        return rc;
    }
    *outer = buf[0];
    *record_len = REC_HDR + body;
    return CH_OK;
}
