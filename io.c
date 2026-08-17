#include "io.h"

#include "record.h"

int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    return cfg->send(cfg->io, p, n) == 0 ? CH_OK : CH_EIO;
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

int io_read_record(const ch_cfg *cfg, uint8_t *buf, size_t cap, uint8_t *outer,
                   size_t *record_len) {
    if (cap < REC_HDR) {
        return CH_ECAP;
    }
    int rc = read_exact(cfg, buf, REC_HDR);
    if (rc != CH_OK) {
        return rc;
    }
    size_t body = ((size_t)buf[3] << 8) | buf[4];
    if (body == 0 || body > 0x4000 + 256) {
        return CH_EPROTO;
    }
    if (REC_HDR + body > cap) {
        return CH_ECAP;
    }
    rc = read_exact(cfg, buf + REC_HDR, body);
    if (rc != CH_OK) {
        return rc;
    }
    *outer = buf[0];
    *record_len = REC_HDR + body;
    return CH_OK;
}
