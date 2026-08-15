#include "io.h"

int io_send_all(const ms_cfg *cfg, const uint8_t *p, size_t n) {
    return cfg->send(cfg->io, p, n) == 0 ? MS_OK : MS_EIO;
}

static int read_exact(const ms_cfg *cfg, uint8_t *p, size_t n) {
    while (n > 0) {
        int got = cfg->recv(cfg->io, p, n);
        if (got <= 0 || (size_t)got > n) {
            return MS_EIO;
        }
        p += got;
        n -= (size_t)got;
    }
    return MS_OK;
}

int io_read_record(const ms_cfg *cfg, uint8_t *buf, size_t cap, uint8_t *outer, size_t *reclen) {
    if (cap < REC_HDR) {
        return MS_ECAP;
    }
    int rc = read_exact(cfg, buf, REC_HDR);
    if (rc != MS_OK) {
        return rc;
    }
    size_t body = ((size_t)buf[3] << 8) | buf[4];
    if (body == 0 || body > 0x4000 + 256) {
        return MS_EPROTO;
    }
    if (REC_HDR + body > cap) {
        return MS_ECAP;
    }
    rc = read_exact(cfg, buf + REC_HDR, body);
    if (rc != MS_OK) {
        return rc;
    }
    *outer = buf[0];
    *reclen = REC_HDR + body;
    return MS_OK;
}
