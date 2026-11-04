#include "buf.h"

#include <string.h>

void wb_init(wbuf *w, uint8_t *p, size_t cap) {
    w->p = p;
    w->cap = cap;
    w->len = 0;
    w->err = 0;
}

static int wb_room(wbuf *w, size_t n) {
    if (w->err || n > w->cap - w->len) {
        w->err = 1;
        return 0;
    }
    return 1;
}

void wb_u8(wbuf *w, uint8_t v) {
    if (wb_room(w, 1)) {
        w->p[w->len++] = v;
    }
}

void wb_u16(wbuf *w, uint16_t v) {
    wb_u8(w, (uint8_t)(v >> 8));
    wb_u8(w, (uint8_t)v);
}

void wb_u24(wbuf *w, uint32_t v) {
    wb_u8(w, (uint8_t)(v >> 16));
    wb_u8(w, (uint8_t)(v >> 8));
    wb_u8(w, (uint8_t)v);
}

void wb_bytes(wbuf *w, const uint8_t *src, size_t n) {
    if (wb_room(w, n)) {
        memcpy(w->p + w->len, src, n);
        w->len += n;
    }
}

size_t wb_mark(wbuf *w, size_t n) {
    size_t off = w->len;
    if (wb_room(w, n)) {
        memset(w->p + w->len, 0, n);
        w->len += n;
    }
    return off;
}

void wb_patch16(wbuf *w, size_t off) {
    if (w->err) {
        return;
    }
    size_t n = w->len - off - 2;
    w->p[off] = (uint8_t)(n >> 8);
    w->p[off + 1] = (uint8_t)n;
}

void wb_patch24(wbuf *w, size_t off) {
    if (w->err) {
        return;
    }
    size_t n = w->len - off - 3;
    w->p[off] = (uint8_t)(n >> 16);
    w->p[off + 1] = (uint8_t)(n >> 8);
    w->p[off + 2] = (uint8_t)n;
}

void rb_init(rbuf *r, const uint8_t *p, size_t len) {
    r->p = p;
    r->len = len;
    r->off = 0;
    r->err = 0;
}

static int rb_have(rbuf *r, size_t n) {
    if (r->err || n > r->len - r->off) {
        r->err = 1;
        return 0;
    }
    return 1;
}

uint8_t rb_u8(rbuf *r) {
    if (!rb_have(r, 1)) {
        return 0;
    }
    return r->p[r->off++];
}

uint16_t rb_u16(rbuf *r) {
    uint16_t hi = rb_u8(r);
    return (uint16_t)(hi << 8) | rb_u8(r);
}

uint32_t rb_u24(rbuf *r) {
    uint32_t v = rb_u8(r);
    v = (v << 8) | rb_u8(r);
    return (v << 8) | rb_u8(r);
}

const uint8_t *rb_bytes(rbuf *r, size_t n) {
    if (!rb_have(r, n)) {
        return NULL;
    }
    const uint8_t *p = r->p + r->off;
    r->off += n;
    return p;
}

void rb_skip(rbuf *r, size_t n) {
    (void)rb_bytes(r, n);
}

size_t rb_left(const rbuf *r) {
    return r->err ? 0 : r->len - r->off;
}
