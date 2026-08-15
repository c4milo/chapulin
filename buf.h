// Bounds-checked byte reader and writer. Every wire byte in matasapos
// moves through these two; no raw buffer arithmetic exists outside them.
// Errors are sticky: after the first overrun every later call is a no-op
// and the final err check catches the lot, so parse/build code stays
// straight-line. Multi-byte integers are big-endian on the wire (TLS) and
// always move byte-by-byte — host endianness never leaks.
#ifndef MS_BUF_H
#define MS_BUF_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *p;
    size_t cap;
    size_t len;
    int err;
} wbuf;

void wb_init(wbuf *w, uint8_t *p, size_t cap);
void wb_u8(wbuf *w, uint8_t v);
void wb_u16(wbuf *w, uint16_t v);
void wb_u24(wbuf *w, uint32_t v);
void wb_bytes(wbuf *w, const uint8_t *src, size_t n);
// Reserves n bytes for a length field to be patched later; returns its
// offset (meaningless once w->err is set).
size_t wb_mark(wbuf *w, size_t n);
// Patches the u16/u24 at off with (current length - off - field size),
// i.e. the byte count written since the mark.
void wb_patch16(wbuf *w, size_t off);
void wb_patch24(wbuf *w, size_t off);

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
    int err;
} rbuf;

void rb_init(rbuf *r, const uint8_t *p, size_t len);
uint8_t rb_u8(rbuf *r);
uint16_t rb_u16(rbuf *r);
uint32_t rb_u24(rbuf *r);
// Returns a pointer into the underlying buffer and advances, or NULL on
// underrun (err set).
const uint8_t *rb_bytes(rbuf *r, size_t n);
void rb_skip(rbuf *r, size_t n);
size_t rb_left(const rbuf *r);

#endif
