// buf.h's contract for wb_init and wb_bytes, with the copy as a loop of
// one store per byte. buf.c copies with memcpy, and CBMC's model of a
// memcpy of a symbolic length into ch_tls, an object of several KiB, took
// the write_parts formula past 6 GB in 19 s; this loop takes it to 1.2 GB.
// The writer's lengths and its refusal are buf.c's, and each store is a
// bounds-checked write, so a harness that links this proves each copy
// stays inside its source and its room. The buf harness proves buf.c's
// own memcpy.
#include "buf.h"

void wb_init(wbuf *w, uint8_t *p, size_t cap) {
    w->p = p;
    w->cap = cap;
    w->len = 0;
    w->err = 0;
}

void wb_bytes(wbuf *w, const uint8_t *src, size_t n) {
    if (w->err || n > w->cap - w->len) {
        w->err = 1;
        return;
    }
    for (size_t i = 0; i < n; i++) {
        w->p[w->len + i] = src[i];
    }
    w->len += n;
}
