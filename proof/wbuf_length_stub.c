// buf.h's contract for wb_init and wb_bytes with the copy left out: the
// writer moves its length as buf.c does, and wb_bytes checks that its
// source is readable and its room writable, but writes no byte. The
// writable_len harnesses count lengths alone, and the copy of up to
// 1,630 symbolic bytes into ch_tls.tx took their formula past the memory
// of its weight. The buf harness proves buf.c's own copy, and
// write_parts_harness.c runs ch_write_parts over a copy of each byte
// (proof/wbuf_byte_stub.c).
#include "harness.h"

#include "buf.h"

void wb_init(wbuf *w, uint8_t *p, size_t cap) {
    w->p = p;
    w->cap = cap;
    w->len = 0;
    w->err = 0;
}

void wb_bytes(wbuf *w, const uint8_t *src, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(src, n), "wb_bytes: the source is readable");
    if (w->err || n > w->cap - w->len) {
        w->err = 1;
        return;
    }
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(w->p + w->len, n), "wb_bytes: the room is writable");
    w->len += n;
}
