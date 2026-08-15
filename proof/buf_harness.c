// Proves: any sequence of 12 reader/writer operations with any arguments
// on any buffer up to 64 bytes is memory-safe and UB-free, and the sticky
// error keeps len within cap and off within len at every step. This is
// the module every wire byte crosses, so it gets the op-sequence
// treatment rather than one fixed call pattern.
#include "harness.h"

#include "buf.c"

int main(void) {
    uint8_t wmem[64];
    wbuf w;
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof wmem);
    wb_init(&w, wmem, cap);
    uint8_t rmem[64];
    fill_nondet(rmem, sizeof rmem);
    rbuf r;
    size_t rlen = nondet_size_t();
    __CPROVER_assume(rlen <= sizeof rmem);
    rb_init(&r, rmem, rlen);

    uint8_t src[16];
    fill_nondet(src, sizeof src);
    size_t mark = 0;
    for (int step = 0; step < 12; step++) {
        switch (nondet_u8() % 8) {
        case 0:
            wb_u8(&w, nondet_u8());
            break;
        case 1:
            wb_u16(&w, (uint16_t)nondet_size_t());
            break;
        case 2:
            wb_u24(&w, (uint32_t)nondet_size_t());
            break;
        case 3: {
            size_t n = nondet_size_t();
            __CPROVER_assume(n <= sizeof src);
            wb_bytes(&w, src, n);
            break;
        }
        case 4:
            mark = wb_mark(&w, 2);
            break;
        case 5:
            // patch is only legal after its mark, like real callers do
            if (!w.err && mark + 2 <= w.len) {
                wb_patch16(&w, mark);
            }
            break;
        case 6:
            (void)rb_u8(&r);
            (void)rb_u16(&r);
            (void)rb_u24(&r);
            break;
        default: {
            size_t n = nondet_size_t();
            __CPROVER_assume(n <= 96); // deliberately past rlen sometimes
            (void)rb_bytes(&r, n);
            break;
        }
        }
        __CPROVER_assert(w.len <= w.cap, "writer len within cap");
        __CPROVER_assert(r.off <= r.len, "reader off within len");
    }
    return 0;
}
