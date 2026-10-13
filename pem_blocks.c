// A run of CERTIFICATE blocks and the text around them. Contract in
// pem_blocks.h; each block's own grammar in pem.c.
#include "pem_blocks.h"

#include "buf.h"
#include "ch_assert.h"
#include "pem.h"

// What the text before a block leaves at the reader.
#define NEXT_BLOCK 1   // a block opens at the reader's position
#define NEXT_END 0     // the input ended where the rule lets it
#define NEXT_REFUSED 2 // the text broke the rule

uint8_t pem_skip_line_breaks(rbuf *r) {
    CH_ASSERT(r != NULL);
    // A copy of the reader counts the bytes, so the first other byte
    // stays unread, and then the reader skips them.
    rbuf scan = *r;
    size_t gap = 0;
    uint8_t last = 0;
    while (rb_left(&scan) != 0) {
        uint8_t c = rb_u8(&scan);
        if (c != '\r' && c != '\n') {
            break;
        }
        last = c;
        gap++;
    }
    rb_skip(r, gap);
    return last;
}

// PEM_TEXT_REFUSED's text. Before the first block there is none: the
// block opens at the first byte, and pem_read_block judges that byte.
// After a block, CR and LF bytes. Before a next block the last of them
// is LF, so the BEGIN line starts a line.
static int next_strict(rbuf *r, uint8_t started) {
    if (!started) {
        return NEXT_BLOCK;
    }
    uint8_t last = pem_skip_line_breaks(r);
    if (rb_left(r) == 0) {
        return NEXT_END;
    }
    return last == '\n' ? NEXT_BLOCK : NEXT_REFUSED;
}

// The end of an END line's line: the input ends there, or LF or CR LF
// follows. A lone CR ends no line, as in pem.c.
static int line_ends(rbuf *r) {
    if (rb_left(r) == 0) {
        return 1;
    }
    uint8_t c = rb_u8(r);
    if (c == '\r') {
        c = rb_u8(r);
    }
    return !r->err && c == '\n';
}

// PEM_TEXT_SKIPPED's text. After a block, the END line ends its line.
// Then the loop reads the text a byte at a time, and stops at the first
// "-----BEGIN ". line_start says the reader stands at the start of a
// line, the one place a block may open. There the caller reads a block,
// and pem_read_block refuses every BEGIN line but CERTIFICATE's. At any
// other byte "-----BEGIN " refuses the file. So no BEGIN line, of any
// label and behind any byte, is skipped with the text around it. One loop
// runs over the bytes, with no inner loop over a line's bytes, so a
// harness unwinds it once per byte (proof/pem_blocks_harness.c).
static int next_skipping(rbuf *r, uint8_t started) {
    if (started && !line_ends(r)) {
        return NEXT_REFUSED;
    }
    int line_start = 1;
    while (rb_left(r) != 0) {
        if (pem_begins_boundary(r)) {
            return line_start ? NEXT_BLOCK : NEXT_REFUSED;
        }
        line_start = rb_u8(r) == '\n';
    }
    return NEXT_END;
}

void pem_blocks_init(pem_blocks *b, const uint8_t *pem, size_t pem_len, uint8_t rule) {
    CH_ASSERT(b != NULL);
    CH_ASSERT(pem != NULL || pem_len == 0);
    CH_ASSERT(rule == PEM_TEXT_REFUSED || rule == PEM_TEXT_SKIPPED);
    rb_init(&b->text, pem, pem_len);
    b->rule = rule;
    b->started = 0;
}

int pem_blocks_next(pem_blocks *b, wbuf *der, const uint8_t **block, size_t *block_len) {
    CH_ASSERT(b != NULL && der != NULL && block != NULL && block_len != NULL);
    int next = b->rule == PEM_TEXT_SKIPPED ? next_skipping(&b->text, b->started)
                                           : next_strict(&b->text, b->started);
    if (next == NEXT_END) {
        return PEM_BLOCKS_END;
    }
    if (next == NEXT_REFUSED) {
        return PEM_BLOCKS_REFUSED;
    }
    size_t before = der->len;
    if (!pem_read_block(&b->text, PEM_LABEL_CERTIFICATE, der)) {
        return PEM_BLOCKS_REFUSED;
    }
    b->started = 1;
    // The block's DER is what der gained, read back through a reader of
    // the bytes der holds.
    rbuf written;
    rb_init(&written, der->p, der->len);
    rb_skip(&written, before);
    *block_len = rb_left(&written);
    *block = rb_bytes(&written, *block_len);
    return PEM_BLOCKS_READ;
}
