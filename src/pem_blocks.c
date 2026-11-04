// A run of blocks and the text around them. Contract in pem_blocks.h;
// each block's own grammar in pem.c.
#include "pem_blocks.h"

#include "buf.h"
#include "ch_assert.h"
#include "pem.h"

// What the text before a block leaves at the reader.
#define NEXT_BLOCK 1   // a block opens at the reader's position
#define NEXT_END 0     // the input ended where the rule lets it
#define NEXT_REFUSED 2 // the text broke the rule

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

// The text before a block. After a block, the END line ends its line.
// Then the loop reads the text a byte at a time, and stops at the first
// "-----BEGIN ". line_start says the reader stands at the start of a
// line, the one place a block may open. There the caller reads a block,
// and pem_read_block refuses every BEGIN line but its label's. At any
// other byte "-----BEGIN " refuses the file. So no BEGIN line, of any
// label and behind any byte, is skipped with the text around it. One loop
// runs over the bytes, with no inner loop over a line's bytes, so a
// harness unwinds it once per byte (proof/pem_blocks_harness.c).
static int next_text(rbuf *r, uint8_t started) {
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

void pem_blocks_init(pem_blocks *b, const uint8_t *pem, size_t pem_len) {
    CH_ASSERT(b != NULL);
    CH_ASSERT(pem != NULL || pem_len == 0);
    rb_init(&b->text, pem, pem_len);
    b->started = 0;
}

int pem_blocks_next(pem_blocks *b, uint8_t label, wbuf *der, const uint8_t **block,
                    size_t *block_len) {
    CH_ASSERT(b != NULL && der != NULL && block != NULL && block_len != NULL);
    int next = next_text(&b->text, b->started);
    if (next == NEXT_END) {
        return PEM_BLOCKS_END;
    }
    if (next == NEXT_REFUSED) {
        return PEM_BLOCKS_REFUSED;
    }
    size_t before = der->len;
    if (!pem_read_block(&b->text, label, der)) {
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
