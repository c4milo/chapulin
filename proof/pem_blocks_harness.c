// Proves: pem_blocks_init and pem_blocks_next (pem_blocks.c) are
// memory-safe and UB-free under both text rules, for every room and
// every text up to CH_PROOF_BLOCKS_LEN bytes. The driver makes the calls
// a caller makes, until the text ends or a rule breaks. They honour their
// contract:
//
//   - PEM_BLOCKS_READ names the DER this call appended, 1 byte or more.
//     The DER runs from the writer's length before the call to its length
//     after, inside its room, with its sticky error clear;
//   - PEM_BLOCKS_END appends nothing and leaves the reader empty;
//   - every call returns one of the three values.
//
// Under the bundle's rule the calls also keep the rule of 2026-10-13
// (pem_blocks.h). The text scan asks pem_begins_boundary about each byte
// in turn and skips none unasked:
//
//   - the first question is about the text's first byte. That is the
//     input's first byte, or after a block the byte after the LF that
//     ends the END line's line;
//   - each next question is about the byte after the last one;
//   - a call that ends the run asked about each byte to the end, or had
//     no byte to ask about.
//
// The scan stops at the first byte where the answer is 1. pem_read_block
// runs only there, and only at the start of a line. A call that met
// "-----BEGIN " never returns PEM_BLOCKS_END. So no BEGIN line of any
// label is skipped as text. By pem.h's contract, pem_read_block then
// refuses a boundary that is not CERTIFICATE's.
//
// The chain's rule and pem_files.c's key reader call
// pem_skip_line_breaks. The harness proves it over any reader too. It
// returns 0, CR or LF, and leaves the reader at its end or at a byte that
// is neither.
//
// Layered: pem.c's two calls are stubs. They assert their pem.h contracts
// and havoc within what proof/pem_harness.c and pem_step_harness.c prove.
// pem_read_block either fails, or consumes at least the 27 bytes of a
// BEGIN line and appends at least one DER byte through the writer. It may
// set the writer's sticky error. pem_begins_boundary answers either way
// and leaves the reader where it was, a superset of the real answers. So
// the object under proof is the text rules between the blocks and the
// name of each block's DER, with real rbuf and wbuf (buf.c). The rules'
// CR, LF and line tests read the text's bytes unconstrained.
//
// Bounded at CH_PROOF_BLOCKS_LEN. The text rules read one byte at a time,
// the shape whose cost grows fastest with the length. The bound reaches
// every state the rules hold, with the stub's blocks of 27 bytes or more.
// The states are a line start, a gap of CR and LF, and a block read or
// none. 64 bytes hold
// two such blocks and the gaps around them. So a caller makes three calls
// at most, two that read a block and one that ends the run, and the
// driver makes three.
#include "harness.h"

#include "buf.h"
#include "pem.h"
#include "pem_blocks.h"

int nondet_int(void);

#ifndef CH_PROOF_BLOCKS_LEN
#define CH_PROOF_BLOCKS_LEN 64
#endif
// The room the writer may have: any capacity up to this many bytes.
#define PROOF_ROOM 8

// The stub's smallest block: a BEGIN CERTIFICATE line alone.
#define STUB_BEGIN_LEN 27

// The text rule under proof, and what pem_begins_boundary saw in the
// pem_blocks_next call under way: how many bytes it was asked about, the
// offset of the last one, and whether it answered 1.
static uint8_t proof_rule;
static size_t boundary_checks;
static size_t boundary_last_off;
static int boundary_found;
// Whether the stub read a block, and the offset where the last block it
// read left the reader. The driver sets scan_start before each call: the
// offset of the first byte the bundle's scan must ask about.
static int block_read;
static size_t block_end_off;
static size_t scan_start;

int pem_read_block(rbuf *r, uint8_t label, wbuf *der) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r) && __CPROVER_w_ok(der, sizeof *der),
                     "pem_read_block: reader and writer writable");
    __CPROVER_assert(label == PEM_LABEL_CERTIFICATE, "pem_read_block: a certificate block");
    if (proof_rule == PEM_TEXT_SKIPPED) {
        __CPROVER_assert(boundary_found && r->off == boundary_last_off,
                         "bundle: a block opens only where \"-----BEGIN \" begins");
        __CPROVER_assert(r->off == 0 || r->p[r->off - 1] == '\n',
                         "bundle: a block opens only at the start of a line");
    }
    if (!nondet_int()) {
        // A refusal leaves both where it stopped; the caller reads neither.
        r->err = nondet_int();
        return 0;
    }
    size_t take = nondet_size_t();
    __CPROVER_assume(take >= STUB_BEGIN_LEN && take <= rb_left(r));
    rb_skip(r, take);
    size_t n = nondet_size_t();
    __CPROVER_assume(n >= 1);
    if (n > der->cap - der->len) {
        der->err = 1;
        return 0;
    }
    der->len += n;
    block_read = 1;
    block_end_off = r->off;
    return 1;
}

int pem_begins_boundary(const rbuf *r) {
    __CPROVER_assert(__CPROVER_r_ok(r, sizeof *r), "pem_begins_boundary: reader readable");
    __CPROVER_assert(proof_rule == PEM_TEXT_SKIPPED, "pem_begins_boundary: the bundle's rule");
    __CPROVER_assert(!boundary_found, "bundle: the scan stops at the first \"-----BEGIN \"");
    __CPROVER_assert(rb_left(r) != 0, "bundle: the scan asks about a byte");
    __CPROVER_assert(boundary_checks != 0 || r->off == scan_start,
                     "bundle: the scan asks first about the text's first byte");
    __CPROVER_assert(boundary_checks == 0 || r->off == boundary_last_off + 1,
                     "bundle: the scan skips no byte unasked");
    boundary_checks++;
    boundary_last_off = r->off;
    boundary_found = nondet_int() != 0;
    return boundary_found;
}

#include "pem_blocks.c"

static void prove_skip_line_breaks(void) {
    uint8_t bytes[4];
    fill_nondet(bytes, sizeof bytes);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof bytes);
    rbuf r;
    rb_init(&r, bytes, n);
    uint8_t last = pem_skip_line_breaks(&r);
    __CPROVER_assert(last == 0 || last == '\r' || last == '\n', "skip: 0, CR or LF");
    __CPROVER_assert(!r.err, "skip: the reader stays clear");
    if (rb_left(&r) != 0) {
        uint8_t next = bytes[r.off];
        __CPROVER_assert(next != '\r' && next != '\n', "skip: stops at another byte");
    }
}

int main(void) {
    uint8_t pem[CH_PROOF_BLOCKS_LEN];
    fill_nondet(pem, sizeof pem);
    size_t pem_len = nondet_size_t();
    __CPROVER_assume(pem_len <= sizeof pem);
    uint8_t rule = nondet_u8();
    __CPROVER_assume(rule == PEM_TEXT_REFUSED || rule == PEM_TEXT_SKIPPED);
    proof_rule = rule;

    uint8_t room[PROOF_ROOM];
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof room);
    wbuf der;
    wb_init(&der, room, cap);
    pem_blocks blocks;
    pem_blocks_init(&blocks, pem, pem_len, rule);

    for (size_t call = 0; call < 3; call++) {
        size_t before = der.len;
        const uint8_t *block = NULL;
        size_t block_len = 0;
        boundary_checks = 0;
        boundary_found = 0;
        // The text's first byte: the input's first byte, or the byte
        // after the LF or CR LF that ends the last block's END line.
        scan_start = 0;
        if (block_read) {
            scan_start = block_end_off;
            if (scan_start < pem_len && pem[scan_start] == '\r') {
                scan_start++;
            }
            if (scan_start < pem_len) {
                scan_start++;
            }
        }
        int next = pem_blocks_next(&blocks, &der, &block, &block_len);
        __CPROVER_assert(next == PEM_BLOCKS_READ || next == PEM_BLOCKS_END ||
                             next == PEM_BLOCKS_REFUSED,
                         "next: one of three values");
        if (rule == PEM_TEXT_SKIPPED && next == PEM_BLOCKS_END) {
            __CPROVER_assert(!boundary_found, "bundle: the run ends at no \"-----BEGIN \"");
            __CPROVER_assert(boundary_checks == 0 || boundary_last_off + 1 == pem_len,
                             "bundle: the scan asked about each byte to the end");
            __CPROVER_assert(boundary_checks != 0 || scan_start == pem_len,
                             "bundle: a scan that asked about no byte had no text");
        }
        if (next == PEM_BLOCKS_READ) {
            __CPROVER_assert(block == room + before && block_len >= 1 &&
                                 block_len == der.len - before && der.len <= der.cap && !der.err,
                             "read: the block is the DER this call appended, inside the room");
            continue;
        }
        if (next == PEM_BLOCKS_END) {
            __CPROVER_assert(der.len == before && rb_left(&blocks.text) == 0,
                             "end: nothing appended, and the text read whole");
        }
        break;
    }
    prove_skip_line_breaks();
    return 0;
}
