// Proves: over any extension block of up to BLOCK_MAX bytes, every byte and
// the length symbolic, srv_ext_duplicate and add_frozen_extensions in
// srv_parser.c are memory safe and free of UB, and together they build the
// frozen digest srv_parser.h states:
//
//   - every sha256_update the walk makes reads bytes inside the block;
//   - on a block whose framing is whole, srv_ext_duplicate answers 1 exactly
//     when two extensions share a type, unknown types included;
//   - on a whole block with no duplicate, the walk hands sha256_update each
//     covered extension exactly once, whole, from its type through its
//     body, in strictly ascending type order, and hands it nothing else.
//
// Ascending order, the count, and each call naming a covered extension
// together mean the calls are the covered extensions sorted by type: an
// injection from calls into covered extensions, between two sets of one
// size. The digest input is therefore one string per set of covered
// extensions, which is what lets the retry check compare them as a set
// (docs/decisions.md 59).
//
// What is real and what is a stub. srv_parser.c and buf.c are real. The
// harness defines its own SHA-256, which records each update rather than
// hashing, because the property is about which bytes reach the hash and
// in what order. It is not harness.h's contract stub, whose 112-byte
// context havoc is the formula cost proof/run.sh records for the walk.
// srv_read_extension has a body here only so the translation unit has
// none missing: nothing below calls srv_parse_client_hello.
//
// The harness restates the five types the digest leaves out rather than
// calling frozen_covers, so a change to that predicate fails here as well
// as in bin/srv_test.
#include "harness.h"

#include <string.h>

#include "srv_parser.c"

// Six four-byte extensions at most, so each walk runs at most seven rounds.
#define BLOCK_MAX 24
#define EXT_MAX (BLOCK_MAX / 4)

static const uint8_t *call_at[EXT_MAX + 1];
static size_t call_len[EXT_MAX + 1];
static size_t calls;

void sha256_init(sha256 *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_init: ctx writable");
}

void sha256_update(sha256 *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_update: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha256_update: input readable");
    __CPROVER_assert(calls <= EXT_MAX, "at most one update per extension");
    if (calls <= EXT_MAX) {
        call_at[calls] = in;
        call_len[calls] = n;
        calls++;
    }
}

void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_final: ctx writable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "sha256_final: output writable");
}

int srv_read_extension(rbuf *e, uint16_t type, size_t data_off, hello_parse *p) {
    (void)e;
    (void)type;
    (void)data_off;
    (void)p;
    return CH_EPROTO;
}

// The five extension types RFC 9846 §4.2.2 lets a second hello change.
static int left_out(uint16_t type) {
    return type == 51 || type == 42 || type == 44 || type == 41 || type == 21;
}

static uint16_t type_at(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

// The harness's own reading of the block: where each extension starts, its
// whole length and its type, and whether the framing fills the block.
static size_t ext_off[EXT_MAX + 1];
static size_t ext_len[EXT_MAX + 1];
static uint16_t ext_type[EXT_MAX + 1];

static int frame(const uint8_t *block, size_t n, size_t *count) {
    size_t off = 0;
    *count = 0;
    while (off < n) {
        if (n - off < 4 || *count > EXT_MAX) {
            return 0;
        }
        size_t len = 4 + ((size_t)block[off + 2] << 8 | block[off + 3]);
        if (len > n - off) {
            return 0;
        }
        ext_off[*count] = off;
        ext_len[*count] = len;
        ext_type[*count] = type_at(block + off);
        (*count)++;
        off += len;
    }
    return 1;
}

static int has_duplicate(size_t count) {
    int found = 0;
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            if (ext_type[i] == ext_type[j]) {
                found = 1;
            }
        }
    }
    return found;
}

// Whether call k names one covered extension of the block, whole.
static int names_covered(const uint8_t *block, size_t count, size_t k) {
    int found = 0;
    for (size_t i = 0; i < count; i++) {
        if (call_at[k] == block + ext_off[i] && call_len[k] == ext_len[i] &&
            !left_out(ext_type[i])) {
            found = 1;
        }
    }
    return found;
}

int main(void) {
    static uint8_t block[BLOCK_MAX];
    for (size_t i = 0; i < sizeof block; i++) {
        block[i] = nondet_u8();
    }
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof block);

    int duplicate = srv_ext_duplicate(block, n);
    __CPROVER_assert(duplicate == 0 || duplicate == 1, "the duplicate answer is 0 or 1");
    sha256 s;
    add_frozen_extensions(&s, block, n);

    for (size_t k = 0; k < calls; k++) {
        __CPROVER_assert(call_at[k] >= block && call_len[k] <= n &&
                             (size_t)(call_at[k] - block) <= n - call_len[k],
                         "every update lies inside the block");
    }

    size_t count = 0;
    if (!frame(block, n, &count)) {
        return 0;
    }
    __CPROVER_assert(duplicate == has_duplicate(count),
                     "a whole block is a duplicate exactly when two types match");
    if (duplicate) {
        return 0;
    }
    size_t covered = 0;
    for (size_t i = 0; i < count; i++) {
        if (!left_out(ext_type[i])) {
            covered++;
        }
    }
    __CPROVER_assert(calls == covered, "one update per covered extension");
    for (size_t k = 0; k < calls; k++) {
        __CPROVER_assert(names_covered(block, count, k), "each update is one covered extension");
        __CPROVER_assert(k == 0 || type_at(call_at[k - 1]) < type_at(call_at[k]),
                         "the updates run in strictly ascending type order");
    }
    return 0;
}
