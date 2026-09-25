// Proves: over any extension block of up to BLOCK_MAX bytes, every byte and
// the length symbolic, srv_ext_over_max in srv_parser.c is memory safe and
// free of UB, reads at most SRV_CLIENT_HELLO_EXT_MAX + 1 extension headers
// whatever the block holds after them, and answers 1 exactly when the block
// begins with SRV_CLIENT_HELLO_EXT_MAX + 1 whole extensions.
//
// The bound. srv_parser.h sets SRV_CLIENT_HELLO_EXT_MAX to 128, which needs a
// block of 516 bytes to pass. This formula takes it at 3, which the header
// admits for a harness, so that a 24-byte block, six empty extensions at
// most, holds blocks on both sides of it. proof/run.sh bounds the
// predicate's loop at four passes, and its unwinding assertion fails if the
// walk ever reads a fifth header. That is the claim that the count stops at
// the bound however long the block is, and with it that the count never
// passes SRV_CLIENT_HELLO_EXT_MAX + 1.
//
// What is real and what is a stub. srv_parser.c and buf.c are real. The
// SHA-256 calls and srv_read_extension have bodies here only so the
// translation unit has none missing: nothing below calls them.
#define SRV_CLIENT_HELLO_EXT_MAX 3

#include "harness.h"

#include <string.h>

#include "srv_parser.c"

#define BLOCK_MAX 24

void sha256_init(sha256 *s) {
    (void)s;
}

void sha256_update(sha256 *s, const uint8_t *in, size_t n) {
    (void)s;
    (void)in;
    (void)n;
}

void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]) {
    (void)s;
    (void)out;
}

int srv_read_extension(rbuf *e, uint16_t type, size_t data_off, hello_parse *p) {
    (void)e;
    (void)type;
    (void)data_off;
    (void)p;
    return CH_EPROTO;
}

// The harness's own reading: how many whole extensions the block begins
// with, up to the end of the block or the first extension whose header or
// body runs past it.
static size_t whole_prefix(const uint8_t *block, size_t n) {
    size_t off = 0;
    size_t count = 0;
    while (n - off >= 4) {
        size_t len = 4 + ((size_t)block[off + 2] << 8 | block[off + 3]);
        if (len > n - off) {
            break;
        }
        off += len;
        count++;
    }
    return count;
}

int main(void) {
    static uint8_t block[BLOCK_MAX];
    for (size_t i = 0; i < sizeof block; i++) {
        block[i] = nondet_u8();
    }
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof block);

    int over = srv_ext_over_max(block, n);
    __CPROVER_assert(over == 0 || over == 1, "the answer is 0 or 1");
    __CPROVER_assert(over == (whole_prefix(block, n) > SRV_CLIENT_HELLO_EXT_MAX),
                     "1 exactly when the block begins with more than the bound's whole "
                     "extensions");
    return 0;
}
