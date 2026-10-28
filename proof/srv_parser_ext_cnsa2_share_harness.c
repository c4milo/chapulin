// Proves: srv_parser_ext.c's PROFILE=cnsa2 key_share reader
// (docs/decisions.md 162) over a body that carries one KeyShareEntry for
// ML-KEM-1024 at the encapsulation key's length, MLKEM_EK_LEN, or one byte
// either side of it, with any list length and up to four bytes after the
// entry. It reads and writes only inside the body, commits no undefined
// behavior, and:
//  - sets mlkem_share, and its bit in shares, exactly when the entry's
//    length is MLKEM_EK_LEN and the list fills the body;
//  - points mlkem_share at the entry's key_exchange, MLKEM_EK_LEN readable
//    bytes inside the body;
//  - refuses an entry one byte short or one byte long with
//    illegal_parameter.
//
// srv_parser_ext_cnsa2 runs srv_parser_ext_harness.c under the profile's
// defines for every other reader and every short body. This harness holds
// the one shape that harness cannot reach, a full-length share, at a bound
// the walk's loop keeps to two entries. SHA-256 is the contract stub in
// harness.h, as in srv_parser_ext_harness.c.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

#include "srv_parser_ext.c"

uint16_t nondet_u16(void);

// The list length, the entry's group and length words, the longest share
// held, and up to four bytes after it.
#define SHARE_BODY_MAX (2 + 4 + MLKEM_EK_LEN + 1 + 4)

int main(void) {
    static uint8_t body[SHARE_BODY_MAX];
    fill_nondet(body, sizeof body);
    size_t share_len = nondet_size_t();
    __CPROVER_assume(share_len >= MLKEM_EK_LEN - 1 && share_len <= MLKEM_EK_LEN + 1);
    size_t tail = nondet_size_t();
    __CPROVER_assume(tail <= 4);
    size_t n = 2 + 4 + share_len + tail;
    uint16_t list_len = nondet_u16();
    body[0] = (uint8_t)(list_len >> 8);
    body[1] = (uint8_t)list_len;
    body[2] = 0x02; // ML-KEM-1024, 0x0202
    body[3] = 0x02;
    body[4] = (uint8_t)(share_len >> 8);
    body[5] = (uint8_t)share_len;

    client_hello ch;
    memset(&ch, 0, sizeof ch);
    uint8_t alert = 0;
    hello_parse p;
    memset(&p, 0, sizeof p);
    p.ch = &ch;
    p.alert = &alert;
    rbuf e;
    rb_init(&e, body, n);
    int rc = srv_read_extension(&e, EXT_KEY_SHARE, 0, &p);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "the reader accepts or returns CH_EPROTO");
    __CPROVER_assert((ch.mlkem_share != NULL) == ((ch.shares & SRV_GROUP_MLKEM1024) != 0),
                     "the pointer is set exactly when its bit is");
    if (ch.mlkem_share != NULL) {
        __CPROVER_assert(share_len == MLKEM_EK_LEN, "only a full-length key is kept");
        __CPROVER_assert(ch.mlkem_share == body + 6, "the pointer is the entry's key_exchange");
        __CPROVER_assert(__CPROVER_r_ok(ch.mlkem_share, MLKEM_EK_LEN),
                         "the key is readable at its length");
    }
    if (share_len != MLKEM_EK_LEN && list_len == 4 + share_len && tail == 0) {
        __CPROVER_assert(rc == CH_EPROTO && alert == ALERT_ILLEGAL_PARAMETER,
                         "a key one byte short or long is illegal_parameter");
    }
    return 0;
}
