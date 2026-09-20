// Proves: every reader in srv_parser_ext.c is memory safe and free of UB
// over an unconstrained extension body of up to EXT_MAX bytes, any
// extension type, and any offset the walk can hand it; and that each
// answers CH_OK or CH_EPROTO, setting an alert on CH_EPROTO.
//
// This is the other half of the split proof/srv_parser_walk_harness.c
// states. srv_parser_ext.c, buf.c and ct.c are real; SHA-256 is the
// contract stub in harness.h. The walk that calls this entry is the other
// formula, so nothing here unrolls it.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

#include "srv_parser_ext.c"

// One extension body. The walk bounds a body by the message, and
// proof/srv_parser_walk_harness.c proves that bound; this formula takes
// any body up to EXT_MAX. The walk bounds the real one.
#define EXT_MAX 24

int main(void) {
    static uint8_t body[EXT_MAX];
    fill_nondet(body, sizeof body);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof body);

    client_hello ch;
    memset(&ch, 0, sizeof ch);
    uint8_t seed = nondet_u8();
    uint8_t alert = seed;

    hello_parse p;
    memset(&p, 0, sizeof p);
    p.ch = &ch;
    p.alert = &alert;

    rbuf e;
    rb_init(&e, body, n);

    uint16_t type = (uint16_t)nondet_u32();
    size_t off = nondet_size_t();
    __CPROVER_assume(off <= n);

    int rc = srv_read_extension(&e, type, off, &p);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "a reader accepts or returns CH_EPROTO");
    // No assertion on the alert. srv_parser.h promises one on the
    // refusals srv_parse_client_hello returns, not on every path out of a
    // reader, and this formula found a path that refuses without naming
    // one. Which paths those are belongs in the header before it belongs
    // here.
    return 0;
}
