// Proves: parse_key_share under -DCH_KEX_PQ — the one hybrid arm of the
// ServerHello parser — is memory-safe and UB-free on any extension
// bytes, and that when it accepts, the ciphertext pointer it hands back
// is one hybrid_secret may dereference: MLKEM_CT_LEN readable bytes
// inside the caller's message.
//
// That last property is the link between two proofs. hybrid_secret's
// harness assumes info->server_ct points at a whole ciphertext; this
// one proves the parser establishes it, so neither rests on the
// assumption alone.
//
// Narrow on purpose. handshake_parser's own harness bounds its message
// at 256 bytes and a hybrid key_share extension is 1,128, so raising
// that bound to reach this arm would grow the fast tier's heaviest
// formula (9.9 GB measured) by a factor docs/proofs.md says not to
// attempt. Driving the one static function costs a fraction of it.
#include "harness.h"

#include <string.h>

#include "handshake_parser.c"

int main(void) {
    // Room for a whole hybrid share plus its two length words, and
    // enough slack that a short extension exercises every refusal.
    uint8_t body[4 + MLKEM_CT_LEN + X25519_LEN + 8];
    fill_nondet(body, sizeof body);

    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof body);

    rbuf e;
    rb_init(&e, body, n);

    server_hello_info info;
    memset(&info, 0, sizeof info);

    int hrr = nondet_u8() & 1;
    int rc = parse_key_share(&e, &info, hrr);

    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "key_share returns OK or EPROTO");
    if (rc == CH_OK) {
        __CPROVER_assert(hrr == 0, "an HRR key_share is always refused");
        __CPROVER_assert(info.have_share == 1, "acceptance sets have_share");
        // The contract hybrid_secret depends on: a whole ciphertext,
        // readable, inside the bytes this parser actually consumed.
        // Against e.off rather than against body, because body is
        // larger than the message: a short read would still land
        // inside the array and prove nothing.
        __CPROVER_assert(__CPROVER_r_ok(info.server_ct, MLKEM_CT_LEN),
                         "server_ct spans a readable ciphertext");
        __CPROVER_assert(info.server_ct >= body && info.server_ct + MLKEM_CT_LEN <= body + e.off,
                         "server_ct lies inside the consumed bytes");
        // The share is the ciphertext then the x25519 point, contiguous
        // and exactly CH_KEX_SERVER_SHARE long, so a read of either
        // that is short or overlapping fails here.
        __CPROVER_assert(info.server_ct + MLKEM_CT_LEN + X25519_LEN == body + e.off,
                         "the share consumed exactly ct then point");
    }
    return 0;
}
