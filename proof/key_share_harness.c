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
// Built a second time with -DCH_TRUST_WEBPKI (the key_share_webpki
// launch line), where CH_KEX_TWO_GROUPS makes the arm accept two more
// shapes (docs/decisions.md entry 39): a HelloRetryRequest key_share
// naming x25519, and a ServerHello key_share selecting x25519 with a
// 32-byte share. The asserts below state each shape's contract, and the
// one-group build keeps its own.
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
#ifdef CH_KEX_TWO_GROUPS
    if (rc == CH_OK && hrr) {
        // A retry names x25519 and nothing else, in the one NamedGroup
        // the caller then requires to fill the extension exactly.
        __CPROVER_assert(info.retry_group == CH_GROUP_X25519, "a retry names x25519 alone");
        __CPROVER_assert(info.have_share == 0, "a retry carries no share");
        __CPROVER_assert(e.off == 2, "a retry's key_share is one NamedGroup");
        return 0;
    }
    if (rc == CH_OK && info.group == CH_GROUP_X25519) {
        // The answer to that retry: the group, a 32-byte length and the
        // x25519 point, and no ciphertext pointer.
        __CPROVER_assert(info.have_share == 1, "acceptance sets have_share");
        __CPROVER_assert(info.server_ct == NULL, "an x25519 share carries no ciphertext");
        __CPROVER_assert(e.off == 4 + X25519_LEN, "the share consumed the group, length and point");
        return 0;
    }
#endif
    if (rc == CH_OK) {
        __CPROVER_assert(hrr == 0, "an HRR key_share is always refused");
        __CPROVER_assert(info.have_share == 1, "acceptance sets have_share");
        // The group the parser reports is the one this build offers,
        // read from the wire: ch_tls.group reports this value and
        // cfg.require_pq compares it, so the harness proves it beside
        // the pointer contract.
        __CPROVER_assert(info.group == CH_KEX_GROUP, "acceptance records the one offered group");
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
