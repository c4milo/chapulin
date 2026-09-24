// The ALPN arm of the EncryptedExtensions parser (RFC 7301 §3.2),
// proven where it lives: parse_alpn over an extension body of any bytes,
// against the widest protocol offer ch_connect admits — CH_ALPN_MAX
// names of up to CH_ALPN_NAME_MAX bytes, every byte and every length
// symbolic. Beyond memory safety it proves the selection contract
// handshake_parser.h states: an accepted body names a protocol the offer
// holds, a refused one leaves the caller's CH_ALPN_NONE, and the alert
// is the caller's seed or one of the arm's two.
//
// It reaches the static parse_alpn by including handshake_parser_ee.c, the
// hello_build precedent, so its launch line carries buf.c alone. Driving
// the same offer through the whole EncryptedExtensions loop instead
// multiplies the two bounds: each extension a message holds may reach
// the offer loop, and each pass compares up to 32 symbolic bytes. At a
// 256-byte message that formula reached the SAT solver after 21 minutes
// with no verdict, and at 48 bytes it verified once at 14.7 GB and then
// lost its solver to the machine's memory on a second run. So the loop
// around this arm stays eeparse_webpki's, at its 256-byte message with
// an empty offer, and the arm itself is proven here.
//
// -DCH_TRUST_WEBPKI comes from the launch line rather than a #define
// here, because buf.c is its own translation unit on that line and a
// define in this file would not reach it.
#ifndef CH_TRUST_WEBPKI
#error "eeparse_alpn proves the TRUST=webpki arm; its launch line must pass -DCH_TRUST_WEBPKI"
#endif
#include "harness.h"

#include "cfg.h"
#include "handshake_message.h"
#include "handshake_parser.h"

#include "handshake_parser_ee.c"

int main(void) {
    // The extension_data of one ALPN extension. 40 bytes holds the
    // longest body the arm can accept — 2 list-length bytes, 1 name
    // length byte and a name of CH_ALPN_NAME_MAX — with room for the
    // trailing bytes it must refuse.
    uint8_t body[40];
    fill_nondet(body, sizeof body);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof body);

    // The offer, in one flat buffer: every entry is then a slice of a
    // single object, and CBMC's addressed-object budget (--object-bits,
    // 256 by default) holds. Nothing constrains the names, so the offer
    // covers a repeated name too, which ch_connect refuses and this
    // parser never assumes.
    static uint8_t names[CH_ALPN_MAX * CH_ALPN_NAME_MAX];
    fill_nondet(names, sizeof names);
    ch_alpn_protocol offered[CH_ALPN_MAX];
    for (size_t i = 0; i < CH_ALPN_MAX; i++) {
        offered[i].name = names + i * CH_ALPN_NAME_MAX;
        offered[i].name_len = nondet_size_t();
        __CPROVER_assume(offered[i].name_len <= CH_ALPN_NAME_MAX);
    }
    size_t offered_count = nondet_size_t();
    __CPROVER_assume(offered_count <= CH_ALPN_MAX);

    uint8_t seed = nondet_u8();
    uint8_t alert = seed;
    uint8_t selected = CH_ALPN_NONE;
    const alpn_out out = {offered, offered_count, &selected, &alert};

    int rc = parse_alpn(body, n, &out);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "the arm accepts or returns CH_EPROTO");
    // The selection contract. Asserting rc != CH_OK instead fails, so
    // the accepting tail is reached.
    __CPROVER_assert(rc != CH_OK || (size_t)selected < offered_count,
                     "an accepted selection names a protocol the client offered");
    __CPROVER_assert(rc == CH_OK || selected == CH_ALPN_NONE,
                     "a refusal leaves the caller's no-selection value");
    __CPROVER_assert(alert == seed || alert == ALERT_DECODE_ERROR ||
                         alert == ALERT_ILLEGAL_PARAMETER,
                     "the arm keeps the seed or writes decode_error or illegal_parameter");
    return 0;
}
