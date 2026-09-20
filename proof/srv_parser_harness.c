// Proves: the ClientHello parser (srv_parse_client_hello, with the two
// predicates srv_ext_known and srv_ext_duplicate it runs) is memory safe
// and free of UB over any body of up to HELLO_MAX bytes, every byte and
// the length symbolic, and honours the contract srv_parser.h states.
// On CH_OK: the caller's seeded alert stands; supported_versions was
// read; every share, cookie and server_name pointer lies inside the
// message with its length; a share is CH_KEX_CLIENT_SHARE bytes and
// shares reports it; truncated_len lies inside the message; the seen
// mask holds §9.2's pairings; a record_size_limit is 0 or at least 64;
// and every share's group was listed in supported_groups. On CH_EPROTO
// the alert is one of the four descriptions the header lists, so the
// parser writes no other.
//
// What is real and what is a stub. srv_parser.c, srv_parser_ext.c,
// buf.c and ct.c are real. SHA-256 is the contract stub in harness.h,
// so the frozen digest is any 32 bytes and nothing here proves what it
// covers; test/srv_parser_tests.h checks that against a byte string
// assembled by hand. The stub's own assertion is what proves every
// sha256_update reads inside the message.
//
// The thirteen CH_OK assertions are not vacuous: test_golden_hello
// parses a 216-byte ClientHello and gets CH_OK, and every byte of it
// lies inside this harness's symbolic input, whose length runs to 256.
//
// The ALPN offer is empty, for the reason eeparse_harness.c gives:
// driving an offer through the whole extension loop multiplies the
// offer's bound by the message's. test/srv_parser_tests.h drives the
// selection.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

// Both halves of the parser: srv_parser.c walks the message and
// srv_parser_ext.c reads each recognized extension. srv_parser.h says
// why the one parser sits in two files.
#include "srv_parser.c"
#include "srv_parser_ext.c"

// The message bound. handshake_parser_harness.c proves the client's
// parsers at 256 bytes, and this hello holds the head, the extension
// block and every recognized extension at that size.
#define HELLO_MAX 256

// Whether p points at len bytes inside the n bytes at msg.
static int inside(const uint8_t *msg, size_t n, const uint8_t *p, size_t len) {
    return p >= msg && p <= msg + n && len <= (size_t)(msg + n - p);
}

int main(void) {
    static uint8_t msg[HELLO_MAX];
    fill_nondet(msg, sizeof msg);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof msg);

    // The caller zeroes ch and seeds the alert (srv_parser.h).
    client_hello ch;
    memset(&ch, 0, sizeof ch);
    uint8_t seed = nondet_u8();
    uint8_t alert = seed;

    int rc = srv_parse_client_hello(msg, n, &ch, NULL, 0, &alert);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "the parser accepts or returns CH_EPROTO");
    if (rc == CH_OK) {
        __CPROVER_assert(alert == seed, "an accepted hello keeps the caller's seed");
        __CPROVER_assert((ch.seen & SRV_EXT_SUPPORTED_VERSIONS) != 0,
                         "an accepted hello carried supported_versions");
        __CPROVER_assert(ch.session_id_len <= SRV_SESSION_ID_MAX,
                         "legacy_session_id fits the session's copy");
        __CPROVER_assert(ch.share == NULL || (ch.share_len == CH_KEX_CLIENT_SHARE &&
                                              inside(msg, n, ch.share, ch.share_len)),
                         "a share is CH_KEX_CLIENT_SHARE bytes inside the message");
        __CPROVER_assert((ch.shares == 0) == (ch.share == NULL), "shares reports the share");
        __CPROVER_assert((ch.shares & (uint8_t)~ch.groups) == 0,
                         "every share's group was listed in supported_groups");
        __CPROVER_assert(ch.cookie == NULL || inside(msg, n, ch.cookie, ch.cookie_len),
                         "a cookie lies inside the message");
        __CPROVER_assert(ch.server_name == NULL ||
                             inside(msg, n, ch.server_name, ch.server_name_len),
                         "a server_name lies inside the message");
        __CPROVER_assert(ch.truncated_len <= n, "truncated_len lies inside the message");
        __CPROVER_assert(ch.alpn_selected == CH_ALPN_NONE, "no offer selects nothing");
        __CPROVER_assert(ch.record_size_limit == 0 || ch.record_size_limit >= 64,
                         "a record_size_limit is absent or at least 64");
        __CPROVER_assert((ch.seen & SRV_EXT_PRE_SHARED_KEY) == 0 ||
                             (ch.seen & SRV_EXT_PSK_MODES) != 0,
                         "pre_shared_key came with psk_key_exchange_modes");
        uint16_t auth = SRV_EXT_SIGNATURE_ALGORITHMS | SRV_EXT_SUPPORTED_GROUPS;
        __CPROVER_assert((ch.seen & SRV_EXT_PRE_SHARED_KEY) != 0 || (ch.seen & auth) == auth,
                         "without pre_shared_key both auth extensions were read");
        __CPROVER_assert(((ch.seen & SRV_EXT_SUPPORTED_GROUPS) == 0) ==
                             ((ch.seen & SRV_EXT_KEY_SHARE) == 0),
                         "supported_groups and key_share came together");
    } else {
        __CPROVER_assert(alert == ALERT_DECODE_ERROR || alert == ALERT_ILLEGAL_PARAMETER ||
                             alert == ALERT_PROTOCOL_VERSION || alert == ALERT_MISSING_EXTENSION,
                         "a refusal writes one of the four descriptions the header lists");
    }
    return 0;
}
