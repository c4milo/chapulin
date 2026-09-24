// Proves: the ClientHello walk in srv_parser.c is memory safe and free of
// UB over any body of up to HELLO_MAX bytes, every byte and the length
// symbolic, and honours the contract srv_parser.h states on CH_OK and on
// CH_EPROTO.
//
// What is real and what is a stub. srv_parser.c, buf.c and ct.c are real,
// the duplicate check and the ascending walk that feeds the frozen digest
// included. srv_read_extension is the contract stub below, and SHA-256 is
// a stub of this harness's own. proof/srv_parser_ext_harness.c proves the
// readers that stub stands for, and proof/srv_parser_frozen_harness.c
// proves which bytes the walk hands the hash.
//
// Why the parser is two formulas. srv_parser.c walks the extension block
// and calls a reader that loops again inside each round, so one formula
// over both nests ten loops: it returned no verdict in 33 minutes at
// --unwind 260, none in 5 minutes at --unwind 65 with fill_nondet and
// ct_memeq bounded, and none at a 112-byte body. Splitting at the one
// entry between the files is the layering proof/p256_ecdh_harness.c and
// proof/srv_accept_harness.c use.
//
// Why SHA-256 is not harness.h's stub. That stub writes nondet bytes over
// the whole 112-byte context on every call, and this formula returned no
// verdict at any fill bound large enough to cover that context. The walk
// never reads the context, so the stubs below assert the contract and
// keep no context at all; sha256_final still returns an unconstrained
// digest.
#include "harness.h"

#include <string.h>

#include "srv_parser.c"

// A 60-byte message has room for the four empty extensions an accepted
// hello needs here: supported_versions, signature_algorithms,
// supported_groups and key_share. The head and the extension block's
// length take at least 43 bytes, which leaves 17, and the four take 16.
// At 64 bytes the formula returned no verdict in 18 minutes.
#define HELLO_MAX 60

void sha256_init(sha256 *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_init: ctx writable");
}

void sha256_update(sha256 *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_update: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha256_update: input readable");
}

void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha256_final: ctx writable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "sha256_final: output writable");
    for (size_t i = 0; i < SHA256_LEN; i++) {
        out[i] = nondet_u8();
    }
}

// The reader contract, asserted and then havocked. srv_read_extension
// reads inside e and writes only through p; it answers CH_OK having read
// any part of its body, or CH_EPROTO with one of the four alerts the
// readers write. The walk may depend on none of what it writes, which an
// unconstrained answer is what proves.
int srv_read_extension(rbuf *e, uint16_t type, size_t data_off, hello_parse *p) {
    __CPROVER_assert(__CPROVER_r_ok(e, sizeof *e), "srv_read_extension: reader readable");
    __CPROVER_assert(__CPROVER_w_ok(p, sizeof *p), "srv_read_extension: parse state writable");
    (void)type;
    (void)data_off;
    if (nondet_u8() != 0) {
        uint8_t alert = nondet_u8();
        __CPROVER_assume(alert == ALERT_DECODE_ERROR || alert == ALERT_ILLEGAL_PARAMETER ||
                         alert == ALERT_PROTOCOL_VERSION || alert == ALERT_UNSUPPORTED_EXTENSION);
        *p->alert = alert;
        return CH_EPROTO;
    }
    size_t used = nondet_size_t();
    __CPROVER_assume(used <= rb_left(e));
    rb_skip(e, used);
    return CH_OK;
}

// Whether p points at len bytes inside the n bytes at msg.
static int inside(const uint8_t *msg, size_t n, const uint8_t *p, size_t len) {
    return p >= msg && p <= msg + n && len <= (size_t)(msg + n - p);
}

int main(void) {
    static uint8_t msg[HELLO_MAX];
    // The message gets its own loop rather than fill_nondet, so its bound
    // stands apart from any other fill.
    for (size_t i = 0; i < sizeof msg; i++) {
        msg[i] = nondet_u8();
    }
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
        __CPROVER_assert(ch.x25519_share == NULL || inside(msg, n, ch.x25519_share, X25519_LEN),
                         "an x25519 share is X25519_LEN bytes inside the message");
        __CPROVER_assert(ch.hybrid_share == NULL ||
                             inside(msg, n, ch.hybrid_share, CH_HYBRID_CLIENT_SHARE),
                         "a hybrid share is CH_HYBRID_CLIENT_SHARE bytes inside the message");
        __CPROVER_assert(((ch.shares & SRV_GROUP_X25519) == 0) == (ch.x25519_share == NULL),
                         "shares reports the x25519 share");
        __CPROVER_assert(((ch.shares & SRV_GROUP_X25519MLKEM768) == 0) == (ch.hybrid_share == NULL),
                         "shares reports the hybrid share");
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
                             alert == ALERT_PROTOCOL_VERSION || alert == ALERT_MISSING_EXTENSION ||
                             alert == ALERT_UNSUPPORTED_EXTENSION,
                         "a refusal writes one of the five descriptions the header lists");
    }
    return 0;
}
