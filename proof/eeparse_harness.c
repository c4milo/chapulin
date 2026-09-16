// Proves: the EncryptedExtensions parser (hsp_parse_encrypted_exts) — a message
// parser that faces attacker bytes under the handshake keys — is
// memory-safe and UB-free on any input up to 256 bytes. Parse results
// feed decisions and the peer_limit clamp, not memory offsets, so safety
// here plus the rbuf proof covers this side of the handshake's parsing
// attack surface; handshake_parser_harness proves hsp_parse_server_hello and
// certparse_harness the Certificate pair, its siblings. The ServerHello
// parser gets its own formula, the hkdf split's lesson: the combined
// instance crossed from minutes into hours of SAT time. Built with handshake_parser.c and
// buf.c on the CBMC command line — the parser's full dependency closure.
// See run.sh: a missing body would havoc the callee and void the proof.
#include "harness.h"

#include "cfg.h"
#include "handshake_message.h"
#include "handshake_parser.h"

int main(void) {
    uint8_t msg[256];
    fill_nondet(msg, sizeof msg);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof msg);

    uint16_t peer_limit = CH_TX_PT;
    uint8_t seed = nondet_u8();
    uint8_t alert = seed;
#ifdef CH_TRUST_WEBPKI
    // No offer: the shape a caller that skips ALPN configures, where an
    // ALPN extension is a response to a request that never went out.
    // The arm that reads an offered protocol is eeparse_alpn's, which
    // drives parse_alpn directly, because the two bounds multiply here.
    const ch_alpn_protocol *offered = NULL;
    size_t offered_count = 0;
    uint8_t selected = CH_ALPN_NONE;
    (void)hsp_parse_encrypted_exts(msg, n, &peer_limit, offered, offered_count, &selected, &alert);
    // The selection contract handshake_parser.h states: the parser
    // either leaves the caller's CH_ALPN_NONE or writes the index of a
    // protocol the offer holds.
    __CPROVER_assert(selected == CH_ALPN_NONE || (size_t)selected < offered_count,
                     "an ALPN selection names a protocol the client offered");
#else
    (void)hsp_parse_encrypted_exts(msg, n, &peer_limit, &alert);
#endif
    // The alert contract handshake_parser.h states: the parser keeps the
    // caller's seed or writes unsupported_extension. The TRUST=webpki
    // arm may also write decode_error, the alert for a server_name that
    // carries data. With an offer it may also write illegal_parameter,
    // which eeparse_alpn asserts over the arm that writes it.
#ifdef CH_TRUST_WEBPKI
    __CPROVER_assert(alert == seed || alert == ALERT_UNSUPPORTED_EXTENSION ||
                         alert == ALERT_DECODE_ERROR,
                     "the parser keeps the seed or writes unsupported_extension or decode_error");
#else
    __CPROVER_assert(alert == seed || alert == ALERT_UNSUPPORTED_EXTENSION,
                     "the parser keeps the seeded alert or writes unsupported_extension");
#endif
    return 0;
}
