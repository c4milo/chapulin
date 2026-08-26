// Proves: the EncryptedExtensions parser (hsp_parse_encrypted_exts) — a message
// parser that faces attacker bytes under the handshake keys — is
// memory-safe and UB-free on any input up to 256 bytes. Parse results
// feed decisions and the peer_limit clamp, not memory offsets, so safety
// here plus the rbuf proof covers this side of the handshake's parsing
// attack surface; handshake_parse_harness proves hsp_parse_server_hello and
// certparse_harness the Certificate pair, its siblings. The ServerHello
// parser gets its own formula, the hkdf split's lesson: the combined
// instance crossed from minutes into hours of SAT time. Built with handshake_parse.c and
// buf.c on the CBMC command line — the parser's full dependency closure.
// See run.sh: a missing body would havoc the callee and void the proof.
#include "harness.h"

#include "cfg.h"
#include "handshake_parse.h"

int main(void) {
    uint8_t msg[256];
    fill_nondet(msg, sizeof msg);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof msg);

    uint16_t peer_limit = CH_TX_PT;
    uint8_t alert = 0;
    (void)hsp_parse_encrypted_exts(msg, n, &peer_limit, &alert);
    return 0;
}
