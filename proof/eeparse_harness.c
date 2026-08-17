// Proves: the EncryptedExtensions parser (hsp_parse_ee) — a message
// parser that faces attacker bytes under the handshake keys — is
// memory-safe and UB-free on any input up to 256 bytes. Parse results
// feed decisions and the peer_limit clamp, not memory offsets, so safety
// here plus the rbuf proof covers this side of the handshake's parsing
// attack surface; hsparse_harness proves hsp_parse_sh, its sibling. One
// parser per formula, the hkdf split's lesson: the combined instance
// crossed from minutes into hours of SAT time. Built with hsparse.c and
// buf.c on the CBMC command line — the parser's full dependency closure.
// See run.sh: a missing body would havoc the callee and void the proof.
#include "harness.h"

#include "cfg.h"
#include "hsparse.h"

int main(void) {
    uint8_t msg[256];
    fill_nondet(msg, sizeof msg);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof msg);

    uint16_t peer_limit = CH_TX_PT;
    uint8_t alert = 0;
    (void)hsp_parse_ee(msg, n, &peer_limit, &alert);
    return 0;
}
