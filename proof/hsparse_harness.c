// Proves: the ServerHello parser (hsp_parse_sh) — a message parser that
// faces pre-authentication attacker bytes — is memory-safe and UB-free
// on any input up to 256 bytes. Parse results feed decisions, not memory
// offsets, so safety here plus the rbuf proof covers this side of the
// handshake's parsing attack surface; eeparse_harness proves
// hsp_parse_ee, its sibling. One parser per formula, the hkdf split's
// lesson: the combined instance crossed from minutes into hours of SAT
// time. Built with hsparse.c and buf.c on the CBMC command line — the
// parser's full dependency closure. See run.sh: a missing body would
// havoc the callee and void the proof.
#include "harness.h"

#include "hsparse.h"

int main(void) {
    uint8_t msg[256];
    fill_nondet(msg, sizeof msg);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof msg);

    sh_info si;
    for (size_t i = 0; i < sizeof si; i++) {
        ((uint8_t *)&si)[i] = 0;
    }
    (void)hsp_parse_sh(msg, n, &si, nondet_u8() & 1);
    return 0;
}
