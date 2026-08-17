// Proves: the ServerHello parser (hsp_parse_server_hello) — a message parser that
// faces pre-authentication attacker bytes — is memory-safe and UB-free
// on any input up to 256 bytes. Parse results feed decisions, not memory
// offsets, so safety here plus the rbuf proof covers this side of the
// handshake's parsing attack surface; eeparse_harness proves
// hsp_parse_encrypted_exts, its sibling. One parser per formula, the hkdf split's
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

    server_hello_info info;
    for (size_t i = 0; i < sizeof info; i++) {
        ((uint8_t *)&info)[i] = 0;
    }
    (void)hsp_parse_server_hello(msg, n, &info, nondet_u8() & 1);
    return 0;
}
