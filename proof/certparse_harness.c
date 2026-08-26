// Proves: the Certificate and CertificateVerify body parsers
// (hsp_parse_certificate, hsp_parse_certificate_verify) — message
// parsers that face attacker bytes under the handshake keys — are
// memory-safe and UB-free on any input up to 256 bytes, and on CH_OK
// hand back a slice that lies inside the input body. The pinned-mode
// handshake driver's stubs assume exactly those contracts; this
// harness is what discharges them. One formula for both parsers: each
// is a short rbuf walk, so together they stay minutes from the
// handshake_parse/eeparse split point. Built with handshake_parse.c and buf.c on the
// CBMC command line — the full dependency closure; a missing body
// would havoc the callee and void the proof (see run.sh).
#include "harness.h"

#include "cfg.h"
#include "handshake_parse.h"

int main(void) {
    uint8_t msg[256];
    fill_nondet(msg, sizeof msg);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof msg);

    const uint8_t *list = 0;
    size_t list_len = 0;
    uint8_t alert = 0;
    if (hsp_parse_certificate(msg, n, &list, &list_len, &alert) == CH_OK) {
        __CPROVER_assert(list >= msg && list + list_len <= msg + n,
                         "certificate list lies inside the body");
    }

    fill_nondet(msg, sizeof msg);
    n = nondet_size_t();
    __CPROVER_assume(n <= sizeof msg);
    const uint8_t *sig = 0;
    size_t sig_len = 0;
    alert = 0;
    if (hsp_parse_certificate_verify(msg, n, &sig, &sig_len, &alert) == CH_OK) {
        __CPROVER_assert(sig >= msg && sig + sig_len <= msg + n, "signature lies inside the body");
    }
    return 0;
}
