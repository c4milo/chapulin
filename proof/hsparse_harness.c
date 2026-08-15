// Proves: the ServerHello and EncryptedExtensions parsers — the two
// message parsers that face pre-authentication attacker bytes — are
// memory-safe and UB-free on any input up to 256 bytes. Parse results
// feed decisions, not memory offsets, so safety here plus the rbuf proof
// covers the parsing attack surface of the handshake.
// Built with buf.c on the CBMC command line — the parsers' only real
// dependency. See run.sh: a missing body would havoc the callee and void
// the proof.
#include "harness.h"

// handshake.c needs these symbols; the parsers under proof never call
// them, and CBMC verifies that claim by proving the asserts unreachable.
#include "tls.h"
void ms_rand_bytes(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = nondet_u8();
    }
}
int io_send_all(const ms_cfg *cfg, const uint8_t *p, size_t n) {
    (void)cfg;
    (void)p;
    (void)n;
    __CPROVER_assert(0, "io_send_all unreachable from parsers");
    return -1;
}
int io_read_record(const ms_cfg *cfg, uint8_t *buf, size_t cap, uint8_t *outer, size_t *reclen) {
    (void)cfg;
    (void)buf;
    (void)cap;
    (void)outer;
    (void)reclen;
    __CPROVER_assert(0, "io_read_record unreachable from parsers");
    return -1;
}
void tlsi_fail(ms_tls *t, uint8_t desc) {
    (void)t;
    (void)desc;
    __CPROVER_assert(0, "tlsi_fail unreachable from parsers");
}
int tlsi_send_alert(ms_tls *t, uint8_t level, uint8_t desc) {
    (void)t;
    (void)level;
    (void)desc;
    __CPROVER_assert(0, "tlsi_send_alert unreachable from parsers");
    return -1;
}
#include "p256.h"
int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t *sig_der,
                      size_t sig_len) {
    (void)pub;
    (void)msg_hash;
    (void)sig_der;
    (void)sig_len;
    __CPROVER_assert(0, "p256 unreachable from parsers");
    return 0;
}

#include "handshake.c"

int main(void) {
    uint8_t msg[256];
    fill_nondet(msg, sizeof msg);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof msg);

    sh_info si;
    for (size_t i = 0; i < sizeof si; i++) {
        ((uint8_t *)&si)[i] = 0;
    }
    (void)parse_sh(msg, n, &si, nondet_u8() & 1);

    ms_tls t;
    hs h;
    for (size_t i = 0; i < sizeof h; i++) {
        ((uint8_t *)&h)[i] = 0;
    }
    h.t = &t;
    t.peer_limit = MS_TX_PT;
    (void)parse_ee(&h, msg, n);
    return 0;
}
