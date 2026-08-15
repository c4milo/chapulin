// Proves: handle_post_hs and handle_ticket — the parsers that run over
// decrypted post-handshake bytes (NewSessionTicket and KeyUpdate) — are
// memory-safe and UB-free against ANY plaintext up to 128 bytes, and
// report a consumed length no larger than the input. This is the last
// attacker-facing parser; a peer that reaches a connected session feeds
// it arbitrary decrypted bytes.
//
// The full ch_read/pump_post_hs driver that calls this (record pump,
// cross-record reassembly, ch_write, ch_close) does not converge as one
// CBMC formula; its integration is covered by test/e2e.sh, the
// mock-transport unit tests, and fuzz/fuzz_posths.c. Here the record I/O,
// crypto, and key schedule are stubs asserting their proven contracts,
// so what is under proof is the parser's own arithmetic. buf.c and ct.c
// are real.
#include "harness.h"

#include <string.h>

#include "hsmsg.h"
#include "io.h"
#include "keysched.h"
#include "record.h"
#include "session.h"

int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    __CPROVER_assert(cfg != NULL, "send: cfg valid");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(p, n), "send: bytes readable");
    return (nondet_u8() & 1) ? CH_OK : CH_EIO;
}

int io_read_record(const ch_cfg *cfg, uint8_t *buf, size_t cap, uint8_t *outer, size_t *reclen) {
    (void)cfg;
    (void)buf;
    (void)cap;
    (void)outer;
    (void)reclen;
    // pump_post_hs never runs here; the harness drives handle_post_hs on a
    // whole buffer that leaves no partial trailing message.
    __CPROVER_assert(0, "io_read_record unreachable from handle_post_hs");
    return CH_EIO;
}

void rec_dir_update(uint8_t secret[SHA256_LEN], rec_dir *d) {
    __CPROVER_assert(__CPROVER_w_ok(secret, SHA256_LEN), "upd: secret writable");
    fill_nondet(secret, SHA256_LEN);
    fill_nondet((uint8_t *)d, sizeof *d);
}

int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *outn) {
    (void)type;
    __CPROVER_assert(__CPROVER_w_ok(d, sizeof *d), "seal: dir writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "seal: pt readable");
    size_t total = REC_HDR + n + 1 + AEAD_TAG;
    if (total > cap) {
        return -1;
    }
    __CPROVER_assert(__CPROVER_w_ok(out, total), "seal: out writable");
    fill_nondet(out, total);
    *outn = total;
    return 0;
}

void ks_res_psk(const uint8_t res_master[SHA256_LEN], const uint8_t *nonce, size_t noncelen,
                uint8_t psk[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(res_master, SHA256_LEN), "res: master readable");
    __CPROVER_assert(noncelen == 0 || __CPROVER_r_ok(nonce, noncelen), "res: nonce readable");
    fill_nondet(psk, SHA256_LEN);
}

// These exist so tls.c links; handle_post_hs never calls them.
void rec_dir_init(rec_dir *d, const uint8_t secret[SHA256_LEN]) {
    (void)secret;
    __CPROVER_assert(0, "rec_dir_init unreachable");
    fill_nondet((uint8_t *)d, sizeof *d);
}
int rec_open(rec_dir *d, const uint8_t *rec, size_t n, uint8_t *pt, size_t cap, size_t *ptn,
             uint8_t *type) {
    (void)d;
    (void)rec;
    (void)n;
    (void)pt;
    (void)cap;
    (void)ptn;
    (void)type;
    __CPROVER_assert(0, "rec_open unreachable");
    return -1;
}
int ch_handshake(ch_tls *t) {
    (void)t;
    __CPROVER_assert(0, "ch_handshake unreachable");
    return CH_EPROTO;
}

// Every pointer the driver hands the application must be readable.
static void on_ticket(void *io, const ch_ticket *tk) {
    (void)io;
    __CPROVER_assert(__CPROVER_r_ok(tk->psk, sizeof tk->psk), "cb: psk readable");
    __CPROVER_assert(tk->identity_len == 0 || __CPROVER_r_ok(tk->identity, tk->identity_len),
                     "cb: identity readable");
}

#include "tls.c"

int main(void) {
    static ch_tls t;
    memset(&t, 0, sizeof t);
    uint8_t buf[128];
    t.cfg.buf = buf;
    t.cfg.buf_len = sizeof buf;
    if (nondet_u8() & 1) {
        t.cfg.on_ticket = on_ticket;
    }
    fill_nondet(t.rd_secret, sizeof t.rd_secret);
    fill_nondet(t.wr_secret, sizeof t.wr_secret);
    fill_nondet(t.res_master, sizeof t.res_master);
    fill_nondet((uint8_t *)&t.wr, sizeof t.wr);
    fill_nondet((uint8_t *)&t.rd, sizeof t.rd);

    uint8_t pt[128];
    fill_nondet(pt, sizeof pt);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof pt);
    size_t used = nondet_size_t();
    int rc = handle_post_hs(&t, pt, n, &used);
    if (rc == CH_OK) {
        __CPROVER_assert(used <= n, "consumed no more than the input");
    }
    return 0;
}
