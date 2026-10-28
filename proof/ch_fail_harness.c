// Proves: ch_fail (tls_write.c) keeps tls.h's contract for every session
// state and every description byte. A description that is not an error
// alert of RFC 9846 §6.2 returns CH_EINVAL. A session that is not
// connected returns CH_EPROTO. Neither calls tlsi_fail, so neither
// sends, records an alert or changes the state. Every other call runs
// tlsi_fail once, with the description, and returns what it returned.
//
// spec_error_alert below lists the 26 error alerts a second time, from
// the AlertDescription enum of rfc9846.txt:3796-3823, so the proof holds
// tls_write.c's table to an independent copy of the list. tlsi_fail is a
// stub that records its call and returns any of the three results
// session.c's version can return; session.c is proved by its own
// harnesses. ch_write and ch_writable_len are not called, so their
// callees are stubs that fail the proof if they ever were.
#include "harness.h"

#include "handshake_post.h"
#include "io.h"
#include "record.h"
#include "session.h"
#include "tls.h"

int nondet_int(void);

int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    (void)cfg;
    (void)p;
    (void)n;
    __CPROVER_assert(0, "io_send_all unreachable: ch_fail sends through tlsi_fail");
    return CH_EIO;
}

int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *out_len) {
    (void)d;
    (void)type;
    (void)pt;
    (void)n;
    (void)out;
    (void)cap;
    (void)out_len;
    __CPROVER_assert(0, "rec_seal unreachable: ch_fail seals through tlsi_fail");
    return -1;
}

int hspost_send_key_update(ch_tls *t) {
    (void)t;
    __CPROVER_assert(0, "hspost_send_key_update unreachable: ch_fail sends no KeyUpdate");
    return CH_EIO;
}

static int fail_calls;
static uint8_t fail_description;
static int fail_result;

int tlsi_fail(ch_tls *t, uint8_t description) {
    __CPROVER_assert(__CPROVER_w_ok(t, sizeof *t), "fail: session writable");
    fail_calls++;
    fail_description = description;
    t->state = CH_ST_FAILED;
    return fail_result;
}

#include "tls_write.c"

static int spec_error_alert(uint8_t d) {
    return d == 10 || d == 20 || d == 22 || d == 40 || d == 42 || d == 43 || d == 44 || d == 45 ||
           d == 46 || d == 47 || d == 48 || d == 49 || d == 50 || d == 51 || d == 70 || d == 71 ||
           d == 80 || d == 86 || d == 109 || d == 110 || d == 112 || d == 113 || d == 115 ||
           d == 116 || d == 117 || d == 120;
}

static ch_tls session;

int main(void) {
    uint8_t state = nondet_u8();
    __CPROVER_assume(state <= CH_ST_FAILED);
    session.state = state;
    uint8_t description = nondet_u8();
    int result = nondet_int();
    __CPROVER_assume(result == CH_OK || result == CH_EIO || result == CH_ECAP);
    fail_result = result;

    int rc = ch_fail(&session, description);

    if (!spec_error_alert(description)) {
        __CPROVER_assert(rc == CH_EINVAL && fail_calls == 0 && session.state == state,
                         "ch_fail: a description outside RFC 9846 §6.2 is refused unchanged");
    } else if (state != CH_ST_CONNECTED) {
        __CPROVER_assert(rc == CH_EPROTO && fail_calls == 0 && session.state == state,
                         "ch_fail: a session that is not connected is refused unchanged");
    } else {
        __CPROVER_assert(fail_calls == 1 && fail_description == description && rc == result,
                         "ch_fail: a connected session fails once with the description");
        __CPROVER_assert(session.state == CH_ST_FAILED, "ch_fail: the session is failed");
    }
    return 0;
}
