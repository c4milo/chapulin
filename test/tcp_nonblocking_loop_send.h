// INV-28 for both tcp-nonblocking drivers: no call of this transport
// sends through cfg.send or reads through cfg.recv, and each init call
// refuses a configuration that sets either one (tcp_nonblocking.h). So
// server_config and client_config set neither, and the two calls below
// set never_send on each session's copy of cfg once its init took the
// configuration. A call that sent would then count in io_calls, which the
// cases check. Included by test/tcp_nonblocking_loop_test.c before its
// handshake helpers.
#ifndef CH_TEST_TCP_NONBLOCKING_LOOP_SEND_H
#define CH_TEST_TCP_NONBLOCKING_LOOP_SEND_H

#include <string.h>

#include "session_convert.h"
#include "srv_tcp_nonblocking.h"
#include "tcp_nonblocking.h"

static size_t io_calls;

static int never_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    io_calls++;
    return -1;
}

// A recv for the refusal cases alone, which init refuses before any call
// could read through it. It poisons the buffer as well as counting, so a
// call that read through it could not still look right.
static int never_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    memset(p, 0xEE, n);
    io_calls++;
    return -1;
}

// ch_srv_tcp_init, then never_send on the session's copy of cfg.
static int server_init(ch_tcp_priv *server, const ch_cfg *cfg) {
    int rc = ch_srv_tcp_init(tcp_public(server), cfg);
    if (rc == CH_OK) {
        server->t.cfg.send = never_send;
    }
    return rc;
}

// ch_tcp_init, then never_send on the session's copy of cfg.
static int client_init(ch_tcp_priv *client, const ch_cfg *cfg) {
    int rc = ch_tcp_init(tcp_public(client), cfg);
    if (rc == CH_OK) {
        client->t.cfg.send = never_send;
    }
    return rc;
}

// One init of each role over cfg with a send or a recv set: CH_EINVAL, a
// failed session, nothing staged for ch_tcp_out, and no call of either
// callback.
static void check_init_refuses(const ch_cfg *ccfg, const ch_cfg *scfg, int with_send) {
    static ch_tcp_priv probe;
    ch_cfg c = *ccfg;
    ch_cfg s = *scfg;
    if (with_send) {
        c.send = never_send;
        s.send = never_send;
    } else {
        c.recv = never_recv;
        s.recv = never_recv;
    }
    uint8_t wire[64];
    size_t n = 0;
    io_calls = 0;
    CHECK(ch_tcp_init(tcp_public(&probe), &c) == CH_EINVAL);
    CHECK(ch_tcp_state(tcp_public(&probe)) == CH_ST_FAILED);
    CHECK(ch_tcp_out(tcp_public(&probe), wire, sizeof wire, &n) == CH_EINVAL && n == 0);
    CHECK(ch_srv_tcp_init(tcp_public(&probe), &s) == CH_EINVAL);
    CHECK(ch_tcp_state(tcp_public(&probe)) == CH_ST_FAILED);
    CHECK(ch_tcp_out(tcp_public(&probe), wire, sizeof wire, &n) == CH_EINVAL && n == 0);
    CHECK(io_calls == 0);
}

// Each role refuses a cfg.send and a cfg.recv, and takes the same
// configuration with neither.
static void test_init_refuses_callbacks(const ch_cfg *ccfg, const ch_cfg *scfg) {
    check_init_refuses(ccfg, scfg, 1);
    check_init_refuses(ccfg, scfg, 0);
    static ch_tcp_priv probe;
    CHECK(client_init(&probe, ccfg) == CH_OK);
    ch_tcp_close(tcp_public(&probe));
    CHECK(server_init(&probe, scfg) == CH_OK);
    ch_tcp_close(tcp_public(&probe));
    CHECK(io_calls == 0);
}

#endif
