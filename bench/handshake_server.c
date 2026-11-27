// The server side of the connection
// https://github.com/c4milo/chapulin/issues/188 measures, over chapulin's
// TRANSPORT=tcp-nonblocking object: bench/handshake-n2.sh builds this file
// against the object build.zig makes with colibri's options, and counts
// it beside bench/handshake_openssl_server.c.
//
// It calls the object as colibri's server does: ch_srv_tcp_init and
// ch_srv_tcp_in until the handshake is complete, then ch_read_in_place,
// ch_write and ch_close. Its identity is a P-256 leaf and the root that
// signed it, read from PEM files through ch_chain_from_pem and
// ch_p256_key_from_pem. It offers ALPN h2 and http/1.1, holds a cookie
// key and no ticket key, so every handshake is a full one. Each draw of
// randomness is one getentropy call for each 256 bytes.
//
// Usage: handshake_server PORT CONNECTIONS COUNTED CPU CHAIN_PEM KEY_PEM [--count]
//
// CPU is the ch_cfg.cpu value every session states, such as 0xe7. Each
// connection reads a request of REQUEST_LEN bytes, writes a response of
// RESPONSE_LEN bytes, reads the client's close_notify and sends its own
// (bench/handshake_window.h).
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#include "ch_assert.h"
#include "handshake_window.h"
#include "pem_files.h"
#include "session_convert.h"
#include "srv_tcp_nonblocking.h"
#include "tcp_nonblocking.h"
#include "tls.h"

#define REQUEST_LEN 100
#define RESPONSE_LEN 256
#define PEM_MAX 8192
#define DER_MAX 4096
#define CHAIN_MAX 4
// Room for a whole record of the largest plaintext and its overhead.
#define RECORD_ROOM (16384 + 256)

static uint8_t rx_buf[RECORD_ROOM];
static uint8_t chain_der[DER_MAX];
static ch_cert chain[CHAIN_MAX];
static uint8_t priv[32];
static uint8_t pub[64];
static uint8_t cookie_key[CH_SRV_COOKIE_KEY_LEN];
static const ch_alpn_protocol alpn[2] = {
    {(const uint8_t *)"h2",       2},
    {(const uint8_t *)"http/1.1", 8},
};
static ch_cfg cfg;
static ch_tcp_priv session;

// The socket of the connection in progress, and the bytes read from it
// that no call has consumed yet.
static struct {
    int fd;
    uint8_t bytes[RECORD_ROOM];
    size_t len;
} wire;

static void fail(const char *what) {
    fprintf(stderr, "handshake_server: %s\n", what);
    exit(1);
}

// The image's handler for a programmer-error invariant (ch_assert.h).
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    fprintf(stderr, "handshake_server: %s:%d: %s\n", file, line, cond);
    abort();
}

// RAND=session's source: getentropy fills at most 256 bytes a call.
static void draw(void *rand_io, uint8_t *p, size_t n) {
    (void)rand_io;
    while (n > 0) {
        size_t take = n < 256 ? n : 256;
        if (getentropy(p, take) != 0) {
            fail("getentropy failed");
        }
        p += take;
        n -= take;
    }
}

static int send_all(void *io, const uint8_t *p, size_t n) {
    (void)io;
    while (n > 0) {
        ssize_t sent = write(wire.fd, p, n);
        if (sent <= 0) {
            return -1;
        }
        p += sent;
        n -= (size_t)sent;
    }
    return 0;
}

static int send_bytes(void *io, const uint8_t *p, size_t n) {
    return send_all(io, p, n) == 0 ? (int)n : -1;
}

// Opens the next record of wire where it lies, reading the socket until
// wire holds one whole, and drops it. Returns the call's result, with the
// plaintext copied to out: the bytes left over from the handshake first,
// then the socket's, as colibri's server reads them (tcp_nonblocking.h).
static int read_record(uint8_t *out, size_t cap, size_t *out_len) {
    for (;;) {
        uint8_t reply[CH_ALERT_RECORD_LEN];
        ch_read_result result;
        int rc = ch_read_in_place(ch_tcp_tls(tcp_public(&session)), wire.bytes, wire.len, reply,
                                  sizeof reply, &result);
        if (rc == CH_OK || rc == CH_ECLOSED) {
            *out_len = result.pt_len < cap ? result.pt_len : cap;
            memcpy(out, wire.bytes + result.pt_off, *out_len);
            memmove(wire.bytes, wire.bytes + result.consumed, wire.len - result.consumed);
            wire.len -= result.consumed;
            return rc;
        }
        if (rc != CH_TCP_AGAIN) {
            return rc;
        }
        ssize_t got = read(wire.fd, wire.bytes + wire.len, sizeof wire.bytes - wire.len);
        if (got <= 0) {
            return CH_EIO;
        }
        wire.len += (size_t)got;
    }
}

__attribute__((noinline)) void bench_handshake(void) {
    if (ch_srv_tcp_init(tcp_public(&session), &cfg) != CH_OK) {
        fail("ch_srv_tcp_init refused the configuration");
    }
    wire.len = 0;
    while (ch_tcp_state(tcp_public(&session)) != CH_ST_CONNECTED) {
        ssize_t got = read(wire.fd, wire.bytes + wire.len, sizeof wire.bytes - wire.len);
        if (got <= 0) {
            fail("the client closed during the handshake");
        }
        wire.len += (size_t)got;
        size_t consumed = 0;
        if (ch_srv_tcp_in(tcp_public(&session), wire.bytes, wire.len, &consumed) != CH_OK) {
            fail("ch_srv_tcp_in failed");
        }
        memmove(wire.bytes, wire.bytes + consumed, wire.len - consumed);
        wire.len -= consumed;
    }
    if (session.t.group != CH_GROUP_X25519 || session.t.suite != CH_TLS_AES_256_GCM_SHA384 ||
        session.t.alpn_selected != 0) {
        fail("the handshake did not end on x25519, TLS_AES_256_GCM_SHA384 and h2");
    }
}

__attribute__((noinline)) void bench_exchange(void) {
    uint8_t request[REQUEST_LEN];
    size_t have = 0;
    while (have < sizeof request) {
        size_t got = 0;
        if (read_record(request + have, sizeof request - have, &got) != CH_OK) {
            fail("ch_read_in_place did not return the request");
        }
        have += got;
    }
    uint8_t response[RESPONSE_LEN];
    memset(response, 'r', sizeof response);
    if (ch_write(ch_tcp_tls(tcp_public(&session)), response, sizeof response) != CH_OK) {
        fail("ch_write failed");
    }
    size_t got = 0;
    if (read_record(request, sizeof request, &got) != CH_ECLOSED) {
        fail("ch_read_in_place did not return the client's close_notify");
    }
    ch_close(ch_tcp_tls(tcp_public(&session)));
    close(wire.fd);
}

static void connection(int fd, void *context) {
    (void)context;
    wire.fd = fd;
    bench_window_open();
    bench_handshake();
    bench_window_handshake();
    bench_exchange();
    bench_window_close();
}

static size_t read_file(const char *path, uint8_t *out, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fail("cannot open a PEM file");
    }
    size_t n = fread(out, 1, cap, f);
    fclose(f);
    if (n == 0 || n == cap) {
        fail("a PEM file is empty or too long");
    }
    return n;
}

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr, "usage: %s PORT CONNECTIONS COUNTED CPU CHAIN_PEM KEY_PEM [--count]\n",
                argv[0]);
        return 2;
    }
    unsigned port = (unsigned)strtoul(argv[1], NULL, 10);
    unsigned connections = (unsigned)strtoul(argv[2], NULL, 10);
    unsigned counted = (unsigned)strtoul(argv[3], NULL, 10);
    uint32_t cpu = (uint32_t)strtoul(argv[4], NULL, 0);
    int count = argc > 7 && strcmp(argv[7], "--count") == 0;

    static uint8_t pem[PEM_MAX];
    size_t pem_len = read_file(argv[5], pem, sizeof pem);
    uint8_t chain_count = 0;
    if (ch_chain_from_pem(pem, pem_len, chain_der, sizeof chain_der, chain, CHAIN_MAX,
                          &chain_count) != CH_OK) {
        fail("ch_chain_from_pem refused the chain");
    }
    pem_len = read_file(argv[6], pem, sizeof pem);
    if (ch_p256_key_from_pem(cpu, pem, pem_len, chain[0].der, chain[0].len, priv, pub) != CH_OK) {
        fail("ch_p256_key_from_pem refused the key");
    }
    draw(NULL, cookie_key, sizeof cookie_key);

    cfg.buf = rx_buf;
    cfg.buf_len = sizeof rx_buf;
    cfg.send = send_bytes;
    cfg.rand_bytes = draw;
    cfg.cpu = cpu;
    cfg.alpn_protocols = alpn;
    cfg.alpn_count = 2;
    cfg.srv.ecdsa_p256.chain = chain;
    cfg.srv.ecdsa_p256.chain_count = chain_count;
    cfg.srv.ecdsa_p256.priv = priv;
    cfg.srv.ecdsa_p256.priv_len = sizeof priv;
    cfg.srv.ecdsa_p256.pub = pub;
    cfg.srv.ecdsa_p256.pub_len = sizeof pub;
    cfg.srv.cookie_key = cookie_key;
    cfg.srv.on_record_out = send_all;

    if (bench_counter_open(count) != 0) {
        fail("the kernel refused the instruction counter");
    }
    return bench_serve(port, connections, counted, connection, NULL);
}
