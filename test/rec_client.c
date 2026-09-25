// The TRANSPORT=tcp-nonblocking client, run against a real TLS 1.3 server. It is
// bin/tlsclient's PSK case with one difference, which is the whole point
// of the mode: this program owns the socket during the handshake and
// chapulin never touches it.
//
// test/e2e.sh runs it against the same server bin/tlsclient uses, so a
// green leg here says the non-blocking driver reaches the same connected
// session the blocking one does, over the same wire.
//
// The loop below is what a caller with an event loop writes, minus the
// event loop: collect what chapulin owes, send it, read what arrives,
// feed it back, and stop when the state says connected. Nothing in it
// blocks inside chapulin.
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rand.h"
#include "rec.h"
#include "tls.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// The e2e legs need no unpredictability, and a fixed stream replays a
// failure exactly. Never a source outside tests.
void ch_rand_bytes(uint8_t *p, size_t n) {
    static uint8_t counter = 1;
    for (size_t i = 0; i < n; i++) {
        p[i] = counter++;
    }
}

static int sock_send(void *io, const uint8_t *p, size_t n) {
    int fd = *(int *)io;
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, p + off, n - off, 0);
        if (w <= 0) {
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static int sock_recv(void *io, uint8_t *p, size_t n) {
    int fd = *(int *)io;
    ssize_t got = recv(fd, p, n, 0);
    return got <= 0 ? -1 : (int)got;
}

static int dial_host(const char *host, const char *port) {
    struct addrinfo hints = {0};
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *ai = NULL;
    if (getaddrinfo(host, port, &hints, &ai) != 0) {
        return -1;
    }
    int fd = socket(ai->ai_family, ai->ai_socktype, 0);
    struct timeval tv = {10, 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (fd < 0 || connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
        perror("connect");
        return -1;
    }
    freeaddrinfo(ai);
    return fd;
}

static int from_hex(const char *hex, uint8_t *out, size_t cap, size_t *len) {
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > cap) {
        return -1;
    }
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v = 0;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    *len = n / 2;
    return 0;
}

// Drives the handshake to connected. Everything chapulin wants to say
// leaves through out_buf, and everything the peer says arrives through
// in_buf; leftover_len holds the bytes of a record that has not all
// arrived, which ch_record_in leaves for the next call.
static int run_handshake(ch_record *r, int fd) {
    uint8_t out_buf[4096];
    uint8_t in_buf[16384];
    size_t leftover = 0;
    for (;;) {
        for (;;) {
            size_t n = 0;
            if (ch_record_out(r, out_buf, sizeof out_buf, &n) != CH_OK) {
                return 1;
            }
            if (n == 0) {
                break;
            }
            if (sock_send(&fd, out_buf, n) != 0) {
                return 1;
            }
        }
        if (ch_record_state(r) == CH_ST_CONNECTED) {
            return 0;
        }
        ssize_t got = recv(fd, in_buf + leftover, sizeof in_buf - leftover, 0);
        if (got <= 0) {
            (void)fprintf(stderr, "recv: %zd\n", got);
            return 1;
        }
        size_t have = leftover + (size_t)got;
        size_t used = 0;
        int rc = ch_record_in(r, in_buf, have, &used);
        if (rc != CH_OK) {
            (void)fprintf(stderr, "rec_in: %d alert=%u\n", rc, ch_record_alert(r));
            return 1;
        }
        leftover = have - used;
        memmove(in_buf, in_buf + used, leftover);
    }
}

int main(int argc, char **argv) {
    if (argc != 5) {
        (void)fprintf(stderr, "usage: %s host port psk-hex psk-id\n", argv[0]);
        return 2;
    }
    int fd = dial_host(argv[1], argv[2]);
    if (fd < 0) {
        return 1;
    }
    uint8_t psk[64];
    size_t psk_len = 0;
    if (from_hex(argv[3], psk, sizeof psk, &psk_len) != 0) {
        return 2;
    }

    static uint8_t buf[16384];
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.buf = buf;
    cfg.buf_len = sizeof buf;
    cfg.psk = psk;
    cfg.psk_len = psk_len;
    cfg.psk_id = (const uint8_t *)argv[4];
    cfg.psk_id_len = strlen(argv[4]);
    // Used only after the handshake, by ch_read and ch_write.
    cfg.send = sock_send;
    cfg.recv = sock_recv;
    cfg.io = &fd;

    static ch_record r;
    int rc = ch_record_init(&r, &cfg);
    if (rc != CH_OK) {
        (void)fprintf(stderr, "rec_init: %d\n", rc);
        return 1;
    }
    if (run_handshake(&r, fd) != 0) {
        return 1;
    }
    // stderr, because e2e compares stdout against the echoed line alone.
    (void)fprintf(stderr, "rec: connected\n");

    // The session is an ordinary connected ch_tls now: one echo, then a
    // clean close, which is what proves the handoff works.
    char line[512];
    if (fgets(line, sizeof line, stdin) != NULL) {
        if (ch_write(&r.t, (const uint8_t *)line, strlen(line)) != CH_OK) {
            return 1;
        }
        uint8_t reply[512];
        int got = ch_read(&r.t, reply, sizeof reply);
        if (got <= 0) {
            (void)fprintf(stderr, "read: %d\n", got);
            return 1;
        }
        (void)fwrite(reply, 1, (size_t)got, stdout);
        (void)fflush(stdout);
    }
    ch_close(&r.t);
    (void)close(fd);
    return 0;
}
