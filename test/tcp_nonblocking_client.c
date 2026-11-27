// The TRANSPORT=tcp-nonblocking client, run against a real TLS 1.3 server. It is
// bin/tlsclient's PSK case with one difference, which is the whole point
// of the mode: this program owns the socket during the handshake and
// chapulin never touches it.
//
// test/e2e.sh runs it against the same server bin/tlsclient uses, so a
// green test here says the non-blocking driver reaches the same connected
// session the blocking one does, over the same wire.
//
// The loop below is what a caller with an event loop writes, minus the
// event loop: collect what chapulin owes, send it, read what arrives,
// feed it back, and stop when the state says connected. Nothing in it
// blocks inside chapulin. Once connected, the program keeps the bytes it
// reads in in_buf, and ch_read_in_place opens each record there
// (tcp_nonblocking.h).
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rand.h"
#include "session_convert.h"
#include "tcp_nonblocking.h"
#include "tls.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// The e2e tests need no unpredictability, and a fixed stream replays a
// failure exactly. Never a source outside tests.
void ch_rand_bytes(uint8_t *p, size_t n) {
    static uint8_t counter = 1;
    for (size_t i = 0; i < n; i++) {
        p[i] = counter++;
    }
}

// cfg.send: one send(), whose count chapulin reads, and it calls again
// for the rest (cfg.h).
static int sock_send(void *io, const uint8_t *p, size_t n) {
    ssize_t w = send(*(int *)io, p, n, 0);
    return w > 0 ? (int)w : -1;
}

// Writes all n bytes that ch_tcp_out staged, and returns 0, or -1 when
// the socket refuses them.
static int sock_write_all(int fd, const uint8_t *p, size_t n) {
    while (n > 0) {
        ssize_t w = send(fd, p, n, 0);
        if (w <= 0) {
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
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

// Sends everything chapulin has staged. It returns 0 once ch_tcp_out
// answers that nothing is owed, and 1 when it answers anything else, which
// after a failure comes right after the alert record has gone out.
static int send_staged(ch_tcp_priv *r, int fd) {
    uint8_t out_buf[4096];
    for (;;) {
        size_t n = 0;
        if (ch_tcp_out(tcp_public(r), out_buf, sizeof out_buf, &n) != CH_OK) {
            return 1;
        }
        if (n == 0) {
            return 0;
        }
        if (sock_write_all(fd, out_buf, n) != 0) {
            return 1;
        }
    }
}

// The bytes the peer sent that no call has consumed yet, for the
// handshake and then for the reads. It is as long as cfg.buf: the session
// takes no record longer than cfg.buf_len, and the records of one message
// in parts take no more than that together (tcp_nonblocking.h).
static uint8_t in_buf[16384];

// The records one read takes at most before it gives up: the records that
// carry no data, such as a NewSessionTicket, and the recv calls between
// them.
#define READ_STEPS_MAX 64

// Drives the handshake to connected. Everything chapulin wants to say
// leaves through send_staged, and everything the peer says arrives through
// in_buf; leftover counts the bytes of a record that has not all arrived,
// which ch_tcp_in leaves for the next call. Once connected, *leftover_out
// gets that count, and the read after the handshake starts from them.
static int run_handshake(ch_tcp_priv *r, int fd, size_t *leftover_out) {
    size_t leftover = 0;
    for (;;) {
        if (send_staged(r, fd) != 0) {
            return 1;
        }
        if (ch_tcp_state(tcp_public(r)) == CH_ST_CONNECTED) {
            *leftover_out = leftover;
            return 0;
        }
        ssize_t got = recv(fd, in_buf + leftover, sizeof in_buf - leftover, 0);
        if (got <= 0) {
            (void)fprintf(stderr, "recv: %zd\n", got);
            return 1;
        }
        size_t have = leftover + (size_t)got;
        size_t used = 0;
        int rc = ch_tcp_in(tcp_public(r), in_buf, have, &used);
        if (rc != CH_OK) {
            // The failure staged its alert record, which goes to the
            // server before the connection closes.
            (void)fprintf(stderr, "rec_in: %d alert=%u\n", rc, ch_alert_sent(tls_public(&r->t)));
            (void)send_staged(r, fd);
            return 1;
        }
        leftover = have - used;
        memmove(in_buf, in_buf + used, leftover);
    }
}

// Reads the first record of application data into stdout. Each record is
// opened where it lies in in_buf, and a record that carries no data is
// dropped and the read goes on. On a failure the alert that
// ch_read_in_place wrote goes to the server before the connection closes.
static int read_reply(ch_tcp_priv *r, int fd, size_t have) {
    for (int step = 0; step < READ_STEPS_MAX; step++) {
        uint8_t alert[CH_ALERT_RECORD_LEN];
        ch_read_result result = {0};
        int rc =
            ch_read_in_place(ch_tcp_tls(tcp_public(r)), in_buf, have, alert, sizeof alert, &result);
        if (rc == CH_OK && result.pt_len > 0) {
            (void)fwrite(in_buf + result.pt_off, 1, result.pt_len, stdout);
            return 0;
        }
        if (rc == CH_OK) {
            have -= result.consumed;
            memmove(in_buf, in_buf + result.consumed, have);
            continue;
        }
        ssize_t got = rc == CH_TCP_AGAIN && have < sizeof in_buf
                          ? recv(fd, in_buf + have, sizeof in_buf - have, 0)
                          : -1;
        if (got <= 0) {
            (void)fprintf(stderr, "read: %d\n", rc);
            (void)sock_write_all(fd, alert, result.reply_len);
            return 1;
        }
        have += (size_t)got;
    }
    return 1;
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
    // Used only after the handshake, by ch_write and ch_close. No call
    // reads through a recv, and ch_tcp_init refuses one (tcp_nonblocking.h).
    cfg.send = sock_send;
    cfg.io = &fd;

    static ch_tcp_priv r;
    int rc = ch_tcp_init(tcp_public(&r), &cfg);
    if (rc != CH_OK) {
        (void)fprintf(stderr, "rec_init: %d\n", rc);
        return 1;
    }
    size_t leftover = 0;
    if (run_handshake(&r, fd, &leftover) != 0) {
        return 1;
    }
    // stderr, because e2e compares stdout against the echoed line alone.
    (void)fprintf(stderr, "rec: connected\n");

    // The session is an ordinary connected ch_tls now: one echo, then a
    // clean close, which is what proves the handoff works.
    char line[512];
    if (fgets(line, sizeof line, stdin) != NULL) {
        if (ch_write(ch_tcp_tls(tcp_public(&r)), (const uint8_t *)line, strlen(line)) != CH_OK) {
            return 1;
        }
        if (read_reply(&r, fd, leftover) != 0) {
            return 1;
        }
        (void)fflush(stdout);
    }
    ch_close(ch_tcp_tls(tcp_public(&r)));
    (void)close(fd);
    return 0;
}
