// Host e2e client: connects to host port, speaks the matasapos profile,
// sends each line from stdin, prints what the server answers. Exists for
// test/e2e.sh; firmware replaces this file and nothing below it.
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "ms_assert.h"
#include "rand.h"
#include "tls.h"

noreturn void ms_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

void ms_rand_bytes(uint8_t *p, size_t n) {
    arc4random_buf(p, n);
}

static int io_send(void *io, const uint8_t *p, size_t n) {
    int fd = *(const int *)io;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) {
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int io_recv(void *io, uint8_t *p, size_t n) {
    ssize_t r = read(*(const int *)io, p, n);
    return r <= 0 ? -1 : (int)r;
}

static void on_ticket(void *io, const ms_ticket *tk) {
    (void)io;
    (void)fprintf(stderr, "ticket: id %zu bytes, lifetime %us\n", tk->identity_len, tk->lifetime_s);
}

static int nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

static size_t unhex(const char *hex, uint8_t *out, size_t cap) {
    size_t n = strlen(hex) / 2;
    if (n > cap) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        int hi = nibble(hex[2 * i]);
        int lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        (void)fprintf(stderr, "usage: %s host port psk-hex psk-id\n", argv[0]);
        return 2;
    }
    struct addrinfo hints = {0};
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *ai = NULL;
    if (getaddrinfo(argv[1], argv[2], &hints, &ai) != 0) {
        return 2;
    }
    int fd = socket(ai->ai_family, ai->ai_socktype, 0);
    struct timeval tv = {10, 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (fd < 0 || connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
        perror("connect");
        return 2;
    }
    freeaddrinfo(ai);

    uint8_t psk[64];
    size_t psklen = unhex(argv[3], psk, sizeof psk);
    if (psklen == 0) {
        return 2;
    }
    static uint8_t rxbuf[2048];
    ms_cfg cfg = {0};
    cfg.psk = psk;
    cfg.psk_len = psklen;
    cfg.psk_id = (const uint8_t *)argv[4];
    cfg.psk_id_len = strlen(argv[4]);
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = io_send;
    cfg.recv = io_recv;
    cfg.io = &fd;
    cfg.on_ticket = on_ticket;

    static ms_tls tls;
    int rc = ms_connect(&tls, &cfg);
    if (rc != MS_OK) {
        (void)fprintf(stderr, "handshake failed: %d\n", rc);
        return 1;
    }
    (void)fprintf(stderr, "connected\n");

    char line[512];
    while (fgets(line, sizeof line, stdin) != NULL) {
        if (ms_write(&tls, (const uint8_t *)line, strlen(line)) != MS_OK) {
            return 1;
        }
        uint8_t reply[512];
        int got = ms_read(&tls, reply, sizeof reply);
        if (got <= 0) {
            (void)fprintf(stderr, "read: %d\n", got);
            return got == 0 ? 0 : 1;
        }
        (void)fwrite(reply, 1, (size_t)got, stdout);
        (void)fflush(stdout);
    }
    ms_close(&tls);
    (void)close(fd);
    return 0;
}
