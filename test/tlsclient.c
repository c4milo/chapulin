// Host e2e client: connects to host port, speaks the chapulin profile,
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

#include "ch_assert.h"
#include "rand.h"
#include "testrand.h"
#include "tls.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
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

static const char *g_ticket_path; // save the first ticket here, if set
static int g_ticket_saved;

static void put_hex(FILE *f, const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        (void)fprintf(f, "%02x", p[i]);
    }
}

// Persists one ticket as "identity-hex psk-hex age_add" so a later run can
// resume with it.
static void on_ticket(void *io, const ch_ticket *tk) {
    (void)io;
    (void)fprintf(stderr, "ticket: id %zu bytes, lifetime %us\n", tk->identity_len, tk->lifetime_s);
    if (g_ticket_path == NULL || g_ticket_saved) {
        return;
    }
    FILE *f = fopen(g_ticket_path, "w");
    if (f == NULL) {
        return;
    }
    put_hex(f, tk->identity, tk->identity_len);
    (void)fputc(' ', f);
    put_hex(f, tk->psk, sizeof tk->psk);
    (void)fprintf(f, " %u\n", tk->age_add);
    (void)fclose(f);
    g_ticket_saved = 1;
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
    size_t len = strlen(hex);
    if (len % 2 != 0) {
        return 0; // an odd trailing character is a typo, not padding
    }
    size_t n = len / 2;
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

// Loads a ticket saved by on_ticket. The identity replaces the psk-id, the
// derived PSK replaces the external one, and obfuscated_age = 0 + age_add
// (we reconnect within moments, so the true age rounds to zero).
static int load_ticket(const char *path, uint8_t *id, size_t *idlen, uint8_t *psk, size_t *psklen,
                       uint32_t *age) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    char idhex[2 * CH_TICKET_ID_MAX + 1];
    char pskhex[2 * SHA256_LEN + 1];
    char agestr[16];
    int rc = fscanf(f, "%640s %64s %15s", idhex, pskhex, agestr);
    (void)fclose(f);
    if (rc != 3) {
        return -1;
    }
    char *end = NULL;
    unsigned long age_add = strtoul(agestr, &end, 10);
    if (end == agestr || *end != 0 || age_add > 0xffffffffUL) {
        return -1;
    }
    *idlen = unhex(idhex, id, CH_TICKET_ID_MAX);
    *psklen = unhex(pskhex, psk, SHA256_LEN);
    *age = (uint32_t)age_add;
    return (*idlen > 0 && *psklen == SHA256_LEN) ? 0 : -1;
}

// Fills the auth part of cfg: "pin:<pubkey-hex>" for pinned-key mode, a
// saved ticket ("@file"), or an external psk-hex + identity pair.
static int setup_psk(char **argv, ch_cfg *cfg, uint8_t *psk, size_t pskcap, uint8_t *id) {
    static uint8_t pin[64];
    if (strncmp(argv[3], "pin:", 4) == 0) {
        if (unhex(argv[3] + 4, pin, sizeof pin) != sizeof pin) {
            (void)fprintf(stderr, "pin must be 128 hex chars (P-256 X||Y)\n");
            return -1;
        }
        cfg->server_pubkey = pin;
        (void)fprintf(stderr, "pinned-key mode\n");
        return 0;
    }
    if (argv[3][0] == '@') {
        size_t idlen = 0;
        size_t psklen = 0;
        uint32_t age = 0;
        if (load_ticket(argv[3] + 1, id, &idlen, psk, &psklen, &age) != 0) {
            (void)fprintf(stderr, "bad ticket file: %s\n", argv[3] + 1);
            return -1;
        }
        cfg->psk = psk;
        cfg->psk_len = psklen;
        cfg->psk_id = id;
        cfg->psk_id_len = idlen;
        cfg->resumption = 1;
        cfg->obfuscated_age = age;
        (void)fprintf(stderr, "resuming with a %zu-byte ticket\n", idlen);
        return 0;
    }
    cfg->psk = psk;
    cfg->psk_len = unhex(argv[3], psk, pskcap);
    if (cfg->psk_len == 0) {
        return -1;
    }
    cfg->psk_id = (const uint8_t *)argv[4];
    cfg->psk_id_len = strlen(argv[4]);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5 && argc != 6) {
        (void)fprintf(stderr,
                      "usage: %s host port psk-hex psk-id [save-ticket-file]\n"
                      "       %s host port @ticket-file - [save-ticket-file]\n",
                      argv[0], argv[0]);
        return 2;
    }
    g_ticket_path = argc == 6 ? argv[5] : NULL;
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
    uint8_t id[CH_TICKET_ID_MAX];
    static uint8_t rxbuf[2048];
    ch_cfg cfg = {0};
    if (setup_psk(argv, &cfg, psk, sizeof psk, id) != 0) {
        return 2;
    }
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = io_send;
    cfg.recv = io_recv;
    cfg.io = &fd;
    cfg.on_ticket = on_ticket;

    static ch_tls tls;
    int rc = ch_connect(&tls, &cfg);
    if (rc != CH_OK) {
        (void)fprintf(stderr, "handshake failed: %d\n", rc);
        return 1;
    }
    (void)fprintf(stderr, "connected\n");

    char line[512];
    while (fgets(line, sizeof line, stdin) != NULL) {
        if (ch_write(&tls, (const uint8_t *)line, strlen(line)) != CH_OK) {
            return 1;
        }
        uint8_t reply[512];
        int got = ch_read(&tls, reply, sizeof reply);
        if (got <= 0) {
            (void)fprintf(stderr, "read: %d\n", got);
            return got == 0 ? 0 : 1;
        }
        (void)fwrite(reply, 1, (size_t)got, stdout);
        (void)fflush(stdout);
    }
    ch_close(&tls);
    (void)close(fd);
    return 0;
}
