// Host e2e server: this tree's ROLE=server object over TCP, for
// test/e2e.sh. It proves one ECDSA P-256 identity with the certificate and
// key it is given, issues a resumption ticket after every handshake, reads
// one line, answers it reversed the way s_server -rev does, and closes.
// It serves one connection after another until it is killed, and prints
// two lines per connection, whether the handshake resumed a ticket and
// the NamedGroup ch_tls.group reports, which are what the e2e legs read. Firmware replaces this
// file and nothing below it.
//
// Usage: tlsserver <cert.der> <priv-hex> <pub-hex>
//
// priv-hex is the 32-byte P-256 private scalar and pub-hex the 64-byte
// X||Y point, both as hex. The ticket key and the cookie key are drawn
// fresh at start, so tickets live as long as this process, and the clock
// is time(), which is what ch_srv_cfg.now_seconds asks for.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rand.h"
#include "srv.h"
#include "srv_ticket.h"
#include "test_random.h"

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

static int nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

// Exactly n bytes of hex into out, or -1.
static int unhex_exact(const char *hex, uint8_t *out, size_t n) {
    if (strlen(hex) != 2 * n) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        int hi = nibble(hex[2 * i]);
        int lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static uint8_t cert_der[4096];
static uint8_t priv[32];
static uint8_t pub[64];
static uint8_t ticket_key[SRV_TICKET_KEY_LEN];
static uint8_t cookie_key[32];
static uint8_t rxbuf[16384 + 256];

static int load_identity(char **argv, ch_cert *cert) {
    FILE *f = fopen(argv[1], "rb");
    if (f == NULL) {
        return -1;
    }
    size_t n = fread(cert_der, 1, sizeof cert_der, f);
    (void)fclose(f);
    if (n == 0 || n == sizeof cert_der) {
        return -1;
    }
    cert->der = cert_der;
    cert->len = n;
    return unhex_exact(argv[2], priv, sizeof priv) != 0 ||
                   unhex_exact(argv[3], pub, sizeof pub) != 0
               ? -1
               : 0;
}

// Reads one line, answers it reversed with its newline kept last, and
// closes. A client that closes first gets nothing.
static void echo_reversed(ch_tls *t) {
    uint8_t line[512];
    int n = ch_read(t, line, sizeof line);
    if (n > 0) {
        size_t len = (size_t)n;
        size_t body = line[len - 1] == '\n' ? len - 1 : len;
        for (size_t i = 0; i < body / 2; i++) {
            uint8_t c = line[i];
            line[i] = line[body - 1 - i];
            line[body - 1 - i] = c;
        }
        (void)ch_write(t, line, len);
    }
    ch_close(t);
}

static int listen_any(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof addr;
    if (fd < 0 || bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(fd, 8) != 0 ||
        getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        return -1;
    }
    // The line test/e2e.sh reads the port from, in s_server's own shape.
    (void)printf("ACCEPT 127.0.0.1:%u\n", (unsigned)ntohs(addr.sin_port));
    (void)fflush(stdout);
    return fd;
}

int main(int argc, char **argv) {
    static ch_cert chain[1];
    if (argc != 4 || load_identity(argv, &chain[0]) != 0) {
        (void)fprintf(stderr, "usage: tlsserver <cert.der> <priv-hex> <pub-hex>\n");
        return 2;
    }
    ch_rand_bytes(ticket_key, sizeof ticket_key);
    ch_rand_bytes(cookie_key, sizeof cookie_key);
    // The boot-time check srv.h asks for: the key signs, and what it signs
    // verifies under the public key beside it.
    ch_cfg boot;
    memset(&boot, 0, sizeof boot);
    boot.srv.ecdsa_p256.chain = chain;
    boot.srv.ecdsa_p256.chain_count = 1;
    boot.srv.ecdsa_p256.priv = priv;
    boot.srv.ecdsa_p256.priv_len = sizeof priv;
    boot.srv.ecdsa_p256.pub = pub;
    boot.srv.ecdsa_p256.pub_len = sizeof pub;
    if (ch_srv_check(&boot) != CH_OK) {
        (void)fprintf(stderr, "tlsserver: the key pair does not sign and verify\n");
        return 2;
    }
    int lfd = listen_any();
    if (lfd < 0) {
        perror("listen");
        return 1;
    }
    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            continue;
        }
        struct timeval tv = {10, 0};
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        ch_cfg cfg;
        memset(&cfg, 0, sizeof cfg);
        cfg.buf = rxbuf;
        cfg.buf_len = sizeof rxbuf;
        cfg.send = io_send;
        cfg.recv = io_recv;
        cfg.io = &fd;
        cfg.srv.ecdsa_p256.chain = chain;
        cfg.srv.ecdsa_p256.chain_count = 1;
        cfg.srv.ecdsa_p256.priv = priv;
        cfg.srv.ecdsa_p256.priv_len = sizeof priv;
        cfg.srv.ecdsa_p256.pub = pub;
        cfg.srv.ecdsa_p256.pub_len = sizeof pub;
        cfg.srv.cookie_key = cookie_key;
        cfg.srv.ticket_key = ticket_key;
        cfg.srv.now_seconds = (uint64_t)time(NULL);
        static ch_tls t;
        int rc = ch_srv_accept(&t, &cfg);
        if (rc == CH_OK) {
            (void)printf("handshake: %s\n", t.psk_selected ? "resumed" : "full");
            (void)printf("group: 0x%04x\n", (unsigned)t.group);
            (void)fflush(stdout);
            echo_reversed(&t);
        } else {
            (void)printf("handshake failed: %d\n", rc);
            (void)fflush(stdout);
        }
        (void)close(fd);
    }
}
