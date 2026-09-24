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
#include "test_random.h"
#include "tls.h"
#ifdef CH_TRUST_WEBPKI
#include "webpki.h"
#endif

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

// Persists one ticket as "identity-hex psk-hex age_add" so a later run can resume with it. A
// fourth field carries what resumption presents back: the CA build's epoch, for
// cfg.ticket_epoch, or the webpki build's binding in hex, for cfg.ticket_binding.
static void on_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    (void)fprintf(stderr, "ticket: id %zu bytes, lifetime %us\n", ticket->identity_len,
                  ticket->lifetime_s);
    if (g_ticket_path == NULL || g_ticket_saved) {
        return;
    }
    FILE *f = fopen(g_ticket_path, "w");
    if (f == NULL) {
        return;
    }
    put_hex(f, ticket->identity, ticket->identity_len);
    (void)fputc(' ', f);
    put_hex(f, ticket->psk, sizeof ticket->psk);
    (void)fprintf(f, " %u", ticket->age_add);
#ifdef CH_TRUST_CA
    (void)fprintf(f, " %u", ticket->epoch);
#endif
#ifdef CH_TRUST_WEBPKI
    (void)fputc(' ', f);
    put_hex(f, ticket->binding, sizeof ticket->binding);
#endif
    (void)fputc('\n', f);
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

static int parse_u32(const char *s, uint32_t *out) {
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (end == s || *end != 0 || v > 0xffffffffUL) {
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

// Loads a ticket saved by on_ticket. The identity replaces the psk-id, the derived PSK replaces
// the external one, and obfuscated_age = 0 + age_add (we reconnect within moments, so the true
// age rounds to zero). The fourth field stays text in extra, which keeps "0" when there is none.
static int load_ticket(const char *path, uint8_t *id, size_t *id_len, uint8_t *psk, size_t *psk_len,
                       uint32_t *age, char extra[2 * SHA256_LEN + 1]) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    char id_hex[2 * CH_TICKET_ID_MAX + 1];
    char psk_hex[2 * SHA256_LEN + 1];
    char age_str[16];
    int rc = fscanf(f, "%640s %64s %15s %64s", id_hex, psk_hex, age_str, extra);
    (void)fclose(f);
    if (rc < 3 || parse_u32(age_str, age) != 0) {
        return -1;
    }
    *id_len = unhex(id_hex, id, CH_TICKET_ID_MAX);
    *psk_len = unhex(psk_hex, psk, SHA256_LEN);
    return (*id_len > 0 && *psk_len == SHA256_LEN) ? 0 : -1;
}

// Owns the "pin:<pubkey-hex>[,<pubkey2-hex>]" form: parses one or two
// hex pins into cfg (the second pin is the staged rotation key).
static int setup_pin(char *arg, ch_cfg *cfg) {
    // Sized for the largest pin either build takes: an RSA-3072 modulus.
    // ch_connect enforces the exact length its compiled algorithm needs.
    static uint8_t pin[384];
    static uint8_t pin2[384];
    char *sep = strchr(arg, ',');
    if (sep != NULL) {
        *sep = 0;
    }
    size_t n = unhex(arg, pin, sizeof pin);
    if (n == 0) {
        (void)fprintf(stderr, "pin must be hex: P-256 X||Y or an RSA modulus\n");
        return -1;
    }
    cfg->server_pubkey = pin;
    cfg->server_pubkey_len = n;
    if (sep != NULL) {
        size_t n2 = unhex(sep + 1, pin2, sizeof pin2);
        if (n2 == 0) {
            (void)fprintf(stderr, "second pin must be hex like the first\n");
            return -1;
        }
        cfg->server_pubkey2 = pin2;
        cfg->server_pubkey2_len = n2;
    }
    (void)fprintf(stderr, "pinned-key mode (%zu-byte key%s)\n", n,
                  sep != NULL ? " + staged next" : "");
    return 0;
}

#ifdef CH_TRUST_CA
// The stored revocation epoch, kept as one decimal number in a file:
// smallest thing that behaves like the integrator's persistent
// storage. A missing file reads as epoch 0.
static const char *g_epoch_path;

static int epoch_load_file(void *io, uint32_t *value) {
    (void)io;
    *value = 0;
    FILE *f = fopen(g_epoch_path, "r");
    if (f == NULL) {
        return 0;
    }
    unsigned long v = 0;
    int got = fscanf(f, "%lu", &v);
    (void)fclose(f);
    if (got != 1 || v > CH_EPOCH_MAX) {
        return -1;
    }
    *value = (uint32_t)v;
    return 0;
}

static int epoch_store_file(void *io, uint32_t value) {
    (void)io;
    FILE *f = fopen(g_epoch_path, "w");
    if (f == NULL) {
        return -1;
    }
    (void)fprintf(f, "%u\n", value);
    return fclose(f) == 0 ? 0 : -1;
}
#endif

// A ticket file's fourth field: the webpki binding, required, or the epoch, "0" when absent.
static int load_ticket_extra(const char *extra, ch_cfg *cfg, uint32_t *ticket_epoch) {
#ifdef CH_TRUST_WEBPKI
    static uint8_t binding[SHA256_LEN];
    (void)ticket_epoch;
    cfg->ticket_binding = binding;
    return unhex(extra, binding, sizeof binding) == sizeof binding ? 0 : -1;
#else
    (void)cfg;
    return parse_u32(extra, ticket_epoch);
#endif
}

// Owns the "@ticket-file" form: loads a saved ticket into cfg for resumption.
static int setup_ticket(const char *path, ch_cfg *cfg, uint8_t *psk, uint8_t *id) {
    size_t id_len = 0;
    size_t psk_len = 0;
    uint32_t age = 0;
    uint32_t ticket_epoch = 0;
    char extra[2 * SHA256_LEN + 1] = "0";
    if (load_ticket(path, id, &id_len, psk, &psk_len, &age, extra) != 0 ||
        load_ticket_extra(extra, cfg, &ticket_epoch) != 0) {
        (void)fprintf(stderr, "bad ticket file: %s\n", path);
        return -1;
    }
    cfg->psk = psk;
    cfg->psk_len = psk_len;
    cfg->psk_id = id;
    cfg->psk_id_len = id_len;
    cfg->resumption = 1;
    cfg->obfuscated_age = age;
    cfg->ticket_epoch = ticket_epoch;
    (void)fprintf(stderr, "resuming with a %zu-byte ticket (epoch %u)\n", id_len, ticket_epoch);
    return 0;
}

#ifdef CH_TRUST_WEBPKI
// The webpki arm: anchors, SPKI pins, hostname, clock and ALPN.
#include "tls_client_webpki.h"
#endif

// Fills the auth part of cfg: one branch per argv form — "pin:..." for
// pinned-key mode, "@file" for a saved ticket, or an external psk-hex +
// identity pair. The CA-mode build adds its "ca:" form as one more
// branch here.
static int setup_psk(char **argv, ch_cfg *cfg, uint8_t *psk, size_t psk_cap, uint8_t *id) {
    if (strncmp(argv[3], "pin:", 4) == 0) {
        return setup_pin(argv[3] + 4, cfg);
    }
#ifdef CH_TRUST_WEBPKI
    if (strncmp(argv[3], "webpki:", 7) == 0) {
        // "@file" in the psk-id slot resumes a ticket a webpki run saved.
        int rc = setup_webpki(argv[3] + 7, cfg);
        return rc == 0 && argv[4][0] == '@' ? setup_ticket(argv[4] + 1, cfg, psk, id) : rc;
    }
#endif
    if (strncmp(argv[3], "ca:", 3) == 0) {
        // The CA build reads the same slots as a CA key; the prefix
        // only names the operator's intent.
        return setup_pin(argv[3] + 3, cfg);
    }
    if (argv[3][0] == '@') {
        return setup_ticket(argv[3] + 1, cfg, psk, id);
    }
    cfg->psk = psk;
    cfg->psk_len = unhex(argv[3], psk, psk_cap);
    if (cfg->psk_len == 0) {
        return -1;
    }
    cfg->psk_id = (const uint8_t *)argv[4];
    cfg->psk_id_len = strlen(argv[4]);
    return 0;
}

// Owns the TCP setup: resolves host and port, connects with a 10-second
// receive timeout, and returns the socket, or -1 on failure.
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

// Owns the echo loop: sends each stdin line, prints the reply. Returns the
// process exit code, or -1 once stdin ends and the caller should close.
static int echo_lines(ch_tls *tls) {
    char line[512];
    while (fgets(line, sizeof line, stdin) != NULL) {
        if (ch_write(tls, (const uint8_t *)line, strlen(line)) != CH_OK) {
            return 1;
        }
        uint8_t reply[512];
        int got = ch_read(tls, reply, sizeof reply);
        if (got <= 0) {
            (void)fprintf(stderr, "read: %d\n", got);
            return got == 0 ? 0 : 1;
        }
        (void)fwrite(reply, 1, (size_t)got, stdout);
        (void)fflush(stdout);
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 5 || argc > 7) {
        (void)fprintf(stderr,
                      "usage: %s host port psk-hex psk-id [save-ticket-file [epoch-file]]\n"
                      "       %s host port @ticket-file - [save-ticket-file [epoch-file]]\n"
                      "       %s host port pin:hex[,hex2] - [save-ticket-file [epoch-file]]\n"
                      "       %s host port webpki:name-file,spki-file|- @ticket-file|- "
                      "[save-ticket-file]\n",
                      argv[0], argv[0], argv[0], argv[0]);
        return 2;
    }
    g_ticket_path = argc >= 6 && argv[5][0] != '-' ? argv[5] : NULL;
    int fd = dial_host(argv[1], argv[2]);
    if (fd < 0) {
        return 2;
    }

    uint8_t psk[64];
    uint8_t id[CH_TICKET_ID_MAX];
#ifdef CH_TRUST_CA
    // The CA build's floor covers a two-certificate flight.
    static uint8_t rxbuf[4096];
#elif defined(CH_TRUST_WEBPKI)
    // The web PKI floor covers four entries of 3072 bytes.
    static uint8_t rxbuf[CH_MIN_RXBUF];
#else
    static uint8_t rxbuf[2048];
#endif
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
    // REQUIRE_PQ in the environment sets ch_cfg.require_pq, so e2e drives
    // the flag without a new positional argument.
    cfg.require_pq = getenv("REQUIRE_PQ") != NULL;
#ifdef CH_TRUST_WEBPKI
    setup_alpn(&cfg);
#endif
#ifdef CH_TRUST_CA
    if (argc == 7) {
        g_epoch_path = argv[6];
        cfg.epoch_load = epoch_load_file;
        cfg.epoch_store = epoch_store_file;
    }
#endif

    static ch_tls tls;
    int rc = ch_connect(&tls, &cfg);
    if (rc != CH_OK) {
        (void)fprintf(stderr, "handshake failed: %d\n", rc);
        return 1;
    }
    (void)fprintf(stderr, "connected\n");
    // e2e asserts on this line: the group the ServerHello selected.
    (void)fprintf(stderr, "group 0x%04x\n", (unsigned)tls.group);
#ifdef CH_SUITE_AES_GCM
    // And the cipher suite, in a build that can negotiate one.
    (void)fprintf(stderr, "suite 0x%04x\n", (unsigned)tls.suite);
#endif
#ifdef CH_TRUST_WEBPKI
    report_webpki(&cfg, &tls);
#endif
    if (cfg.server_pubkey != NULL) {
        // e2e asserts on this line to watch rotation: 2 = the staged pin.
        (void)fprintf(stderr, "pin slot %u\n", tls.pin_slot);
    }
#ifdef CH_TRUST_CA
    if (cfg.epoch_load != NULL) {
        // e2e asserts on this line to watch the epoch move up.
        (void)fprintf(stderr, "epoch %u store_failed %u\n", tls.epoch, tls.epoch_store_failed);
    }
#endif

    int exit_code = echo_lines(&tls);
    if (exit_code >= 0) {
        return exit_code;
    }
    ch_close(&tls);
    (void)close(fd);
    return 0;
}
