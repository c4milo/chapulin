/*
 * A chapulin client for the TRUST=webpki build: a host-side program
 * that verifies a public server's certificate chain against root
 * certificates you embed, checks the chain's dates against your clock,
 * and checks the server's name against the leaf's subjectAltName. An
 * S3-compatible object store is what the mode was built to reach
 * (docs/webpki.md).
 *
 * Everything except the trust decision matches the other examples in
 * this directory. You fill in a ch_cfg, call ch_connect, then ch_write,
 * ch_read, and ch_close. Three things change, and this file marks each
 * one:
 *
 *   1. The trust anchors. Instead of one pinned key, ch_cfg.anchors
 *      points at 1 to CH_WEBPKI_ANCHOR_MAX roots, each as two DER
 *      fields cut from the root certificate. Any anchor may certify any
 *      name, so configure only roots whose authority you accept over
 *      every name you will connect to.
 *   2. The hostname and the clock. ch_cfg.hostname is the ASCII name
 *      the leaf must carry, sent as the ClientHello's server_name, and
 *      ch_cfg.now_seconds is your clock, compared exactly with no skew
 *      tolerance.
 *   3. CH_MIN_RXBUF is 12,338 bytes. The build derives it from the
 *      largest chain it admits, and this file sizes its buffer from the
 *      constant.
 *
 * What the check covers: the chain verifies up to one of your anchors,
 * every certificate on the path is valid at now_seconds, and a dNSName
 * in the leaf's subjectAltName matches the hostname. What it does not
 * cover: revocation, Certificate Transparency, name constraints, and
 * resumption. docs/webpki.md, "What the mode does not check", is the
 * list; read it before deploying.
 *
 * Getting the anchors. Download the root certificate from the CA's own
 * site — Amazon Trust Services publishes Amazon Root CA 1 through 4 and
 * the Starfield Services Root G2 — and cut the two fields out of it:
 *
 *   examples/webpki-anchor.sh AmazonRootCA1.pem roots/AmazonRootCA1
 *
 * writes roots/AmazonRootCA1.name and roots/AmazonRootCA1.spki. Repeat
 * per root. AWS documents that an endpoint may move between its roots
 * without notice, so embed the whole set.
 *
 * Build the library, then this file against it:
 *
 *   make TRUST=webpki RAND=extern lib
 *   cc -Wall -Wextra -Wpedantic -Werror -std=c11 -D_DEFAULT_SOURCE \
 *      -DCH_TRUST_WEBPKI -DCH_RAND_EXTERN -I. \
 *      -o webpki_client examples/webpki_client.c bin/chapulin.o
 *
 * Pass -DCH_TRUST_WEBPKI and -DCH_RAND_EXTERN to your own translation
 * units too, not just to the library: the anchor, hostname and clock
 * fields of ch_cfg exist only under the first, CH_MIN_RXBUF depends on
 * it, and cfg.h refuses to compile without a declared entropy pattern.
 *
 * Run:
 *
 *   ./webpki_client s3.amazonaws.com 443 s3.amazonaws.com \
 *       roots/AmazonRootCA1.name roots/AmazonRootCA1.spki
 *
 * The first argument is where to connect, the third is the name the
 * certificate must carry; they differ when you connect through an
 * address. Each further pair is one anchor. The exchange below sends
 * one line and prints the reply, which is what test/e2e.sh checks
 * against a local server; against S3, replace it with an HTTP request.
 *
 * This builds on a POSIX host, which is where a webpki build runs.
 */

#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rand.h"
#include "tls.h"
#include "webpki.h"

// --- The trust anchors ---------------------------------------------------
//
// One anchor is a root's subject Name as its whole DER Name TLV and its
// public key as its whole DER SubjectPublicKeyInfo. The chain walk
// compares the Name byte for byte against an issuer Name and verifies
// the signature under the key; nothing else of the root is read, not
// even its dates (docs/webpki.md, "Trust anchors").
//
// The bytes are public data, so they need integrity but not secrecy.
// This example reads them from the files examples/webpki-anchor.sh
// writes, so it can run against a real server and so test/e2e.sh
// catches it if the API around it changes. A deployment embeds them as
// const arrays.
#define ANCHOR_NAME_MAX 512
#define ANCHOR_SPKI_MAX (CH_WEBPKI_KEY_MAX + 64)

static uint8_t g_anchor_name[CH_WEBPKI_ANCHOR_MAX][ANCHOR_NAME_MAX];
static uint8_t g_anchor_spki[CH_WEBPKI_ANCHOR_MAX][ANCHOR_SPKI_MAX];
static ch_trust_anchor g_anchors[CH_WEBPKI_ANCHOR_MAX];

// The whole file, or 0 when it does not open, is empty, or does not fit.
// Measuring first turns a wrong file into a message that names it: a
// truncated anchor would fail much later as CH_EAUTH, which reads like
// an attack rather than a provisioning mistake.
static size_t read_der_file(const char *path, uint8_t *out, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        (void)fprintf(stderr, "cannot open %s\n", path);
        return 0;
    }
    long size = -1;
    if (fseek(f, 0, SEEK_END) == 0) {
        size = ftell(f);
    }
    if (size <= 0 || (size_t)size > cap) {
        (void)fprintf(stderr, "%s: empty, unreadable, or over %zu bytes\n", path, cap);
        (void)fclose(f);
        return 0;
    }
    size_t got = 0;
    if (fseek(f, 0, SEEK_SET) == 0) {
        got = fread(out, 1, (size_t)size, f);
    }
    (void)fclose(f);
    if (got != (size_t)size) {
        (void)fprintf(stderr, "cannot read %s\n", path);
        return 0;
    }
    return got;
}

// Fills g_anchors from count name-file, spki-file pairs. Returns 0, or
// -1 with the file named.
static int read_anchors(char **paths, size_t count) {
    for (size_t i = 0; i < count; i++) {
        g_anchors[i].name = g_anchor_name[i];
        g_anchors[i].name_len = read_der_file(paths[2 * i], g_anchor_name[i], ANCHOR_NAME_MAX);
        g_anchors[i].spki = g_anchor_spki[i];
        g_anchors[i].spki_len = read_der_file(paths[2 * i + 1], g_anchor_spki[i], ANCHOR_SPKI_MAX);
        if (g_anchors[i].name_len == 0 || g_anchors[i].spki_len == 0) {
            return -1;
        }
    }
    return 0;
}

// --- Platform hooks ------------------------------------------------------

// Programmer-error invariants only (ch_assert.h). Bad peer input, short
// buffers, and I/O failures return ch_err codes instead, so nothing a
// peer sends can arrive here.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "assert %s:%d: %s\n", file, line, cond);
    abort();
}

// The random source (rand.h). Each handshake draws the ephemeral key
// exchange secret and the ClientHello random from it, so a guessable
// stream costs the session its confidentiality. This reads the host
// OS entropy source, which is what a webpki build has under it.
#ifdef __APPLE__
void ch_rand_bytes(uint8_t *p, size_t n) {
    arc4random_buf(p, n);
}
#else
#include <sys/random.h>
void ch_rand_bytes(uint8_t *p, size_t n) {
    while (n > 0) {
        ssize_t got = getrandom(p, n, 0); // capped per call, so loop
        if (got <= 0) {
            abort(); // no entropy, no handshake
        }
        p += got;
        n -= (size_t)got;
    }
}
#endif

// --- Transport -----------------------------------------------------------
//
// chapulin moves bytes only through these two callbacks and knows
// nothing else about the network. send moves all n bytes and returns
// 0; every other value is a failure. recv returns 1 to n bytes, or -1.
// Both block, bounded by the receive timeout dial sets, because the
// library owns no timer.

static int io_send(void *io, const uint8_t *p, size_t n) {
    int fd = *(const int *)io;
    while (n > 0) {
        ssize_t wrote = write(fd, p, n);
        if (wrote <= 0) {
            return -1;
        }
        p += wrote;
        n -= (size_t)wrote;
    }
    return 0;
}

static int io_recv(void *io, uint8_t *p, size_t n) {
    ssize_t got = read(*(const int *)io, p, n);
    return got <= 0 ? -1 : (int)got;
}

// Opens the TCP connection. The receive timeout is what bounds a
// handshake against a server that stops answering.
static int dial(const char *host, const char *port) {
    struct addrinfo hints = {0};
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *ai = NULL;
    if (getaddrinfo(host, port, &hints, &ai) != 0) {
        return -1;
    }
    int fd = socket(ai->ai_family, ai->ai_socktype, 0);
    if (fd >= 0) {
        struct timeval timeout = {10, 0};
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            (void)close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(ai);
    return fd;
}

// --- The session ---------------------------------------------------------

// Tickets arrive in this mode too, and the client parses and exposes
// them as RFC 9846 requires, but a webpki config cannot present one
// back: nothing binds a ticket to the hostname it was issued for, so
// ch_connect refuses a PSK in this mode and every connection is a full
// handshake (docs/webpki.md, "No PSK, and no resumption"). This
// example only reports what arrived.
static void on_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    (void)fprintf(stderr, "ticket: %zu-byte identity, lifetime %us, not presentable in this mode\n",
                  ticket->identity_len, ticket->lifetime_s);
}

// The ch_err codes a webpki session returns (cfg.h), in the words an
// operator needs. Every one of them kills the session: chapulin wipes
// its keys and you reconnect.
static const char *error_text(int rc) {
    switch (rc) {
    case CH_EINVAL:
        return "bad config: anchors, hostname, clock, a buffer under CH_MIN_RXBUF, or a PSK, "
               "pin or epoch callback this mode refuses";
    case CH_EAUTH:
        return "the chain did not verify: no anchor signed it, a certificate is outside "
               "now_seconds, the leaf does not name the hostname, or CertificateVerify failed";
    case CH_EPROTO:
        return "the server broke the one profile chapulin speaks, or sent a certificate "
               "outside the web PKI profile";
    case CH_ECAP:
        return "the receive buffer is too small for a message the server sent";
    case CH_EIO:
        return "the transport failed or closed";
    default:
        return "unexpected";
    }
}

// One request and one reply, to show that ch_write and ch_read do not
// change between trust modes. Returns 0 on success. Against S3 this is
// where an HTTP request goes.
static int one_exchange(ch_tls *tls) {
    static const uint8_t request[] = "listo\n";
    if (ch_write(tls, request, sizeof request - 1) != CH_OK) {
        (void)fprintf(stderr, "write failed\n");
        return -1;
    }
    // ch_read hands back what one record held, never more, so framing
    // stays the application's job. This reply is one line, so read
    // until the newline arrives.
    uint8_t reply[256];
    size_t have = 0;
    while (have < sizeof reply) {
        int got = ch_read(tls, reply + have, sizeof reply - have);
        if (got == 0) {
            break; // the peer closed before the newline
        }
        if (got < 0) {
            (void)fprintf(stderr, "read returned %d, %s\n", got, error_text(got));
            return -1;
        }
        have += (size_t)got;
        if (memchr(reply, '\n', have) != NULL) {
            break;
        }
    }
    (void)fwrite(reply, 1, have, stdout);
    (void)fflush(stdout);
    return 0;
}

// Fills in the config. Every field set here exists in cfg.h under
// CH_TRUST_WEBPKI, and this mode needs no others. What stays zero is
// deliberate: psk, psk_id, resumption, both pin slots and the epoch
// callbacks all stay unset, because ch_connect refuses a webpki config
// that sets any of them.
static void configure(ch_cfg *cfg, int *fd, const char *server_name, size_t anchor_count,
                      uint8_t *rxbuf, size_t rxbuf_len) {
    cfg->anchors = g_anchors;
    cfg->anchor_count = anchor_count;
    // The name the leaf must carry, as an A-label; ch_connect refuses
    // any other shape before it sends a byte.
    cfg->hostname = (const uint8_t *)server_name;
    cfg->hostname_len = strlen(server_name);
    // Your clock, compared exactly against every certificate's validity.
    // 0 is refused as an unset clock, so a host whose clock is not set
    // fails here rather than mid-handshake.
    cfg->now_seconds = (uint64_t)time(NULL);
    cfg->buf = rxbuf;
    cfg->buf_len = rxbuf_len;
    cfg->send = io_send;
    cfg->recv = io_recv;
    cfg->io = fd;
    cfg->on_ticket = on_ticket;
}

int main(int argc, char **argv) {
    // host, port, server-name, then 1 to CH_WEBPKI_ANCHOR_MAX pairs.
    if (argc < 6 || argc % 2 != 0 || (size_t)(argc - 4) / 2 > CH_WEBPKI_ANCHOR_MAX) {
        (void)fprintf(stderr,
                      "usage: %s host port server-name anchor.name anchor.spki"
                      " [anchor.name anchor.spki ...]\n"
                      "  1 to %d anchors, each cut from a root by examples/webpki-anchor.sh\n",
                      argv[0], CH_WEBPKI_ANCHOR_MAX);
        return 2;
    }
    size_t anchor_count = (size_t)(argc - 4) / 2;
    if (read_anchors(argv + 4, anchor_count) != 0) {
        return 2;
    }
    // POSIX only: writing to a socket the peer already closed must
    // return -1 to io_send, not kill the process.
    (void)signal(SIGPIPE, SIG_IGN);

    int fd = dial(argv[1], argv[2]);
    if (fd < 0) {
        (void)fprintf(stderr, "could not connect to %s:%s\n", argv[1], argv[2]);
        return 1;
    }

    // The receive buffer. Its size minus record overhead goes out as
    // the client's record_size_limit (RFC 8449), so the server can
    // never send a record this buffer cannot hold. CH_MIN_RXBUF is the
    // floor ch_connect accepts: the largest Certificate message the
    // mode admits, four entries of 3,072 bytes, plus the record that
    // completes it. A larger buffer is fine and raises the limit the
    // client advertises.
    static uint8_t rxbuf[CH_MIN_RXBUF];
    ch_cfg cfg = {0};
    configure(&cfg, &fd, argv[3], anchor_count, rxbuf, sizeof rxbuf);

    // One static session struct, the whole working set beside rxbuf.
    static ch_tls tls;
    int rc = ch_connect(&tls, &cfg);
    if (rc != CH_OK) {
        // Any error already wiped the key material and left the session
        // dead. There is no resumable error state: reconnect.
        (void)fprintf(stderr, "handshake failed: %d, %s\n", rc, error_text(rc));
        (void)close(fd);
        return 1;
    }
    (void)fprintf(stderr, "connected; the chain verified up to one of %zu anchors, group 0x%04x\n",
                  anchor_count, (unsigned)tls.group);

    int exit_code = one_exchange(&tls) == 0 ? 0 : 1;
    ch_close(&tls);
    (void)close(fd);
    return exit_code;
}
