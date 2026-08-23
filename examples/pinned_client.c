/*
 * Pinned-key mode, chapulin's default build: the device holds the
 * server's public key and checks the server's handshake signature
 * against it.
 *
 * A pin is public data. It needs integrity, not secrecy: an attacker who
 * reads it learns the same key the server hands to everyone who
 * connects. Provision it the way you provision a PSK, but the
 * requirement is different: a pin must be unmodifiable by anyone but
 * you, not unreadable.
 *
 * What this example shows:
 *   1. Where the pin comes from, and how long it must be in each of the
 *      two PIN builds.
 *   2. How to size the receive buffer. Pinned mode constrains it in a
 *      way PSK mode does not, and ch_connect cannot check the difference
 *      for you.
 *   3. The two-slot pin, and reading ch_tls.pin_slot after a connect to
 *      watch a key rotation move through a fleet.
 *
 * This file is written to be read and lifted. It builds; it proves
 * nothing. test/e2e.sh runs the live handshakes against OpenSSL and Go.
 *
 * Build it against the packaged library object, from the repo root:
 *
 *   make lib                                     # RSA-PSS pins
 *   cc -Wall -Wextra -Wpedantic -Werror -std=c11 -D_DEFAULT_SOURCE -I. \
 *      -o pinned_client examples/pinned_client.c bin/chapulin.o
 *
 * For P-256 pins, build the library with `make lib PIN=ecdsa` and add
 * -DCH_PIN_ECDSA to that cc line. -D_DEFAULT_SOURCE is for this file's
 * POSIX sockets, not for chapulin: glibc hides getaddrinfo and
 * getrandom under -std=c11 without it.
 *
 * Run: ./pinned_client 192.0.2.10 4433 server_pin.bin [next_pin.bin]
 */
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#ifndef __APPLE__
#include <sys/random.h> // getrandom; macOS has arc4random_buf instead
#endif

#include "ch_assert.h"
#include "rand.h"
#include "tls.h"

/*
 * --- Getting the pin -------------------------------------------------
 *
 * The pin is the server's public key as raw bytes: no PEM, no DER
 * wrapper, no certificate. Each build pins one algorithm, and the
 * Makefile's PIN variable picks which.
 *
 * Default build (PIN=rsa): the RSA modulus, big-endian, 256 to 384 bytes
 * in multiples of 8, which covers RSA-2048 through RSA-3072. chapulin
 * fixes the public exponent at 65537 and verifies RSA-PSS, so the
 * modulus is the whole pin.
 *
 *   openssl rsa -in server.key -noout -modulus \
 *     | sed 's/^Modulus=//' | xxd -r -p > server_pin.bin
 *
 * Swap `rsa -in server.key` for `x509 -in server.crt` when the
 * certificate is all you hold; both print the same modulus.
 *
 * PIN=ecdsa build: the P-256 public point as X||Y, exactly 64 bytes,
 * without the 0x04 uncompressed-point prefix. The last 64 bytes of the
 * DER SubjectPublicKeyInfo are exactly that.
 *
 *   openssl ec -in server.key -pubout -outform DER \
 *     | tail -c 64 > server_pin.bin
 *
 *   openssl x509 -in server.crt -pubkey -noout \
 *     | openssl ec -pubin -pubout -outform DER | tail -c 64 > server_pin.bin
 *
 * The RSA build also checks that the modulus is odd. Every real modulus
 * is, being a product of odd primes, so an even one is corrupted
 * provisioning: ch_connect rejects it with CH_EINVAL before sending
 * anything, instead of letting it surface later as a failed signature
 * that would read like an attack.
 *
 * One algorithm per build, and neither build carries the other's
 * verifier. An RSA pin handed to a PIN=ecdsa build is the wrong length,
 * and ch_connect answers CH_EINVAL.
 */

// The pin length this build accepts. Change 384 to 256 for an RSA-2048
// server: ch_connect compares the length you pass in
// ch_cfg.server_pubkey_len against its build rule, so a mismatch fails
// at setup rather than during the handshake.
#ifdef CH_PIN_ECDSA
#define PIN_LEN 64
#else
#define PIN_LEN 384
#endif

// These arrays are in RAM because read_pin fills them at startup. On a
// device the pins are more likely const objects in flash that
// provisioning wrote once and nothing copies: ch_cfg takes a pointer,
// and chapulin only reads through it.
static uint8_t g_pin_a[PIN_LEN];
static uint8_t g_pin_b[PIN_LEN];

// --- What a pinned build never does ----------------------------------
//
// It never parses the certificate. The default build compiles no DER
// parser at all: the Makefile leaves x509.c and x509_der.c out of the
// library object, and only TRUST=ca puts them back. chapulin hashes
// the Certificate message into the handshake transcript and reads
// nothing out of it.
//
// Authentication is one check: the server's CertificateVerify signature
// must verify under a pinned key. Everything else follows from that.
//
//   - A self-signed certificate works. So does an expired one.
//   - A certificate from a public CA proves nothing here unless the key
//     inside it is the key you pinned.
//   - Nothing reads the subject, the SAN list, notBefore, or notAfter,
//     and nothing walks a chain.
//   - There is no hostname check, and none is needed: the pin names one
//     key directly instead of naming a host and trusting an authority to
//     map it to a key.
//   - Nothing expires, so nothing forces rotation on a schedule. You
//     rotate deliberately through the two slots below, or you build
//     TRUST=ca and let a CA you run reissue server certificates
//     (docs/ca.md).

// --- Sizing the receive buffer ---------------------------------------
//
// You own this buffer; chapulin allocates nothing. Its size decides two
// things.
//
// First, the client advertises buf_len minus the 5-byte record header
// and the 16-byte AEAD tag as its record_size_limit (RFC 8449). A server
// that honors the extension can never send a record this buffer cannot
// hold, and one that ignores it fails the session with CH_ECAP once its record
// will not fit; only a body past the TLS maximum of 0x4000 + 256 bytes
// gets CH_EPROTO.
//
// Second — pinned mode's rule, not PSK mode's — the server's Certificate
// message is reassembled whole inside this same buffer.
// record_size_limit bounds records, and a handshake message spans as
// many records as it needs. A PSK handshake sends no certificate at all,
// and the flights it does send fit in the CH_MIN_RXBUF floor of 512
// bytes, so in PSK mode the floor is the only rule.
//
// ch_connect checks buf_len against CH_MIN_RXBUF and stops there. It
// cannot check the second rule, because a pinned build never parses the
// certificate and so cannot know how large the server's is. That
// measurement is yours:
//
//   openssl x509 -in server.crt -outform DER | wc -c
//
// Add the 4-byte message header and the certificate-list framing, then
// leave room. Count every certificate the server sends, not only the
// leaf — pinned mode ignores the extra ones but still buffers them — and
// count a stapled OCSP response or SCT list, which the server carries in
// the same message. A self-signed P-256 certificate runs about 600 bytes
// and an RSA-3072 one about 1.2 kB, so 2048 holds either with room to
// spare. A buffer too small fails the handshake with CH_ECAP mid-flight,
// not at setup with CH_EINVAL.
static uint8_t g_rxbuf[2048];

// --- The two hooks firmware provides ---------------------------------

// Programmer-error invariants only (ch_assert.h). Bad peer input, short
// buffers, and I/O failures return ch_err codes instead, so nothing a
// peer sends can arrive here. A device points this at its fault handler.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// The random source (rand.h). The handshake draws from it twice: the
// ephemeral x25519 private key and the ClientHello random. In pinned
// mode the ephemeral key carries all the confidentiality, so a guessable
// stream lets a passive attacker decrypt everything.
//
// SWAP THIS. The version below reads the host OS entropy source. A part
// with a hardware RNG wires the hook to that peripheral. A part without
// one links drbg.c and calls ch_drbg_seed once at boot with a seed
// layered from several sources; docs/entropy.md gives the recipe and the
// reasons. Either way the hook must not fail: a device without entropy
// has no business starting a handshake.
#ifdef __APPLE__
void ch_rand_bytes(uint8_t *p, size_t n) {
    arc4random_buf(p, n);
}
#else
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

// --- The transport: replace all of it --------------------------------
//
// chapulin makes no OS assumptions. It moves bytes only through these
// two callbacks and never touches a socket itself, so lwIP, a UART, or a
// vendor SDK stack replaces them the same way. POSIX sockets appear here
// because they are the illustration every reader already knows.
//
// The contract lives in cfg.h: send moves all n bytes and returns 0, and
// any other value — a positive byte count included — means failure; recv
// returns 1 to n bytes, or -1. Both block. chapulin runs no timers, so
// the only bound on a stalled peer is the one you set here.

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
    return 0; // every byte moved
}

static int io_recv(void *io, uint8_t *p, size_t n) {
    ssize_t got = read(*(const int *)io, p, n);
    // A short read is normal: chapulin reassembles records itself.
    return got <= 0 ? -1 : (int)got;
}

// Opens the TCP connection. Firmware replaces this with whatever its own
// stack calls; chapulin never sees it. The receive timeout does matter:
// it is the entire bound on a peer that goes quiet mid-handshake.
static int dial(const char *host, const char *port) {
    struct addrinfo hints = {0};
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *ai = NULL;
    if (getaddrinfo(host, port, &hints, &ai) != 0) {
        return -1;
    }
    int fd = socket(ai->ai_family, ai->ai_socktype, 0);
    if (fd < 0) {
        freeaddrinfo(ai);
        return -1;
    }
    struct timeval timeout = {10, 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);
    if (rc != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

// Loads one pin from provisioning storage.
//
// SWAP THIS. A device reads the bytes from flash or an EEPROM page, not
// from a file. Where they come from matters less than what can change
// them: a pin needs integrity, so it belongs where an update path you
// control writes it and a peer cannot.
static int read_pin(const char *path, uint8_t pin[PIN_LEN]) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        (void)fprintf(stderr, "cannot open %s\n", path);
        return -1;
    }
    // Measure before reading. The file holds the pin and nothing else: a
    // longer one would be read as its first PIN_LEN bytes, and that
    // truncated pin would fail much later as CH_EAUTH, which reads like
    // an attack. ch_connect checks the length too, but a check here says
    // "provisioning is wrong" instead of "the connection failed".
    if (fseek(f, 0, SEEK_END) != 0 || ftell(f) != PIN_LEN) {
        (void)fprintf(stderr, "%s: this build pins exactly %d bytes\n", path, PIN_LEN);
        (void)fclose(f);
        return -1;
    }
    size_t got = 0;
    if (fseek(f, 0, SEEK_SET) == 0) {
        got = fread(pin, 1, (size_t)PIN_LEN, f);
    }
    (void)fclose(f);
    if (got != (size_t)PIN_LEN) {
        (void)fprintf(stderr, "cannot read %s\n", path);
        return -1;
    }
    return 0;
}

// Tickets arrive in pinned mode too, and they are worth taking: a
// resumed connection presents the ticket as a PSK, so the signature
// verify — tens of milliseconds on the reference core, see the README's
// speed table — is paid once per ticket lifetime instead of once per
// connection. Storing one is PSK work: copy ticket->identity and
// ticket->psk, which are valid only during this call, then set psk,
// psk_id, resumption = 1, and obfuscated_age in the next ch_cfg. This
// example only reports what arrived.
static void on_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    (void)fprintf(stderr, "ticket: %zu-byte identity, lifetime %us\n", ticket->identity_len,
                  ticket->lifetime_s);
}

// The ch_err codes a pinned session returns (cfg.h), in the words an
// operator needs. Every one of them kills the session: chapulin wipes
// its keys and you reconnect. There is no resumable error here.
static const char *error_text(int rc) {
    switch (rc) {
    case CH_EINVAL:
        return "bad config: pin length, an even RSA modulus, or a buffer under CH_MIN_RXBUF";
    case CH_EAUTH:
        return "the server proved possession of neither pinned key";
    case CH_EPROTO:
        return "the server broke the one profile chapulin speaks";
    case CH_ECAP:
        return "the receive buffer is too small for a message the server sent";
    case CH_EIO:
        return "the transport failed or closed";
    default:
        return "unexpected";
    }
}

// --- The two-slot pin ------------------------------------------------
//
// ch_cfg holds up to two pins. Slot A (server_pubkey) is the key the
// server signs with today; slot B (server_pubkey2) is the next key,
// staged before the server switches to it. The handshake accepts a
// server that proves possession of either one and records which matched
// in ch_tls.pin_slot: 1 for slot A, 2 for slot B, 0 before a pinned
// handshake finishes.
//
// The pair is what makes a rotation survivable without a CA. Push slot B
// to the fleet over the TLS session it will replace, switch the server,
// then promote B into A and stage the next key. Read pin_slot after each
// connect to see which key a device is using; the value is public
// information, safe to report anywhere. docs/rotation.md has the full
// procedure and the one case it cannot fix: a device that sleeps through
// both pushes trusts two keys the server no longer uses, and needs
// out-of-band re-provisioning.
//
// Slot B follows every slot-A rule — same length, same build, same
// odd-modulus check under PIN=rsa — and never stands alone: a config
// with only slot B fails with CH_EINVAL. Verification tries slot A
// first, so during the rotation window a connect to an already-switched
// server pays one failed verify before slot B matches. Promote promptly.

// Fills in the config. Every field set here exists in cfg.h, and pinned
// mode needs no others: no cipher list, no server name, no trust store.
// What stays zero is deliberate. psk and psk_id stay NULL because a
// config carrying both a PSK and a pin is a provisioning mistake, not
// something to resolve silently. The epoch callbacks stay NULL because
// only a TRUST=ca build enforces them, and a pinned build rejects them
// rather than accept revocation state it would ignore.
static void configure(ch_cfg *cfg, int *fd, int staged_pin) {
    cfg->server_pubkey = g_pin_a; // slot A
    cfg->server_pubkey_len = PIN_LEN;
    if (staged_pin) {
        cfg->server_pubkey2 = g_pin_b; // slot B, optional, never alone
        cfg->server_pubkey2_len = PIN_LEN;
    }
    cfg->buf = g_rxbuf;
    cfg->buf_len = sizeof g_rxbuf;
    cfg->send = io_send;
    cfg->recv = io_recv;
    cfg->io = fd; // handed back to both callbacks untouched
    cfg->on_ticket = on_ticket;
}

// One request and one reply: the smallest exchange that moves bytes both
// ways.
static int exchange(ch_tls *tls) {
    static const uint8_t request[] = "ping\n";
    // ch_write splits the bytes across as many records as they need and
    // returns CH_OK or an error. There is no partial write to retry.
    if (ch_write(tls, request, sizeof request - 1) != CH_OK) {
        (void)fprintf(stderr, "write failed\n");
        return -1;
    }
    static uint8_t reply[256];
    // ch_read returns the byte count, 0 once the peer closed cleanly, or
    // a negative ch_err. It hands back what one record held, and a record
    // is not a message boundary, so a real client loops until its own
    // protocol says it holds a whole message.
    int got = ch_read(tls, reply, sizeof reply);
    if (got < 0) {
        (void)fprintf(stderr, "read failed: %d, %s\n", got, error_text(got));
        return -1;
    }
    if (got == 0) {
        (void)fprintf(stderr, "the server closed the session\n");
        return 0;
    }
    (void)fwrite(reply, 1, (size_t)got, stdout);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4 && argc != 5) {
        (void)fprintf(stderr, "usage: %s host port pin-file [next-pin-file]\n", argv[0]);
        return 2;
    }
    int staged_pin = argc == 5;
    if (read_pin(argv[3], g_pin_a) != 0 || (staged_pin && read_pin(argv[4], g_pin_b) != 0)) {
        return 2;
    }
    int fd = dial(argv[1], argv[2]);
    if (fd < 0) {
        (void)fprintf(stderr, "cannot reach %s port %s\n", argv[1], argv[2]);
        return 1;
    }
    ch_cfg cfg = {0};
    configure(&cfg, &fd, staged_pin);

    // The session struct is about a kilobyte. It stays static, like every
    // other buffer in this file: chapulin never calls malloc, and the
    // code around it should not either.
    static ch_tls tls;
    int rc = ch_connect(&tls, &cfg);
    if (rc != CH_OK) {
        // ch_connect already wiped every key byte, so there is nothing
        // left to close. Reconnect later.
        (void)fprintf(stderr, "handshake failed: %d, %s\n", rc, error_text(rc));
        (void)close(fd);
        return 1;
    }
    // 1 means slot A authenticated the server, 2 means slot B. Collected
    // across a fleet mid-rotation, the counts say how many devices still
    // reach a server on the old key.
    (void)fprintf(stderr, "connected, pin slot %u\n", tls.pin_slot);

    int exit_code = exchange(&tls) == 0 ? 0 : 1;
    // Sends close_notify while the keys are live, then wipes them. Safe
    // on a session that already failed: there is nothing left to send.
    ch_close(&tls);
    (void)close(fd);
    return exit_code;
}
