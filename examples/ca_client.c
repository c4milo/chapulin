/*
 * A chapulin client for the TRUST=ca build: the device pins the public
 * key of a CA you run, and each server presents its own certificate
 * chain.
 *
 * Everything except the trust decision matches the other examples in
 * this directory. You fill in a ch_cfg, call ch_connect, then ch_write,
 * ch_read, and ch_close. Three things change, and this file marks each
 * one:
 *
 *   1. The pinned bytes are a CA key, not one server's key. One key
 *      now authenticates every server that CA signs for.
 *   2. CH_MIN_RXBUF rises. The CA build knows the largest chain it
 *      admits, so it derives the floor and this file sizes its buffer
 *      from the constant.
 *   3. Two optional callbacks turn on the revocation epoch, the only
 *      way this client refuses a certificate it can otherwise verify.
 *
 * What the check covers: the chain verifies up to the pinned CA key,
 * and every certificate matches a fixed shape — version, serial, one
 * signature algorithm, keyUsage, extendedKeyUsage, basicConstraints,
 * canonical DER on every decoded field. The server sends its own
 * certificate, or that plus the one intermediate that signed it. Two
 * entries is the maximum: a server that also sends the root fails the
 * handshake, and OpenSSL appends the root on its own whenever the root
 * sits in the server's store. docs/ca.md, "Server configuration",
 * covers that.
 *
 * What the check does not cover: names and time. The client never
 * compares a hostname, and never reads notBefore or notAfter as a date,
 * because the target has no clock — the revocation epoch below is the
 * one thing read out of notBefore, and it reads it as a number.
 * Freshness comes from issuance instead: sign short-lived certificates
 * and reissue on a schedule. docs/ca.md states the contract your CA
 * must meet, and this file is worth nothing without it.
 *
 * Build the library, then this file against it:
 *
 *   make TRUST=ca lib                 # RSA-PSS chains, the default PIN
 *   make TRUST=ca PIN=ecdsa lib       # P-256 chains instead
 *   cc -Wall -Wextra -Wpedantic -Werror -std=c11 -D_DEFAULT_SOURCE \
 *      -DCH_TRUST_CA -I. -o ca_client examples/ca_client.c bin/chapulin.o
 *
 * Pass -DCH_TRUST_CA to your own translation units too, not just to the
 * library: CH_MIN_RXBUF depends on it and this file sizes its receive
 * buffer from that constant.
 *
 * This builds on a POSIX host and is not a device port. Every line a
 * firmware tree replaces carries a "Replace on a device" comment.
 */

#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "ch_assert.h"
#include "rand.h"
#include "tls.h"

// --- The pinned CA key ---------------------------------------------------
//
// One build verifies one signature algorithm, everywhere in the chain.
// The default build pins an RSA modulus: 256 to 384 bytes, big-endian,
// exponent fixed at 65537, RSA-PSS signatures. A PIN=ecdsa build pins
// the CA's P-256 public point as 64 bytes, X then Y.
//
// Take the bytes from the CA key you already hold:
//
//   openssl rsa -in caroot.key -noout -modulus   # RSA: hex, strip "Modulus="
//   openssl ec -in ecroot.key -text -noout       # ECDSA: the "pub:" block
//
// The CA key this device trusts. It is public data, so it needs
// integrity but not secrecy, and it can sit in flash beside the
// firmware.
//
// Replace on a device: read these bytes from the region your factory
// provisions. This example reads them from a file so it can run against
// a real CA, which is also what lets the e2e suite catch it if the API
// around it changes.
#ifdef CH_PIN_ECDSA
#define CA_KEY_LEN 64
#else
#define CA_KEY_LEN 384
#endif
static uint8_t ca_key[CA_KEY_LEN];

// Fills ca_key from a file holding exactly the key and nothing else.
// Measuring first turns a provisioning mistake into a message that says
// so: a short or long file read as CA_KEY_LEN bytes would fail much
// later as CH_EAUTH, which reads like an attack rather than a typo.
static int read_ca_key(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        (void)fprintf(stderr, "cannot open %s\n", path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0 || ftell(f) != CA_KEY_LEN) {
        (void)fprintf(stderr, "%s: this build pins exactly %d CA key bytes\n", path, CA_KEY_LEN);
        (void)fclose(f);
        return -1;
    }
    size_t got = 0;
    if (fseek(f, 0, SEEK_SET) == 0) {
        got = fread(ca_key, 1, (size_t)CA_KEY_LEN, f);
    }
    (void)fclose(f);
    if (got != (size_t)CA_KEY_LEN) {
        (void)fprintf(stderr, "cannot read %s\n", path);
        return -1;
    }
    return 0;
}

// Rotating the CA key uses a second slot: set cfg.server_pubkey2 to the
// next CA key and the handshake accepts a chain anchored at either one.
// ch_tls.pin_slot then reports which answered, 1 or 2, so an operator
// can watch a fleet move over. See docs/rotation.md.

// --- Platform hooks ------------------------------------------------------

// Replace on a device: map this to your fault handler. chapulin calls
// it only for programmer errors, meaning states that cannot happen
// unless the code is wrong. Bad peer input, short buffers, and I/O
// failures return ch_err codes instead and never arrive here.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "assert %s:%d: %s\n", file, line, cond);
    abort();
}

// Replace on a device: wire this to the part's hardware generator, or
// to the seeded generator in drbg.[ch] when the part has none. Each
// handshake draws two values here, the ephemeral x25519 private key and
// the ClientHello random, so a guessable stream costs the session its
// confidentiality. The hook must not fail: block or fault rather than
// return weak bytes. docs/entropy.md covers seeding.
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
// Replace on a device: these functions are the whole operating-system
// dependency. chapulin calls send and recv through the ch_cfg and knows
// nothing else about the network. On lwIP they wrap lwip_write and
// lwip_read; on a bare-metal stack they drive your own driver. Both
// block, bounded by a timeout you set, and the client never retries a
// failure: an I/O error kills the session and the device reconnects.

// send moves all n bytes and returns 0. Every other value is a failure,
// including a positive byte count.
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

// recv returns 1 to n bytes, or -1 on failure or on a closed socket.
static int io_recv(void *io, uint8_t *p, size_t n) {
    ssize_t got = read(*(const int *)io, p, n);
    return got <= 0 ? -1 : (int)got;
}

// Replace on a device: opens the TCP connection. The receive timeout is
// what bounds a handshake against a server that stops answering,
// because chapulin's callbacks block and the library owns no timer.
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

// --- The revocation epoch, optional --------------------------------------
//
// Leave the two callbacks unset and the client checks no revocation at
// all. Whoever steals a server's private key then authenticates as that
// server until you replace the CA key on every device, because this
// client reads no expiry and fetches no revocation list.
//
// Set them and the CA gets a revocation mechanism that needs no clock.
// The CA writes an epoch into each server certificate's notBefore field
// and adds one step to revoke. A device stores the highest epoch it has
// accepted and refuses any certificate below it. docs/ca.md gives the
// date encoding, the issuance procedure, and the order to enable it in
// — get that order wrong and the fleet goes offline.
//
// What the API enforces:
//
//   - Give both callbacks or neither. One alone fails with CH_EINVAL,
//     as does setting them in a build without CH_TRUST_CA.
//   - epoch_load runs inside ch_connect before any byte goes out, and a
//     load that fails or returns above CH_EPOCH_MAX fails ch_connect.
//     Provision the epoch at manufacture; an unprovisioned device never
//     connects.
//   - epoch_store runs only after CertificateVerify proved the server
//     holds the leaf key. Certificates are public, so moving on the
//     certificate alone would let anyone replay one and push a device
//     past the servers it still needs.
//   - A failed store does not kill the session. It sets
//     ch_tls.epoch_store_failed and the application retries.
//   - A certificate more than CH_EPOCH_BOUND steps above the stored
//     epoch is refused, so one far-future date cannot lock a device out
//     for good.

// One uint32 is the entire persistent state. Use two storage slots: a
// power cut during a write can leave a slot unreadable, and a device
// whose only slot is corrupt fails every later ch_connect. Load takes
// the highest valid slot; store writes the slot holding the older
// value, so the newer value survives a torn write.
//
// Replace on a device: slot_read and slot_write use a file so the
// example runs on a host. On a device they read and write a flash word.
// The epoch changes once per revocation, far inside any flash write
// budget (docs/ca.md, "Flash wear").
//
// Production wants two slots in different erase blocks, not the one
// here: a power cut during a write can leave a slot unreadable, and a
// device whose only slot is corrupt fails every later ch_connect with
// CH_EINVAL. Load takes the highest readable slot, store overwrites the
// one holding the older value. That is storage engineering rather than
// anything about this API, so it stays out of the example.
typedef struct {
    const char *slot_path;
} epoch_slots;

static int slot_read(const char *path, uint32_t *value) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    char text[16];
    const char *line = fgets(text, sizeof text, f);
    (void)fclose(f);
    if (line == NULL) {
        return -1;
    }
    char *end = NULL;
    unsigned long stored = strtoul(line, &end, 10);
    if (end == line || stored > CH_EPOCH_MAX) {
        return -1; // empty, unparsable, or out of range: treat as corrupt
    }
    *value = (uint32_t)stored;
    return 0;
}

static int epoch_load(void *epoch_io, uint32_t *value) {
    const epoch_slots *slots = epoch_io;
    // An unreadable slot fails ch_connect with CH_EINVAL, which is the
    // right answer: a device that cannot read its epoch cannot enforce
    // revocation, and answering zero would trust every certificate the
    // CA has ever issued.
    return slot_read(slots->slot_path, value);
}

static int epoch_store(void *epoch_io, uint32_t value) {
    const epoch_slots *slots = epoch_io;
    FILE *f = fopen(slots->slot_path, "w");
    if (f == NULL) {
        return -1;
    }
    (void)fprintf(f, "%u\n", value);
    return fclose(f) == 0 ? 0 : -1;
}

static const char *epoch_verdict(uint8_t status) {
    switch (status) {
    case CH_EPOCH_MATCHED:
        return "matched: the server sits at this device's epoch";
    case CH_EPOCH_AHEAD:
        return "ahead: the server is newer, so this device moves up";
    case CH_EPOCH_REVOKED:
        return "revoked: the server is older than this device, handshake failed";
    case CH_EPOCH_UNTRUSTED:
        return "untrusted: not an epoch date, or too far ahead, handshake failed";
    default: // CH_EPOCH_NONE
        return "none: no epoch configured, or no certificate judged";
    }
}

// Read these after every ch_connect, successful or not. Both epoch
// failures return CH_EAUTH, so epoch_status is the only thing that
// tells them apart, and they need opposite responses: a revoked server
// needs reissuing, while an untrusted date means a mis-issued
// certificate or an attempt to strand the device. Send the numbers with
// your telemetry — the spread of ch_tls.epoch across a fleet is its
// drift, and it must stay under CH_EPOCH_BOUND.
static void report_epoch(const ch_tls *tls) {
    (void)fprintf(stderr, "epoch: stored %u, peer showed %u, %s\n", tls->epoch, tls->epoch_seen,
                  epoch_verdict(tls->epoch_status));
}

// A failed store leaves the session running, so the retry belongs to
// the application. An unwritten epoch is lost at the next power cut,
// and the device trusts the revoked certificates again.
static void retry_epoch_store(const ch_tls *tls, const ch_cfg *cfg) {
    if (!tls->epoch_store_failed) {
        return;
    }
    for (int attempt = 0; attempt < 3; attempt++) {
        if (cfg->epoch_store(cfg->epoch_io, tls->epoch) == 0) {
            (void)fprintf(stderr, "epoch %u written on retry\n", tls->epoch);
            return;
        }
    }
    (void)fprintf(stderr, "epoch %u still unwritten; keep retrying before power off\n", tls->epoch);
}

// --- The session ---------------------------------------------------------

// Tickets arrive in CA mode too, so a reconnect resumes over PSK and
// skips the chain verify entirely. Under CH_TRUST_CA a ticket also
// carries the epoch it was issued under. Store that beside the ticket
// and present it back in ch_cfg.ticket_epoch on the next ch_connect: a
// resumed session shows no certificate, so the ticket's own epoch is
// the only revocation check left, and advancing the epoch retires
// every earlier ticket.
//
// The ch_ticket is valid only during this call. Copy what you keep.
static void on_ticket(void *io, const ch_ticket *ticket) {
    (void)io; // this is cfg.io, the socket pointer
    (void)fprintf(stderr, "ticket: %zu-byte identity, lifetime %us, epoch %u\n",
                  ticket->identity_len, ticket->lifetime_s, ticket->epoch);
    // A device copies ticket->identity (identity_len bytes),
    // ticket->psk (SHA256_LEN bytes), ticket->age_add, and
    // ticket->epoch into persistent storage here.
}

// One request and one reply, to show that ch_write and ch_read do not
// change between trust modes. Returns 0 on success.
static int one_exchange(ch_tls *tls) {
    static const uint8_t request[] = "estado\n";
    if (ch_write(tls, request, sizeof request - 1) != CH_OK) {
        (void)fprintf(stderr, "write failed\n");
        return -1;
    }
    // ch_read hands back what one record held, never more, so framing
    // stays the application's job. This reply is one line, so read until
    // the newline arrives. A protocol that ends on close instead would
    // loop until ch_read returns 0.
    uint8_t reply[256];
    size_t have = 0;
    while (have < sizeof reply) {
        int got = ch_read(tls, reply + have, sizeof reply - have);
        if (got == 0) {
            break; // the peer closed before the newline
        }
        if (got < 0) {
            (void)fprintf(stderr, "read returned %d\n", got);
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

// Points cfg at the two slot files and turns the revocation epoch on.
// Without this the client verifies chains and enforces no revocation.
static void configure_epoch(ch_cfg *cfg, epoch_slots *slots, char **argv) {
    slots->slot_path = argv[4];
    cfg->epoch_load = epoch_load;
    cfg->epoch_store = epoch_store;
    cfg->epoch_io = slots;
}

int main(int argc, char **argv) {
    if (argc != 4 && argc != 5) {
        (void)fprintf(stderr,
                      "usage: %s host port ca-key-file [epoch-file]\n"
                      "  without the epoch file the revocation epoch stays off\n",
                      argv[0]);
        return 2;
    }
    if (read_ca_key(argv[3]) != 0) {
        return 2;
    }
    // Replace on a device: POSIX only. Without this, writing to a
    // socket the peer already closed kills the process with SIGPIPE
    // instead of returning -1 to io_send, and the error handling below
    // never runs. A device has no signals.
    (void)signal(SIGPIPE, SIG_IGN);

    int fd = dial(argv[1], argv[2]);
    if (fd < 0) {
        (void)fprintf(stderr, "could not connect to %s:%s\n", argv[1], argv[2]);
        return 1;
    }

    // The receive buffer. Its size minus record overhead goes out as
    // the client's record_size_limit (RFC 8449), so the server can
    // never send a record this buffer cannot hold.
    //
    // CH_MIN_RXBUF is the floor ch_connect accepts, and the CA build
    // raises it, because the whole Certificate flight must fit at once:
    // up to two certificates at CH_X509_MAX plus their entry framing
    // and the message header. That is 3098 bytes in the RSA build and
    // 1562 under PIN=ecdsa, against 512 in a raw-pin build, where the
    // integrator sizes up for the server's certificate by hand. Sizing
    // from the constant means changing PIN or TRUST resizes the buffer,
    // and a buffer below the floor fails at setup with CH_EINVAL rather
    // than mid-handshake with CH_ECAP. A larger buffer is fine and
    // raises the record size limit the client advertises.
    static uint8_t rxbuf[CH_MIN_RXBUF];

    ch_cfg cfg = {0};
    // The pin holds the CA key. server_pubkey is the same field a
    // raw-pin build fills with one server's key; -DCH_TRUST_CA is what
    // decides how the handshake reads it.
    cfg.server_pubkey = ca_key;
    cfg.server_pubkey_len = sizeof ca_key;
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = io_send;
    cfg.recv = io_recv;
    cfg.io = &fd;
    cfg.on_ticket = on_ticket;

    epoch_slots slots = {0};
    if (argc == 5) {
        configure_epoch(&cfg, &slots, argv);
    }

    // One static session struct, the whole working set beside rxbuf.
    static ch_tls tls;
    int rc = ch_connect(&tls, &cfg);
    if (cfg.epoch_load != NULL) {
        report_epoch(&tls);
    }
    if (rc != CH_OK) {
        // Any error already wiped the key material and left the session
        // dead. There is no resumable error state: the device
        // reconnects. CH_EAUTH here means the chain failed the pin, the
        // profile, or the epoch rule.
        (void)fprintf(stderr, "handshake failed: %d\n", rc);
        (void)close(fd);
        return 1;
    }
    (void)fprintf(stderr, "connected; the chain verified up to CA pin slot %u\n", tls.pin_slot);
    if (cfg.epoch_load != NULL) {
        retry_epoch_store(&tls, &cfg);
    }

    int exit_code = one_exchange(&tls) == 0 ? 0 : 1;
    ch_close(&tls);
    (void)close(fd);
    return exit_code;
}
