// Example: a device with a provisioned pre-shared key connects, sends
// one request, reads one reply, and closes.
//
// PSK mode is the smallest way to use chapulin. The device and the
// server already share secret bytes and a name for them, so this client
// parses no certificate and checks no signature. The x25519 exchange
// still runs (psk_dhe_ke), so someone who steals the PSK tomorrow
// cannot decrypt the traffic they recorded today.
//
// This file is built, not run: the test suite covers live handshakes.
// To try it by hand, start a server on port 4433 and run it:
//
//   openssl s_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 \
//       -psk 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 \
//       -psk_identity device-42 -nocert -accept 4433 -rev -quiet
//
//   make lib
//   cc -Wall -Wextra -Wpedantic -Werror -std=c11 -D_DEFAULT_SOURCE -I. \
//       examples/psk_client.c bin/chapulin.o -o psk_client
//
// Every line below that belongs to this host rather than to firmware is
// marked SWAP. Those are the parts you replace; the rest is what a
// device writes.
#include <netdb.h>
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
#include "tls.h"

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT "4433"

// --- Platform hooks: chapulin asks for exactly two -------------------

// SWAP: this host prints and aborts; a device calls its fault handler.
// CH_ASSERT fires only on programmer-error invariants — states chapulin's
// own code cannot reach. Bad peer input, short buffers, and I/O failures
// never come through here; they come back as ch_err return codes.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "chapulin assert %s:%d: %s\n", file, line, cond);
    abort();
}

// SWAP: this host asks the operating system. chapulin draws randomness at
// exactly two points, both inside the handshake: the ephemeral x25519
// private key and the ClientHello random. The ephemeral key is what keeps
// today's traffic safe from tomorrow's stolen PSK, so predictable bytes
// here give a passive attacker every session it recorded.
//
// A part with a hardware RNG wires this call to it. A part without one
// links drbg.c, calls ch_drbg_seed once at boot, and builds that seed
// from layered sources as docs/entropy.md describes. A counter, the boot
// time, and a MAC address are not seeds. The hook must not fail: a device
// with no entropy has no business starting a handshake, so block or
// fault rather than return weak bytes.
#ifdef __APPLE__
void ch_rand_bytes(uint8_t *p, size_t n) {
    arc4random_buf(p, n);
}
#else
#include <sys/random.h>
void ch_rand_bytes(uint8_t *p, size_t n) {
    while (n > 0) {
        ssize_t got = getrandom(p, n, 0); // capped per call, so loop like read(2)
        if (got <= 0) {
            abort(); // no entropy, no handshake
        }
        p += got;
        n -= (size_t)got;
    }
}
#endif

// --- Transport: SWAP this whole section ------------------------------
//
// chapulin never opens a socket and never names one. It calls cfg.send
// and cfg.recv, handing back the void *io the caller stored in cfg.io.
// On lwIP these wrap lwip_send and lwip_recv; on a cellular modem they
// wrap the AT-command driver. Only the contract matters:
//
//   send: move all n bytes, then return 0. Every other value is a
//         failure, including a positive count of bytes moved.
//   recv: return 1 to n bytes, or -1 on error, timeout, or peer close.
//
// Both calls block. chapulin has no clock and waits exactly as long as
// the transport does, so put your timeouts here.

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

// Opens the TCP connection and returns the socket, or -1. The receive
// timeout is what stops a silent server from blocking io_recv forever.
static int tcp_connect(const char *host, const char *port) {
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

// --- What the factory provisioned ------------------------------------

// The pre-shared key and the identity the server knows it by. Firmware
// points these at the flash the factory wrote; the bytes here only make
// the example build, and they match the openssl command above.
//
// Provision one key per device. A fleet that shares one key loses the
// whole fleet when one device is opened. 32 bytes because the key
// schedule runs HKDF over SHA-256 and a longer key adds no strength;
// chapulin accepts any nonzero length.
static const uint8_t g_psk[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                  0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                  0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

// The identity travels in the clear in the ClientHello. It names a
// device to the server; it must not carry a secret.
static const char g_psk_id[] = "device-42";

// The request this device sends. Yours is a CoAP datagram, an MQTT
// publish, or a line of JSON. The newline is this example's framing, and
// read_reply below stops at it.
static const char g_request[] = "hola sapo\n";

// The receive buffer, and the only working memory chapulin needs besides
// the session struct. Three facts set its size:
//
//   - chapulin advertises this size, less record overhead, as our
//     record_size_limit (RFC 8449). A peer record whose plaintext would
//     not fit is then a protocol error, not a resize.
//   - CH_MIN_RXBUF is the floor ch_connect accepts. It is 512 bytes,
//     which holds this profile's handshake flights, and a TRUST=ca
//     build raises it to hold a certificate chain. Sizing from the
//     constant keeps this array correct in either build; PSK mode
//     itself receives no certificate.
//   - chapulin reassembles a NewSessionTicket in this buffer, so a
//     ticket larger than the buffer fails the session. chapulin drops
//     identities above CH_TICKET_ID_MAX (320 bytes) instead of storing
//     them, and the 512 bytes above the floor hold one plus its framing.
//
// Every byte past that is SRAM spent on longer records, and nothing else.
static uint8_t g_rxbuf[CH_MIN_RXBUF + 512];

// --- Resumption: storing the ticket the server issues ----------------
//
// A NewSessionTicket carries a PSK derived from this session plus the
// identity to present it under. So resumption is PSK mode again with
// different bytes: same call, same fields, one extra flag.
//
// A resumed handshake here costs what a provisioned one costs, because
// both run x25519. It does rotate the key: each reconnect uses a key
// derived from the last session, so the provisioned PSK protects fewer
// connections. A pinned-key or TRUST=ca build saves more, since a
// resumed handshake verifies no signature.
//
// Storing tickets is optional. Leave cfg.on_ticket NULL and every
// reconnect uses the provisioned PSK.

typedef struct {
    uint8_t identity[CH_TICKET_ID_MAX];
    size_t identity_len;
    uint8_t psk[SHA256_LEN];
    uint32_t age_add;
    uint32_t arrival_ms;
    int valid;
} stored_ticket;

// SWAP: RAM here, so this ticket dies with the process. A device writes
// these bytes to the storage that already holds its PSK. The ticket is
// key material — it authenticates the next connection — so it belongs
// there and not in a log or a config file.
static stored_ticket g_ticket;

// Milliseconds counted from a fixed origin. The ticket age is a
// difference, so only the tick rate matters, not where zero is.
// SWAP: a device reads its own millisecond counter.
static uint32_t now_ms(void) {
    struct timespec ts = {0, 0};
    (void)timespec_get(&ts, TIME_UTC);
    return (uint32_t)ts.tv_sec * 1000U + (uint32_t)(ts.tv_nsec / 1000000);
}

// Called once per NewSessionTicket. Tickets arrive after the handshake,
// so this runs inside ch_read, never inside ch_connect: a device that
// connects and never reads is issued nothing. The ch_ticket and the
// bytes it points at are valid only during this call, so copy what you
// keep. This example keeps the newest ticket and overwrites the last.
static void on_ticket(void *io, const ch_ticket *ticket) {
    (void)io; // the pointer cfg.io carries; this example does not need it
    if (ticket->identity_len > sizeof g_ticket.identity) {
        return; // too big to store, so keep the ticket we already have
    }
    memcpy(g_ticket.identity, ticket->identity, ticket->identity_len);
    g_ticket.identity_len = ticket->identity_len;
    memcpy(g_ticket.psk, ticket->psk, sizeof g_ticket.psk);
    g_ticket.age_add = ticket->age_add;
    g_ticket.arrival_ms = now_ms();
    g_ticket.valid = 1;
}

// --- One session -----------------------------------------------------
//
// One rule covers recovery: every chapulin error kills the session.
// ch_connect, ch_write, and ch_read wipe the keys and mark the session
// dead before they return, so no call resumes it and no state needs
// repairing. The device drops the socket and connects again, which is
// what it does after any failure anyway. That rule is why this file has
// no retry paths.

// SWAP: host logging. A device reports through whatever it already uses.
static const char *err_name(int rc) {
    switch (rc) {
    case CH_OK:
        return "CH_OK";
    case CH_EIO:
        return "CH_EIO: the transport failed or closed";
    case CH_EPROTO:
        return "CH_EPROTO: the peer broke the protocol";
    case CH_EAUTH:
        return "CH_EAUTH: authentication failed";
    case CH_ECAP:
        return "CH_ECAP: our buffer was too small for the peer's message";
    case CH_ECLOSED:
        return "CH_ECLOSED: the peer closed cleanly";
    case CH_EINVAL:
        return "CH_EINVAL: this config or call is wrong; nothing was sent";
    default:
        return "unknown";
    }
}

// Drops a stored ticket. A server that restarted, or one that expired
// the ticket, does not select our identity, and ch_connect returns
// CH_EAUTH. The ticket is the only thing that changed since the last
// working connect, so forget it and let the next attempt present the
// provisioned key again. Without this a device that stored a ticket the
// server no longer knows keeps offering it and never reconnects.
static void forget_ticket(void) {
    memset(&g_ticket, 0, sizeof g_ticket);
}

// Fills the authentication half of the config. Both branches are PSK
// mode: a ticket is a PSK the server issued, so resumption changes which
// bytes go in, not which call runs. Neither branch sets server_pubkey —
// a config carrying both a PSK and a pinned key is a provisioning
// mistake, and ch_connect returns CH_EINVAL rather than choosing one.
static void fill_auth(ch_cfg *cfg) {
    if (!g_ticket.valid) {
        cfg->psk = g_psk;
        cfg->psk_len = sizeof g_psk;
        cfg->psk_id = (const uint8_t *)g_psk_id;
        cfg->psk_id_len = sizeof g_psk_id - 1; // the text, without its terminator
        return;
    }
    cfg->psk = g_ticket.psk;
    cfg->psk_len = sizeof g_ticket.psk;
    cfg->psk_id = g_ticket.identity;
    cfg->psk_id_len = g_ticket.identity_len;
    cfg->resumption = 1;
    // The server ages the ticket itself and compares. Claim the ticket's
    // age in milliseconds plus the age_add it arrived with. The uint32
    // wrap is deliberate: the protocol defines this field modulo 2^32.
    cfg->obfuscated_age = now_ms() - g_ticket.arrival_ms + g_ticket.age_add;
}

// Reads until the reply's newline arrives or the buffer fills. ch_read
// returns what has arrived, not a whole message, so framing stays the
// application's job. Returns the byte count, 0 if the peer closed first,
// or a ch_err — the same three answers ch_read gives.
static int read_reply(ch_tls *tls, uint8_t *out, size_t cap) {
    size_t have = 0;
    while (have < cap) {
        int got = ch_read(tls, out + have, cap - have);
        if (got <= 0) {
            return got;
        }
        have += (size_t)got;
        if (memchr(out, '\n', have) != NULL) {
            break;
        }
    }
    return (int)have;
}

// Sends the request and prints the reply. Returns CH_OK, or the ch_err
// that killed the session.
static int exchange(ch_tls *tls) {
    int rc = ch_write(tls, (const uint8_t *)g_request, sizeof g_request - 1);
    if (rc != CH_OK) {
        return rc;
    }
    uint8_t reply[256];
    int got = read_reply(tls, reply, sizeof reply);
    if (got < 0) {
        return got;
    }
    if (got == 0) {
        // ch_read reports a clean close as 0. Name it with the code the
        // library uses for the same event, so run_session below reports
        // every ending with one line.
        return CH_ECLOSED;
    }
    (void)fwrite(reply, 1, (size_t)got, stdout); // SWAP: host logging
    return CH_OK;
}

// Runs one session from socket to close. Returns CH_OK when the reply
// arrived; any other return means the session is dead and its keys are
// already wiped.
static int run_session(void) {
    int fd = tcp_connect(SERVER_HOST, SERVER_PORT);
    if (fd < 0) {
        (void)fprintf(stderr, "cannot reach %s:%s\n", SERVER_HOST, SERVER_PORT);
        return CH_EIO;
    }
    // ch_connect copies this struct into the session but not the bytes
    // it points at, so everything named here outlives the session:
    // g_psk, g_psk_id, and g_rxbuf are static, and fd lives until after
    // ch_close below.
    ch_cfg cfg = {0};
    fill_auth(&cfg);
    cfg.buf = g_rxbuf;
    cfg.buf_len = sizeof g_rxbuf;
    cfg.send = io_send;
    cfg.recv = io_recv;
    cfg.io = &fd;
    cfg.on_ticket = on_ticket; // optional; drop it and reconnects use g_psk

    // One session struct, static: firmware has no heap to put it on.
    // It holds the record keys for both directions, the transcript, and
    // the staging area for outgoing records. The README's memory table
    // gives its measured size.
    static ch_tls tls;
    int rc = ch_connect(&tls, &cfg);
    if (rc == CH_OK) {
        (void)fprintf(stderr, "connected with %s\n",
                      cfg.resumption ? "a stored ticket" : "the provisioned PSK");
        rc = exchange(&tls);
    }
    if (rc != CH_OK) {
        (void)fprintf(stderr, "session failed: %s\n", err_name(rc));
        if (cfg.resumption) {
            forget_ticket();
        }
    }
    // Safe on a live session and on a dead one: ch_close sends
    // close_notify only while the keys are live, and wipes either way.
    ch_close(&tls);
    (void)close(fd);
    return rc;
}

int main(void) {
    // Two sessions on purpose. The first authenticates with the
    // provisioned PSK and stores the ticket the server issues; the
    // second presents that ticket. A device does the same thing across a
    // reboot or a dropped link, with more time in between.
    if (run_session() != CH_OK) {
        return 1;
    }
    if (run_session() != CH_OK) {
        return 1;
    }
    return 0;
}
