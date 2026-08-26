// The caller-facing configuration and result codes, at the bottom of the
// include graph so transport (io) and message building (handshake_message) can see
// them without needing the session or the public API.
//
// Everything here configures the CLIENT. chapulin has no server role,
// so nothing in this file describes a server: server_pubkey is the key
// this client pins FOR a server, not a key a server holds. Configure
// the server in whatever software terminates TLS there — OpenSSL, Go,
// or another stack — as docs/ca.md describes.
#ifndef CH_CFG_H
#define CH_CFG_H

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

// The entropy pattern is a declared build choice with no default. An
// image either supplies its own ch_rand_bytes (-DCH_RAND_EXTERN) or
// links the reference generator in drbg.[ch] and seeds it once at boot
// with ch_drbg_seed (-DCH_RAND_DRBG). Neither macro selects code. The
// declaration exists because no build can judge an integrator's
// generator: a weak one completes the handshake, produces a key share
// that looks uniform on the wire, and returns CH_OK, so the only
// defence left is making the choice a written line in the image's build
// files rather than one nobody made. docs/entropy.md says how to seed.
#if defined(CH_RAND_EXTERN) && defined(CH_RAND_DRBG)
#error "CH_RAND_EXTERN and CH_RAND_DRBG are exclusive: declare exactly one"
#endif
#if !defined(CH_RAND_EXTERN) && !defined(CH_RAND_DRBG)
#error "no entropy pattern declared: use -DCH_RAND_EXTERN or -DCH_RAND_DRBG (docs/entropy.md)"
#endif

#define CH_OK 0
#define CH_EIO (-1)     // transport failed or closed under us
#define CH_EPROTO (-2)  // peer broke the protocol; session dead
#define CH_EAUTH (-3)   // authentication failed; session dead
#define CH_ECAP (-4)    // caller buffer too small for the peer's message
#define CH_ECLOSED (-5) // clean close_notify from the peer
#define CH_EINVAL (-6)  // invalid configuration or call; nothing was sent

// Outgoing records are staged in the session struct so writes never
// disturb buffered incoming data; 512 bytes of plaintext per record.
#define CH_TX_PT 512

// Smallest receive buffer ch_connect accepts. The profile's control
// flights fit in 512 bytes. A raw-pin server's Certificate message has
// no fixed size, so raw-pin deployments size the buffer for their
// server's chain (the e2e suite uses 2048). A build that needs more
// room raises the floor, so a too-small buffer fails at setup with
// CH_EINVAL, not mid-handshake with CH_ECAP. See docs/decisions.md 23.
// The per-algorithm defaults, named so the mirrors derive from one
// definition: the differential driver and the mutation kit size
// their material from these, and spec/Spec/X509.lean pins the same
// two numbers as the spec's modeled caps.
#define CH_X509_DEFAULT_MAX_RSA 1536
#define CH_X509_DEFAULT_MAX_ECDSA 768
#ifndef CH_X509_MAX
#ifdef CH_PIN_ECDSA
#define CH_X509_MAX CH_X509_DEFAULT_MAX_ECDSA
#else
#define CH_X509_MAX CH_X509_DEFAULT_MAX_RSA
#endif
#endif

#ifndef CH_MIN_RXBUF
// Two independent demands, and the buffer must satisfy both. The trust
// mode sets the largest admitted Certificate flight: two certificates
// at the cap plus their entry framing and message header. The key
// exchange sets the largest ServerHello record: 5-byte record header,
// 4-byte message header, 40-byte fixed body, then the
// supported_versions (6), key_share (2 + 2 + 2 + 2 + 1120 = 1128),
// and pre_shared_key (6) replies. At the default caps the CA demand is
// the larger, but CH_X509_MAX is overridable down to 512, which puts
// its flight under the hybrid ServerHello — so take the maximum rather
// than assume an ordering a build can change.
#ifdef CH_TRUST_CA
#define CH_TRUST_MIN_RXBUF (2 * (CH_X509_MAX + 5) + 16)
#else
#define CH_TRUST_MIN_RXBUF 512
#endif
#ifdef CH_KEX_PQ
#define CH_KEX_MIN_RXBUF (5 + 4 + 40 + 6 + 1128 + 6)
#else
#define CH_KEX_MIN_RXBUF 512
#endif
#if defined(CH_TRUST_CA) || defined(CH_KEX_PQ)
#define CH_MIN_RXBUF (CH_TRUST_MIN_RXBUF > CH_KEX_MIN_RXBUF ? CH_TRUST_MIN_RXBUF : CH_KEX_MIN_RXBUF)
#else
// Neither feature raises the floor, so the base profile's 512 stands on
// its own rather than as a comparison of two equal terms.
#define CH_MIN_RXBUF 512
#endif
#endif
// The library builds as C, so the guard always runs.
#ifndef __cplusplus
_Static_assert(CH_MIN_RXBUF >= 512, "the floor only rises; the base profile needs 512");
#endif

// Ticket identities beyond this cannot fit a future ClientHello, so
// larger tickets are silently dropped rather than surfaced.
#define CH_TICKET_ID_MAX 320

// A resumption ticket surfaced to the application: store psk + identity
// and present them on the next ch_connect (resumption = 1) for a cheaper
// reconnect. Valid only during the callback; copy what you keep.
typedef struct {
    const uint8_t *identity;
    size_t identity_len;
    uint8_t psk[SHA256_LEN];
    uint32_t lifetime_s;
    uint32_t age_add;
    // The stored epoch when the ticket arrived; zero outside CA
    // builds. Present it back in ch_cfg.ticket_epoch on resumption, so
    // an epoch bump also retires every earlier ticket.
    uint32_t epoch;
} ch_ticket;

// Monotonic revocation epoch (docs/ca.md). The CA writes each server
// certificate's notBefore as one of a restricted set of dates — year
// 2000..2049, day 01..28, time 000000Z — and advances it one step per
// revocation. The value compared is the number YY*336 + (MM-1)*28 +
// (DD-1), so CH_EPOCH_MAX is 49*336 + 11*28 + 27. A certificate more
// than CH_EPOCH_BOUND steps above the stored epoch is rejected, so a
// poisoned far-future date cannot lock the fleet out for good, and a
// tool that stamped today's date exceeds the bound instead of raising
// the stored epoch.
#define CH_EPOCH_MAX 16799
#ifndef CH_EPOCH_BOUND
#define CH_EPOCH_BOUND 64
#endif
// No epoch exceeds CH_EPOCH_MAX, so a bound that large disables the
// check; a bound of zero rejects every increase, so the fleet stays
// at its provisioned epoch. Both are build mistakes, caught here, not
// in the field. The upper guard also keeps the stored epoch plus the
// bound inside uint32. The library builds as C, so the guard runs.
#ifndef __cplusplus
_Static_assert(CH_EPOCH_BOUND >= 1 && CH_EPOCH_BOUND < CH_EPOCH_MAX,
               "the jump bound stays in range");
#endif

// How the epoch rule judged the certificate this session saw,
// reported in ch_tls.epoch_status beside the value in
// ch_tls.epoch_seen. The handshake fails on the last two. They stay
// distinct because the operator response differs: a server behind the
// fleet still needs reissuing, while an out-of-range date is a
// mis-issued certificate or an attempt to strand the device.
#define CH_EPOCH_NONE 0      // no epoch configured, or no certificate judged
#define CH_EPOCH_MATCHED 1   // the peer's epoch equals the stored epoch
#define CH_EPOCH_AHEAD 2     // above the stored epoch, inside the bound: it moves up
#define CH_EPOCH_REVOKED 3   // below the stored epoch: a bump retired this certificate
#define CH_EPOCH_UNTRUSTED 4 // not an allowed date, or too far ahead

typedef struct {
    // Authentication is one of two modes:
    //  - PSK: psk/psk_id set (external, resumption = 0) or a stored ticket
    //    (resumption = 1, obfuscated_age = ticket age ms + age_add).
    //  - Pinned key: psk NULL, server_pubkey = the server's raw public
    //    key, provisioned like a PSK would be. The key is an RSA modulus
    //    (256..384 bytes big-endian, exponent fixed at 65537, RSA-PSS) by
    //    default, or 64 P-256 bytes (X||Y, ECDSA) when built with
    //    -DCH_PIN_ECDSA — one algorithm per build, never both. An RSA
    //    modulus must be odd (any product of odd primes is); an even pin
    //    is provisioning corruption and fails ch_connect with CH_EINVAL.
    //    The server proves possession by signing the handshake. A raw-pin
    //    build never parses the certificate, only hashes it into the
    //    transcript — no chains, no names, no expiry; one key, fail
    //    closed — and works against stock cert-based endpoints (Go,
    //    OpenSSL). A CH_TRUST_CA build reads the same slots as CA keys
    //    instead: the server's chain must verify up to the pinned CA key
    //    (see docs/ca.md). Tickets still arrive either way, so reconnects
    //    resume via PSK.
    const uint8_t *psk;
    size_t psk_len;
    const uint8_t *psk_id;
    size_t psk_id_len;
    int resumption;
    uint32_t obfuscated_age;
    const uint8_t *server_pubkey;
    size_t server_pubkey_len;

    // Optional second pin, the staged "next" key during key rotation:
    // the server key in raw-pin builds, the CA key under CH_TRUST_CA.
    // The handshake accepts a proof against either slot and records
    // which in ch_tls.pin_slot. Same length and oddness rules as
    // server_pubkey, never set without it. See docs/rotation.md.
    const uint8_t *server_pubkey2;
    size_t server_pubkey2_len;

    // Receive buffer; its size (minus record overhead) is advertised as
    // our record_size_limit, so the peer can never overflow it.
    uint8_t *buf;
    size_t buf_len;

    // send moves all n bytes and returns 0 — any other value, including a
    // positive byte count, is failure; recv returns 1..n bytes or -1.
    // Both block, bounded by the caller's socket timeouts.
    int (*send)(void *io, const uint8_t *p, size_t n);
    int (*recv)(void *io, uint8_t *p, size_t n);
    void *io;

    // Optional; called once per NewSessionTicket.
    void (*on_ticket)(void *io, const ch_ticket *ticket);

    // Revocation. Implement these if you need to retire a stolen
    // server key. Without them, whoever steals a server's private key
    // authenticates as that server until you replace the CA key on
    // every device, because this client checks no expiry and no
    // revocation list. With them, the CA counts revocations in each
    // certificate and a device refuses any certificate older than the
    // highest count it has accepted, so reissuing a server on a new
    // key retires the old one. docs/ca.md has the procedure.
    //
    // Give both or neither. They store one uint32 in whatever
    // persistent memory the device has. Both return 0 on success.
    // A failed load fails ch_connect, so provision the fleet's
    // current count before first use. A failed store keeps the
    // session running and sets ch_tls.epoch_store_failed; the caller
    // retries. On resumption, pass the saved ticket's count in
    // ticket_epoch. Only a CH_TRUST_CA build enforces this; other
    // builds reject a config that sets it rather than ignoring it.
    int (*epoch_load)(void *epoch_io, uint32_t *value);
    int (*epoch_store)(void *epoch_io, uint32_t value);
    void *epoch_io;
    uint32_t ticket_epoch;
} ch_cfg;

#endif
