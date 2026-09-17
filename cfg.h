// The caller-facing configuration and result codes, at the bottom of the
// include graph so transport (io) and message building (handshake_message) can see
// them without needing the session or the public API.
//
// Everything here configures the CLIENT. chapulin has no server role, so nothing in this
// file describes a server: server_pubkey is the key this client pins FOR a server, not a
// key a server holds. Configure the server in whatever software terminates TLS there —
// OpenSSL, Go, or another stack — as docs/ca.md describes.
#ifndef CH_CFG_H
#define CH_CFG_H

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

// The entropy pattern is a declared build choice with no default. An image either supplies
// its own ch_rand_bytes (-DCH_RAND_EXTERN) or links the reference generator in drbg.[ch]
// and seeds it once at boot with ch_drbg_seed (-DCH_RAND_DRBG). Neither macro selects code.
// The declaration exists because no build can judge an integrator's generator: a weak one
// completes the handshake, produces a key share that looks uniform on the wire, and returns
// CH_OK, so the only defence left is making the choice a written line in the image's build
// files rather than one nobody made. docs/entropy.md says how to seed.
#if defined(CH_RAND_EXTERN) && defined(CH_RAND_DRBG)
#error "CH_RAND_EXTERN and CH_RAND_DRBG are exclusive: declare exactly one"
#endif
#if !defined(CH_RAND_EXTERN) && !defined(CH_RAND_DRBG)
#error "no entropy pattern declared: use -DCH_RAND_EXTERN or -DCH_RAND_DRBG (docs/entropy.md)"
#endif

// A build has one trust mode (Makefile TRUST): raw pins by default,
// -DCH_TRUST_CA, or -DCH_TRUST_WEBPKI. Both defines together would
// compile the CA epoch rules and the web PKI config rules into one
// ch_connect, which no mode describes.
#if defined(CH_TRUST_CA) && defined(CH_TRUST_WEBPKI)
#error "CH_TRUST_CA and CH_TRUST_WEBPKI are exclusive: a build has one trust mode"
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

// Smallest receive buffer ch_connect accepts. The profile's control flights fit in 512
// bytes. A raw-pin server's Certificate message has no fixed size, so raw-pin deployments
// size the buffer for their server's chain (the e2e suite uses 2048). A build that needs
// more room raises the floor, so a too-small buffer fails at setup with CH_EINVAL, not
// mid-handshake with CH_ECAP. See docs/decisions.md 23. The per-algorithm defaults, named
// so the mirrors derive from one definition: the differential driver and the mutation kit
// size their material from these, and spec/Spec/X509.lean pins the same two numbers as the
// spec's modeled caps.
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
// Two independent demands, and the buffer must satisfy both. The trust mode sets the
// largest admitted Certificate message, and the buffer must hold that message beside the
// record that completes it. The message is a 4-byte handshake header, a 1-byte
// certificate_request_context length and a 3-byte list length, 8 bytes, then one entry per
// certificate: a 3-byte length, the certificate at the cap, and a 2-byte empty extensions
// vector, the cap + 5. handshake_record.c reassembles a message in place: the plaintext of
// every earlier record sits at the front of the buffer, and the last record lands after it
// whole, so the buffer also holds that record's 5-byte header, its 1-byte inner content
// type and its 16-byte AEAD tag, 22 bytes, whatever the fragmentation. A floor without
// those 22 bytes fails the largest admitted message with CH_ECAP one record before it
// completes. The key exchange sets the largest ServerHello record: 5-byte record header,
// 4-byte message header, 40-byte fixed body, then the supported_versions (6), key_share
// (2 + 2 + 2 + 2 + 1120 = 1128), and pre_shared_key (6) replies. At the default caps the CA
// demand is the larger, but CH_X509_MAX is overridable down to 512, which puts its flight
// under the hybrid ServerHello — so take the maximum rather than assume an ordering a build
// can change. test/rxbuf_floor_tests.h reassembles the largest message at the floor and
// fails it at the floor minus one.
#ifdef CH_TRUST_CA
#define CH_TRUST_MIN_RXBUF (2 * (CH_X509_MAX + 5) + 8 + 22)
#elif defined(CH_TRUST_WEBPKI)
// The same formula over the flight a public server sends: four entries
// (CH_WEBPKI_FLIGHT_ENTRIES) of up to 3072 bytes each (CH_WEBPKI_CERT_MAX), 12338 bytes
// (docs/webpki.md, "Bounds"). Those two constants live in webpki.h, which includes this
// header, so the value is written out here and tls.c asserts that it matches them.
#define CH_TRUST_MIN_RXBUF (4 * (3072 + 5) + 8 + 22)
#else
#define CH_TRUST_MIN_RXBUF 512
#endif
#ifdef CH_KEX_PQ
#define CH_KEX_MIN_RXBUF (5 + 4 + 40 + 6 + 1128 + 6)
#else
#define CH_KEX_MIN_RXBUF 512
#endif
#ifdef CH_TRANSPORT_QUIC
// A TRANSPORT=quic build takes the maximum over three QUIC terms and over nothing else. It
// has no record layer (RFC 9001 §4.1.3, rfc9001.txt:462-464), so cfg.buf_len is the only
// bound a peer meets and it bounds one whole handshake message at one encryption level.
// CH_QUIC_TRUST_MIN_RXBUF is the trust term without the 22 bytes that pay for the record
// completing a message; under TRUST=raw that is 512 - 22, or 490, the smallest term any
// QUIC build takes. CH_QUIC_KEX_MIN_RXBUF is the key-exchange term without its 5
// record-header bytes; under KEX=pq the 1184 bytes left are the hybrid ServerHello message
// itself, and dropping the term would floor a TRANSPORT=quic KEX=pq TRUST=raw build at 490
// against that message. CH_QUIC_PARAMS_MIN_RXBUF is the server's transport-parameters
// body, which arrives inside the EncryptedExtensions this buffer holds whole (§8.2,
// rfc9001.txt:1926-1928).
//
// open: that third number, and 0 is not one. No server body has been measured, in either
// direction (docs/quic.md, "Bounds that need measuring"), so the term raises no floor at
// this commit and 0 says that rather than claiming an empty body. The commit that lands
// quic.c measures a real EncryptedExtensions and writes the number here, beside the
// re-measured CH_TX_STAGE; a caller that already knows its server's body raises it sooner.
#define CH_QUIC_TRUST_MIN_RXBUF (CH_TRUST_MIN_RXBUF - 22)
#define CH_QUIC_KEX_MIN_RXBUF (CH_KEX_MIN_RXBUF - 5)
#ifndef CH_QUIC_PARAMS_MIN_RXBUF
#define CH_QUIC_PARAMS_MIN_RXBUF 0
#endif
#define CH_QUIC_MIN_RXBUF                                                                          \
    (CH_QUIC_TRUST_MIN_RXBUF > CH_QUIC_KEX_MIN_RXBUF                                               \
         ? (CH_QUIC_TRUST_MIN_RXBUF > CH_QUIC_PARAMS_MIN_RXBUF ? CH_QUIC_TRUST_MIN_RXBUF           \
                                                               : CH_QUIC_PARAMS_MIN_RXBUF)         \
         : (CH_QUIC_KEX_MIN_RXBUF > CH_QUIC_PARAMS_MIN_RXBUF ? CH_QUIC_KEX_MIN_RXBUF               \
                                                             : CH_QUIC_PARAMS_MIN_RXBUF))
#define CH_MIN_RXBUF CH_QUIC_MIN_RXBUF
#elif defined(CH_TRUST_CA) || defined(CH_TRUST_WEBPKI) || defined(CH_KEX_PQ)
#define CH_MIN_RXBUF (CH_TRUST_MIN_RXBUF > CH_KEX_MIN_RXBUF ? CH_TRUST_MIN_RXBUF : CH_KEX_MIN_RXBUF)
#else
// Neither feature raises the floor, so the base profile's 512 stands on
// its own rather than as a comparison of two equal terms.
#define CH_MIN_RXBUF 512
#endif
#endif
// The library builds as C, so the guards always run. The QUIC floor only rises too, and
// its smallest term is 490. The driver's termination argument rests on that number: a full
// buffer always holds the 4-byte handshake header hsr_peek_message reads, so a full buffer
// never answers HSR_INCOMPLETE (docs/quic.md, "Suspending the driver").
#ifndef __cplusplus
#ifdef CH_TRANSPORT_QUIC
_Static_assert(CH_MIN_RXBUF >= 490, "the QUIC floor only rises; its smallest term is 490");
#else
_Static_assert(CH_MIN_RXBUF >= 512, "the floor only rises; the base profile needs 512");
#endif
#endif

// Ticket identities beyond this cannot fit a future ClientHello, so larger tickets are
// silently dropped rather than surfaced.
#define CH_TICKET_ID_MAX 320

// The NamedGroup code points of the two key exchanges a build can offer, one per build
// (Makefile KEX): x25519 (RFC 9846 §4.2.7) by default, or the X25519MLKEM768 hybrid
// (RFC 10024) under -DCH_KEX_PQ. ch_tls.group reports which one the ServerHello selected.
#define CH_GROUP_X25519 0x001d
#define CH_GROUP_X25519MLKEM768 0x11ec

// A resumption ticket surfaced to the application: store psk + identity and present them
// on the next ch_connect (resumption = 1) for a cheaper reconnect. Valid only during the
// callback; copy what you keep.
typedef struct {
    const uint8_t *identity;
    size_t identity_len;
    uint8_t psk[SHA256_LEN];
    uint32_t lifetime_s;
    uint32_t age_add;
    // The stored epoch when the ticket arrived; zero outside CA builds. Present it back in
    // ch_cfg.ticket_epoch on resumption, so an epoch bump also retires every earlier ticket.
    uint32_t epoch;
} ch_ticket;

// Monotonic revocation epoch (docs/ca.md). The CA writes each server certificate's
// notBefore as one of a restricted set of dates — year 2000..2049, day 01..28, time
// 000000Z — and advances it one step per revocation. The value compared is the number
// YY*336 + (MM-1)*28 + (DD-1), so CH_EPOCH_MAX is 49*336 + 11*28 + 27. A certificate more
// than CH_EPOCH_BOUND steps above the stored epoch is rejected, so a poisoned far-future
// date cannot lock the fleet out for good, and a tool that stamped today's date exceeds
// the bound instead of raising the stored epoch.
#define CH_EPOCH_MAX 16799
#ifndef CH_EPOCH_BOUND
#define CH_EPOCH_BOUND 64
#endif
// No epoch exceeds CH_EPOCH_MAX, so a bound that large disables the check; a bound of zero
// rejects every increase, so the fleet stays at its provisioned epoch. Both are build
// mistakes, caught here, not in the field. The upper guard also keeps the stored epoch plus
// the bound inside uint32. The library builds as C, so the guard runs.
#ifndef __cplusplus
_Static_assert(CH_EPOCH_BOUND >= 1 && CH_EPOCH_BOUND < CH_EPOCH_MAX,
               "the jump bound stays in range");
#endif

// How the epoch rule judged the certificate this session saw, reported in
// ch_tls.epoch_status beside the value in ch_tls.epoch_seen. The handshake fails on the
// last two. They stay distinct because the operator response differs: a server behind the
// fleet still needs reissuing, while an out-of-range date is a mis-issued certificate or an
// attempt to strand the device.
#define CH_EPOCH_NONE 0      // no epoch configured, or no certificate judged
#define CH_EPOCH_MATCHED 1   // the peer's epoch equals the stored epoch
#define CH_EPOCH_AHEAD 2     // above the stored epoch, inside the bound: it moves up
#define CH_EPOCH_REVOKED 3   // below the stored epoch: a bump retired this certificate
#define CH_EPOCH_UNTRUSTED 4 // not an allowed date, or too far ahead

#ifdef CH_TRUST_WEBPKI
// A trust anchor for a TRUST=webpki build: a root's subject Name and its public key, each
// the whole DER TLV the root certificate carries — the Name SEQUENCE and the
// SubjectPublicKeyInfo SEQUENCE, header included. Nothing else is read from the root, not
// even its dates. The caller embeds the roots it trusts; the array is the whole trust
// boundary, and any anchor may certify any name (docs/webpki.md, "Trust anchors"). Only a
// TRUST=webpki build declares this type, the constant below and the ch_cfg fields that use
// them (see the end of ch_cfg).
typedef struct {
    const uint8_t *name;
    size_t name_len;
    const uint8_t *spki;
    size_t spki_len;
} ch_trust_anchor;

// Anchors one configuration may carry. The number is a measurement: nine roots cover the
// endpoints docs/webpki.md captures, five of them Amazon Trust Services'.
#define CH_WEBPKI_ANCHOR_MAX 12
#endif

// The ALPN declarations below serve two builds: a TRUST=webpki build offers a protocol list
// over TCP (docs/decisions.md 37), and RFC 9001 §8.1 requires ALPN of every QUIC client
// (rfc9001.txt:1891-1895), so a TRANSPORT=quic build offers one in every trust mode and
// closes with no_application_protocol when none is negotiated (rfc9001.txt:1896-1902),
// where a TCP client keeps CH_ALPN_NONE and completes. Only this guard widens; no
// declaration moves.
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC)

// One application protocol name the caller offers through ALPN (RFC 7301 §3.1), shaped
// like ch_trust_anchor: the caller owns the bytes and they must outlive the session. "h2"
// is 2 bytes and "http/1.1" is 8.
typedef struct {
    const uint8_t *name;
    size_t name_len;
} ch_alpn_protocol;

// The two caps on that list. Both are ClientHello budget: the extension costs 4 type and
// length bytes, 2 ProtocolNameList length bytes, and one length byte per name, so
// CH_ALPN_MAX names of CH_ALPN_NAME_MAX bytes cost 4 + 2 + 8 * (1 + 32) = 270 bytes, which
// is what CH_HELLO_MAX and CH_TX_STAGE grow by in this mode
// (test/webpki_session_cases.h measures the built hello). RFC 7301 allows a ProtocolName
// of 1 to 255 bytes, and four of those would cost the hello a kilobyte, so 32 caps one
// name: every protocol ID this tree offers or tests is under 11 bytes. Eight names is four
// times the two-name offer an HTTP caller sends. ch_connect returns CH_EINVAL for a longer
// name or a longer list.
#define CH_ALPN_MAX 8
#define CH_ALPN_NAME_MAX 32

// ch_tls.alpn_selected when no protocol was selected: the caller offered none, or the
// server sent no ALPN extension (RFC 7301 §3.2 lets a server that does not support ALPN
// leave it out). Every other value is an index into ch_cfg.alpn_protocols.
#define CH_ALPN_NONE 255
#endif

#ifdef CH_TRANSPORT_QUIC
// A TRANSPORT=quic build runs this client over QUIC's CRYPTO frames and protects QUIC
// packets with the keys the handshake produces (RFC 9001, docs/quic.md). It has no record
// layer: §4.1.3 takes the unprotected content of TLS handshake records as the content of
// CRYPTO frames and uses no TLS record protection (rfc9001.txt:462-464).
//
// One caller contract holds for every call that takes CRYPTO bytes, and nothing checks it
// at run time: the caller delivers each level's bytes once and in order, and never
// re-delivers bytes chapulin has consumed. A retransmitted CRYPTO frame is a duplicate the
// caller drops, and chapulin stores no CRYPTO stream offset to tell one from new data. The
// two result codes below sit beside CH_EINVAL above, both int. The CH_QUIC_ prefix says
// neither has a meaning on the TLS transport, and ch_quic_open alone returns either.
//
// CH_QUIC_DISCARD is the one operational error in this library that leaves the session
// live, for a packet the caller drops: one that failed to authenticate, which RFC 9001 §5.5
// says does not necessarily indicate a protocol error or an attack (rfc9001.txt:1373-1376),
// or one too short to hold a header protection sample, which §5.4.2 discards
// (rfc9001.txt:1280-1281). Only the first raises ch_quic's open_failures, and quic.h states
// both cases in full. INV-13 carries the code.
//
// CH_QUIC_AEAD_LIMIT ends that tolerance: §6.6 makes an endpoint close and process no
// further packets once failed authentications exceed the AEAD's integrity limit
// (rfc9001.txt:1823-1827). A call that carries open_failures past it leaves the session
// dead.
#define CH_QUIC_DISCARD (-7)
#define CH_QUIC_AEAD_LIMIT (-8)

// The encryption levels, in the order the handshake reaches them (RFC 9001 §4.1.3,
// rfc9001.txt:455-460). CH_LEVEL_APPLICATION is QUIC's 1-RTT level; this build offers no
// 0-RTT, so no level names it. The values are compared, never used as an index into a key
// field.
#define CH_LEVEL_INITIAL 0
#define CH_LEVEL_HANDSHAKE 1
#define CH_LEVEL_APPLICATION 2

// The direction on_level_ready reports and aes_public_key_initial derives for: CH_KEY_READ
// opens what the server sent, CH_KEY_WRITE protects what this client sends. RFC 9001 §5.1
// gives each level separate secrets per direction (rfc9001.txt:1010-1012).
#define CH_KEY_READ 0
#define CH_KEY_WRITE 1

// The 1-RTT receive key set names are CH_QUIC_KEY_PREVIOUS, CH_QUIC_KEY_CURRENT and
// CH_QUIC_KEY_NEXT, and they sit in quic_keys.h beside CH_QUIC_KEY_SETS, the count they
// must agree with. quic.h includes that header, so a caller reading ch_quic_open's key_set
// output sees all four.

// Largest encoded transport-parameters body ch_quic_init accepts. The ClientHello copies
// those bytes unread into extension 0x39 (RFC 9001 §8.2, rfc9001.txt:1922-1924), so the cap
// is a ClientHello budget like CH_ALPN_MAX's.
//
// open: the number. No body has been measured, in either direction (docs/quic.md, "Bounds
// that need measuring"). 256 is a policy cap, not a measurement: it holds the RFC 9000
// §18.2 parameters a client sets, each an identifier byte, a length byte and a value of at
// most 8 bytes, with one connection ID of at most 20 among them. The commit that captures
// real bodies decides the number, beside the re-measured CH_HELLO_MAX and CH_TX_STAGE; a
// build that needs more raises it here.
#ifndef CH_TRANSPORT_PARAMS_MAX
#define CH_TRANSPORT_PARAMS_MAX 256
#endif
#endif

typedef struct {
    // Authentication is one of two modes:
    //  - PSK: psk/psk_id set (external, resumption = 0) or a stored ticket
    //    (resumption = 1, obfuscated_age = ticket age ms + age_add).
    //  - Pinned key: psk NULL, server_pubkey = the server's raw public
    //    key, provisioned like a PSK would be. The key is an RSA modulus
    //    (256..384 bytes big-endian, RSA-2048 to RSA-3072 — the value
    //    rsa.h's CH_RSA_MODULUS_MAX takes in the device modes; exponent
    //    fixed at 65537, RSA-PSS) by default, or 64 P-256 bytes (X||Y,
    //    ECDSA) when built with
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
    // A CH_TRUST_WEBPKI build reads neither: it authenticates the server
    // by a public chain, configured by the fields at the end of this
    // struct. It refuses a config that sets any of these fields but
    // obfuscated_age, which it never reads because it sends no PSK.
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

    // Revocation. Implement these if you need to retire a stolen server key. Without them,
    // whoever steals a server's private key authenticates as that server until you replace
    // the CA key on every device, because this client checks no expiry and no revocation
    // list. With them, the CA counts revocations in each certificate and a device refuses
    // any certificate older than the highest count it has accepted, so reissuing a server
    // on a new key retires the old one. docs/ca.md has the procedure.
    //
    // Give both or neither. They store one uint32 in whatever persistent memory the device
    // has. Both return 0 on success. A failed load fails ch_connect, so provision the
    // fleet's current count before first use. A failed store keeps the session running and
    // sets ch_tls.epoch_store_failed; the caller retries. On resumption, pass the saved
    // ticket's count in ticket_epoch. Only a CH_TRUST_CA build enforces this; other builds
    // reject a config that sets it rather than ignoring it.
    int (*epoch_load)(void *epoch_io, uint32_t *value);
    int (*epoch_store)(void *epoch_io, uint32_t value);
    void *epoch_io;
    uint32_t ticket_epoch;

    // Refuse a session whose key exchange was not post-quantum. Set it and the handshake
    // fails closed unless ch_tls.group is CH_GROUP_X25519MLKEM768 once the handshake
    // accepts the ServerHello's key_share. A KEX=pq build offers that group alone and
    // refuses any other, so there the flag checks at run time what the build promises,
    // against the field the parser wrote rather than the constant the build offered. A
    // classic build offers x25519 alone, so no handshake it runs can satisfy the flag;
    // ch_connect rejects such a config with CH_EINVAL before it sends a byte, as it rejects
    // epoch callbacks outside a CA build. docs/decisions.md 12 says why a build never falls
    // back to the other group.
    int require_pq;

#ifdef CH_TRUST_WEBPKI
    // Web PKI trust (TRUST=webpki, docs/webpki.md):
    //  - anchors: anchor_count entries, 1 to CH_WEBPKI_ANCHOR_MAX, each
    //    with a non-empty name and spki. The server's chain must verify
    //    up to one of them.
    //  - hostname: hostname_len bytes of an ASCII hostname that
    //    webpki_hostname_ok (webpki.h) accepts: 1 to 253 bytes of
    //    [A-Za-z0-9.-], no NUL, no empty label and no IP literal. A
    //    caller with an internationalized name converts each U-label to
    //    its A-label first. A dNSName in the leaf's subjectAltName must
    //    match it, and the client sends it as the ClientHello's
    //    server_name.
    //  - now_seconds: the caller's clock, in seconds since
    //    1970-01-01T00:00:00Z. Every certificate the walk reads must be
    //    valid at it, compared exactly with no skew tolerance. 0 means
    //    the caller never set the clock.
    // ch_connect returns CH_EINVAL before it sends a byte when any of
    // those rules fails, when now_seconds is 0, and when a webpki config
    // sets psk, psk_len, psk_id, psk_id_len, resumption, either
    // server_pubkey slot or its length, or the epoch callbacks. This
    // mode reads no pin, and nothing binds a ticket to the hostname it
    // was issued for (docs/webpki.md, "No PSK, and no resumption").
    //
    // These five fields exist only in a TRUST=webpki build, so the raw
    // and ca objects keep the ch_cfg and ch_tls layout they had before
    // this mode. A raw or ca build that sets one fails to compile, which
    // is stricter than a CH_EINVAL from ch_connect.
    const ch_trust_anchor *anchors;
    size_t anchor_count;
    const uint8_t *hostname;
    size_t hostname_len;
    uint64_t now_seconds;
#endif

// The same two fields serve both builds. Two rules differ under TRANSPORT=quic, where the
// paragraph below states the TCP ones: ch_quic_init applies the checks in place of
// ch_connect, and it refuses an offer of no protocols (rfc9001.txt:1891-1895).
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC)
    // Application protocols to offer through ALPN (RFC 7301), in the order the caller
    // prefers them: alpn_count entries, 0 to CH_ALPN_MAX. Offering none — alpn_protocols
    // NULL and alpn_count 0 — is legal and sends no extension. Every offered entry needs a
    // non-NULL name of 1 to CH_ALPN_NAME_MAX bytes, and no two entries may carry the same
    // name; ch_connect returns CH_EINVAL otherwise. The server picks one, and
    // ch_tls.alpn_selected is its index in this array, or CH_ALPN_NONE when no protocol was
    // selected. This is the second place the mode offers more than one of something, after
    // the signature schemes (docs/decisions.md 37).
    const ch_alpn_protocol *alpn_protocols;
    size_t alpn_count;
#endif

#ifdef CH_TRANSPORT_QUIC
    // The caller's own encoded QUIC transport parameters, the body of the
    // quic_transport_parameters extension. The ClientHello copies these bytes unread into
    // extension 0x39 (RFC 9001 §8.2, rfc9001.txt:1922-1924); chapulin reads none of them,
    // because their content belongs to the QUIC version in use. The caller owns the bytes,
    // and ch_quic_init is the only call that reads them. Required: §8.2 makes an endpoint
    // that sends no extension a protocol violation (rfc9001.txt:1929-1936), so
    // ch_quic_init returns CH_EINVAL, and sends nothing, for a NULL pointer, a zero length
    // or a length above CH_TRANSPORT_PARAMS_MAX.
    const uint8_t *transport_params;
    size_t transport_params_len;

    // Reports that one direction at one encryption level can now protect or unprotect
    // packets: level is a CH_LEVEL_ value, direction is CH_KEY_READ or CH_KEY_WRITE. It
    // carries no key material, so no secret leaves the session through it. One level
    // produces two calls, one per direction, because RFC 9001 §4.1.4 has TLS indicate that
    // reading or writing keys are available (rfc9001.txt:526-528). Required: ch_quic_init
    // returns CH_EINVAL when it is NULL, because a caller that never learns a level is
    // usable can protect no packet.
    //
    // Re-entrancy: it fires from inside ch_quic_crypto_in, never from a poll, because
    // §4.1.4 makes the availability of new keys a result of providing input to TLS
    // (rfc9001.txt:530-531), and it must not call back into the ch_quic it fired from. That
    // rule is a caller contract with no run-time check: a re-entrant call reads state a
    // step is in the middle of writing.
    void (*on_level_ready)(void *io, uint8_t level, uint8_t direction);

    // Hands the server's quic_transport_parameters body to the caller, n bytes of it, as
    // the EncryptedExtensions carried it. The body is opaque to TLS (§8.2), so chapulin
    // passes it on unread. Valid only during the callback: body points into cfg.buf, which
    // the next call overwrites, so copy what you keep. Optional: when it is NULL the body
    // is dropped, and a missing extension still fails the handshake, because §8.2 makes an
    // EncryptedExtensions without it an error of type 0x016d (rfc9001.txt:1929-1936) and
    // the parser enforces that whether or not this callback is set. Re-entrancy:
    // on_level_ready's rule, for the same reason.
    void (*on_transport_params)(void *io, const uint8_t *body, size_t n);
#endif
} ch_cfg;

#endif
