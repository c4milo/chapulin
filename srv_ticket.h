// The resumption ticket a ROLE=server build issues and accepts: seal and
// open. A server that keeps no session database puts everything it needs
// to resume a session inside the ticket, sealed under a key only the
// server holds, which RFC 9846 §4.7.1 permits: the ticket "MAY be either
// a database lookup key or a self-encrypted and self-authenticated value"
// (rfc9846.txt:3276-3277). This file is the second kind.
//
// Only a ROLE=server build compiles it. docs/server.md, "Resumption",
// states the role, and srv_resume.h is the flight that calls it.
//
// The two calls are pure functions over caller buffers. They take the key
// and no session, and they draw no randomness: the caller draws the AEAD
// nonce and passes it in, so a test and a proof replay a ticket exactly.
//
// The ticket layout, byte by byte:
//
//   offset  bytes  field
//   0       1      SRV_TICKET_VERSION
//   1       12     the AEAD nonce, drawn fresh for this ticket
//   13      75     the sealed body, laid out below
//   88      16     the Poly1305 tag
//
// The body, before it is sealed:
//
//   offset  bytes  field
//   0       8      auth_seconds, most significant byte first
//   8       2      suite, the cipher suite code point
//   10      1      alpn_len, 0 to CH_ALPN_NAME_MAX
//   11      32     the ALPN protocol name, zero past alpn_len
//   43      32     psk, the resumption PSK
//
// The body is sealed with aead_seal, ChaCha20-Poly1305 (RFC 8439 §2.8),
// under the caller's ticket key and the nonce at offset 1. The associated
// data is the version byte, so a ticket whose first byte changed fails to
// open rather than being read under another layout.
//
// Why a random nonce is safe here, and where it stops being safe. Every
// ticket under one key takes its own 96-bit nonce from ch_rand_bytes, and
// two tickets that drew one nonce would leak the XOR of their bodies and
// let a forger compute tags. The chance of any repeat among 2^32 tickets
// is about 2^-33, which is the bound NIST SP 800-38D §8.3 sets for random
// 96-bit nonces under one key. A deployment rotates its ticket key before
// it has issued 2^32 tickets under it; at one ticket per handshake that is
// 7,000 handshakes a second for a week.
//
// The ticket key is as valuable as the signing keys, for as long as the
// tickets it sealed live. Whoever holds it opens every ticket, reads the
// PSK inside, and resumes as this server with any client that kept one.
// psk_dhe_ke still runs a key exchange on every resumed handshake, so a
// stolen ticket key decrypts no recorded session (rfc9846.txt:6569-6571).
#ifndef CH_SRV_TICKET_H
#define CH_SRV_TICKET_H
#ifdef CH_ROLE_SERVER

#include <stddef.h>
#include <stdint.h>

#include "aead.h"
#include "cfg.h"
#include "hkdf.h"
#include "sha256.h"

// The ticket key: 32 bytes of ChaCha20-Poly1305 key the caller owns and
// holds in ch_cfg's srv.ticket_key. One key per deployment, so a ticket
// one server issued opens on another server that holds the same key, the
// way srv_cookie.h's cookie key works. It must be a key of its own, not
// the cookie key: the two protect different formats with different
// primitives, and nothing here checks that they differ.
#define SRV_TICKET_KEY_LEN AEAD_KEY

// The first byte of every ticket: this format's own version number, not a
// TLS version. A deployment that changes the layout moves it, and every
// ticket under the old layout then fails to open and costs its client
// one full handshake.
#define SRV_TICKET_VERSION 1

// The longest time a ticket stays usable, in seconds, counted from
// auth_seconds. RFC 9846 §4.7.1 caps ticket_lifetime at 604800
// (rfc9846.txt:3257-3258), and this build takes the whole week by
// default. A build that wants a shorter one defines the constant; the
// assertion in srv_ticket.c holds any value to 1..604800.
#ifndef SRV_TICKET_LIFETIME
#define SRV_TICKET_LIFETIME 604800
#endif

// The sealed body's length, in bytes: auth_seconds (8), suite (2),
// alpn_len (1), the name at its longest (CH_ALPN_NAME_MAX) and the PSK at
// the longest hash the build holds (HKDF_HASH_MAX). It is 75, and 91 in a
// -DCH_SUITE_AES_GCM build, where a SHA-256 PSK leaves its last 16 bytes
// zero.
#define SRV_TICKET_BODY_LEN (8 + 2 + 1 + CH_ALPN_NAME_MAX + HKDF_HASH_MAX)

// The whole ticket's length, in bytes, and the only length a ticket has
// in one build: the version byte, the AEAD nonce, the body and the tag.
// It is 104, and 120 in a -DCH_SUITE_AES_GCM build. The fixed length is
// what lets srv_resume.c pass over an identity of any other length
// without running the AEAD.
#define SRV_TICKET_LEN (1 + AEAD_NONCE + SRV_TICKET_BODY_LEN + AEAD_TAG)

// What one ticket carries.
//
// auth_seconds is the instant, on the caller's clock, of the handshake in
// which this server last proved its identity with a certificate. A ticket
// issued after a full handshake carries that handshake's instant. A ticket
// issued after a resumed handshake carries the instant the resumed ticket
// carried, because nothing in a resumed handshake proves the certificate
// again. So a chain of resumptions ends SRV_TICKET_LIFETIME seconds after
// the full handshake it started from, however many tickets it passed
// through.
//
// suite is the cipher suite of the connection that issued the ticket. RFC
// 9846 §4.7.1 lets a ticket resume only under a suite with the same KDF
// hash (rfc9846.txt:3219-3220), and suite_hash_len (suite.h) of it names
// that hash, so the hash is not stored separately.
//
// alpn and alpn_len are the application protocol that connection
// negotiated, and alpn_len is 0 when it negotiated none. srv_resume.h
// states why a ticket resumes only a connection that negotiates the same
// protocol.
//
// psk is the ticket's PSK, HKDF-Expand-Label(resumption_secret,
// "resumption", ticket_nonce, Hash.length) (rfc9846.txt:3298-3301): its
// first suite_hash_len(suite) bytes, and zero past them. It is the one
// secret here, and every holder wipes it.
typedef struct {
    uint64_t auth_seconds;
    uint16_t suite;
    uint8_t alpn_len;
    uint8_t alpn[CH_ALPN_NAME_MAX];
    uint8_t psk[HKDF_HASH_MAX];
} srv_ticket_contents;

// Seals one ticket carrying c under key, with the AEAD nonce at nonce.
//
// Requires: key points at SRV_TICKET_KEY_LEN readable bytes; nonce at
// AEAD_NONCE readable bytes the caller drew through ch_rand_bytes for
// this ticket alone; c at a readable srv_ticket_contents; out at cap
// writable bytes that overlap no input.
//
// Returns SRV_TICKET_LEN and writes the whole ticket. Returns 0 and writes
// nothing when cap is below SRV_TICKET_LEN or c->alpn_len is above
// CH_ALPN_NAME_MAX. It stages the body on its own frame and wipes that
// staging before it returns, because the body holds the PSK.
size_t srv_ticket_seal(const uint8_t key[SRV_TICKET_KEY_LEN], const uint8_t nonce[AEAD_NONCE],
                       const srv_ticket_contents *c, uint8_t *out, size_t cap);

// Opens the n bytes of one ticket under key and writes what it carried to
// *c.
//
// It reads the length and the version byte first, because both travel in
// the clear and fix everything after them. A ticket of any length but
// SRV_TICKET_LEN, or whose first byte is not SRV_TICKET_VERSION, is
// refused before the AEAD runs. aead_open then checks the tag over the
// whole body before it releases a byte (aead.h), and compares it in
// constant time.
//
// Requires: key points at SRV_TICKET_KEY_LEN readable bytes; ticket at n
// readable bytes; c at a writable srv_ticket_contents.
//
// Returns CH_OK and writes *c.
//
// Returns CH_EAUTH, and leaves *c zeroed, when the length or the version
// byte is wrong, when the tag does not verify, which is what a ticket
// sealed under another key or altered in any byte gives, and when the
// body's alpn_len is above CH_ALPN_NAME_MAX. The last one cannot come from
// a ticket this format sealed; it is refused so that no caller reads a
// length past the name. Every refusal means only "not a ticket this key
// sealed", and srv_resume.c answers each one by passing over the identity,
// which RFC 9846 §4.3.11 asks of an unknown PSK (rfc9846.txt:2533-2537).
int srv_ticket_open(const uint8_t key[SRV_TICKET_KEY_LEN], const uint8_t *ticket, size_t n,
                    srv_ticket_contents *c);

#endif // CH_ROLE_SERVER
#endif
