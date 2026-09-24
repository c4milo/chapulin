// The HelloRetryRequest cookie: mint and open. A ROLE=server build
// keeps no state between the two ClientHellos of a retry, so everything
// it must carry across the round trip travels in this cookie, under a
// MAC the client cannot forge. RFC 9846 §4.3.2 describes exactly that
// use — a stateless server stores Hash(ClientHello1) in the cookie
// under integrity protection (rfc9846.txt:1779-1783) — and §4.1's
// synthetic message_hash transcript exists so that one hash is all the
// server must keep (rfc9846.txt:1084-1087). §9.2 makes the extension
// mandatory to implement (rfc9846.txt:4560).
//
// Only a ROLE=server build compiles it. docs/server.md states the role
// and gives the format this header implements.
//
// The cookie is public: it goes out in the clear and comes back in the
// clear, and it carries no key material. Two things here are still
// constant time. The MAC comparison goes through ct_memeq over all 32
// bytes, because a byte-at-a-time compare would let a client search for
// a valid MAC one byte per round trip. The frozen-fields digest the
// caller compares afterwards goes through ct_memeq for the same reason.
// CLAUDE.md requires both, and test/violations carries a mutant that
// replaces each with memcmp.
#ifndef CH_SRV_COOKIE_H
#define CH_SRV_COOKIE_H
#ifdef CH_ROLE_SERVER

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "sha256.h"

// The cookie key: 32 bytes of HMAC-SHA-256 key the caller owns and
// holds in ch_cfg's srv.cookie_key. One key per deployment, so a second
// ClientHello that lands on a different session, or on a different
// device behind a load balancer, still verifies.
#define SRV_COOKIE_KEY_LEN SHA256_LEN

// The first byte of the cookie body: this format's own version number,
// not a TLS version. It exists so a deployment that changes the format
// can refuse the old shape rather than misread it, and so the cookie's
// length is never the only thing that identifies it.
#define SRV_COOKIE_VERSION 1

// The largest transcript hash any cipher suite in RFC 9846 §9.1 names,
// in bytes (rfc9846.txt:4055-4056 binds the hash to the suite). It is
// 48, for TLS_AES_256_GCM_SHA384. This build selects only
// TLS_CHACHA20_POLY1305_SHA256 and therefore mints only SHA256_LEN
// cookies, and the constant is stated at the larger value so that the
// buffer sizes below do not move when that suite arrives.
#define SRV_COOKIE_HASH_MAX 48

// The largest cookie this server mints, in bytes: 1 version byte, 2
// suite bytes, 2 group bytes, SRV_COOKIE_HASH_MAX bytes of
// Hash(ClientHello1), SHA256_LEN bytes of the frozen-fields digest and
// SHA256_LEN bytes of MAC. That is 117. A SHA-256 suite mints 101 of
// those bytes, because the Hash(ClientHello1) term is 16 bytes shorter.
//
// Both fit HSP_COOKIE_MAX (handshake_parser.h), which is 128, so the
// cookie costs the session nothing new: handshake_state already carries
// uint8_t cookie[HSP_COOKIE_MAX] (handshake_record.h). srv_flight.h
// asserts the relation, where both constants are visible.
#define SRV_COOKIE_MAX (1 + 2 + 2 + SRV_COOKIE_HASH_MAX + SHA256_LEN + SHA256_LEN)

// Mints one cookie: the body, then HMAC-SHA-256 over that body under
// key. The body is the version byte, suite and group as two bytes each
// in network byte order, hash_len bytes of Hash(ClientHello1), and
// SHA256_LEN bytes of the digest over the fields RFC 9846 §4.2.2
// freezes (client_hello.frozen, srv_parser.h).
//
// Why each term is in the body. Hash(ClientHello1) is what §4.1's
// synthetic transcript needs (rfc9846.txt:1084-1087). The suite is
// there because a HelloRetryRequest carries one
// (rfc9846.txt:1449-1452), so the server must rebuild those bytes
// without holding them, and because the suite is what fixes the length
// of the hash term beside it, which the hash cannot do for itself. The
// group is there for the same rebuild: the HelloRetryRequest's
// key_share names the group it asked for. The frozen digest is there
// so the second ClientHello can be checked against the first without
// storing the first.
//
// Requires key pointing at SRV_COOKIE_KEY_LEN readable bytes;
// ch1_hash pointing at hash_len readable bytes, the transcript hash of
// the first ClientHello; hash_len equal to the selected suite's hash
// length, from SHA256_LEN to SRV_COOKIE_HASH_MAX; frozen pointing at
// SHA256_LEN readable bytes; cap bytes writable at out, not
// overlapping any input.
//
// Writes the whole cookie and returns its length in bytes, which is
// 5 + hash_len + 2 * SHA256_LEN. Returns 0 and writes nothing when cap
// is below that length or hash_len is outside its range. It draws no
// randomness: two retries of one ClientHello mint the same bytes, which
// costs nothing, because the cookie authenticates a message the client
// already sent.
size_t srv_cookie_mint(const uint8_t key[SRV_COOKIE_KEY_LEN], uint16_t suite, uint16_t group,
                       const uint8_t *ch1_hash, size_t hash_len, const uint8_t frozen[SHA256_LEN],
                       uint8_t *out, size_t cap);

// Opens one cookie the client echoed: checks the MAC, then reports what
// the body carried.
//
// It reads the version byte and the suite first, because the suite
// fixes the length of the hash term and therefore the length the whole
// cookie must have. A cookie whose length does not match the suite it
// names is refused before the MAC runs, so no read goes past n. The MAC
// is then computed over the body and compared with ct_memeq over all
// SHA256_LEN bytes.
//
// Requires key pointing at SRV_COOKIE_KEY_LEN readable bytes; cookie
// pointing at n readable bytes, the bytes client_hello.cookie names;
// ch1_hash pointing at SRV_COOKIE_HASH_MAX writable bytes; suite,
// group, hash_len and frozen pointing at writable objects. frozen takes
// SHA256_LEN bytes.
//
// Returns CH_OK and writes all five outputs: *suite and *group as the
// mint recorded them, *hash_len as the suite fixes it, hash_len bytes
// at ch1_hash, and SHA256_LEN bytes at frozen.
//
// Returns CH_EPROTO and writes none of them when the version byte is
// not SRV_COOKIE_VERSION, when the suite is not one this build holds,
// when n is not the length that suite fixes, or when the MAC does not
// compare equal. The caller answers illegal_parameter for every one of
// them: a cookie this server did not mint is a field that parses and is
// semantically invalid, which is what RFC 9846 §6.2 describes
// illegal_parameter as covering (rfc9846.txt:3947). It is not
// decrypt_error: nothing here verifies a signature, a Finished or a PSK
// binder, which are the three failures §6.2 gives that description
// (rfc9846.txt:3968-3970).
int srv_cookie_open(const uint8_t key[SRV_COOKIE_KEY_LEN], const uint8_t *cookie, size_t n,
                    uint16_t *suite, uint16_t *group, uint8_t *ch1_hash, size_t *hash_len,
                    uint8_t frozen[SHA256_LEN]);

#endif // CH_ROLE_SERVER
#endif
