// The address validation token a QUIC server puts in a Retry packet: mint one
// when the server sends a Retry, check the one the client's next Initial
// carries (RFC 9000 §8.1.2, rfc9000.txt:2268-2273). Only a build with a server
// role and TRANSPORT=quic compiles it, and srv_quic.h includes this header, so
// a caller of the server's QUIC calls sees these two as well.
//
// A server that sends a Retry keeps no state for the connection, so what it
// needs from the first Initial travels in the token: the Original Destination
// Connection ID, the Source Connection ID the Retry carried, and the instant
// the token was issued. The server needs both connection IDs again for the
// original_destination_connection_id and retry_source_connection_id transport
// parameters (RFC 9000 §7.3, rfc9000.txt:1911-1917), and a stateless server
// has no other source for them.
//
// RFC 9000 §8.1.4 requires integrity protection against modification or
// falsification by clients (rfc9000.txt:2434-2437), and HMAC-SHA-256 under a
// key only the server holds provides it. Nothing here encrypts: every field
// the token carries is one the client and the path already saw in the clear,
// except the issue instant, and the client's address is covered by the tag
// without travelling in the token. RFC 9000 §8.1.3's rule against linkable
// fields is for NEW_TOKEN tokens (rfc9000.txt:2346-2350), which this build
// does not mint.
//
// The two calls are pure functions over caller buffers. They take the key
// directly and no session, because a Retry precedes every piece of
// connection state. docs/quic_server.md, "The Retry token", states what the
// caller still owns.
//
// The token layout, byte by byte. o is original_dcid_len and r is
// retry_scid_len, each 0 to CH_QUIC_DCID_MAX.
//
//   offset      bytes  field
//   0           1      QUIC_TOKEN_TYPE_RETRY
//   1           8      issued_seconds, most significant byte first
//   9           1      o
//   10          o      the Original Destination Connection ID
//   10 + o      1      r
//   11 + o      r      the Retry's Source Connection ID
//   11 + o + r  32     the tag
//
// The body is every byte before the tag. The tag is HMAC-SHA-256 under the
// key over, in order: the 19 ASCII bytes "chapulin quic token", one byte
// holding address_len, the address_len bytes of the address, and the body.
// The label keeps a token's tag from ever being computed over the same bytes
// as another MAC this tree writes, the HelloRetryRequest cookie of
// srv_cookie.h among them, so a deployment that gave both one key still
// could not present one as the other.
#ifndef CH_QUIC_TOKEN_H
#define CH_QUIC_TOKEN_H
#if defined(CH_ROLE_SERVER) && defined(CH_TRANSPORT_QUIC)

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "sha256.h"

// The token key: 32 bytes of HMAC-SHA-256 key the caller owns. One key per
// deployment, the way ch_srv_cfg's cookie_key is one (srv_cfg.h), so a token
// one process minted checks in another that holds the same key.
#define CH_QUIC_TOKEN_KEY_LEN SHA256_LEN

// The longest client address a token binds, in bytes: a 16-byte IPv6
// address and a 2-byte port. The address is opaque to chapulin, and the
// caller chooses its encoding; mint and check must be given the same bytes
// for the same client.
#define CH_QUIC_TOKEN_ADDRESS_MAX 18

// The first byte of every token, which says how the server handed the token
// to the client. RFC 9000 §8.1.1 requires a server to tell a Retry token from
// a NEW_TOKEN token, because the two need different handling
// (rfc9000.txt:2263-2266). This build mints the first alone.
// QUIC_TOKEN_TYPE_NEW_TOKEN is reserved for a NEW_TOKEN mint, and the check
// refuses it today.
#define QUIC_TOKEN_TYPE_RETRY 0x01
#define QUIC_TOKEN_TYPE_NEW_TOKEN 0x02

// The longest token this build mints, in bytes, for a caller that sizes its
// buffer: 1 type byte, 8 bytes of issued_seconds, two length bytes, two
// connection IDs of CH_QUIC_DCID_MAX bytes and SHA256_LEN bytes of tag. That
// is 83. The shortest is 43, with both connection IDs empty, so a minted
// token is never the zero-length token RFC 9000 §17.2.5.2 makes a client
// discard a Retry for (rfc9000.txt:5410-5411).
#define CH_QUIC_TOKEN_MAX (1 + 8 + 1 + CH_QUIC_DCID_MAX + 1 + CH_QUIC_DCID_MAX + SHA256_LEN)

// The two connection IDs a Retry token carries. original_dcid is the
// Destination Connection ID of the client's first Initial, which the server
// sends back as original_destination_connection_id. retry_scid is the Source
// Connection ID the server put in its Retry, which it sends back as
// retry_source_connection_id (RFC 9000 §7.3, rfc9000.txt:1911-1917). Each
// length counts bytes and is at most CH_QUIC_DCID_MAX, the RFC 9000 §17.2 cap
// (rfc9000.txt:4991-4998).
typedef struct {
    uint8_t original_dcid[CH_QUIC_DCID_MAX];
    uint8_t original_dcid_len;
    uint8_t retry_scid[CH_QUIC_DCID_MAX];
    uint8_t retry_scid_len;
} ch_quic_retry_cids;

// Mints one Retry token for the client at address, carrying the two
// connection IDs in cids and the instant issued_seconds.
//
// issued_seconds is a count of seconds the caller reads from its own clock.
// chapulin reads no clock and compares only the difference between two
// instants, so any epoch serves, provided every process that holds the key
// uses the same one; Unix time is the plain choice.
//
// Requires: key points at CH_QUIC_TOKEN_KEY_LEN readable bytes; address at
// address_len readable bytes; cids at a readable ch_quic_retry_cids; out at
// cap writable bytes that overlap no input; out_len at a writable size_t.
//
// Returns CH_OK, writes the token to out and writes its length in bytes to
// *out_len: 43 + cids->original_dcid_len + cids->retry_scid_len, which is at
// most CH_QUIC_TOKEN_MAX.
//
// Returns CH_EINVAL and writes nothing when address_len is 0 or above
// CH_QUIC_TOKEN_ADDRESS_MAX, or when either length in cids is above
// CH_QUIC_DCID_MAX. A token bound to no address would validate every
// address, so the empty one is refused rather than minted.
//
// Returns CH_ECAP and writes nothing when cap is below the token's length.
// A cap of CH_QUIC_TOKEN_MAX never returns it.
//
// It draws no randomness: the same inputs mint the same bytes, so a seeded
// simulation replays a token exactly. RFC 9000 §8.1.4 requires a token to be
// difficult to guess (rfc9000.txt:2429), and the tag is what makes it so: a
// client without the key cannot compute the 32 bytes that end the token.
int ch_srv_quic_token_mint(const uint8_t key[CH_QUIC_TOKEN_KEY_LEN], const uint8_t *address,
                           size_t address_len, const ch_quic_retry_cids *cids,
                           uint64_t issued_seconds, uint8_t *out, size_t cap, size_t *out_len);

// Checks the n token bytes a client's Initial carried and, when they verify,
// writes the two connection IDs they hold to *cids.
//
// A token verifies when all four of these hold: its first byte is
// QUIC_TOKEN_TYPE_RETRY; its length is the one its two length bytes fix, and
// each of those is at most CH_QUIC_DCID_MAX; its tag equals the tag this key
// computes over this address and its body; and its issue instant is at most
// lifetime_seconds before now_seconds and not after it. now_seconds comes
// from the same clock as issued_seconds.
//
// The length fields are read before the tag is computed. They travel in the
// clear, so reading them first tells a client nothing it did not send, and
// the reader is bounded by n, so no read goes past the token. The tag is
// compared with ct_memeq over all SHA256_LEN bytes, because a compare that
// stopped at the first differing byte would let a client search for a valid
// tag one byte per attempt. The instant is judged only after the tag
// verifies, so the check never acts on an instant the key did not cover.
//
// Requires: key points at CH_QUIC_TOKEN_KEY_LEN readable bytes; token at n
// readable bytes; address at address_len readable bytes; cids at a writable
// ch_quic_retry_cids.
//
// Returns CH_OK and writes *cids.
//
// Every other return writes nothing to *cids.
//
// Returns CH_EINVAL when address_len is 0 or above CH_QUIC_TOKEN_ADDRESS_MAX.
// That is the caller's error, and the token is not read.
//
// Returns CH_EPROTO when n is 0 or the first byte is not
// QUIC_TOKEN_TYPE_RETRY, QUIC_TOKEN_TYPE_NEW_TOKEN included: the token is not
// a Retry token this server minted. RFC 9000 §8.1.3 has a server then proceed
// as if the client had no validated address, which may mean sending a Retry
// (rfc9000.txt:2397-2399). An Initial with an empty Token field carries no
// token at all, and a caller need not call this for one.
//
// Returns CH_EAUTH for a token whose first byte is QUIC_TOKEN_TYPE_RETRY and
// that fails any other rule above: a length that does not match its length
// bytes, a length byte above CH_QUIC_DCID_MAX, a tag that does not equal the
// one this key computes for this address, or an issue instant after
// now_seconds or more than lifetime_seconds before it. RFC 9000 §8.1.2 has a
// server close the connection with INVALID_TOKEN then, because a client that
// received a Retry accepts no second one (rfc9000.txt:2295-2301).
int ch_srv_quic_token_check(const uint8_t key[CH_QUIC_TOKEN_KEY_LEN], const uint8_t *token,
                            size_t n, const uint8_t *address, size_t address_len,
                            uint64_t now_seconds, uint64_t lifetime_seconds,
                            ch_quic_retry_cids *cids);

#endif // CH_ROLE_SERVER && CH_TRANSPORT_QUIC
#endif
