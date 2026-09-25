// The server's key exchange: which group it selects from a ClientHello,
// the key_exchange bytes its ServerHello carries for that group, and the
// input keying material the key schedule extracts from. srv_flight.c
// calls the four functions here from srv_select, srv_check_retry_hello,
// srv_send_server_hello and srv_derive_handshake_secrets; this pair
// writes no message and sends nothing. Only a ROLE=server build
// compiles it.
//
// Every server build holds three groups, X25519MLKEM768, x25519 and
// secp256r1, and the Makefile KEX variable selects nothing here: KEX
// chooses a raw or ca client's one group, and a server has no such choice
// (docs/decisions.md 54). The server prefers the hybrid, because it is
// the group whose recorded traffic stays confidential against a later
// quantum computer, then x25519, and takes secp256r1 last, only from a
// client that lists neither of the others: RFC 9846 §9.1 makes secp256r1
// a MUST and X25519 a SHOULD (rfc9846.txt:4548-4550), and one P-256
// scalar multiplication here takes 1,228 microseconds against x25519's
// 953, measured on an M1 Pro (bench/notes-primitives.md,
// docs/decisions.md 63).
//
// The hybrid follows RFC 10024. The client's key_exchange is the
// ML-KEM-768 encapsulation key, MLKEM_EK_LEN bytes, then its x25519
// public value. The server's is the ML-KEM-768 ciphertext, MLKEM_CT_LEN
// bytes, then its own x25519 public value. The shared secret is the
// ML-KEM shared secret, then the x25519 one. The ML-KEM bytes come first
// in all three despite the group's name, and handshake_flight.c's
// hybrid_secret reads them in the same order on the client.
//
// secp256r1 follows RFC 9846 §4.3.8.2 and §7.4.2. Each side's
// key_exchange is its point in the 65-byte uncompressed form, and the
// shared secret is the 32-byte X coordinate of the product, with no
// leading zero dropped (rfc9846.txt:4266-4276). The arithmetic is
// p256_ecdh.[ch], which runs the same instructions whatever the scalar
// holds.
//
// Every value a branch here reads is public: the group, the client's
// shares, and the verdicts, the encapsulation key check, the P-256 point
// check, whether a drawn P-256 candidate was in range and the x25519
// all-zero check, which the peer learns from the alert anyway. The
// secrets, the encapsulation randomness, the P-256 scalar, the ML-KEM
// shared secret and the x25519 and P-256 ones, are copied and wiped and
// never branched on.
#ifndef CH_SRV_KEX_H
#define CH_SRV_KEX_H
#ifdef CH_ROLE_SERVER

#include <stddef.h>
#include <stdint.h>

#include "handshake_record.h"
#include "mlkem.h"
#include "p256_ecdh.h"
#include "srv_parser.h"
#include "x25519.h"

// The longest key_exchange this server writes, the hybrid one, and the
// longest input keying material it derives, the hybrid's two shared
// secrets side by side. An x25519 or secp256r1 key exchange uses the
// first 32 bytes of the secret, and a secp256r1 share the first
// P256_POINT_LEN bytes of the share.
#define SRV_KEX_SHARE_MAX CH_HYBRID_SERVER_SHARE
#define SRV_KEX_SECRET_MAX (MLKEM_SS_LEN + X25519_LEN)
#ifndef __cplusplus
_Static_assert(P256_POINT_LEN <= SRV_KEX_SHARE_MAX && P256_SECRET_LEN <= SRV_KEX_SECRET_MAX,
               "a secp256r1 share and secret fit the hybrid's arrays");
#endif

// The group this server selects, read from the client's supported_groups
// alone: CH_GROUP_X25519MLKEM768 when the client listed it, else
// CH_GROUP_X25519 when the client listed that, else CH_GROUP_SECP256R1
// when the client listed that, else 0, which srv_select answers with
// handshake_failure (rfc9846.txt:1145-1148).
//
// The key_share does not move the choice. RFC 9846 §4.3.8 asks a server
// that respects the client's preferences to select from supported_groups
// first and then send a ServerHello or a HelloRetryRequest depending on
// the key_share (rfc9846.txt:2172-2177). This server applies its own
// preference the same way, so a client that lists the hybrid and shares
// only x25519 gets a HelloRetryRequest naming the hybrid, one that shares
// both gets the hybrid in one round trip, and one that lists x25519 and
// shares only secp256r1 gets a HelloRetryRequest naming x25519.
//
// It is a predicate over public values and changes nothing.
uint16_t srv_kex_group(const client_hello *ch);

// Whether the client's key_share carried an entry for group. Returns 0 for
// a group this build does not hold. srv_select owes a HelloRetryRequest
// exactly when this is 0 for the group srv_kex_group chose
// (rfc9846.txt:1158-1161).
int srv_kex_shared(const client_hello *ch, uint16_t group);

// Writes this server's KeyShareEntry.key_exchange for group into share and
// its length into *share_len.
//
// For x25519 it copies h->pub, X25519_LEN bytes. For X25519MLKEM768 it
// draws the 32-byte ML-KEM encapsulation randomness through ch_rand_bytes
// (INV-4), encapsulates to the encapsulation key that begins
// ch->hybrid_share, writes the ciphertext and then h->pub, and keeps the
// ML-KEM shared secret in h->mlkem_ss for srv_kex_secret. The randomness
// is wiped before this returns, on both exits. For secp256r1 it first
// checks the client's point, ch->p256_share, as RFC 9846 §4.3.8.2
// requires (rfc9846.txt:2277-2286), then draws the P-256 key pair through
// ch_rand_bytes (INV-4), the scalar into h->p256_priv and the uncompressed
// point into share, P256_POINT_LEN bytes. A candidate outside [1, n-1] is
// drawn again, up to P256_ECDH_DRAWS draws in all, and CH_ASSERT holds
// the generator to rand.h's contract past that.
//
// Requires srv_begin to have run, so h->pub holds the server's x25519
// public value; a group srv_kex_group returned; and a ch whose share for
// that group is set. The last is a call-order rule, because srv_select
// owes a HelloRetryRequest rather than a ServerHello for a hello that
// carried no share for its group, and CH_ASSERT holds it.
//
// Returns CH_OK with share and *share_len written. Returns CH_EPROTO, with
// h->mlkem_ss and h->p256_priv zero and nothing written to *share_len,
// when the client's share fails its check: for the hybrid, a coefficient
// of the encapsulation key at or above the modulus, the check FIPS 203
// §7.2 requires before encapsulation, which RFC 10024 has the server
// abort on; for secp256r1, a point that is not on the curve or not in
// the uncompressed form. The caller answers illegal_parameter, before any
// ServerHello goes out and, for secp256r1, before anything is drawn.
int srv_kex_share(handshake_state *h, const client_hello *ch, uint16_t group,
                  uint8_t share[SRV_KEX_SHARE_MAX], size_t *share_len);

// Writes the input keying material for group into ikm and its length into
// *ikm_len: for x25519, the x25519 shared secret of h->priv and
// ch->x25519_share; for X25519MLKEM768, h->mlkem_ss, then the x25519
// shared secret of h->priv and the x25519 public value that ends
// ch->hybrid_share, the order RFC 10024 fixes and handshake_flight.c's
// hybrid_secret computes on the client; for secp256r1, the P-256 shared
// secret of h->p256_priv and ch->p256_share, P256_SECRET_LEN bytes.
//
// Requires srv_kex_share to have run for the same group and ch, and the
// share it reads to still point at live bytes in cfg.buf.
//
// Wipes h->priv, h->pub, h->mlkem_ss and h->p256_priv on both exits,
// because the key exchange is over either way (INV-17).
//
// Returns CH_OK with *ikm_len bytes of ikm written. Returns CH_EPROTO with
// all SRV_KEX_SECRET_MAX bytes of ikm zero when x25519 yields the all-zero
// shared secret, which RFC 9846 §7.4.2 makes a MUST (rfc9846.txt:4293-4295)
// and RFC 10024 keeps for the hybrid's x25519 half, or when p256_ecdh
// refuses the client's point, which srv_kex_share already checked; the
// caller answers illegal_parameter (INV-3).
int srv_kex_secret(handshake_state *h, const client_hello *ch, uint16_t group,
                   uint8_t ikm[SRV_KEX_SECRET_MAX], size_t *ikm_len);

#endif // CH_ROLE_SERVER
#endif
