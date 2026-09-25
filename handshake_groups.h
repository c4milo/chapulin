// The key exchange rules of a client that offers more than one group
// (CH_KEX_TWO_GROUPS, cfg.h): every TRUST=webpki client, and no other.
// Its first hello lists X25519MLKEM768, x25519 and secp256r1 and carries a
// key share for the first two (docs/decisions.md 53 and 63). This pair
// holds what that offer adds to handshake_flight.c's one-group rules: the
// HelloRetryRequest that names secp256r1, which group a ServerHello may
// then select, and the shared secret of the two classic groups. The
// hybrid secret stays in handshake_flight.c, because a raw or ca KEX=pq
// client runs it too.
//
// Only a build that defines CH_KEX_TWO_GROUPS compiles or links this
// pair, and handshake_flight.c calls it only under that define.
//
// Every branch here reads a public value: a group code point off the
// wire, the configuration's require_pq, and whether a drawn P-256
// candidate was in range, which says nothing about the candidate kept.
// The private values, the x25519 and P-256 scalars and the ML-KEM seed,
// are copied, computed over and wiped, and never branched on.
#ifndef CH_HANDSHAKE_GROUPS_H
#define CH_HANDSHAKE_GROUPS_H

// cfg.h defines CH_KEX_TWO_GROUPS from CH_TRUST_WEBPKI, so it comes first.
#include "cfg.h"

#ifdef CH_KEX_TWO_GROUPS

#include <stddef.h>
#include <stdint.h>

#include "handshake_parser.h"
#include "handshake_record.h"
#include "p256_ecdh.h"
#include "x25519.h"

// Takes what a HelloRetryRequest asks of this client's key exchange: the
// group its key_share names, info->retry_group, which the parser accepted
// only as CH_GROUP_SECP256R1, the one group the first hello lists without
// a share (RFC 9846 §4.3.8, rfc9846.txt:2205-2215), or 0 when it names
// none. The caller copies the cookie.
//
// A retry that names no group returns CH_OK when it carries a cookie and
// CH_EPROTO when it carries none either, because it then asks for no
// change (RFC 9846 §4.2.4, rfc9846.txt:1467-1469). With cfg.require_pq
// set the hello listed the hybrid alone, so a retry naming secp256r1
// names a group it never listed, and this returns CH_EPROTO. Neither
// refusal changes anything, and the caller answers illegal_parameter.
//
// Otherwise it writes h->retry_group, draws the P-256 key pair the retry
// hello carries through ch_rand_bytes, the scalar into h->p256_priv and
// the uncompressed point into h->p256_pub, and wipes h->priv, h->pub and
// h->dz: the retry hello carries the secp256r1 share alone (§4.2.2,
// rfc9846.txt:1194-1196) and the ServerHello must select secp256r1
// (rfc9846.txt:2233-2238), so the x25519 and ML-KEM key pairs of the first
// hello go unused from here on (INV-17). The draw is INV-4's P-256 client
// site, and it runs only here. It retries a candidate outside [1, n-1] up
// to P256_ECDH_DRAWS draws in all, and CH_ASSERT holds the generator to
// rand.h's contract past that, as every draw site holds it against an
// all-zero draw.
//
// Requires hsf_begin to have run, and info filled by
// hsp_parse_server_hello from a HelloRetryRequest. Returns CH_OK or
// CH_EPROTO.
int hsg_take_retry(handshake_state *h, const server_hello_info *info);

// Whether a ServerHello that selected group answers the hello this client
// sent last: CH_GROUP_SECP256R1 after a retry that named it, since the
// retry hello carried that share alone, and X25519MLKEM768 or x25519
// otherwise, since the first hello carried those two shares and no
// secp256r1 share (RFC 9846 §4.3.8, rfc9846.txt:2224-2238). The parser
// accepts all three groups because it cannot tell which hello a
// ServerHello answers. A predicate over public values; it changes
// nothing.
int hsg_selected_group_ok(const handshake_state *h, uint16_t group);

// The longest secret hsg_classic_secret writes. Both groups' secrets are
// 32 bytes, and this holds that as a build fact.
#define HSG_CLASSIC_SECRET_MAX 32
#ifndef __cplusplus
_Static_assert(X25519_LEN == HSG_CLASSIC_SECRET_MAX && P256_SECRET_LEN == HSG_CLASSIC_SECRET_MAX,
               "both classic secrets are 32 bytes");
#endif

// Runs the key exchange of a ServerHello that selected one of the two
// classic groups, writing the shared secret into ikm and its length,
// HSG_CLASSIC_SECRET_MAX, into *ikm_len. The caller runs the hybrid
// itself, and hsf_accept_server_hello has already refused a group the
// hello it answers carried no share for (hsg_selected_group_ok).
//
// For CH_GROUP_X25519: x25519 over h->priv, the x25519 half of the key
// pair hsf_begin drew and the value both first-hello shares carried,
// against info->server_pub. The ML-KEM key pair the hello offered beside
// it goes unused, so the seed h->dz is wiped before the exchange runs
// rather than kept until the handshake ends. A refusal is the all-zero
// shared secret, which RFC 9846 §7.4.2 makes a MUST (rfc9846.txt:4293-4295).
//
// For CH_GROUP_SECP256R1: the X coordinate of h->p256_priv times the
// server's point at info->server_p256, 32 big-endian bytes with no leading
// zero dropped (RFC 9846 §7.4.2, rfc9846.txt:4266-4276). p256_ecdh
// validates the point first, as §4.3.8.2 requires (rfc9846.txt:2277-2286):
// the form byte 0x04, both coordinates below p and the curve equation,
// which also refuses the point at infinity, since that point has no
// 65-byte encoding. h->p256_priv is wiped on both exits, because the
// exchange is over either way (INV-17). This arm requires
// hsg_take_retry to have run and info->server_p256 to point at the
// live ServerHello bytes; CH_ASSERT holds both.
//
// Returns CH_OK, or CH_EPROTO with all HSG_CLASSIC_SECRET_MAX bytes of ikm
// zero for a refused exchange; the caller answers illegal_parameter.
int hsg_classic_secret(handshake_state *h, const server_hello_info *info,
                       uint8_t ikm[HSG_CLASSIC_SECRET_MAX], size_t *ikm_len);

#endif // CH_KEX_TWO_GROUPS
#endif
