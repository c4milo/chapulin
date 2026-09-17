// QUIC packet protection keys (RFC 9001 §5.1) and the key update of
// §6.1, for every encryption level whose AEAD is the cipher suite this
// client offers, TLS_CHACHA20_POLY1305_SHA256. It takes the place of
// record.[ch] in a TRANSPORT=quic build: rec_dir holds one direction of
// TLS record protection, and the types here hold one direction of one
// QUIC encryption level. The Initial level is the exception and takes
// quic_aes.h's aes_public_key instead, because RFC 9001 §5.2 fixes
// AEAD_AES_128_GCM there.
//
// Pure derivation. Nothing here seals, opens, samples a packet or reads
// a packet number; quic_packet.[ch] does that over the values this file
// writes. Only a TRANSPORT=quic build compiles it. docs/quic.md states
// the mode.
#ifndef CH_QUIC_KEYS_H
#define CH_QUIC_KEYS_H
#ifdef CH_TRANSPORT_QUIC

#include <stddef.h>
#include <stdint.h>

#include "aead.h"
#include "cfg.h"
#include "chacha20.h"
#include "sha256.h"

// The 1-RTT receive key sets a session holds, and the three names that
// index them, which ch_quic_open reports in its key_set output and
// ch_quic_key_update rotates. RFC 9001 §6.3 makes the current and the
// next set a floor (rfc9001.txt:1711-1712) and the previous set is this
// design's choice, so a packet delayed across a key update still opens
// (docs/quic.md, "The decision"). A CH_QUIC_KEY_NEXT result is a
// peer-initiated key update (rfc9001.txt:1654-1656). Every read of the
// array uses one of the three names; no index is computed, and no index
// comes from a secret.
#define CH_QUIC_KEY_SETS 3
#define CH_QUIC_KEY_PREVIOUS 0
#define CH_QUIC_KEY_CURRENT 1
#define CH_QUIC_KEY_NEXT 2

// The library builds as C, so the guard always runs. It holds the array
// size and the slot names to one statement of the same fact.
#ifndef __cplusplus
_Static_assert(CH_QUIC_KEY_SETS == CH_QUIC_KEY_NEXT + 1,
               "the key set count and its slot names must agree");
#endif

// One direction of one encryption level: the packet protection key and
// the packet protection IV of RFC 9001 §5.1, derived under the labels
// "quic key" and "quic iv" (rfc9001.txt:1029-1032). It carries no
// sequence number, where rec_dir carries one: QUIC's packet number
// comes from the caller on every call, so nothing here counts packets.
typedef struct {
    uint8_t key[AEAD_KEY];
    uint8_t iv[AEAD_NONCE];
} quic_keys;

// The header protection key of RFC 9001 §5.1, derived under the label
// "quic hp", one per direction per encryption level. It is a type of
// its own rather than a third field of quic_keys because its lifetime
// differs: §5.4 uses the same header protection key for the whole
// connection, with the value not changing after a key update
// (rfc9001.txt:1172-1174), and §6.1 repeats the rule for the update
// step, where the header protection key is not updated
// (rfc9001.txt:1607). So each value here is written once, when that
// level's traffic secret arrives, and quic_keys_update never touches
// one. A build that derived a new header protection key on an update
// would compute a mask the peer cannot reproduce, and every 1-RTT
// packet after the first update would fail header protection removal at
// both ends.
typedef struct {
    uint8_t key[CHACHA20_KEY];
} quic_hp_key;

// Derives one direction's packet protection key and IV from that
// direction's traffic secret: HKDF-Expand-Label(secret, "quic key", "",
// AEAD_KEY) and HKDF-Expand-Label(secret, "quic iv", "", AEAD_NONCE).
// QUIC passes a zero-length context to every one of these labels
// (RFC 9001 §5.1, rfc9001.txt:1017-1021, rfc9001.txt:1029-1032). RFC
// 9001 Appendix A.5 is the vector for the 1-RTT level.
//
// Requires: k is not NULL; secret holds SHA256_LEN bytes, one of the
// traffic secrets keysched.c derives for this level and direction. The
// caller owns the secret and this call does not wipe it, because the
// §6.1 update step reads it again.
//
// Writes k whole and cannot fail, so it returns nothing. It is the
// rec_dir_init of this transport.
void quic_keys_init(quic_keys *k, const uint8_t secret[SHA256_LEN]);

// Derives one direction's header protection key from the same traffic
// secret: HKDF-Expand-Label(secret, "quic hp", "", CHACHA20_KEY).
//
// Requires: h is not NULL; secret holds SHA256_LEN bytes, the same
// secret quic_keys_init took for this level and direction. The caller
// calls it once per direction per level, when that level's traffic
// secret arrives, and never again for that level: the value does not
// change for the life of the connection (rfc9001.txt:1172-1174).
//
// Writes h whole and cannot fail, so it returns nothing.
void quic_hp_key_init(quic_hp_key *h, const uint8_t secret[SHA256_LEN]);

// The key update of RFC 9001 §6.1: secret' =
// HKDF-Expand-Label(secret, "quic ku", "", SHA256_LEN)
// (rfc9001.txt:1605-1607, rfc9001.txt:1612-1613), written back over
// secret, then the packet protection key and IV re-derived from it into
// k. The caller owns the traffic secret and passes it here, the way
// rec_dir_update takes the TLS one.
//
// It rewrites the packet protection key and the IV and nothing else. No
// quic_hp_key is passed to it, because §6.1 does not update the header
// protection key (rfc9001.txt:1607), and the type system says so: this
// call cannot reach one.
//
// Requires: k is not NULL; secret holds SHA256_LEN bytes of the current
// 1-RTT traffic secret for that direction. Only the 1-RTT level takes
// this call: keys at other levels are never updated, because they come
// from the handshake alone (rfc9001.txt:1629-1631).
//
// Writes the new secret over secret and k whole, wipes its own copy of
// the new secret, and cannot fail, so it returns nothing. The caller
// wipes the old key set it no longer needs; this call never drops one,
// because RFC 9001 §6.1 makes an endpoint retain its old keys until a
// packet under the new keys opens (rfc9001.txt:1637-1638).
void quic_keys_update(uint8_t secret[SHA256_LEN], quic_keys *k);

#endif // CH_TRANSPORT_QUIC
#endif
