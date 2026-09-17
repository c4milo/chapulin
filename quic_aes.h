// The AES-128 forward cipher (FIPS 197) and the one key type it takes.
// This file exists for QUIC Initial packets and the QUIC Retry tag, and
// for nothing else: RFC 9001 §5.2 fixes AEAD_AES_128_GCM for Initial
// packets, §5.4.3 fixes AES-ECB for their header protection, and §5.8
// fixes AEAD_AES_128_GCM under a printed key for the Retry integrity
// tag. None of the three is negotiable, and none of them reaches a key
// the TLS key schedule derived. Only a TRANSPORT=quic build compiles
// it. docs/quic.md, "Where packet protection lives", states the trade
// and INV-26 in docs/invariants.md states the rule that holds it.
//
// Forward cipher only. GCM uses the forward cipher function alone (NIST
// SP 800-38D) and the §5.4.3 mask is one forward block, so no inverse
// cipher and no decryption round keys exist here.
#ifndef CH_QUIC_AES_H
#define CH_QUIC_AES_H
#ifdef CH_TRANSPORT_QUIC

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"

#define AES_BLOCK 16      // FIPS 197 block size
#define AES_128_KEY 16    // the only key size this build uses
#define AES_128_ROUNDS 10 // FIPS 197 Table 3, Nr for Nk = 4
#define AES_ROUND_KEYS 11 // Nr + 1 round keys, AES_BLOCK bytes each
#define AES_IV 12         // the 12-byte packet protection IV of §5.1

// Largest Destination Connection ID aes_public_key_initial accepts. RFC
// 9000 §17.2 caps a QUIC version 1 connection ID at 20 bytes
// (rfc9000.txt:4991-4998). There is no lower bound to check. A client's
// own first Destination Connection ID is at least 8 bytes (RFC 9000
// §7.2, rfc9000.txt:1856), but after a Retry the client derives from
// the server's Source Connection ID, and RFC 9001 §5.2 states that this
// field can be any length up to 20 bytes, zero included
// (rfc9001.txt:1098-1100).
#define AES_DCID_MAX 20

// One AES-128 key expanded into its round keys (FIPS 197 §5.2, Key
// Expansion). Bytes rather than words, so no step of the schedule or
// the cipher assumes host endianness.
typedef struct {
    uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK];
} aes_key_schedule;

// One direction of one QUIC encryption level whose AEAD is
// AEAD_AES_128_GCM: the packet protection key expanded into its round
// keys, the packet protection IV, and the header protection key
// expanded into its own round keys. Those are RFC 9001 §5.1's "quic
// key", "quic iv" and "quic hp" (rfc9001.txt:1029-1032). Every aes_ and
// gcm_ entry takes this type and nothing else, so a call that hands one
// of them a rec_dir key, a quic_keys key or a bare byte array does not
// compile.
//
// Every key this type ever holds is public, and that is the whole
// reason a table-driven cipher is allowed in this tree. The Initial
// keys come from HKDF-Extract over RFC 9001 §5.2's printed salt and the
// Destination Connection ID, which travels in the clear in every long
// header, and the RFC draws the conclusion itself: anyone can compute
// them, so Initial packets have no confidentiality or integrity
// protection (rfc9001.txt:999-1001). The Retry key is printed in the
// RFC (rfc9001.txt:1500-1502).
//
// Filling this struct with anything else is what INV-26 forbids, and a
// traffic secret from keysched.c is the case it names: the day one
// reaches a lookup-table cipher, this tree has a timing story to defend
// and docs/decisions.md entry 6's stated gain is gone. The two
// constructors below are the first check: nothing else may write these
// fields. The struct is visible because ch_quic stores two of these
// values and this tree allocates nothing, not because a caller may
// build one. Three build gates check the rest. The Semgrep rule
// inv-26-aes-public-keys-only fails any call to an aes_ or gcm_ symbol,
// and any aes_public_key initializer, outside quic_initial.c,
// quic_retry.c, quic_aes.c and quic_gcm.c; a .violation mutant proves
// that rule fires; lint-codegen-partition holds quic_aes.c and
// quic_gcm.c in WIDEMUL_PUBLIC,
// the list whose comment says a secret arriving in any of these is a
// design change; and lib-check keeps every aes_ and gcm_ symbol out of
// the packaged object's exports, so no caller reuses this cipher on
// something else.
typedef struct {
    aes_key_schedule key;
    uint8_t iv[AES_IV];
    aes_key_schedule hp;
} aes_public_key;

// Derives one direction of the Initial-level keys from the client's
// Destination Connection ID and writes all three fields of k: the
// 16-byte AEAD_AES_128_GCM packet protection key, the 12-byte packet
// protection IV and the 16-byte AES-128-ECB header protection key,
// expanding both keys into their round keys. The derivation is RFC 9001
// §5.2: initial_secret = HKDF-Extract(0x38762cf7f55934b34d179ae6a4c80cad
// ccbb7f0a, dcid) (rfc9001.txt:1051-1055, rfc9001.txt:1066), then the
// label "client in" for CH_KEY_WRITE and "server in" for CH_KEY_READ
// (rfc9001.txt:1057-1061), then §5.1's "quic key", "quic iv" and "quic
// hp" over that secret with a zero-length context
// (rfc9001.txt:1017-1021, rfc9001.txt:1029-1032). RFC 9001 Appendix A.1
// is the vector.
//
// Requires: k is not NULL; dcid points at dcid_len readable bytes, and
// dcid is read only when dcid_len is above 0; direction is CH_KEY_READ
// or CH_KEY_WRITE. The caller calls it again after a Retry, because the
// Destination Connection ID changes there and so do the keys
// (rfc9001.txt:1092-1094); that rewrites k whole and is not a key
// update.
//
// Returns CH_OK and writes k whole. Returns CH_EINVAL and writes
// nothing when dcid_len is above AES_DCID_MAX, or when direction is
// neither CH_KEY_READ nor CH_KEY_WRITE; k keeps whatever it held. No
// other code can be returned: the derivation itself cannot fail.
int aes_public_key_initial(aes_public_key *k, const uint8_t *dcid, size_t dcid_len,
                           uint8_t direction);

// Writes the Retry integrity tag key of RFC 9001 §5.8 into k: the
// 128-bit constant 0xbe0c690b9f66575a1d766b54e368c84e
// (rfc9001.txt:1499-1500), expanded into its round keys. It leaves
// k->iv and k->hp zero, because §5.8 prints the nonce the caller passes
// to gcm_seal (rfc9001.txt:1502) and a Retry packet carries no header
// protection. quic_retry.c is the only caller.
//
// Requires: k is not NULL. Writes k whole and cannot fail, so it
// returns nothing.
void aes_public_key_retry(aes_public_key *k);

// One forward-cipher block under the packet protection key, k->key:
// out = CIPH_K(in), FIPS 197 §5.1. quic_gcm.c calls it for the counter
// blocks and the GHASH subkey of AEAD_AES_128_GCM.
//
// Requires: k was written by a constructor above; in and out point at
// AES_BLOCK readable and writable bytes. in == out is allowed. Writes
// AES_BLOCK bytes and cannot fail.
void aes_encrypt_block(const aes_public_key *k, const uint8_t in[AES_BLOCK],
                       uint8_t out[AES_BLOCK]);

// One forward-cipher block under the header protection key, k->hp:
// out = CIPH_hp(sample). That is RFC 9001 §5.4.3's mask, which the RFC
// writes as AES-ECB(hp_key, sample) (rfc9001.txt:1332-1336).
//
// It writes all AES_BLOCK bytes and applies no mask itself. The caller
// reads the first 5 as the mask, the way quic_packet.c reads the first
// 5 bytes of a chacha20_block, and passes those 5 to the pair of
// functions in quic_packet.c that write a masked byte.
//
// Requires: k was written by aes_public_key_initial, so k->hp is a
// header protection key rather than zero; sample points at AES_BLOCK
// readable bytes, taken from the packet the way §5.4.2 says; out points
// at AES_BLOCK writable bytes. sample == out is allowed. Writes
// AES_BLOCK bytes and cannot fail.
void aes_encrypt_block_hp(const aes_public_key *k, const uint8_t sample[AES_BLOCK],
                          uint8_t out[AES_BLOCK]);

#endif // CH_TRANSPORT_QUIC
#endif
