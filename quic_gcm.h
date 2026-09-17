// AEAD_AES_128_GCM (NIST SP 800-38D, RFC 5116 §5.1) and the GHASH
// function under it. It exists for the two QUIC packet types whose keys
// RFC 9001 prints or derives from public bytes: Initial packets (§5.2)
// and the Retry integrity tag (§5.8). Only a TRANSPORT=quic build
// compiles it, and the calls take an aes_public_key and nothing else,
// so no key from the TLS key schedule reaches this AEAD. INV-26 in
// docs/invariants.md states that rule and names the checks; quic_aes.h
// states it at the key type.
//
// Every QUIC level above Initial runs ChaCha20-Poly1305 through
// aead.[ch] instead, because that is the cipher suite this client
// offers. This file never becomes one.
#ifndef CH_QUIC_GCM_H
#define CH_QUIC_GCM_H
#ifdef CH_TRANSPORT_QUIC

#include <stddef.h>
#include <stdint.h>

#include "quic_aes.h"

#define GCM_TAG 16 // the 128-bit authentication tag, the only length used

// The nonce is AES_IV bytes, the 96-bit IV of SP 800-38D §5.2.1.1 and
// the only length QUIC produces: RFC 9001 §5.3 builds it from the
// 12-byte packet protection IV and the packet number
// (rfc9001.txt:1134-1139), and §5.8 prints a 96-bit nonce
// (rfc9001.txt:1502). No other IV length is accepted, so the
// SP 800-38D GHASH step for a longer IV has no caller and no code.

// Seals n plaintext bytes under k's packet protection key: ct gets n
// ciphertext bytes and tag gets GCM_TAG bytes, which is SP 800-38D's
// GCM-AE with the tag written separately so a packet caller can place
// it after the ciphertext. That is aead_seal's shape, for the same
// reason.
//
// Requires: k was written by a constructor in quic_aes.h; nonce points at
// AES_IV readable bytes; aad points at aad_len readable bytes, and aad
// may be NULL when aad_len is 0; pt points at n readable bytes and ct
// at n writable bytes, with pt == ct allowed and no other overlap; tag
// points at GCM_TAG writable bytes. A QUIC caller passes the whole
// unprotected packet header as aad, of whatever length the header has
// (RFC 9001 §5.3, rfc9001.txt:1141-1143), and the Retry caller passes
// the Retry Pseudo-Packet with an empty plaintext (§5.8).
//
// The caller never reuses a nonce under one key: for packet protection
// the packet number makes each nonce distinct, and the §6.6 limit on
// packets sealed under the Initial keys is the caller's to count.
//
// Writes n ciphertext bytes and GCM_TAG tag bytes, and cannot fail, so
// it returns nothing.
void gcm_seal(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
              size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[GCM_TAG]);

// Opens n ciphertext bytes under k's packet protection key, the GCM-AD
// of SP 800-38D. It computes the tag over the ciphertext first and
// releases no plaintext byte on a mismatch, as aead_open does.
//
// Requires: the same shapes gcm_seal requires, with ct readable and pt
// writable for n bytes. pt == ct is allowed, and so is pt below ct
// (pt <= ct), because decryption copies forward: each byte is written
// at or after the address it was read from.
//
// Returns 1 and writes n plaintext bytes when the tag matches. Returns
// 0 and writes nothing when it does not. The caller decides what a 0
// means: for a QUIC packet it is a discard that leaves the session live
// and raises the RFC 9001 §6.6 count of failed opens
// (rfc9001.txt:1829-1831), and for a Retry packet it is a packet the
// caller drops.
int gcm_open(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
             size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[GCM_TAG], uint8_t *pt);

// GHASH over the associated data and the ciphertext, SP 800-38D §6.4:
// out = GHASH_H(A || pad || C || pad || [len(A)]64 || [len(C)]64),
// where the hash subkey H is CIPH_K(0^128) under k's packet protection
// key. gcm_seal and gcm_open are its callers; it is declared here
// because SP 800-38D's own vectors test it directly and its proof
// harness drives it directly.
//
// Requires: k was written by a constructor in quic_aes.h; aad points at
// aad_len readable bytes and ct at n readable bytes, either of which
// may be NULL when its length is 0; out points at AES_BLOCK writable
// bytes.
//
// Writes AES_BLOCK bytes and cannot fail, so it returns nothing.
void gcm_ghash(const aes_public_key *k, const uint8_t *aad, size_t aad_len, const uint8_t *ct,
               size_t n, uint8_t out[AES_BLOCK]);

#endif // CH_TRANSPORT_QUIC
#endif
