// AEAD_AES_128_GCM and AEAD_AES_256_GCM (NIST SP 800-38D, RFC 5116
// §5.1 and §5.2) and the GHASH function under them. The first three
// entries exist for the two QUIC packet types whose keys RFC 9001 prints
// or derives from public bytes: Initial packets (§5.2) and the Retry
// integrity tag (§5.8). They take an aes_public_key and nothing else, and
// run AES-128. A -DCH_SUITE_AES_GCM build adds two entries that take an
// aes_traffic_key, for the two AES-GCM cipher suites, and run AES-128 or
// AES-256 as the key's round count says. Both types are incomplete here:
// every call below takes a pointer, so this header needs no body, and a
// file that includes it cannot build a key at all. INV-26 in
// docs/invariants.md states that rule and names the checks; aes.h
// states it at the two key types.
#ifndef CH_GCM_H
#define CH_GCM_H
#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)

#include <stddef.h>
#include <stdint.h>

#include "aes.h"
#include "public_sizes.h"

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
// Requires: k was written by a constructor in aes.h; nonce points at
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
// of SP 800-38D. It decrypts as it hashes, in one pass over the
// ciphertext, and compares the tag after both are done. On a mismatch it
// has already written the plaintext, so it wipes those n bytes before it
// returns, and a failed open returns no plaintext byte (docs/decisions.md
// 85). aead_open still compares first and writes nothing on a mismatch.
//
// Requires: the same shapes gcm_seal requires, with ct readable and pt
// writable for n bytes. pt == ct is allowed, and so is pt below ct
// (pt <= ct), because decryption copies forward: each byte is hashed and
// then written at or before the address it was read from.
//
// Returns 1 and writes n plaintext bytes when the tag matches. Returns 0
// and leaves n zero bytes at pt when it does not. Either way it writes no
// byte outside those n, so the tag and anything after pt's n bytes stay
// as they were: a QUIC caller that opens in place still finds the tag
// bytes, which RFC 9000 §10.3.1 compares with its Stateless Reset tokens
// (rfc9000.txt:3486-3497). The caller decides what a 0 means: for a QUIC
// packet it is a discard that leaves the session live and raises the RFC
// 9001 §6.6 count of failed opens (rfc9001.txt:1829-1831), and for a Retry
// packet it is a packet the caller drops.
int gcm_open(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
             size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[GCM_TAG], uint8_t *pt);

// GHASH over the associated data and the ciphertext, SP 800-38D §6.4:
// out = GHASH_H(A || pad || C || pad || [len(A)]64 || [len(C)]64),
// where the hash subkey H is CIPH_K(0^128) under k's packet protection
// key. gcm_seal and gcm_open are its callers; it is declared here
// because SP 800-38D's own vectors test it directly and its proof
// harness drives it directly.
//
// Requires: k was written by a constructor in aes.h; aad points at
// aad_len readable bytes and ct at n readable bytes, either of which
// may be NULL when its length is 0; out points at AES_BLOCK writable
// bytes.
//
// Writes AES_BLOCK bytes and cannot fail, so it returns nothing.
void gcm_ghash(const aes_public_key *k, const uint8_t *aad, size_t aad_len, const uint8_t *ct,
               size_t n, uint8_t out[AES_BLOCK]);

#ifdef CH_SUITE_AES_GCM
// The same AEAD over a TLS traffic key, for TLS_AES_128_GCM_SHA256 and
// TLS_AES_256_GCM_SHA384: AEAD_AES_128_GCM or AEAD_AES_256_GCM, as the
// key aes_traffic_key_init expanded says. The contracts are gcm_seal's
// and gcm_open's. Two entries rather than one taking both types, because
// the type is the whole mechanism: a public key cannot reach a traffic
// entry and a traffic key cannot reach the three QUIC call sites INV-26
// admits for public keys.
void gcm_traffic_seal(const aes_traffic_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                      size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                      uint8_t tag[GCM_TAG]);

int gcm_traffic_open(const aes_traffic_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                     size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[GCM_TAG],
                     uint8_t *pt);

#ifdef CH_CPU_RUNTIME
// aes_traffic_key_store for a key that runs AES-GCM: it writes schedule as
// that call does, and beside it powers, the powers H^1 to H^8 of the
// key's hash subkey in the form suite.h states, which each seal and open
// under the key reads from there (docs/decisions.md 234). record.c calls it
// when it derives a record key and quic_keys.c when it derives a packet
// protection key, so a KeyUpdate and a QUIC key update write both again. A
// header protection key runs no GHASH and takes aes_traffic_key_store.
// The hash subkey and the powers are computed on the AES instructions and
// the carry-less multiply, so the call writes them only where cpu, the
// session's ch_cfg.cpu, holds CH_CPU_CONSTANT_TIME_AES.
//
// Requires: schedule points at SUITE_AES_SCHEDULE_LEN writable bytes and
// powers at SUITE_GHASH_POWERS_LEN writable bytes; key points at key_len
// readable bytes; key_len is AES_128_KEY or AES_256_KEY. Returns 1 when it
// wrote both, and 0 when cpu lacks the bit and it wrote neither. The owner
// keeps the answer in its stored byte. It wipes the schedule and the hash
// subkey it computed on its frame, and cannot fail.
int gcm_traffic_key_store(uint8_t *schedule, uint8_t *powers, uint32_t cpu, const uint8_t *key,
                          size_t key_len);
#endif
#endif

#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
