// The AES forward cipher (FIPS 197) and the two key types it takes.
// Every build that compiles this file has the first: RFC 9001 §5.2 fixes
// AEAD_AES_128_GCM for Initial packets, §5.4.3 fixes AES-ECB for their
// header protection, and §5.8 fixes AEAD_AES_128_GCM under a printed key
// for the Retry integrity tag. None of the three is negotiable, and every
// key they use is public, so they take aes_public_key. A
// -DCH_SUITE_AES_GCM build adds the second, aes_traffic_key, for the two
// AES-GCM cipher suites, whose keys the TLS key schedule derives. A
// TRANSPORT=quic-nonblocking build compiles this file, and so does a suite build over
// any transport. docs/quic.md, "Where packet protection lives", states the
// trade and INV-26 in docs/invariants.md states the rule that holds both.
//
// Forward cipher only. GCM uses the forward cipher function alone (NIST
// SP 800-38D) and the §5.4.3 mask is one forward block, so no inverse
// cipher and no decryption round keys exist here.
#ifndef CH_AES_H
#define CH_AES_H
#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"

#define AES_BLOCK 16      // FIPS 197 block size
#define AES_128_KEY 16    // the key size of every public key, and of AES-128 suites
#define AES_128_ROUNDS 10 // FIPS 197 Table 3, Nr for Nk = 4
#define AES_ROUND_KEYS 11 // Nr + 1 round keys, AES_BLOCK bytes each
#define AES_IV 12         // the 12-byte packet protection IV of §5.1

// AES-256, which TLS_AES_256_GCM_SHA384 takes (RFC 9846 §9.1,
// rfc9846.txt:4540-4543). A library object compiles it only under
// -DCH_SUITE_AES_GCM, which ct.h refuses outside a host object and
// AES=extern, so it runs on the AES instructions in aes_hw.c or on the
// image's ch_aes_block through aes_extern.c. A test binary or a proof
// harness defines CH_AES_256_TEST to compile it without the suite: on
// AES=soft that is the software reference in quic_aes_soft.c, which holds
// the hardware path to FIPS 197 where CBMC cannot read an intrinsic, in a
// host object it is the instructions a suite build runs, and on
// AES=extern it is the hook with a 32-byte key. The Makefile's
// LIB_DEF never carries CH_AES_256_TEST, and quic_aes_soft.c refuses the
// suite define outside a QUIC host object and holds no AES-256 there.
// CH_AES_256 is the one name the sources below test, so neither condition
// is spelled twice.
#if defined(CH_SUITE_AES_GCM) || defined(CH_AES_256_TEST)
#define CH_AES_256
#endif

// A QUIC host object holds two ciphers, and each key runs on one:
// aes_hw.c's on the AES instructions, under aes_block.h's own entry
// names, and quic_aes_soft.c's on the S-box table, under the aes_soft_
// names. The table runs QUIC's public keys alone, the Initial keys when
// the caller did not set CH_CPU_CONSTANT_TIME_AES (cpu_cfg.h) and the
// Retry key always, and every schedule records which cipher expanded it
// (aes_schedule.h). A traffic key runs on the instructions alone. A TCP
// host object has no public key to run, so it holds the instructions
// alone. CH_AES_TWO_CIPHERS is the one name the sources test for the
// QUIC object (docs/decisions.md 81 and 89).
#if defined(CH_CPU_RUNTIME) && defined(CH_TRANSPORT_QUIC_NONBLOCKING)
#define CH_AES_TWO_CIPHERS
#endif
#define AES_256_KEY 32        // FIPS 197 Table 3, Nk = 8 words
#define AES_256_ROUNDS 14     // FIPS 197 Table 3, Nr for Nk = 8
#define AES_256_ROUND_KEYS 15 // Nr + 1 round keys, AES_BLOCK bytes each

// How many round keys one aes_key_schedule holds: room for AES-256 in a
// build that has it, and AES-128's eleven in every other build, so the
// public-key frames of a build without AES-256 keep the size INV-19
// measured.
#ifdef CH_AES_256
#define AES_SCHEDULE_ROUND_KEYS AES_256_ROUND_KEYS
#else
#define AES_SCHEDULE_ROUND_KEYS AES_ROUND_KEYS
#endif

// One direction of one QUIC encryption level whose AEAD is
// AEAD_AES_128_GCM: the packet protection key expanded into its round
// keys, the packet protection IV, and the header protection key
// expanded into its own round keys. Those are RFC 9001 §5.1's "quic
// key", "quic iv" and "quic hp" (rfc9001.txt:1029-1032), which RFC 9369
// names "quicv2 key", "quicv2 iv" and "quicv2 hp" in QUIC version 2
// (rfc9369.txt:167-174). Every aes_ and
// gcm_ entry outside the aes_traffic_ and gcm_traffic_ families takes
// this type and nothing else, so a call that hands one of them a rec_dir
// key, a quic_keys key, an aes_traffic_key or a bare byte array does not
// compile.
//
// The type is incomplete here, and aes_public_key.h holds the definition.
// A file that includes only this header can take a pointer to a key and
// pass it on; it cannot declare one, size one, or write a field of one,
// because the compiler does not know what is inside. That is INV-26's
// first check, and the compiler is what runs it. Four sources include
// aes_public_key.h: aes.c, which writes the two constructors,
// quic_initial.c and quic_retry.c, which build a key on their own stack
// at each use, and gcm.c, which reads the round keys to run the
// AEAD. `make lint-quic-surface` fails on a fifth.
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
// and docs/decisions.md entry 6's stated gain is gone. A traffic key has
// its own type below. Nothing stores a public key between calls. ch_quic
// keeps the Destination Connection ID the derivation reads, not the key
// it produces, so no long-lived key object exists for a later line to
// overwrite. The two constructors below are the only way a key is
// written at all.
//
// Four checks in the build hold the rest. The Semgrep rule
// inv-26-aes-public-keys-only fails any use of an aes_ or gcm_ name
// outside the two traffic families, as a call or as a value, outside
// quic_initial.c, quic_retry.c and the definition sites, and
// inv-26-aes-traffic-keys-only fails any use of a traffic-family name
// outside the files aes_traffic_key.h names. lint-quic-surface fails a
// function, a function-like macro or a type in this header or gcm.h
// that the rules do not match, fails a type this header completes, and
// fails a source outside each key header's list that includes it, so the
// rules' own premise is read rather than assumed.
// lint-codegen-partition holds aes.c and gcm.c in
// WIDEMUL_CEILING and BRANCH_SRCS, where a compiler that lowers a masked
// select to a branch shows. lib-check keeps every aes_ and gcm_ symbol
// out of the packaged object's exports, so no caller reuses this cipher
// on something else. INV-26 in docs/invariants.md states what each one
// reads and what review still owes.
// The expanded round keys, forward-declared so the entries below can name
// one without the body. aes_schedule.h completes it, and only the two key
// headers include that, so only the files tools/quic-footprint.py admits
// to one of them can build a schedule.
typedef struct aes_key_schedule aes_key_schedule;

typedef struct aes_public_key aes_public_key;

#ifdef CH_SUITE_AES_GCM
// The other key AES may see, and the only one that is not public: a key
// hkdf_expand_label derived from a TLS traffic secret, under
// TLS_AES_128_GCM_SHA256 or TLS_AES_256_GCM_SHA384. Its body lives in
// aes_traffic_key.h alone, so only the files that header names can build
// one or read one, and every other file sees this incomplete type. Every
// entry that takes one begins aes_traffic_ or gcm_traffic_, and every
// other aes_ and gcm_ entry takes an aes_public_key, so a traffic key
// cannot reach a public-key entry and a public key cannot reach a traffic
// entry. INV-26 states both halves and what each rests on.
typedef struct aes_traffic_key aes_traffic_key;

// Expands one traffic key into k: key_len is AES_128_KEY for
// TLS_AES_128_GCM_SHA256 and AES_256_KEY for TLS_AES_256_GCM_SHA384, the
// "key" length the suite fixes (RFC 9846 §7.3). The key is secret, and
// this build runs AES on the instructions or on the image's peripheral
// alone (ct.h), so no table in this tree is indexed with it. A QUIC host
// object holds the table beside the instructions for public keys, and
// this call records the instructions in k whatever the caller's bits say,
// so the table never runs a traffic key.
//
// Requires: k is not NULL and points at one whole aes_traffic_key, so the
// caller includes aes_traffic_key.h; key points at key_len readable bytes;
// key_len is AES_128_KEY or AES_256_KEY, which the suite fixed. Writes k
// whole and cannot fail. The caller wipes k with ct_wipe when it is done,
// because k holds the expanded secret.
void aes_traffic_key_init(aes_traffic_key *k, const uint8_t *key, size_t key_len);

#ifdef CH_CPU_RUNTIME
// Records in k the description of the CPU its session gave, the low byte
// of ch_cfg.cpu, which holds every bit an object defines and which gcm.c
// reads to pick gcm_vaes.c's 256-bit kernels for k's whole blocks on
// x86-64 (aes_schedule.h). aes_traffic_key_init records 0,
// which names no kernel, so a key this call never sees runs the 128-bit
// loops: a record direction and a QUIC packet call it, and a header
// protection mask, which is one block, does not.
//
// Requires: aes_traffic_key_init wrote k. cpu is a value an init call
// accepted (cpu.h), or 0.
void aes_traffic_key_cpu(aes_traffic_key *k, uint32_t cpu);
#endif

// aes_traffic_key_init for the key a record or a QUIC packet seals or
// opens under, with its session's ch_cfg.cpu. A host object expands the
// key and then records the value in it. Every other build expands the key
// and never evaluates cpu, so the expression may name a field that build
// does not declare, as REC_DIR_INIT_SUITE does with a suite (record.h). It
// is a macro under a function's name, in the aes_ family, because
// inv-26-aes-public-keys-only matches a call by that prefix (INV-26).
#ifdef CH_CPU_RUNTIME
#define aes_traffic_key_init_cpu(k, cpu, key, key_len)                                             \
    (aes_traffic_key_init((k), (key), (key_len)), aes_traffic_key_cpu((k), (cpu)))
#else
#define aes_traffic_key_init_cpu(k, cpu, key, key_len) aes_traffic_key_init((k), (key), (key_len))
#endif

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
// One forward-cipher block under a traffic key: out = CIPH_k(in). It is
// RFC 9001 §5.4.3's header protection mask, AES-ECB(hp_key, sample)
// (rfc9001.txt:1332-1336), under the "quic hp" key of a Handshake or
// 1-RTT level whose suite is TLS_AES_128_GCM_SHA256 or
// TLS_AES_256_GCM_SHA384. That key comes from a traffic secret and is
// secret, so it takes this entry and never aes_encrypt_block_hp, whose
// key is public.
//
// Requires: k was written by aes_traffic_key_init; in and out point at
// AES_BLOCK bytes and may be the same. Writes AES_BLOCK bytes and cannot
// fail. The caller wipes out past the bytes it keeps, because the block
// is cipher output under a secret key.
void aes_traffic_encrypt_block(const aes_traffic_key *k, const uint8_t in[AES_BLOCK],
                               uint8_t out[AES_BLOCK]);
#endif
#endif

// The two endpoints of a QUIC connection. RFC 9001 §5.2 derives one
// Initial secret per endpoint, under the labels "client in" and "server
// in" (rfc9001.txt:1057-1061), and names the results
// client_initial_secret and server_initial_secret
// (rfc9001.txt:2352-2353, rfc9001.txt:2368-2369).
//
// These name an endpoint, and quic_cfg.h's CH_KEY_READ and CH_KEY_WRITE name
// a direction, which is a different question: each endpoint writes under
// its own secret and reads under the other's, so one endpoint's two
// directions use both secrets. quic_initial.h's two calls take one of
// these to say which endpoint the caller is. A client passes
// CH_QUIC_ENDPOINT_CLIENT at every call and a server passes
// CH_QUIC_ENDPOINT_SERVER at every call; neither value is negotiated and
// neither travels on the wire.
//
// They carry the CH_QUIC_ prefix rather than this header's AES_ one
// because they name a QUIC endpoint and not a cipher input, and a caller
// that holds no key still passes one: quic.c names
// CH_QUIC_ENDPOINT_CLIENT at both Initial calls. quic_keys.h owns its
// CH_QUIC_KEY_ names the same way, and quic_cfg.h points at both.
#define CH_QUIC_ENDPOINT_CLIENT 0
#define CH_QUIC_ENDPOINT_SERVER 1

// Derives one endpoint's Initial-level keys in one QUIC version from the
// client's Destination Connection ID and writes all three fields of k: the
// 16-byte AEAD_AES_128_GCM packet protection key, the 12-byte packet
// protection IV and the 16-byte AES-128-ECB header protection key,
// expanding both keys into their round keys. The derivation is RFC 9001
// §5.2: initial_secret = HKDF-Extract(the version's salt, dcid), which is
// 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a in version 1
// (rfc9001.txt:1051-1055, rfc9001.txt:1066) and
// 0x0dede3def700a6db819381be6e269dcbf9bd2ed9 in version 2
// (rfc9369.txt:158-165), then the label "client in" for
// CH_QUIC_ENDPOINT_CLIENT and "server in" for CH_QUIC_ENDPOINT_SERVER
// (rfc9001.txt:1057-1061), which RFC 9369 leaves unchanged, then the
// version's three §5.1 labels over that secret with a zero-length
// context: "quic key", "quic iv" and "quic hp" in version 1
// (rfc9001.txt:1017-1021, rfc9001.txt:1029-1032) and "quicv2 key",
// "quicv2 iv" and "quicv2 hp" in version 2 (rfc9369.txt:167-174;
// quic_version.h). RFC 9001 Appendix A.1 is the version 1 vector for both
// endpoints (rfc9001.txt:2352-2377) and RFC 9369 Appendix A.1 the
// version 2 one (rfc9369.txt:412-464).
//
// Requires: k is not NULL and points at one whole aes_public_key, so
// the caller includes aes_public_key.h; version is one
// quic_version_derived admits, which quic_initial.c checks before it
// calls, and this file holds a salt for each such version; dcid points
// at dcid_len readable bytes, and dcid is read only when dcid_len is
// above 0; endpoint is
// CH_QUIC_ENDPOINT_CLIENT or CH_QUIC_ENDPOINT_SERVER. This file derives
// whichever one it is handed and reads no role: which endpoint each of
// a caller's two directions needs is quic_initial.c's. Every caller
// calls it per use on its own stack and lets the key die with the
// frame, because no field stores one. After a Retry the Destination
// Connection ID changes and so do the keys (rfc9001.txt:1092-1094); the
// caller passes the new one and this call reads nothing it kept.
//
// A QUIC host object's declaration takes one more argument, cpu, the
// session's ch_cfg.cpu. A value with CH_CPU_CONSTANT_TIME_AES expands
// both keys on the AES instructions and every other value on the table,
// and k records which (aes_schedule.h), so each block run under k takes
// the cipher that expanded it. Both keys are public, so the table leaks
// nothing (INV-26).
//
// Returns CH_OK and writes k whole. Returns CH_EINVAL and writes
// nothing when dcid_len is above CH_QUIC_DCID_MAX, or when endpoint is
// neither of the two names above; k keeps whatever it held. No other
// code can be returned: the derivation itself cannot fail.
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#ifdef CH_AES_TWO_CIPHERS
int aes_public_key_initial(aes_public_key *k, uint32_t cpu, uint32_t version, const uint8_t *dcid,
                           size_t dcid_len, uint8_t endpoint);
#else
int aes_public_key_initial(aes_public_key *k, uint32_t version, const uint8_t *dcid,
                           size_t dcid_len, uint8_t endpoint);
#endif

// Writes the Retry integrity tag key of one QUIC version into k, expanded
// into its round keys: in version 1 the 128-bit constant
// 0xbe0c690b9f66575a1d766b54e368c84e that RFC 9001 §5.8 prints
// (rfc9001.txt:1499-1500), and in version 2 the constant
// 0x8fb4b01b56ac48e260fbcbcead7ccc92 that RFC 9369 §3.3.3 prints
// (rfc9369.txt:176-188). It leaves k->iv and k->hp zero, because each RFC
// prints the nonce the caller passes to gcm_seal (rfc9001.txt:1502,
// rfc9369.txt:184) and a Retry packet carries no header protection.
// quic_retry.c is the only caller, and it builds k on its own stack. A
// QUIC host object expands it on the table whatever the caller's bits
// say, because ch_srv_quic_retry_tag takes no configuration to read them
// from; the key is printed, so the table leaks nothing (INV-26).
//
// Requires: k is not NULL and points at one whole aes_public_key, so
// the caller includes aes_public_key.h; version is one
// quic_version_derived admits, which quic_retry.c checks before it calls,
// and this file holds a key for each such version. Writes k whole and
// cannot fail, so it returns nothing.
void aes_public_key_retry(aes_public_key *k, uint32_t version);
#endif // CH_TRANSPORT_QUIC_NONBLOCKING

// One forward-cipher block under the packet protection key, k->key:
// out = CIPH_K(in), FIPS 197 §5.1. gcm.c calls it for the counter
// blocks and the GHASH subkey of AEAD_AES_128_GCM.
//
// Requires: k was written by a constructor above; in and out point at
// AES_BLOCK readable and writable bytes. in == out is allowed. Writes
// AES_BLOCK bytes and cannot fail.
// The forward cipher over an expanded key, whichever key type holds it.
// The typed entries unwrap their key and call this, and so does
// gcm.c, so the cipher is written once and the type system still
// decides which call sites may hold which key (INV-26). In a build with
// AES-256 the schedule records its round count, and this runs the
// fourteen rounds of AES-256 or the ten of AES-128 by it; the count is
// the suite's, which the ServerHello named in the clear.
void aes_encrypt_schedule(const aes_key_schedule *s, const uint8_t in[AES_BLOCK],
                          uint8_t out[AES_BLOCK]);

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
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
void aes_encrypt_block_hp(const aes_public_key *k, const uint8_t sample[AES_BLOCK],
                          uint8_t out[AES_BLOCK]);

#endif // CH_TRANSPORT_QUIC_NONBLOCKING

#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
