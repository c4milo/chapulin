// The cipher suites of RFC 9846 Appendix B.4 this tree holds, and the two
// values each one fixes: the hash the transcript and the key schedule run
// (rfc9846.txt:4055-4056) and the AEAD key length. Every build holds
// TLS_CHACHA20_POLY1305_SHA256. A -DCH_SUITE_AES_GCM build holds
// TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384 beside it, and ct.h
// refuses that define unless the build has the AES instructions or an AES
// peripheral and asserts its timing (docs/decisions.md 58 and 68).
//
// A suite code point is public: the ServerHello names it in the clear.
// So is everything the functions below return, and a branch on any of
// them reads a public value.
#ifndef CH_SUITE_H
#define CH_SUITE_H

#include <stddef.h>
#include <stdint.h>

#include "hkdf.h"

#define SUITE_CHACHA20_POLY1305_SHA256 0x1303
// TLS_AES_128_GCM_SHA256, which RFC 9846 section 9.1 makes mandatory to
// implement, and TLS_AES_256_GCM_SHA384, which it makes a SHOULD
// (rfc9846.txt:4540-4543). Only a -DCH_SUITE_AES_GCM build offers or
// selects either.
#define SUITE_AES_128_GCM_SHA256 0x1301
#define SUITE_AES_256_GCM_SHA384 0x1302

// A SUITE=aesgcm TRUST=webpki client offers all three suites and runs the
// one the ServerHello selects (docs/decisions.md 45 and 58). It offers
// them in suite_default_order below, or in the order ch_cfg.cipher_suites
// names (webpki_cfg.h). A SUITE=aesgcm server selects in
// suite_default_order unless ch_srv_cfg.cipher_suites names another
// (srv_select). A raw or ca client offers ChaCha20 alone, and
// handshake_message.c refuses the define for one that carries no server
// role.
#if defined(CH_SUITE_AES_GCM) && defined(CH_TRUST_WEBPKI)
#define CH_CLIENT_AES_SUITES
#endif

// The suites this build holds, SUITE_HELD_COUNT of them, in the order its
// client offers them and its server prefers them when the caller names no
// order (docs/decisions.md 80). SUITE_AES_FIRST marks a -DCH_SUITE_AES_GCM
// build on AES=hw that defines CH_NATIVE_AES: its AES-GCM runs on the AES
// instructions and the carry-less multiply, which the build asserted run
// in constant time (ct.h), and it puts TLS_AES_256_GCM_SHA384 first, then
// TLS_AES_128_GCM_SHA256, then ChaCha20. AES-256 comes first to align
// with NSA's CNSA 2.0 suite, which requires AES-256 and SHA-384, though
// every handshake proof covers SHA-256 and the SHA-384 schedule is
// proved in its own harnesses alone. Every other suite build,
// AES=extern among them, keeps ChaCha20 first, which runs in constant
// time by construction, then AES-128-GCM, then AES-256-GCM
// (docs/decisions.md 58). A build without the define holds ChaCha20
// alone. Nothing here asks the CPU what it has: a caller that learns it
// at run time names its own order in ch_cfg.cipher_suites or
// ch_srv_cfg.cipher_suites.
#if defined(CH_SUITE_AES_GCM) && defined(CH_AES_HW) && defined(CH_NATIVE_AES)
#define SUITE_AES_FIRST
#endif
#ifdef CH_SUITE_AES_GCM
#define SUITE_HELD_COUNT 3
#else
#define SUITE_HELD_COUNT 1
#endif
// Declared for its two readers alone: a server role, and the client that
// offers more than one suite (handshake_message.h). Each arm defines the
// whole array, so no directive sits inside an initializer.
#if defined(CH_ROLE_SERVER) || defined(CH_CLIENT_AES_SUITES)
#ifdef SUITE_AES_FIRST
static const uint16_t suite_default_order[SUITE_HELD_COUNT] = {
    SUITE_AES_256_GCM_SHA384, SUITE_AES_128_GCM_SHA256, SUITE_CHACHA20_POLY1305_SHA256};
#elif defined(CH_SUITE_AES_GCM)
static const uint16_t suite_default_order[SUITE_HELD_COUNT] = {
    SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_128_GCM_SHA256, SUITE_AES_256_GCM_SHA384};
#else
static const uint16_t suite_default_order[SUITE_HELD_COUNT] = {SUITE_CHACHA20_POLY1305_SHA256};
#endif
#endif

// The longest AEAD key any suite fixes: ChaCha20-Poly1305 and AES-256-GCM
// both take 32 bytes.
#define SUITE_KEY_MAX 32

// The hash length suite fixes, SHA256_LEN or SHA384_LEN, or 0 for a code
// point this build does not hold.
static inline size_t suite_hash_len(uint16_t suite) {
#ifdef CH_SUITE_AES_GCM
    if (suite == SUITE_AES_256_GCM_SHA384) {
        return SHA384_LEN;
    }
    if (suite == SUITE_AES_128_GCM_SHA256) {
        return SHA256_LEN;
    }
#endif
    return suite == SUITE_CHACHA20_POLY1305_SHA256 ? SHA256_LEN : 0;
}

// The AEAD key length suite fixes: 16 bytes for AES-128-GCM and
// SUITE_KEY_MAX for the other two.
static inline size_t suite_key_len(uint16_t suite) {
    return suite == SUITE_AES_128_GCM_SHA256 ? 16 : SUITE_KEY_MAX;
}

#ifdef CH_SUITE_AES_GCM
// Whether suite runs AES-GCM rather than ChaCha20-Poly1305.
static inline int suite_runs_aes_gcm(uint16_t suite) {
    return suite == SUITE_AES_128_GCM_SHA256 || suite == SUITE_AES_256_GCM_SHA384;
}
#endif

#ifdef CH_ROLE_SERVER
// The cipher suites a server role can select, one bit each, as
// srv_parse_client_hello reports the client's offer in
// client_hello.suites and srv_select reads it. A bit is set when the
// ClientHello listed that suite; a suite this build does not hold has no
// bit, and its code point is read and ignored (rfc9846.txt:4636-4637).
//
// RFC 9846 §9.1 names three suites (rfc9846.txt:4540-4543). A build
// without -DCH_SUITE_AES_GCM holds TLS_CHACHA20_POLY1305_SHA256 alone and
// does not meet section 9.1. A -DCH_SUITE_AES_GCM build holds all three
// and selects in suite_default_order above unless ch_srv_cfg.cipher_suites
// names another order.
#define SRV_SUITE_CHACHA20_POLY1305 0x01
#ifdef CH_SUITE_AES_GCM
#define SRV_SUITE_AES_128_GCM 0x02
#define SRV_SUITE_AES_256_GCM 0x04
#endif

// The SRV_SUITE_ bit of a cipher suite code point, or 0 for a suite this
// build does not hold. A predicate over a public value.
static inline uint8_t srv_suite_bit(uint16_t suite) {
#ifdef CH_SUITE_AES_GCM
    if (suite == SUITE_AES_128_GCM_SHA256) {
        return SRV_SUITE_AES_128_GCM;
    }
    if (suite == SUITE_AES_256_GCM_SHA384) {
        return SRV_SUITE_AES_256_GCM;
    }
#endif
    return suite == SUITE_CHACHA20_POLY1305_SHA256 ? SRV_SUITE_CHACHA20_POLY1305 : 0;
}

// The first suite in order, count code points in the server's order of
// preference, whose SRV_SUITE_ bit is in offered, or 0 when there is
// none. A code point this build does not hold has no bit and is passed
// over. srv_select walks the server's order with it (srv_flight.c), so
// the server selects a suite the client listed or none, which RFC 9846
// §4.2.3 requires of it (rfc9846.txt:1373-1376).
static inline uint16_t srv_first_offered_suite(const uint16_t *order, size_t count,
                                               uint8_t offered) {
    for (size_t i = 0; i < count; i++) {
        if ((offered & srv_suite_bit(order[i])) != 0) {
            return order[i];
        }
    }
    return 0;
}
#endif

#endif
