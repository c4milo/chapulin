// The build rules of PROFILE=cnsa2 (docs/decisions.md 151): CNSA 2.0's algorithms alone in a
// raw or ca client, and the pin rules its ML-DSA-87 trust modes change (docs/decisions.md 157).
// cfg.h includes this header after its group code points and the KEX defines. It sits beside cfg.h
// for the reason cpu_cfg.h does: cfg.h stood near the 500-line cap CLAUDE.md sets and make
// lint-size holds.
#ifndef CH_PROFILE_CFG_H
#define CH_PROFILE_CFG_H

// ML-KEM-1024 alone (draft-ietf-tls-mlkem), the one group a PROFILE=cnsa2 client offers.
#define CH_GROUP_MLKEM1024 0x0202

// A PROFILE=cnsa2 client offers ML-KEM-1024 alone and TLS_AES_256_GCM_SHA384 alone, so it runs
// no x25519. It authenticates by an external PSK, or by an ML-DSA-87 key under CH_PIN_MLDSA. The
// Makefile and build.zig pass the define with CH_MLKEM_1024 and CH_SUITE_AES_GCM, and refuse it
// outside a raw or ca client.
#ifdef CH_PROFILE_CNSA2
#if defined(CH_KEX_PQ) || defined(CH_TRUST_WEBPKI) || defined(CH_ROLE_SERVER)
#error                                                                                             \
    "PROFILE=cnsa2 is a raw or ca client's profile: drop CH_KEX_PQ, CH_TRUST_WEBPKI and any server role"
#endif
#if !defined(CH_MLKEM_1024) || !defined(CH_SUITE_AES_GCM)
#error "PROFILE=cnsa2 builds ML-KEM-1024 and AES-256-GCM: pass -DCH_MLKEM_1024 -DCH_SUITE_AES_GCM"
#endif
// The plaintext ServerHello record cfg.h's CH_KEX_MIN_RXBUF sizes, with the profile's share:
// the 1568-byte ML-KEM-1024 ciphertext behind its 8 bytes of framing.
#define CH_PROFILE_KEX_MIN_RXBUF (5 + 4 + 40 + 6 + 1576 + 6)
#endif

// TRUST=raw-mldsa and TRUST=ca-mldsa pin an ML-DSA-87 key, CNSA 2.0's signature, so they build
// under PROFILE=cnsa2 alone, and the Makefile and build.zig refuse them elsewhere
// (docs/decisions.md 157). One pinned algorithm per build.
#ifdef CH_PIN_MLDSA
#ifndef CH_PROFILE_CNSA2
#error "CH_PIN_MLDSA is PROFILE=cnsa2's pinned algorithm: pass -DCH_PROFILE_CNSA2"
#endif
#ifdef CH_PIN_ECDSA
#error "one pinned algorithm per build: drop CH_PIN_ECDSA or CH_PIN_MLDSA"
#endif
// The largest certificate the build admits: an ML-DSA-87 leaf holds a 2592-byte key and a
// 4627-byte signature. OpenSSL 3.5 issues one of 7512 bytes under docs/ca.md's profile, and
// the cap leaves about 300 bytes for longer names, as the RSA and P-256 caps do. cfg.h reads
// CH_X509_MAX after this header, and spec/lean/Spec/X509.lean's certMax .mldsa is this number.
#define CH_X509_DEFAULT_MAX_MLDSA 7808
#ifndef CH_X509_MAX
#define CH_X509_MAX CH_X509_DEFAULT_MAX_MLDSA
#endif
#endif

// The pin length the build's one algorithm fixes: 64 raw P-256 bytes under CH_PIN_ECDSA, and
// the 2592-byte ML-DSA-87 key under CH_PIN_MLDSA. An RSA build takes a range of moduli, so it
// leaves the name undefined, and tls.c and quic_config.c then require an odd modulus.
#ifdef CH_PIN_MLDSA
#define CH_PIN_FIXED_LEN 2592
#elif defined(CH_PIN_ECDSA)
#define CH_PIN_FIXED_LEN 64
#endif

// The receive floor of a raw build, cfg.h's CH_TRUST_MIN_RXBUF outside the ca and webpki modes.
// A raw build parses no certificate, so 512 bytes hold its control flights. An ML-DSA-87
// server's Certificate message is far larger, so a raw-mldsa build holds one certificate at
// CH_X509_MAX, by the formula cfg.h states for a CA build's two (docs/decisions.md 157).
#ifdef CH_PIN_MLDSA
#define CH_RAW_TRUST_MIN_RXBUF ((CH_X509_MAX + 5) + 8 + 22)
#else
#define CH_RAW_TRUST_MIN_RXBUF 512
#endif

// Whether a client takes a pin, or a CA key in a CA build. PROFILE=cnsa2 takes one under
// CH_PIN_MLDSA alone, because CNSA 2.0 admits no RSA or ECDSA key, and every other build takes
// one. tls.c and quic_config.c refuse a pinned configuration where it is 0. Every build takes
// an external PSK in its place.
#if defined(CH_PROFILE_CNSA2) && !defined(CH_PIN_MLDSA)
#define CH_TAKES_PINS 0
#else
#define CH_TAKES_PINS 1
#endif

// CH_KEX_MLKEM marks every client that runs ML-KEM: the hybrid clients, at ML-KEM-768, and the
// profile, at ML-KEM-1024.
#if defined(CH_KEX_HYBRID) || defined(CH_PROFILE_CNSA2)
#define CH_KEX_MLKEM
#endif

#endif
