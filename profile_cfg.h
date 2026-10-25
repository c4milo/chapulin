// The build rules of PROFILE=cnsa2 (docs/decisions.md 151): CNSA 2.0's algorithms alone in a
// raw or ca client. cfg.h includes this header after its group code points and the KEX
// defines. It sits beside cfg.h for the reason cpu_cfg.h does: cfg.h stood near the 500-line
// cap CLAUDE.md sets and make lint-size holds.
#ifndef CH_PROFILE_CFG_H
#define CH_PROFILE_CFG_H

// ML-KEM-1024 alone (draft-ietf-tls-mlkem), the one group a PROFILE=cnsa2 client offers.
#define CH_GROUP_MLKEM1024 0x0202

// A PROFILE=cnsa2 client offers ML-KEM-1024 alone, TLS_AES_256_GCM_SHA384 alone and an
// external PSK alone, so it runs no x25519. The Makefile and build.zig pass the define with
// CH_MLKEM_1024 and CH_SUITE_AES_GCM, and refuse it outside a raw or ca client.
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

// Whether a client takes a pin, or a CA key in a CA build: 1 in every build but PROFILE=cnsa2,
// which authenticates by an external PSK alone until ML-DSA lands. tls.c and quic_config.c
// refuse a pinned configuration where it is 0.
#ifdef CH_PROFILE_CNSA2
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
