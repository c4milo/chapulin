// The sizes the public headers name: the hash lengths that size a ticket's
// secrets, the longest key a CA build extracts, the QUIC key sets
// ch_quic_open reports, and the AES block and key sizes of ch_aes_block.
// Each is defined here once. The internal headers that use one include
// this header, so a public header needs no internal header for a size.
// It holds numbers and the defines that choose between them, and no type
// and no call.
#ifndef CH_PUBLIC_SIZES_H
#define CH_PUBLIC_SIZES_H

// SHA-256 and SHA-384 output lengths (FIPS 180-4).
#define SHA256_LEN 32
#define SHA384_LEN 48

// SHA-384 joins HMAC and HKDF under CH_HASH_SHA384. A -DCH_SUITE_AES_GCM
// build sets it here, because TLS_AES_256_GCM_SHA384 hashes with SHA-384;
// a test binary or a proof harness sets it on its own to run the SHA-384
// vectors on a host with no AES instructions. Every other build compiles
// SHA-256 alone, links no sha512.c, and keeps every secret at 32 bytes.
#if defined(CH_SUITE_AES_GCM) && !defined(CH_HASH_SHA384)
#define CH_HASH_SHA384
#endif

// The longest hash output, and so the longest secret, this build holds.
#ifdef CH_HASH_SHA384
#define HKDF_HASH_MAX SHA384_LEN
#else
#define HKDF_HASH_MAX SHA256_LEN
#endif

// Extracted leaf identity: the SPKI key bytes, copied out because the
// message buffer is reused before CertificateVerify arrives.
#ifdef CH_PIN_ECDSA
#define CH_X509_KEY_MAX 64
#elif defined(CH_PIN_MLDSA)
#define CH_X509_KEY_MAX 2592 // MLDSA87_PK_LEN
#else
#define CH_X509_KEY_MAX 384
#endif

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

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#define AES_BLOCK 16   // FIPS 197 block size
#define AES_128_KEY 16 // the key size of every public key, and of AES-128 suites
#define AES_256_KEY 32 // FIPS 197 Table 3, Nk = 8 words
#endif

#endif
