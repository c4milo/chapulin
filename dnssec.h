// The signature checks a DNSSEC validator needs
// (https://github.com/c4milo/chapulin/issues/189): a hash of the signed
// data, and one call that checks an RRSIG's signature over that digest
// against a DNSKEY's public key field as it arrived. A host object
// (-DCH_CPU_RUNTIME) built with DNSSEC=on, which defines CH_DNSSEC,
// exports the four calls below.
//
// Every input is public: a zone signs its records for everyone to read.
// So the arithmetic is variable time, as the TLS verifiers' is, and the
// RSA operation runs on rsa_mont64.c's words in every session, with no
// AVX-512 IFMA or AVX2 kernel. The hashes run the portable code.
//
// One image may link one object of each transport, so each call carries
// the object's transport in its symbol name, as ch_srv_check does
// (docs/decisions.md 61).
#ifndef CH_DNSSEC_H
#define CH_DNSSEC_H

#include <stddef.h>
#include <stdint.h>

#include "result.h"
#include "sha256.h"
#include "sha512.h"

#if defined(CH_DNSSEC) && !defined(CH_CPU_RUNTIME)
#error "CH_DNSSEC needs a host object: the RSA check runs on rsa_mont64.c"
#endif

// The DNSSEC algorithm numbers the calls take (IANA's DNS Security
// Algorithm Numbers registry).
#define CH_DNSSEC_ALG_RSASHA256 8        // RFC 5702
#define CH_DNSSEC_ALG_RSASHA512 10       // RFC 5702
#define CH_DNSSEC_ALG_ECDSAP256SHA256 13 // RFC 6605

// The longest digest ch_dnssec_hash_final writes: SHA-512's.
#define CH_DNSSEC_DIGEST_MAX 64

// The RSA exponent's longest encoding the check takes, in bytes. A longer
// exponent is a key the check refuses.
#define CH_DNSSEC_RSA_EXPONENT_MAX 8

// The shortest RSA modulus the check takes, in bytes: RFC 5702 section
// 6.1 signs its example with a 512-bit key.
#define CH_DNSSEC_RSA_MODULUS_MIN 64

#ifdef CH_DNSSEC

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_dnssec_hash_init ch_dnssec_hash_init_quic_nonblocking
#define ch_dnssec_hash_update ch_dnssec_hash_update_quic_nonblocking
#define ch_dnssec_hash_final ch_dnssec_hash_final_quic_nonblocking
#define ch_dnssec_verify ch_dnssec_verify_quic_nonblocking
#elif defined(CH_TRANSPORT_TCP_NONBLOCKING)
#define ch_dnssec_hash_init ch_dnssec_hash_init_tcp_nonblocking
#define ch_dnssec_hash_update ch_dnssec_hash_update_tcp_nonblocking
#define ch_dnssec_hash_final ch_dnssec_hash_final_tcp_nonblocking
#define ch_dnssec_verify ch_dnssec_verify_tcp_nonblocking
#else
#define ch_dnssec_hash_init ch_dnssec_hash_init_tcp_blocking
#define ch_dnssec_hash_update ch_dnssec_hash_update_tcp_blocking
#define ch_dnssec_hash_final ch_dnssec_hash_final_tcp_blocking
#define ch_dnssec_verify ch_dnssec_verify_tcp_blocking
#endif

// The hash of an RRSIG's signed data (RFC 4034 section 3.1.8.1), under
// the algorithm the RRSIG names: SHA-256 for algorithms 8 and 13, and
// SHA-512 for 10. The caller owns it and writes it through the calls
// below alone.
typedef struct {
    uint8_t algorithm;
    union {
        sha256 sha256_state;
        sha512 sha512_state;
    } state;
} ch_dnssec_hash;

// Starts h for algorithm. Returns CH_OK, or CH_EINVAL for an algorithm
// the calls do not take, and then h stays unusable.
int CH_MUST_USE ch_dnssec_hash_init(ch_dnssec_hash *h, uint8_t algorithm);

// Adds the n bytes at p. Requires an h that ch_dnssec_hash_init started.
void ch_dnssec_hash_update(ch_dnssec_hash *h, const uint8_t *p, size_t n);

// Writes the digest to digest and returns its length: 32 bytes for
// algorithms 8 and 13, and 64 for 10. Requires an h that
// ch_dnssec_hash_init started; h is wiped afterwards.
size_t ch_dnssec_hash_final(ch_dnssec_hash *h, uint8_t digest[CH_DNSSEC_DIGEST_MAX]);

// Checks sig against key under algorithm. key is the DNSKEY RDATA's
// public key field: RFC 3110 section 2's exponent length, exponent and
// modulus for algorithms 8 and 10, and the 64 bytes of X then Y for
// algorithm 13 (RFC 6605 section 4). digest is the hash of the signed
// data, which ch_dnssec_hash_final writes: 32 bytes for 8 and 13, and 64
// for 10. sig is the RRSIG's signature field: the modulus's length for
// RSA, and r then s, 64 bytes, for algorithm 13.
//
// Returns CH_OK for a valid signature. Returns CH_EAUTH for a signature
// the key does not verify, and CH_EINVAL for an algorithm the call does
// not check, a digest of the wrong length, or a key it refuses: an RSA
// exponent that is even, below 3, longer than CH_DNSSEC_RSA_EXPONENT_MAX
// bytes or begins with a zero byte, and a modulus that begins with a zero
// byte, is even, or is shorter than CH_DNSSEC_RSA_MODULUS_MIN or longer
// than 512 bytes, the RSA-4096 a TRUST=webpki object takes. A modulus too short to hold the encoded
// digest, such as a 64-byte one under algorithm 10, verifies nothing and
// gives CH_EAUTH.
int CH_MUST_USE ch_dnssec_verify(uint8_t algorithm, const uint8_t *key, size_t key_len,
                                 const uint8_t *digest, size_t digest_len, const uint8_t *sig,
                                 size_t sig_len);
#endif

#endif
