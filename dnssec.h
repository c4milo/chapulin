// The signature checks a DNSSEC validator needs
// (https://github.com/c4milo/chapulin/issues/189): one call that checks an
// RRSIG's signature, over the digest the caller computed of the signed
// data, against a DNSKEY's public key field as it arrived. Only a host
// object (-DCH_CPU_RUNTIME) built with -DCH_DNSSEC holds it.
//
// Every input is public: a zone signs its records for everyone to read.
// So the arithmetic is variable time, as the TLS verifiers' is, and the
// RSA operation runs on rsa_mont64.c's words in every session, with no
// AVX-512 IFMA or AVX2 kernel.
#ifndef CH_DNSSEC_H
#define CH_DNSSEC_H

#include <stddef.h>
#include <stdint.h>

#include "rsa_pkcs1.h" // DNSSEC_RSA_MODULUS_MIN

#if defined(CH_DNSSEC) && !defined(CH_CPU_RUNTIME)
#error "CH_DNSSEC needs a host object: the RSA check runs on rsa_mont64.c"
#endif

// The DNSSEC algorithm numbers this file checks (IANA's DNS Security
// Algorithm Numbers registry).
#define DNSSEC_ALG_RSASHA256 8        // RFC 5702
#define DNSSEC_ALG_RSASHA512 10       // RFC 5702
#define DNSSEC_ALG_ECDSAP256SHA256 13 // RFC 6605

// The RSA exponent's longest encoding this file takes, in bytes. A longer
// exponent is a key this file refuses.
#define DNSSEC_RSA_EXPONENT_MAX 8

#ifdef CH_DNSSEC
// Checks sig against key under algorithm. key is the DNSKEY RDATA's
// public key field: RFC 3110 section 2's exponent length, exponent and
// modulus for algorithms 8 and 10, and the 64 bytes of X then Y for
// algorithm 13 (RFC 6605 section 4). digest is the hash of the signed
// data: SHA-256, 32 bytes, for 8 and 13, and SHA-512, 64 bytes, for 10.
// sig is the RRSIG's signature field: the modulus's length for RSA, and r
// then s, 64 bytes, for algorithm 13.
//
// Returns CH_OK for a valid signature. Returns CH_EAUTH for a signature
// the key does not verify, and CH_EINVAL for an algorithm this file does
// not check, a digest of the wrong length, or a key it refuses: an RSA
// exponent that is even, below 3, longer than DNSSEC_RSA_EXPONENT_MAX
// bytes or begins with a zero byte, and a modulus that begins with a zero
// byte, is even, or is shorter than DNSSEC_RSA_MODULUS_MIN or longer than
// CH_RSA_MODULUS_MAX bytes. A modulus too short to hold the encoded
// digest, such as a 64-byte one under algorithm 10, verifies nothing and
// gives CH_EAUTH.
int dnssec_verify(uint8_t algorithm, const uint8_t *key, size_t key_len, const uint8_t *digest,
                  size_t digest_len, const uint8_t *sig, size_t sig_len);
#endif

#endif
