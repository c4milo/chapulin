// The signature checks a DNSSEC validator needs
// (https://github.com/c4milo/chapulin/issues/189): a hash of the signed
// data, and one call that checks an RRSIG's signature over that digest
// against a DNSKEY's public key field as it arrived. A host object
// (-DCH_CPU_RUNTIME) built with DNSSEC=on, which defines CH_DNSSEC,
// exports the five calls below.
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
#include "session_storage.h"

#if defined(CH_DNSSEC) && !defined(CH_CPU_RUNTIME)
#error "CH_DNSSEC needs a host object: the RSA check runs on rsa_mont64.c"
#endif

// The DNSSEC algorithm numbers the calls take (IANA's DNS Security
// Algorithm Numbers registry).
#define CH_DNSSEC_ALG_RSASHA256 8        // RFC 5702
#define CH_DNSSEC_ALG_RSASHA512 10       // RFC 5702
#define CH_DNSSEC_ALG_ECDSAP256SHA256 13 // RFC 6605
#define CH_DNSSEC_ALG_ECDSAP384SHA384 14 // RFC 6605
#define CH_DNSSEC_ALG_ED25519 15         // RFC 8080

// The digest types ch_dnssec_digest_init takes, the numbers of RFC 9904
// section 4's DS registry. SHA-1 serves these hashes alone: the RSA/SHA-1
// signatures of algorithms 5 and 7 stay refused (docs/decisions.md 169). NSEC3's hash algorithm 1
// is SHA-1 too (RFC 5155 section 5), so CH_DNSSEC_DIGEST_SHA1 serves an NSEC3 owner-name hash as
// well as a DS digest of type 1.
#define CH_DNSSEC_DIGEST_SHA1 1
#define CH_DNSSEC_DIGEST_SHA256 2
#define CH_DNSSEC_DIGEST_SHA384 4

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
#define ch_dnssec_digest_init ch_dnssec_digest_init_quic_nonblocking
#define ch_dnssec_hash_update ch_dnssec_hash_update_quic_nonblocking
#define ch_dnssec_hash_final ch_dnssec_hash_final_quic_nonblocking
#define ch_dnssec_verify ch_dnssec_verify_quic_nonblocking
#elif defined(CH_TRANSPORT_TCP_NONBLOCKING)
#define ch_dnssec_hash_init ch_dnssec_hash_init_tcp_nonblocking
#define ch_dnssec_digest_init ch_dnssec_digest_init_tcp_nonblocking
#define ch_dnssec_hash_update ch_dnssec_hash_update_tcp_nonblocking
#define ch_dnssec_hash_final ch_dnssec_hash_final_tcp_nonblocking
#define ch_dnssec_verify ch_dnssec_verify_tcp_nonblocking
#else
#define ch_dnssec_hash_init ch_dnssec_hash_init_tcp_blocking
#define ch_dnssec_digest_init ch_dnssec_digest_init_tcp_blocking
#define ch_dnssec_hash_update ch_dnssec_hash_update_tcp_blocking
#define ch_dnssec_hash_final ch_dnssec_hash_final_tcp_blocking
#define ch_dnssec_verify ch_dnssec_verify_tcp_blocking
#endif

// The storage a caller declares for a ch_dnssec_hash, as session_storage.h declares a session's
// (docs/decisions.md 185). ch_dnssec_hash_priv in dnssec_hash.h is the struct the calls below
// write into it, and the caller writes it through them alone.
#ifndef CH_DNSSEC_HASH_SIZE
#include "dnssec_hash.h"
#define CH_DNSSEC_HASH_SIZE sizeof(ch_dnssec_hash_priv)
#define CH_DNSSEC_HASH_ALIGN CH_ALIGNOF(ch_dnssec_hash_priv)
#endif
typedef struct ch_dnssec_hash {
    CH_ALIGNAS(CH_DNSSEC_HASH_ALIGN) unsigned char opaque[CH_DNSSEC_HASH_SIZE];
} ch_dnssec_hash;

// Starts h for algorithm, with the DNSKEY's key field and the RRSIG's
// signature field, which ch_dnssec_verify takes too. Algorithm 15 hashes
// the signature's first 32 bytes, R, and then the key, A, before the
// signed data (RFC 8032 section 5.1.7); every other algorithm reads
// neither. Returns CH_OK, or CH_EINVAL for an algorithm the calls do not
// take, or for algorithm 15 a key that is not 32 bytes or a signature
// that is not 64, and then h stays unusable.
int CH_MUST_USE ch_dnssec_hash_init(ch_dnssec_hash *h, uint8_t algorithm, const uint8_t *key,
                                    size_t key_len, const uint8_t *sig, size_t sig_len);

// Starts h as a plain hash of digest_type, for a DS digest (RFC 4034
// section 5.1.4) or an NSEC3 owner-name hash (RFC 5155 section 5), which
// iterates by starting h again for each round. Returns CH_OK, or CH_EINVAL
// for a type other than the three above, and then h stays unusable.
int CH_MUST_USE ch_dnssec_digest_init(ch_dnssec_hash *h, uint8_t digest_type);

// Adds the n bytes at p. Requires an h that ch_dnssec_hash_init or
// ch_dnssec_digest_init started.
void ch_dnssec_hash_update(ch_dnssec_hash *h, const uint8_t *p, size_t n);

// Writes the digest to digest and returns its length: 20 bytes for digest
// type 1, 32 for algorithms 8 and 13 and type 2, 48 for 14 and type 4,
// and 64 for 10 and 15. Requires an h that one of the two init
// calls started; h is wiped afterwards.
size_t ch_dnssec_hash_final(ch_dnssec_hash *h, uint8_t digest[CH_DNSSEC_DIGEST_MAX]);

// Checks sig against key under algorithm. key is the DNSKEY RDATA's
// public key field: RFC 3110 section 2's exponent length, exponent and
// modulus for algorithms 8 and 10, and the 64 bytes of X then Y for
// algorithm 13 (RFC 6605 section 4), the 96 bytes of X then Y for 14, and
// the 32-byte A for algorithm 15 (RFC 8080 section 3). digest is the hash
// ch_dnssec_hash_final writes: 32 bytes for 8 and 13, 48 for 14, and 64
// for 10 and 15. sig is the RRSIG's signature field: the modulus's length
// for RSA, r then s, 64 bytes, for algorithm 13 and 96 for 14, and R then
// S, 64 bytes, for 15. Algorithm 15 follows RFC 8032's
// cofactorless rule and refuses what libsodium refuses (ed25519_verify.h).
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
