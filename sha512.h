// SHA-512 and SHA-384 (FIPS 180-4). Streaming, the shape sha256.h has:
// a certificate's TBSCertificate is hashed as the reader walks it, never
// buffered whole. One context type serves both hashes, because SHA-384
// is SHA-512 run from its own initial value with the first 48 bytes of
// the result kept (FIPS 180-4 §5.3.4 and §6.5). sha512_update absorbs
// for either; only init and final know which hash is running.
//
// Two builds package this file. A TRUST=webpki object hashes public
// bytes with it: a certificate's TBS bytes for the ecdsa-with-SHA384
// and sha384WithRSAEncryption signatures a public chain carries, and
// the CertificateVerify signed content. A SUITE=aesgcm object runs
// TLS_AES_256_GCM_SHA384's key schedule on it, through hkdf.c's
// hmac_sha384 and the handshake transcript, so there it hashes secrets:
// HMAC keys and the PSK. That is why sha512.c and sha512_compress.c sit
// in the Makefile's WIDEMUL_CEILING and BRANCH_SRCS, where a compiler
// that puts a branch on a word shows as a count that grew. Every other
// build compiles SHA-256 alone.
#ifndef CH_SHA512_H
#define CH_SHA512_H

#include <stddef.h>
#include <stdint.h>

#define SHA512_LEN 64
#define SHA384_LEN 48
#define SHA512_BLOCK 128

typedef struct {
    uint64_t h[8];
    uint64_t total_bytes; // total message bytes absorbed
    uint8_t block[SHA512_BLOCK];
    size_t fill; // bytes pending in block
} sha512;

void sha512_init(sha512 *s);
void sha384_init(sha512 *s);
void sha512_update(sha512 *s, const uint8_t *in, size_t n);
// Finalizes into out. s is spent; re-init to reuse. Does not wipe, the
// way sha256_final does not: a caller that hashed a secret wipes the
// context itself, as hmac_sha384 does.
void sha512_final(sha512 *s, uint8_t out[SHA512_LEN]);
// The SHA-384 digest: the same finalization, keeping the first 48 of
// the 64 result bytes (FIPS 180-4 §6.5 step 3). Only meaningful after
// sha384_init.
void sha384_final(sha512 *s, uint8_t out[SHA384_LEN]);

void sha512_of(const uint8_t *in, size_t n, uint8_t out[SHA512_LEN]);
void sha384_of(const uint8_t *in, size_t n, uint8_t out[SHA384_LEN]);

#endif
