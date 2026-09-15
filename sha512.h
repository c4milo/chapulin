// SHA-512 and SHA-384 (FIPS 180-4). Streaming, the shape sha256.h has:
// a certificate's TBSCertificate is hashed as the reader walks it, never
// buffered whole. One context type serves both hashes, because SHA-384
// is SHA-512 run from its own initial value with the first 48 bytes of
// the result kept (FIPS 180-4 §5.3.4 and §6.5). sha512_update absorbs
// for either; only init and final know which hash is running.
//
// Only a TRUST=webpki object packages this file, for the
// ecdsa-with-SHA384 and sha384WithRSAEncryption signatures a public
// chain carries. Every byte it hashes in this tree is public: a
// certificate's TBS bytes, or the CertificateVerify signed content,
// which is 64 spaces, a context string and the transcript hash. The
// key schedule and the transcript stay on SHA-256.
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
// Finalizes into out. s is spent; re-init to reuse. Does not wipe —
// nothing secret passes through this module, and a caller that hashed
// a secret anyway wipes the context itself.
void sha512_final(sha512 *s, uint8_t out[SHA512_LEN]);
// The SHA-384 digest: the same finalization, keeping the first 48 of
// the 64 result bytes (FIPS 180-4 §6.5 step 3). Only meaningful after
// sha384_init.
void sha384_final(sha512 *s, uint8_t out[SHA384_LEN]);

void sha512_of(const uint8_t *in, size_t n, uint8_t out[SHA512_LEN]);
void sha384_of(const uint8_t *in, size_t n, uint8_t out[SHA384_LEN]);

#endif
