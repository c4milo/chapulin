// SHA-1 (FIPS 180-4 section 6.1), for the DNSSEC RSA/SHA-1 signatures of
// algorithms 5 and 7 (RFC 3110, RFC 5155) under CH_DNSSEC alone
// (https://github.com/c4milo/chapulin/issues/189, docs/decisions.md 169).
// No TLS path calls it: SHA-1 is broken for collisions, and TLS 1.3 uses
// none of it. A semgrep rule refuses a call outside dnssec.c. Every input
// is public, as a zone's records are.
#ifndef CH_SHA1_H
#define CH_SHA1_H

#include <stddef.h>
#include <stdint.h>

#define SHA1_LEN 20
#define SHA1_BLOCK 64

typedef struct {
    uint32_t h[5];
    uint64_t total_bytes; // total message bytes absorbed
    uint8_t block[SHA1_BLOCK];
    size_t fill; // bytes pending in block
} sha1;

#ifdef CH_DNSSEC
void sha1_init(sha1 *s);
void sha1_update(sha1 *s, const uint8_t *in, size_t n);
// Finalizes into out[20]. s is spent; re-init to reuse.
void sha1_final(sha1 *s, uint8_t out[SHA1_LEN]);
#endif

#endif
