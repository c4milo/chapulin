// TLS 1.3 record protection (RFC 9846 §5). Pure transforms over caller
// buffers — no I/O, no allocation. One rec_dir per direction holds the
// traffic key, IV, and sequence number; the handshake swaps secrets in as
// the key schedule advances and KeyUpdate rekeys in place.
#ifndef CH_RECORD_H
#define CH_RECORD_H

#include <stddef.h>
#include <stdint.h>

#include "aead.h"
#include "sha256.h"

#define REC_HDR 5
#define REC_OVERHEAD (REC_HDR + 1 + AEAD_TAG) // header + inner type + tag

// TLS content types.
#define REC_CCS 20
#define REC_ALERT 21
#define REC_HANDSHAKE 22
#define REC_APPDATA 23

typedef struct {
    // The longest key a suite fixes. TLS_CHACHA20_POLY1305_SHA256 and
    // TLS_AES_256_GCM_SHA384 fill all 32; TLS_AES_128_GCM_SHA256 fills
    // the first 16 and leaves the rest zero. record.c expands an AES key
    // into round keys on its own frame at each use rather than keeping a
    // schedule here, which is what keeps aes_traffic_key's body out of
    // this header (INV-26).
    uint8_t key[AEAD_KEY];
    uint8_t iv[AEAD_NONCE];
    uint64_t seq;
#ifdef CH_SUITE_AES_GCM
    // Which AEAD this direction runs, as the suite's code point. A build
    // with one suite needs no such field and does not declare it.
    uint16_t suite;
#endif
} rec_dir;

// Derives key and IV from a SHA-256 traffic secret and resets the
// sequence: TLS_CHACHA20_POLY1305_SHA256.
void rec_dir_init(rec_dir *d, const uint8_t secret[SHA256_LEN]);

// Rekeys for KeyUpdate: secret' = Expand-Label(secret, "traffic upd").
// The caller owns the traffic secret and passes it here; the new secret
// replaces it in place. The secret is as long as the hash of d's suite,
// SHA384_LEN for TLS_AES_256_GCM_SHA384 and SHA256_LEN otherwise, and
// secret holds that many bytes. A build with several suites keeps
// d->suite: KeyUpdate changes the key and never the AEAD.
void rec_dir_update(uint8_t *secret, rec_dir *d);

#ifdef CH_SUITE_AES_GCM
// rec_dir_init for a build that has several suites: it derives the key
// and IV with the suite's hash from a secret that long, the key at the
// length the suite fixes, and records which AEAD seal and open must run.
// rec_dir_init is this call with TLS_CHACHA20_POLY1305_SHA256, so the
// forty-seven callers that predate the second suite need no change.
void rec_dir_init_suite(rec_dir *d, const uint8_t *secret, uint16_t suite);
#endif

// Keys d with the suite the ServerHello named, for the handshake sites
// that key a direction. A build with several suites calls rec_dir_init_suite. A
// one-suite build has one AEAD, so it calls rec_dir_init and never
// evaluates suite: the expression may name a field that build does not
// declare, and its compiled code is the call it made before a second
// suite existed.
#ifdef CH_SUITE_AES_GCM
#define REC_DIR_INIT_SUITE(d, secret, suite) rec_dir_init_suite((d), (secret), (suite))
#else
#define REC_DIR_INIT_SUITE(d, secret, suite) rec_dir_init((d), (secret))
#endif

// Protects pt as one record of the given inner content type. out gets
// header + ciphertext + tag (n + REC_OVERHEAD bytes); returns 0, or -1 if
// cap is short. pt may alias out + REC_HDR.
int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *out_len);

// Unprotects one full record (header included, n = REC_HDR + body). Writes
// the inner plaintext into pt (cap bytes), strips padding, returns the
// inner content type through type. pt may equal rec — the plaintext then
// lands REC_HDR bytes before the ciphertext it came from, a backward
// overlap aead_open explicitly supports. Returns 0, or -1 on
// authentication failure, malformed record, or short cap — the caller
// treats every -1 as fatal to the connection.
int rec_open(rec_dir *d, const uint8_t *rec, size_t n, uint8_t *pt, size_t cap, size_t *pt_len,
             uint8_t *type);

#endif
