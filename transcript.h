// The handshake transcript (RFC 9846 §4.4.1): the running hash of every
// handshake message so far, which ch_tls.transcript holds.
//
// The cipher suite names the hash (rfc9846.txt:4055-4056), and a client
// hashes its ClientHello before any ServerHello names a suite. So a
// CH_HASH_SHA384 build runs SHA-256 and SHA-384 side by side over the same
// bytes, and each read names the hash it wants by its length. A build
// without it runs SHA-256 alone and its reads take SHA256_LEN. Which hash
// a read takes depends on hash_len alone, and hash_len is the suite's,
// which the ServerHello names in the clear.
//
// hsr_restart_transcript (handshake_record.h) is the one writer that
// feeds the two hashes different bytes: after a HelloRetryRequest it
// writes RFC 9846 §4.4.1's synthetic message at the length of the hash
// the retry's suite names. From there on the other hash covers bytes no
// rule defines, and nothing reads it, because the ServerHello must
// repeat the retry's suite (rfc9846.txt:1489-1491).
#ifndef CH_TRANSCRIPT_H
#define CH_TRANSCRIPT_H

#include <stddef.h>
#include <stdint.h>

#include "hkdf.h"
#include "sha256.h"

typedef struct {
    sha256 sha256_state;
#ifdef CH_HASH_SHA384
    sha512 sha384_state;
#endif
} ch_transcript;

// The three calls are the library's own. session.h reaches this header,
// and chapulin.hpp reaches session.h from C++, which needs the type and
// none of the calls, so C++ sees the type alone.
#ifndef __cplusplus
#include "ch_assert.h"

static inline void transcript_init(ch_transcript *t) {
    sha256_init(&t->sha256_state);
#ifdef CH_HASH_SHA384
    sha384_init(&t->sha384_state);
#endif
}

static inline void transcript_update(ch_transcript *t, const uint8_t *in, size_t n) {
    sha256_update(&t->sha256_state, in, n);
#ifdef CH_HASH_SHA384
    sha512_update(&t->sha384_state, in, n);
#endif
}

// Writes into digest the hash at hash_len of every byte so far followed
// by the n bytes at after, and leaves t as it was. A caller that wants the
// transcript alone passes n 0. The PSK binder is the caller that passes
// bytes: it covers the transcript and then the ClientHello up to its
// binders list (rfc9846.txt:2591-2598). Requires hash_len SHA256_LEN, or
// SHA384_LEN in a CH_HASH_SHA384 build, and digest holding hash_len
// bytes.
static inline void transcript_hash_after(const ch_transcript *t, size_t hash_len,
                                         const uint8_t *after, size_t n, uint8_t *digest) {
#ifdef CH_HASH_SHA384
    if (hash_len == SHA384_LEN) {
        sha512 copy = t->sha384_state;
        sha512_update(&copy, after, n);
        sha384_final(&copy, digest);
        return;
    }
#endif
    CH_ASSERT(hash_len == SHA256_LEN);
    sha256 copy = t->sha256_state;
    sha256_update(&copy, after, n);
    sha256_final(&copy, digest);
}
#endif

#endif
