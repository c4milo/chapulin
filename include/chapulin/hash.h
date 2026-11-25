// The hashes, HMAC and HKDF of chapulin's key schedule, as calls a
// program makes (docs/decisions.md 246): SHA-256, SHA-384 and SHA-512
// (FIPS 180-4), SHA3-256 and SHA3-512, SHAKE128 and SHAKE256 (FIPS 202),
// HMAC over the three SHA-2 hashes (RFC 2104), and HKDF's Extract and
// Expand over them (RFC 5869). A host TRUST=webpki object built with
// HASH=on, which defines CH_HASH, exports the calls below.
//
// Each init call, and each call over a whole input, takes a description
// of the CPU, the bits of ch_cfg.cpu (cpu_cfg.h). It runs each hash where
// those bits put a session's hash: on the CPU's hash instructions, or on
// x86-64 on the AVX2 and BMI kernels, where the bits name them, and on
// the portable code where they do not. It refuses a value without
// CH_CPU_PROBED or with a bit this object does not define, as every
// session's init call does (cpu.h). A streaming state keeps the value its
// init took, so its other calls take none.
//
// No call allocates, draws randomness or keeps a pointer once it returns.
// The bytes may be secret: a key, a password or a secret a program
// derives. Each call wipes every copy of a key and every hash state it
// makes, and the call that ends a streaming state wipes the whole state.
//
// SHA-1 is not here: dnssec.h's DS digests hold it, and no new caller
// takes it. scram.h's ch_sha256 and ch_hmac_sha256 take no CPU value and
// keep their names, so one object holds both axes.
//
// One image may link one object of each transport, so each call carries
// the object's transport in its symbol name, as ch_srv_check does
// (docs/decisions.md 61).
#ifndef CH_HASH_H
#define CH_HASH_H

#include <stddef.h>
#include <stdint.h>

#include "cpu_cfg.h"
#include "public_sizes.h"
#include "result.h"

#if defined(CH_HASH) && !defined(CH_CPU_RUNTIME)
#error "CH_HASH needs a host object: no device object has a measured budget for these calls"
#endif
#if defined(CH_HASH) && !defined(CH_TRUST_WEBPKI)
#error "CH_HASH needs TRUST=webpki, whose object packages SHA-384, SHA-512 and SHA-3"
#endif

// The digest lengths, in bytes. CH_SHA256_LEN is public_sizes.h's.
#define CH_SHA384_LEN 48
#define CH_SHA512_LEN 64
#define CH_SHA3_256_LEN 32
#define CH_SHA3_512_LEN 64

// The hashes ch_hmac, ch_hkdf_extract and ch_hkdf_expand take. Each call
// refuses every other number.
#define CH_HASH_ALGORITHM_SHA256 1
#define CH_HASH_ALGORITHM_SHA384 2
#define CH_HASH_ALGORITHM_SHA512 3

// The most bytes one ch_hkdf_expand call writes under a hash whose digest
// is digest_len bytes: 255 blocks of HashLen (RFC 5869 section 2.3).
#define CH_HKDF_BLOCKS_MAX 255
#define CH_HKDF_EXPAND_LEN_MAX(digest_len) (CH_HKDF_BLOCKS_MAX * (digest_len))

// The storage a caller declares for a streaming hash. The bytes are the
// library's: a caller writes and reads a state through the calls below
// alone. Each size is public_sizes.h's, fixed in every build.
typedef struct ch_sha256_state {
    uint64_t opaque[CH_SHA256_STATE_SIZE / 8];
} ch_sha256_state;
typedef struct ch_sha384_state {
    uint64_t opaque[CH_SHA512_STATE_SIZE / 8];
} ch_sha384_state;
typedef struct ch_sha512_state {
    uint64_t opaque[CH_SHA512_STATE_SIZE / 8];
} ch_sha512_state;
// SHAKE128's and SHAKE256's state: the init call names the function.
typedef struct ch_shake_state {
    uint64_t opaque[CH_SHAKE_STATE_SIZE / 8];
} ch_shake_state;

#ifdef CH_HASH

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_sha256_init ch_sha256_init_quic_nonblocking
#define ch_sha256_update ch_sha256_update_quic_nonblocking
#define ch_sha256_final ch_sha256_final_quic_nonblocking
#define ch_sha256_hash ch_sha256_hash_quic_nonblocking
#define ch_sha384_init ch_sha384_init_quic_nonblocking
#define ch_sha384_update ch_sha384_update_quic_nonblocking
#define ch_sha384_final ch_sha384_final_quic_nonblocking
#define ch_sha384_hash ch_sha384_hash_quic_nonblocking
#define ch_sha512_init ch_sha512_init_quic_nonblocking
#define ch_sha512_update ch_sha512_update_quic_nonblocking
#define ch_sha512_final ch_sha512_final_quic_nonblocking
#define ch_sha512_hash ch_sha512_hash_quic_nonblocking
#define ch_sha3_256_hash ch_sha3_256_hash_quic_nonblocking
#define ch_sha3_512_hash ch_sha3_512_hash_quic_nonblocking
#define ch_shake128_init ch_shake128_init_quic_nonblocking
#define ch_shake256_init ch_shake256_init_quic_nonblocking
#define ch_shake_absorb ch_shake_absorb_quic_nonblocking
#define ch_shake_squeeze ch_shake_squeeze_quic_nonblocking
#define ch_shake_wipe ch_shake_wipe_quic_nonblocking
#define ch_shake128_hash ch_shake128_hash_quic_nonblocking
#define ch_shake256_hash ch_shake256_hash_quic_nonblocking
#define ch_hmac ch_hmac_quic_nonblocking
#define ch_hkdf_extract ch_hkdf_extract_quic_nonblocking
#define ch_hkdf_expand ch_hkdf_expand_quic_nonblocking
#elif defined(CH_TRANSPORT_TCP_NONBLOCKING)
#define ch_sha256_init ch_sha256_init_tcp_nonblocking
#define ch_sha256_update ch_sha256_update_tcp_nonblocking
#define ch_sha256_final ch_sha256_final_tcp_nonblocking
#define ch_sha256_hash ch_sha256_hash_tcp_nonblocking
#define ch_sha384_init ch_sha384_init_tcp_nonblocking
#define ch_sha384_update ch_sha384_update_tcp_nonblocking
#define ch_sha384_final ch_sha384_final_tcp_nonblocking
#define ch_sha384_hash ch_sha384_hash_tcp_nonblocking
#define ch_sha512_init ch_sha512_init_tcp_nonblocking
#define ch_sha512_update ch_sha512_update_tcp_nonblocking
#define ch_sha512_final ch_sha512_final_tcp_nonblocking
#define ch_sha512_hash ch_sha512_hash_tcp_nonblocking
#define ch_sha3_256_hash ch_sha3_256_hash_tcp_nonblocking
#define ch_sha3_512_hash ch_sha3_512_hash_tcp_nonblocking
#define ch_shake128_init ch_shake128_init_tcp_nonblocking
#define ch_shake256_init ch_shake256_init_tcp_nonblocking
#define ch_shake_absorb ch_shake_absorb_tcp_nonblocking
#define ch_shake_squeeze ch_shake_squeeze_tcp_nonblocking
#define ch_shake_wipe ch_shake_wipe_tcp_nonblocking
#define ch_shake128_hash ch_shake128_hash_tcp_nonblocking
#define ch_shake256_hash ch_shake256_hash_tcp_nonblocking
#define ch_hmac ch_hmac_tcp_nonblocking
#define ch_hkdf_extract ch_hkdf_extract_tcp_nonblocking
#define ch_hkdf_expand ch_hkdf_expand_tcp_nonblocking
#else
#define ch_sha256_init ch_sha256_init_tcp_blocking
#define ch_sha256_update ch_sha256_update_tcp_blocking
#define ch_sha256_final ch_sha256_final_tcp_blocking
#define ch_sha256_hash ch_sha256_hash_tcp_blocking
#define ch_sha384_init ch_sha384_init_tcp_blocking
#define ch_sha384_update ch_sha384_update_tcp_blocking
#define ch_sha384_final ch_sha384_final_tcp_blocking
#define ch_sha384_hash ch_sha384_hash_tcp_blocking
#define ch_sha512_init ch_sha512_init_tcp_blocking
#define ch_sha512_update ch_sha512_update_tcp_blocking
#define ch_sha512_final ch_sha512_final_tcp_blocking
#define ch_sha512_hash ch_sha512_hash_tcp_blocking
#define ch_sha3_256_hash ch_sha3_256_hash_tcp_blocking
#define ch_sha3_512_hash ch_sha3_512_hash_tcp_blocking
#define ch_shake128_init ch_shake128_init_tcp_blocking
#define ch_shake256_init ch_shake256_init_tcp_blocking
#define ch_shake_absorb ch_shake_absorb_tcp_blocking
#define ch_shake_squeeze ch_shake_squeeze_tcp_blocking
#define ch_shake_wipe ch_shake_wipe_tcp_blocking
#define ch_shake128_hash ch_shake128_hash_tcp_blocking
#define ch_shake256_hash ch_shake256_hash_tcp_blocking
#define ch_hmac ch_hmac_tcp_blocking
#define ch_hkdf_extract ch_hkdf_extract_tcp_blocking
#define ch_hkdf_expand ch_hkdf_expand_tcp_blocking
#endif

// SHA-256, SHA-384 and SHA-512 as a stream: an init call, any number of
// updates, and a final. The three hashes have the same three calls on
// their own state types, and each one's contract is SHA-256's below.
//
// ch_sha256_init starts state under cpu. Returns CH_OK. Returns CH_EINVAL
// for a cpu value the object refuses, and then state holds no hash, and
// an update or a final on it fails an assertion.
int CH_MUST_USE ch_sha256_init(ch_sha256_state *state, uint32_t cpu);
// Adds the n bytes at p. p may be NULL when n is 0. Requires a state that
// an init call started and no final has ended; an assertion holds it.
void ch_sha256_update(ch_sha256_state *state, const uint8_t *p, size_t n);
// Writes the digest of every byte added to out, and wipes state. A next
// hash starts with an init call. Requires what update requires.
void ch_sha256_final(ch_sha256_state *state, uint8_t out[CH_SHA256_LEN]);

int CH_MUST_USE ch_sha384_init(ch_sha384_state *state, uint32_t cpu);
void ch_sha384_update(ch_sha384_state *state, const uint8_t *p, size_t n);
void ch_sha384_final(ch_sha384_state *state, uint8_t out[CH_SHA384_LEN]);

int CH_MUST_USE ch_sha512_init(ch_sha512_state *state, uint32_t cpu);
void ch_sha512_update(ch_sha512_state *state, const uint8_t *p, size_t n);
void ch_sha512_final(ch_sha512_state *state, uint8_t out[CH_SHA512_LEN]);

// One call over a whole input: writes the digest of the n bytes at p to
// out. p may be NULL when n is 0. Each call wipes the state it hashes in.
// Returns CH_OK. Returns CH_EINVAL, with nothing written, for a cpu value
// the object refuses.
int CH_MUST_USE ch_sha256_hash(uint32_t cpu, const uint8_t *p, size_t n,
                               uint8_t out[CH_SHA256_LEN]);
int CH_MUST_USE ch_sha384_hash(uint32_t cpu, const uint8_t *p, size_t n,
                               uint8_t out[CH_SHA384_LEN]);
int CH_MUST_USE ch_sha512_hash(uint32_t cpu, const uint8_t *p, size_t n,
                               uint8_t out[CH_SHA512_LEN]);
// SHA3-256 and SHA3-512, one call over a whole input, under the same
// contract. sha3.c keeps no stream with SHA-3's padding, so neither hash
// has a streaming state.
int CH_MUST_USE ch_sha3_256_hash(uint32_t cpu, const uint8_t *p, size_t n,
                                 uint8_t out[CH_SHA3_256_LEN]);
int CH_MUST_USE ch_sha3_512_hash(uint32_t cpu, const uint8_t *p, size_t n,
                                 uint8_t out[CH_SHA3_512_LEN]);

// SHAKE128 and SHAKE256 as a stream: an init call, any number of absorbs,
// then any number of squeezes, and last a wipe. ch_shake128_init and
// ch_shake256_init start state under cpu. Each returns CH_OK, or CH_EINVAL
// for a cpu value the object refuses, and then state holds no function,
// and an absorb or a squeeze on it fails an assertion.
int CH_MUST_USE ch_shake128_init(ch_shake_state *state, uint32_t cpu);
int CH_MUST_USE ch_shake256_init(ch_shake_state *state, uint32_t cpu);
// Adds the n bytes at p to the message. p may be NULL when n is 0.
// Requires a state that an init call started, and no squeeze of one byte
// or more since: the first such squeeze ends the message (FIPS 202
// section 4). An assertion holds each.
void ch_shake_absorb(ch_shake_state *state, const uint8_t *p, size_t n);
// Writes the next n bytes of the output to out. The first squeeze of one
// byte or more pads the message, and each next one continues the same
// output, so n bytes and then m are the first n + m bytes of one squeeze.
// A squeeze of 0 bytes does nothing. Requires a state that an init call
// started; an assertion holds it.
void ch_shake_squeeze(ch_shake_state *state, uint8_t *out, size_t n);
// Wipes state. A caller that absorbed a secret calls it once it has
// squeezed what it needs, and a next stream starts with an init call.
void ch_shake_wipe(ch_shake_state *state);
// One call: the first out_len bytes of SHAKE128 or SHAKE256 of the n bytes
// at p. Either pointer may be NULL when its length is 0. Returns CH_OK, or
// CH_EINVAL, with nothing written, for a cpu value the object refuses.
int CH_MUST_USE ch_shake128_hash(uint32_t cpu, const uint8_t *p, size_t n, uint8_t *out,
                                 size_t out_len);
int CH_MUST_USE ch_shake256_hash(uint32_t cpu, const uint8_t *p, size_t n, uint8_t *out,
                                 size_t out_len);

// Writes HMAC (RFC 2104) of msg under key to out, under the hash
// algorithm names. A key longer than the hash's block is hashed first
// (RFC 2104 section 2). out_len is the hash's digest length:
// CH_SHA256_LEN, CH_SHA384_LEN or CH_SHA512_LEN. Either input pointer may
// be NULL when its length is 0.
//
// Returns CH_OK. Returns CH_EINVAL, with nothing written, for a cpu value
// the object refuses, an algorithm other than the three above, or an
// out_len other than the digest length. The key is secret: no branch and
// no memory index reads it.
int CH_MUST_USE ch_hmac(uint32_t cpu, uint8_t algorithm, const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len, uint8_t *out, size_t out_len);

// HKDF-Extract (RFC 5869 section 2.2): writes PRK = HMAC(salt, ikm) to
// prk, under the hash algorithm names. prk_len is the digest length. An
// empty salt is the RFC's default, HashLen zero bytes: HMAC pads a short
// key with zero bytes, so the two give one PRK. Either input pointer may
// be NULL when its length is 0.
//
// Returns CH_OK. Returns CH_EINVAL, with nothing written, for a cpu value
// the object refuses, an algorithm other than the three, or a prk_len
// other than the digest length.
int CH_MUST_USE ch_hkdf_extract(uint32_t cpu, uint8_t algorithm, const uint8_t *salt,
                                size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk,
                                size_t prk_len);

// HKDF-Expand (RFC 5869 section 2.3): writes out_len bytes of OKM to out,
// from prk and info, under the hash algorithm names. prk is a key of the
// digest length, as ch_hkdf_extract writes it. info may be NULL when
// info_len is 0.
//
// Returns CH_OK. Returns CH_EINVAL, with nothing written, for a cpu value
// the object refuses, an algorithm other than the three, a prk_len other
// than the digest length, an info_len above CH_HKDF_INFO_LEN_MAX, an
// out_len of 0, or an out_len above CH_HKDF_EXPAND_LEN_MAX of the digest
// length.
int CH_MUST_USE ch_hkdf_expand(uint32_t cpu, uint8_t algorithm, const uint8_t *prk, size_t prk_len,
                               const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);

#endif // CH_HASH

#endif
