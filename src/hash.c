// hash.h's calls (docs/decisions.md 246). hash.h states each contract.
// This file forwards each call to the entries that end sha256.h, sha512.h,
// sha3.h and hkdf.h, which take a session's ch_cfg.cpu first: each runs a
// hash on the instructions or the kernel the value names, and on the
// portable code where it names none. A streaming state is a struct of
// this file in the caller's storage, the hash's context and the value its
// init took. Outside a CH_HASH build this file holds nothing, and hash.h's
// includes keep the unit from being empty.
#include "hash.h"

#ifdef CH_HASH

#include "ch_assert.h"
#include "cpu.h"
#include "ct.h"
#include "hkdf.h"
#include "sha256.h"
#include "sha3.h"
#include "sha512.h"

_Static_assert(CH_SHA256_LEN == SHA256_LEN, "hash.h states SHA-256's digest length");
_Static_assert(CH_SHA384_LEN == SHA384_LEN, "hash.h states SHA-384's digest length");
_Static_assert(CH_SHA512_LEN == SHA512_LEN, "hash.h states SHA-512's digest length");
_Static_assert(CH_SHA3_256_LEN == SHA3_256_LEN, "hash.h states SHA3-256's digest length");
_Static_assert(CH_SHA3_512_LEN == SHA3_512_LEN, "hash.h states SHA3-512's digest length");
_Static_assert(CH_HKDF_INFO_LEN_MAX <= HKDF_EXPAND_INFO_MAX, "hkdf_expand takes the longest info");
_Static_assert(SHA512_LEN <= HMAC_HASH_MAX, "hmac takes SHA-512 in a CH_HASH build");

// The struct in a caller's state: the hash's context, and the ch_cfg.cpu
// value its init took. A stream that a final ended, or whose init refused
// its value, holds 0 in cpu, which cpu_value_ok refuses.
typedef struct {
    sha256 hash;
    uint32_t cpu;
} sha256_stream;

// SHA-384 and SHA-512 share sha512.h's context, as sha512.h states.
typedef struct {
    sha512 hash;
    uint32_t cpu;
} sha512_stream;

typedef struct {
    shake sponge;
    uint32_t cpu;
} shake_stream;

_Static_assert(sizeof(sha256_stream) <= sizeof(ch_sha256_state), "CH_SHA256_STATE_SIZE holds it");
_Static_assert(sizeof(sha512_stream) <= sizeof(ch_sha384_state), "CH_SHA512_STATE_SIZE holds it");
_Static_assert(sizeof(sha512_stream) <= sizeof(ch_sha512_state), "CH_SHA512_STATE_SIZE holds it");
_Static_assert(sizeof(shake_stream) <= sizeof(ch_shake_state), "CH_SHAKE_STATE_SIZE holds it");
_Static_assert(_Alignof(sha256_stream) <= _Alignof(ch_sha256_state), "a state aligns its stream");
_Static_assert(_Alignof(sha512_stream) <= _Alignof(ch_sha512_state), "a state aligns its stream");
_Static_assert(_Alignof(shake_stream) <= _Alignof(ch_shake_state), "a state aligns its stream");

// The stream in a caller's state. The library compiles with
// -fno-strict-aliasing, as session_convert.h's conversions do.
static sha256_stream *sha256_stream_of(ch_sha256_state *state) {
    return (sha256_stream *)(void *)state;
}
static sha512_stream *sha384_stream_of(ch_sha384_state *state) {
    return (sha512_stream *)(void *)state;
}
static sha512_stream *sha512_stream_of(ch_sha512_state *state) {
    return (sha512_stream *)(void *)state;
}
static shake_stream *shake_stream_of(ch_shake_state *state) {
    return (shake_stream *)(void *)state;
}

// What an empty input points at: memcpy's pointers must be valid even
// for a length of 0 (C11 7.24.1), and hash.h permits NULL there.
static const uint8_t nothing[1] = {0};

static const uint8_t *bytes_or_nothing(const uint8_t *p, size_t n) {
    return n != 0 ? p : nothing;
}

int ch_sha256_init(ch_sha256_state *state, uint32_t cpu) {
    sha256_stream *s = sha256_stream_of(state);
    // A refused value leaves 0, which the other calls' assertion refuses.
    s->cpu = 0;
    if (!cpu_value_ok(cpu)) {
        return CH_EINVAL;
    }
    sha256_init(&s->hash);
    s->cpu = cpu;
    return CH_OK;
}

void ch_sha256_update(ch_sha256_state *state, const uint8_t *p, size_t n) {
    sha256_stream *s = sha256_stream_of(state);
    CH_ASSERT(cpu_value_ok(s->cpu));
    if (n != 0) {
        sha256_update_cpu(s->cpu, &s->hash, p, n);
    }
}

void ch_sha256_final(ch_sha256_state *state, uint8_t out[CH_SHA256_LEN]) {
    sha256_stream *s = sha256_stream_of(state);
    CH_ASSERT(cpu_value_ok(s->cpu));
    sha256_final_cpu(s->cpu, &s->hash, out);
    // The context holds the last block of the input, which may be secret.
    // The wipe covers the caller's whole state, cpu among it.
    ct_wipe(state, sizeof *state);
}

int ch_sha384_init(ch_sha384_state *state, uint32_t cpu) {
    sha512_stream *s = sha384_stream_of(state);
    s->cpu = 0;
    if (!cpu_value_ok(cpu)) {
        return CH_EINVAL;
    }
    sha384_init(&s->hash);
    s->cpu = cpu;
    return CH_OK;
}

void ch_sha384_update(ch_sha384_state *state, const uint8_t *p, size_t n) {
    sha512_stream *s = sha384_stream_of(state);
    CH_ASSERT(cpu_value_ok(s->cpu));
    if (n != 0) {
        sha512_update_cpu(s->cpu, &s->hash, p, n);
    }
}

void ch_sha384_final(ch_sha384_state *state, uint8_t out[CH_SHA384_LEN]) {
    sha512_stream *s = sha384_stream_of(state);
    CH_ASSERT(cpu_value_ok(s->cpu));
    sha384_final_cpu(s->cpu, &s->hash, out);
    ct_wipe(state, sizeof *state);
}

int ch_sha512_init(ch_sha512_state *state, uint32_t cpu) {
    sha512_stream *s = sha512_stream_of(state);
    s->cpu = 0;
    if (!cpu_value_ok(cpu)) {
        return CH_EINVAL;
    }
    sha512_init(&s->hash);
    s->cpu = cpu;
    return CH_OK;
}

void ch_sha512_update(ch_sha512_state *state, const uint8_t *p, size_t n) {
    sha512_stream *s = sha512_stream_of(state);
    CH_ASSERT(cpu_value_ok(s->cpu));
    if (n != 0) {
        sha512_update_cpu(s->cpu, &s->hash, p, n);
    }
}

void ch_sha512_final(ch_sha512_state *state, uint8_t out[CH_SHA512_LEN]) {
    sha512_stream *s = sha512_stream_of(state);
    CH_ASSERT(cpu_value_ok(s->cpu));
    sha512_final_cpu(s->cpu, &s->hash, out);
    ct_wipe(state, sizeof *state);
}

// The one-shots run the stream on their own frame, so each wipes the
// context it hashed in whichever path ran: sha256.c's sha256_of does not.
int ch_sha256_hash(uint32_t cpu, const uint8_t *p, size_t n, uint8_t out[CH_SHA256_LEN]) {
    ch_sha256_state state;
    int rc = ch_sha256_init(&state, cpu);
    if (rc != CH_OK) {
        return rc;
    }
    ch_sha256_update(&state, p, n);
    ch_sha256_final(&state, out);
    return CH_OK;
}

int ch_sha384_hash(uint32_t cpu, const uint8_t *p, size_t n, uint8_t out[CH_SHA384_LEN]) {
    ch_sha384_state state;
    int rc = ch_sha384_init(&state, cpu);
    if (rc != CH_OK) {
        return rc;
    }
    ch_sha384_update(&state, p, n);
    ch_sha384_final(&state, out);
    return CH_OK;
}

int ch_sha512_hash(uint32_t cpu, const uint8_t *p, size_t n, uint8_t out[CH_SHA512_LEN]) {
    ch_sha512_state state;
    int rc = ch_sha512_init(&state, cpu);
    if (rc != CH_OK) {
        return rc;
    }
    ch_sha512_update(&state, p, n);
    ch_sha512_final(&state, out);
    return CH_OK;
}

// sha3.c's one-shots wipe their sponge before they return (sha3.h).
int ch_sha3_256_hash(uint32_t cpu, const uint8_t *p, size_t n, uint8_t out[CH_SHA3_256_LEN]) {
    if (!cpu_value_ok(cpu)) {
        return CH_EINVAL;
    }
    sha3_256_cpu(cpu, bytes_or_nothing(p, n), n, out);
    return CH_OK;
}

int ch_sha3_512_hash(uint32_t cpu, const uint8_t *p, size_t n, uint8_t out[CH_SHA3_512_LEN]) {
    if (!cpu_value_ok(cpu)) {
        return CH_EINVAL;
    }
    sha3_512_cpu(cpu, bytes_or_nothing(p, n), n, out);
    return CH_OK;
}

// shake128_init and shake256_init write zeros and the rate, and take no
// value: both paths of sha3.h start from them.
int ch_shake128_init(ch_shake_state *state, uint32_t cpu) {
    shake_stream *s = shake_stream_of(state);
    s->cpu = 0;
    if (!cpu_value_ok(cpu)) {
        return CH_EINVAL;
    }
    shake128_init(&s->sponge);
    s->cpu = cpu;
    return CH_OK;
}

int ch_shake256_init(ch_shake_state *state, uint32_t cpu) {
    shake_stream *s = shake_stream_of(state);
    s->cpu = 0;
    if (!cpu_value_ok(cpu)) {
        return CH_EINVAL;
    }
    shake256_init(&s->sponge);
    s->cpu = cpu;
    return CH_OK;
}

void ch_shake_absorb(ch_shake_state *state, const uint8_t *p, size_t n) {
    shake_stream *s = shake_stream_of(state);
    CH_ASSERT(cpu_value_ok(s->cpu));
    // sha3.h: input after a squeeze would land in the squeezed state.
    CH_ASSERT(s->sponge.squeezing == 0);
    if (n != 0) {
        shake_absorb_cpu(s->cpu, &s->sponge, p, n);
    }
}

void ch_shake_squeeze(ch_shake_state *state, uint8_t *out, size_t n) {
    shake_stream *s = shake_stream_of(state);
    CH_ASSERT(cpu_value_ok(s->cpu));
    if (n != 0) {
        shake_squeeze_cpu(s->cpu, &s->sponge, out, n);
    }
}

void ch_shake_wipe(ch_shake_state *state) {
    ct_wipe(state, sizeof *state);
}

int ch_shake128_hash(uint32_t cpu, const uint8_t *p, size_t n, uint8_t *out, size_t out_len) {
    ch_shake_state state;
    int rc = ch_shake128_init(&state, cpu);
    if (rc != CH_OK) {
        return rc;
    }
    ch_shake_absorb(&state, p, n);
    ch_shake_squeeze(&state, out, out_len);
    ch_shake_wipe(&state);
    return CH_OK;
}

int ch_shake256_hash(uint32_t cpu, const uint8_t *p, size_t n, uint8_t *out, size_t out_len) {
    ch_shake_state state;
    int rc = ch_shake256_init(&state, cpu);
    if (rc != CH_OK) {
        return rc;
    }
    ch_shake_absorb(&state, p, n);
    ch_shake_squeeze(&state, out, out_len);
    ch_shake_wipe(&state);
    return CH_OK;
}

// The digest length of the hash algorithm names, the hash_len hkdf.h's
// calls take, and 0 for a number hash.h does not name. The number is the
// caller's and public.
static size_t digest_len_of(uint8_t algorithm) {
    switch (algorithm) {
    case CH_HASH_ALGORITHM_SHA256:
        return SHA256_LEN;
    case CH_HASH_ALGORITHM_SHA384:
        return SHA384_LEN;
    case CH_HASH_ALGORITHM_SHA512:
        return SHA512_LEN;
    default:
        return 0;
    }
}

// The digest length of algorithm when cpu is a value the object takes,
// the algorithm is one of the three and out_len is that length; 0
// otherwise. ch_hmac's and ch_hkdf_extract's refusals.
static size_t digest_len_for(uint32_t cpu, uint8_t algorithm, size_t out_len) {
    size_t hash_len = digest_len_of(algorithm);
    if (!cpu_value_ok(cpu) || hash_len == 0 || out_len != hash_len) {
        return 0;
    }
    return hash_len;
}

int ch_hmac(uint32_t cpu, uint8_t algorithm, const uint8_t *key, size_t key_len, const uint8_t *msg,
            size_t msg_len, uint8_t *out, size_t out_len) {
    size_t hash_len = digest_len_for(cpu, algorithm, out_len);
    if (hash_len == 0) {
        return CH_EINVAL;
    }
    // hkdf.c's HMAC wipes its key's copies and its hash states.
    hmac_cpu(cpu, hash_len, bytes_or_nothing(key, key_len), key_len, bytes_or_nothing(msg, msg_len),
             msg_len, out);
    return CH_OK;
}

int ch_hkdf_extract(uint32_t cpu, uint8_t algorithm, const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len, uint8_t *prk, size_t prk_len) {
    size_t hash_len = digest_len_for(cpu, algorithm, prk_len);
    if (hash_len == 0) {
        return CH_EINVAL;
    }
    // The salt pointer is never NULL here, so hkdf_extract hashes under the
    // caller's salt, an empty one too, and never under its own zeros: the
    // two give one PRK (hash.h).
    hkdf_extract_cpu(cpu, hash_len, bytes_or_nothing(salt, salt_len), salt_len,
                     bytes_or_nothing(ikm, ikm_len), ikm_len, prk);
    return CH_OK;
}

int ch_hkdf_expand(uint32_t cpu, uint8_t algorithm, const uint8_t *prk, size_t prk_len,
                   const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len) {
    size_t hash_len = digest_len_for(cpu, algorithm, prk_len);
    if (hash_len == 0 || info_len > CH_HKDF_INFO_LEN_MAX) {
        return CH_EINVAL;
    }
    // RFC 5869 section 2.3: L <= 255*HashLen. An L of 0 asks for no bytes,
    // and hkdf_expand requires one or more.
    if (out_len == 0 || out_len > CH_HKDF_EXPAND_LEN_MAX(hash_len)) {
        return CH_EINVAL;
    }
    hkdf_expand_cpu(cpu, hash_len, prk, bytes_or_nothing(info, info_len), info_len, out, out_len);
    return CH_OK;
}

#endif // CH_HASH
