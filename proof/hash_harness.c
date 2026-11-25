// Proves: hash.c's 24 calls are memory safe and free of UB over any inputs
// of up to the harness's bounds, NULL pointers with a length of 0 among
// them, and any CPU value. And that they keep what hash.h states:
// - each init and each one-shot call answers CH_EINVAL exactly for a value
//   cpu_value_ok refuses, and CH_OK for any other;
// - a stream runs each update, absorb, squeeze and final on the path that
//   the value its init took names, through the entries of sha256.h,
//   sha512.h and sha3.h, and a final or a wipe leaves the caller's whole
//   state zero;
// - ch_hmac, ch_hkdf_extract and ch_hkdf_expand answer CH_OK exactly when
//   the value, the algorithm and each length are ones hash.h takes, hand
//   hkdf.c a hash_len, a key length, an info length and an output length
//   its CH_ASSERTs take, and write nothing when they refuse.
//
// Every hash, HMAC and HKDF call below hash.c is a stub in this file. Each
// asserts its contract, records which path the caller took, and answers an
// unconstrained state and output. The sha256, sha512, sha3_stream and
// hkdf harnesses prove the portable calls, and the equivalence tests hold
// the copies on the instructions to them. ct.c is real, and ct_wipe is
// proof/ct_wipe_stub.c's loop.
//
// Bounds. An input holds INPUT_MAX bytes. An output holds OUT_MAX, SHA-512's
// digest and one byte more, and an output length past it is one hash.h
// refuses under every hash, so a call that took it would write outside
// the room. A state is at most CH_SHAKE_STATE_SIZE bytes, 240, which the
// fill and the wipe loops count to.
#include "harness.h"

#include "cpu.h"
#include "hash.h"
#include "hkdf.h"
#include "sha256.h"
#include "sha3.h"
#include "sha512.h"

#define INPUT_MAX 4
#define OUT_MAX (CH_SHA512_LEN + 1)

// The path the last hash call below took: 1 for the instructions, 0 for
// the portable code, and -1 before any call.
static int path = -1;

// The path every call of one stream took, which each stub folds in: 1 when
// all took the instructions, 0 when all took the portable code, 2 when the
// calls differed.
static int stream_path = -1;

static void took(int on_instructions) {
    path = on_instructions;
    if (stream_path == -1) {
        stream_path = on_instructions;
    } else if (stream_path != on_instructions) {
        stream_path = 2;
    }
}

static void readable(const uint8_t *in, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "a hash reads a readable input");
}

static void written(void *out, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(out, n), "a hash writes a writable output");
    fill_nondet((uint8_t *)out, n);
}

void sha256_init(sha256 *s) {
    written(s, sizeof *s);
}
void sha256_update(sha256 *s, const uint8_t *in, size_t n) {
    readable(in, n);
    written(s, sizeof *s);
    took(0);
}
void sha256_update_hw(sha256 *s, const uint8_t *in, size_t n) {
    readable(in, n);
    written(s, sizeof *s);
    took(1);
}
void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]) {
    written(s, sizeof *s);
    written(out, SHA256_LEN);
    took(0);
}
void sha256_final_hw(sha256 *s, uint8_t out[SHA256_LEN]) {
    written(s, sizeof *s);
    written(out, SHA256_LEN);
    took(1);
}

void sha384_init(sha512 *s) {
    written(s, sizeof *s);
}
void sha512_init(sha512 *s) {
    written(s, sizeof *s);
}
void sha512_update(sha512 *s, const uint8_t *in, size_t n) {
    readable(in, n);
    written(s, sizeof *s);
    took(0);
}
void sha512_update_hw(sha512 *s, const uint8_t *in, size_t n) {
    readable(in, n);
    written(s, sizeof *s);
    took(1);
}
void sha384_final(sha512 *s, uint8_t out[SHA384_LEN]) {
    written(s, sizeof *s);
    written(out, SHA384_LEN);
    took(0);
}
void sha384_final_hw(sha512 *s, uint8_t out[SHA384_LEN]) {
    written(s, sizeof *s);
    written(out, SHA384_LEN);
    took(1);
}
void sha512_final(sha512 *s, uint8_t out[SHA512_LEN]) {
    written(s, sizeof *s);
    written(out, SHA512_LEN);
    took(0);
}
void sha512_final_hw(sha512 *s, uint8_t out[SHA512_LEN]) {
    written(s, sizeof *s);
    written(out, SHA512_LEN);
    took(1);
}

void sha3_256(const uint8_t *in, size_t n, uint8_t out[SHA3_256_LEN]) {
    readable(in, n);
    written(out, SHA3_256_LEN);
    took(0);
}
void sha3_256_hw(const uint8_t *in, size_t n, uint8_t out[SHA3_256_LEN]) {
    readable(in, n);
    written(out, SHA3_256_LEN);
    took(1);
}
void sha3_512(const uint8_t *in, size_t n, uint8_t out[SHA3_512_LEN]) {
    readable(in, n);
    written(out, SHA3_512_LEN);
    took(0);
}
void sha3_512_hw(const uint8_t *in, size_t n, uint8_t out[SHA3_512_LEN]) {
    readable(in, n);
    written(out, SHA3_512_LEN);
    took(1);
}

// The SHAKE stubs keep squeezing's flag as sha3.c does, so the assertion
// that refuses an absorb after a squeeze reads what the real context holds.
void shake128_init(shake *s) {
    written(s, sizeof *s);
    s->squeezing = 0;
}
void shake256_init(shake *s) {
    written(s, sizeof *s);
    s->squeezing = 0;
}
void shake_absorb(shake *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(s->squeezing == 0, "no absorb after a squeeze");
    readable(in, n);
    took(0);
}
void shake_absorb_hw(shake *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(s->squeezing == 0, "no absorb after a squeeze");
    readable(in, n);
    took(1);
}
void shake_squeeze(shake *s, uint8_t *out, size_t n) {
    written(out, n);
    s->squeezing = 1;
    took(0);
}
void shake_squeeze_hw(shake *s, uint8_t *out, size_t n) {
    written(out, n);
    s->squeezing = 1;
    took(1);
}

// hkdf.c's calls, under the CH_ASSERTs each one holds.
static void hmac_contract(size_t hash_len, const uint8_t *key, size_t key_len, const uint8_t *msg,
                          size_t msg_len, uint8_t *out) {
    __CPROVER_assert(hash_len == SHA256_LEN || hash_len == SHA384_LEN || hash_len == SHA512_LEN,
                     "hmac takes the hash_len of one of its hashes");
    readable(key, key_len);
    readable(msg, msg_len);
    written(out, hash_len);
}
void hmac(size_t hash_len, const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
          uint8_t *out) {
    hmac_contract(hash_len, key, key_len, msg, msg_len, out);
    took(0);
}
void hmac_hw(size_t hash_len, const uint8_t *key, size_t key_len, const uint8_t *msg,
             size_t msg_len, uint8_t *out) {
    hmac_contract(hash_len, key, key_len, msg, msg_len, out);
    took(1);
}
void hkdf_extract(size_t hash_len, const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                  size_t ikm_len, uint8_t *prk) {
    __CPROVER_assert(salt != NULL, "hash.c passes its own salt, never hkdf.c's zeros");
    hmac_contract(hash_len, salt, salt_len, ikm, ikm_len, prk);
    took(0);
}
void hkdf_extract_hw(size_t hash_len, const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                     size_t ikm_len, uint8_t *prk) {
    __CPROVER_assert(salt != NULL, "hash.c passes its own salt, never hkdf.c's zeros");
    hmac_contract(hash_len, salt, salt_len, ikm, ikm_len, prk);
    took(1);
}
static void expand_contract(size_t hash_len, const uint8_t *prk, const uint8_t *info,
                            size_t info_len, uint8_t *out, size_t out_len) {
    __CPROVER_assert(hash_len <= HMAC_HASH_MAX, "hkdf_expand's CH_ASSERT on hash_len holds");
    __CPROVER_assert(out_len > 0 && out_len <= (size_t)255 * hash_len,
                     "hkdf_expand's CH_ASSERT on out_len holds");
    __CPROVER_assert(info_len <= HKDF_EXPAND_INFO_MAX, "hkdf_expand's CH_ASSERT on info holds");
    readable(prk, hash_len);
    readable(info, info_len);
    written(out, out_len);
}
void hkdf_expand(size_t hash_len, const uint8_t *prk, const uint8_t *info, size_t info_len,
                 uint8_t *out, size_t out_len) {
    expand_contract(hash_len, prk, info, info_len, out, out_len);
    took(0);
}
void hkdf_expand_hw(size_t hash_len, const uint8_t *prk, const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len) {
    expand_contract(hash_len, prk, info, info_len, out, out_len);
    took(1);
}

// An input of up to INPUT_MAX bytes, or NULL for one of no bytes.
static const uint8_t *input(uint8_t room[INPUT_MAX], size_t *n) {
    fill_nondet(room, INPUT_MAX);
    *n = nondet_size_t();
    __CPROVER_assume(*n <= INPUT_MAX);
    return *n == 0 && (nondet_u8() & 1) ? NULL : room;
}

static int all_zero(const void *p, size_t n) {
    const uint8_t *bytes = p;
    int zero = 1;
    for (size_t i = 0; i < n; i++) {
        if (bytes[i] != 0) {
            zero = 0;
        }
    }
    return zero;
}

// A SHA-256 stream: the init's answer, the path of every call after it,
// and the state its final leaves.
static void sha256_stream(uint32_t cpu) {
    ch_sha256_state state;
    fill_nondet((uint8_t *)&state, sizeof state);
    uint8_t room[INPUT_MAX];
    size_t n = 0;
    const uint8_t *in = input(room, &n);
    uint8_t out[CH_SHA256_LEN];
    int rc = ch_sha256_init(&state, cpu);
    __CPROVER_assert(rc == (cpu_value_ok(cpu) ? CH_OK : CH_EINVAL), "init refuses what cpu.h does");
    if (rc != CH_OK) {
        return;
    }
    stream_path = -1;
    ch_sha256_update(&state, in, n);
    ch_sha256_final(&state, out);
    __CPROVER_assert(stream_path == sha256_on_instructions(cpu), "the stream runs its init's path");
    __CPROVER_assert(all_zero(&state, sizeof state), "the final wipes the whole state");
}

static void sha512_streams(uint32_t cpu) {
    ch_sha384_state state384;
    ch_sha512_state state512;
    uint8_t room[INPUT_MAX];
    size_t n = 0;
    const uint8_t *in = input(room, &n);
    uint8_t out[CH_SHA512_LEN];
    int rc = ch_sha384_init(&state384, cpu);
    __CPROVER_assert(rc == ch_sha512_init(&state512, cpu), "SHA-384 and SHA-512 refuse alike");
    __CPROVER_assert(rc == (cpu_value_ok(cpu) ? CH_OK : CH_EINVAL), "init refuses what cpu.h does");
    if (rc != CH_OK) {
        return;
    }
    stream_path = -1;
    ch_sha384_update(&state384, in, n);
    ch_sha384_final(&state384, out);
    ch_sha512_update(&state512, in, n);
    ch_sha512_final(&state512, out);
    __CPROVER_assert(stream_path == sha512_on_instructions(cpu), "the stream runs its init's path");
    __CPROVER_assert(all_zero(&state384, sizeof state384) && all_zero(&state512, sizeof state512),
                     "each final wipes the whole state");
}

static void shake_stream(uint32_t cpu) {
    ch_shake_state state;
    uint8_t room[INPUT_MAX];
    size_t n = 0;
    const uint8_t *in = input(room, &n);
    uint8_t out[OUT_MAX];
    size_t out_len = nondet_size_t();
    __CPROVER_assume(out_len <= OUT_MAX);
    int rc = (nondet_u8() & 1) ? ch_shake128_init(&state, cpu) : ch_shake256_init(&state, cpu);
    __CPROVER_assert(rc == (cpu_value_ok(cpu) ? CH_OK : CH_EINVAL), "init refuses what cpu.h does");
    if (rc != CH_OK) {
        return;
    }
    stream_path = -1;
    ch_shake_absorb(&state, in, n);
    ch_shake_squeeze(&state, out, out_len);
    ch_shake_squeeze(&state, out, out_len);
    __CPROVER_assert(stream_path == -1 || stream_path == sha3_on_instructions(cpu),
                     "the stream runs its init's path");
    ch_shake_wipe(&state);
    __CPROVER_assert(all_zero(&state, sizeof state), "the wipe leaves the whole state zero");
}

// The one-shot calls: each answers by the value alone, and writes nothing
// when it refuses.
static void one_shots(uint32_t cpu) {
    uint8_t room[INPUT_MAX];
    size_t n = 0;
    const uint8_t *in = input(room, &n);
    uint8_t out[OUT_MAX];
    size_t out_len = nondet_size_t();
    __CPROVER_assume(out_len <= OUT_MAX);
    int want = cpu_value_ok(cpu) ? CH_OK : CH_EINVAL;
    uint8_t part = nondet_u8();
    int rc = part == 0   ? ch_sha256_hash(cpu, in, n, out)
             : part == 1 ? ch_sha384_hash(cpu, in, n, out)
             : part == 2 ? ch_sha512_hash(cpu, in, n, out)
             : part == 3 ? ch_sha3_256_hash(cpu, in, n, out)
             : part == 4 ? ch_sha3_512_hash(cpu, in, n, out)
             : part == 5 ? ch_shake128_hash(cpu, in, n, out, out_len)
                         : ch_shake256_hash(cpu, in, n, out, out_len);
    __CPROVER_assert(rc == want, "a one-shot call refuses what cpu.h does");
}

// The digest length of algorithm, or 0 for a number hash.h does not name.
static size_t length_of(uint8_t algorithm) {
    if (algorithm == CH_HASH_ALGORITHM_SHA256) {
        return SHA256_LEN;
    }
    if (algorithm == CH_HASH_ALGORITHM_SHA384) {
        return SHA384_LEN;
    }
    return algorithm == CH_HASH_ALGORITHM_SHA512 ? SHA512_LEN : 0;
}

static void macs(uint32_t cpu) {
    uint8_t key_room[INPUT_MAX];
    uint8_t msg_room[INPUT_MAX];
    size_t key_len = 0;
    size_t msg_len = 0;
    const uint8_t *key = input(key_room, &key_len);
    const uint8_t *msg = input(msg_room, &msg_len);
    uint8_t out[OUT_MAX];
    size_t out_len = nondet_size_t();
    __CPROVER_assume(out_len <= OUT_MAX);
    uint8_t algorithm = nondet_u8();
    size_t hash_len = length_of(algorithm);
    int takes = cpu_value_ok(cpu) && hash_len != 0 && out_len == hash_len;
    path = -1;
    int rc = (nondet_u8() & 1)
                 ? ch_hmac(cpu, algorithm, key, key_len, msg, msg_len, out, out_len)
                 : ch_hkdf_extract(cpu, algorithm, key, key_len, msg, msg_len, out, out_len);
    __CPROVER_assert(rc == (takes ? CH_OK : CH_EINVAL), "HMAC and Extract refuse what hash.h says");
    __CPROVER_assert(takes ? path == hash_on_instructions(cpu, hash_len) : path == -1,
                     "a call runs its hash's path, and a refusal runs none");
}

static void expand(uint32_t cpu) {
    uint8_t prk[CH_SHA512_LEN];
    uint8_t info_room[INPUT_MAX];
    fill_nondet(prk, sizeof prk);
    size_t prk_len = nondet_size_t();
    __CPROVER_assume(prk_len <= sizeof prk);
    size_t info_len = 0;
    const uint8_t *info = input(info_room, &info_len);
    // An info past the bound, which the call must refuse before it reads one byte.
    if (nondet_u8() & 1) {
        info_len = CH_HKDF_INFO_LEN_MAX + 1 + (size_t)nondet_u8();
    }
    uint8_t out[OUT_MAX];
    size_t out_len = nondet_size_t();
    __CPROVER_assume(out_len <= OUT_MAX || out_len > CH_HKDF_EXPAND_LEN_MAX(SHA512_LEN));
    uint8_t algorithm = nondet_u8();
    size_t hash_len = length_of(algorithm);
    int takes = cpu_value_ok(cpu) && hash_len != 0 && prk_len == hash_len &&
                info_len <= CH_HKDF_INFO_LEN_MAX && out_len != 0 && out_len <= OUT_MAX;
    path = -1;
    int rc = ch_hkdf_expand(cpu, algorithm, prk, prk_len, info, info_len, out, out_len);
    __CPROVER_assert(rc == (takes ? CH_OK : CH_EINVAL), "Expand refuses what hash.h says");
    __CPROVER_assert(takes ? path == hash_on_instructions(cpu, hash_len) : path == -1,
                     "Expand runs its hash's path, and a refusal runs none");
}

int main(void) {
    uint32_t cpu = nondet_u32();
    uint8_t part = nondet_u8();
    if (part == 0) {
        sha256_stream(cpu);
    } else if (part == 1) {
        sha512_streams(cpu);
    } else if (part == 2) {
        shake_stream(cpu);
    } else if (part == 3) {
        one_shots(cpu);
    } else if (part == 4) {
        macs(cpu);
    } else {
        expand(cpu);
    }
    return 0;
}
