// hash.h's calls (docs/decisions.md 246) against the vectors
// test/gen_hash_vectors.py reads out of RFC 6234, RFC 4231 and RFC 5869
// and checks with Python, against hashlib's SHA-3 and SHAKE, and at each
// edge hash.h states. Every vector runs under two CPU values:
// CH_CPU_PROBED alone, which runs the portable code, and the bits this
// CPU has of the hash instructions and kernels, which run sha256_hw.c,
// sha512_hw.c over sha512_avx2.c on x86-64, sha3_hw.c and the copy of
// hkdf.c over them where it has them. A stream is held to the one-shot
// call under uneven splits. The binary builds as a host object with
// CH_HASH. test/hash_dispatch_test.c counts which path each call takes.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "hash.h"
#include "hash_host_cpu.h"
#include "hash_vectors.h"
#include "test_cpu.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures;

static void expect(int got, int want, const char *what) {
    if (got != want) {
        printf("FAIL hash: %s: got %d, want %d\n", what, got, want);
        failures++;
    }
}

static void expect_bytes(const uint8_t *got, const uint8_t *want, size_t n, const char *what) {
    expect(memcmp(got, want, n), 0, what);
}

#define COUNT(a) (sizeof(a) / sizeof(a)[0])

// One of the three SHA-2 streams, by algorithm number.
typedef union {
    ch_sha256_state sha256;
    ch_sha384_state sha384;
    ch_sha512_state sha512;
} sha2_state;

static int sha2_init(sha2_state *s, uint8_t algorithm, uint32_t cpu) {
    if (algorithm == CH_HASH_ALGORITHM_SHA256) {
        return ch_sha256_init(&s->sha256, cpu);
    }
    if (algorithm == CH_HASH_ALGORITHM_SHA384) {
        return ch_sha384_init(&s->sha384, cpu);
    }
    return ch_sha512_init(&s->sha512, cpu);
}

static void sha2_update(sha2_state *s, uint8_t algorithm, const uint8_t *p, size_t n) {
    if (algorithm == CH_HASH_ALGORITHM_SHA256) {
        ch_sha256_update(&s->sha256, p, n);
    } else if (algorithm == CH_HASH_ALGORITHM_SHA384) {
        ch_sha384_update(&s->sha384, p, n);
    } else {
        ch_sha512_update(&s->sha512, p, n);
    }
}

static void sha2_final(sha2_state *s, uint8_t algorithm, uint8_t out[CH_SHA512_LEN]) {
    if (algorithm == CH_HASH_ALGORITHM_SHA256) {
        ch_sha256_final(&s->sha256, out);
    } else if (algorithm == CH_HASH_ALGORITHM_SHA384) {
        ch_sha384_final(&s->sha384, out);
    } else {
        ch_sha512_final(&s->sha512, out);
    }
}

static int sha2_hash(uint8_t algorithm, uint32_t cpu, const uint8_t *p, size_t n,
                     uint8_t out[CH_SHA512_LEN]) {
    if (algorithm == CH_HASH_ALGORITHM_SHA256) {
        return ch_sha256_hash(cpu, p, n, out);
    }
    if (algorithm == CH_HASH_ALGORITHM_SHA384) {
        return ch_sha384_hash(cpu, p, n, out);
    }
    return ch_sha512_hash(cpu, p, n, out);
}

// The digest length of an algorithm number, as the vectors use it.
static size_t digest_len(uint8_t algorithm) {
    if (algorithm == CH_HASH_ALGORITHM_SHA256) {
        return CH_SHA256_LEN;
    }
    return algorithm == CH_HASH_ALGORITHM_SHA384 ? CH_SHA384_LEN : CH_SHA512_LEN;
}

// The size of the state type of an algorithm number.
static size_t state_len(uint8_t algorithm) {
    if (algorithm == CH_HASH_ALGORITHM_SHA256) {
        return sizeof(ch_sha256_state);
    }
    return algorithm == CH_HASH_ALGORITHM_SHA384 ? sizeof(ch_sha384_state)
                                                 : sizeof(ch_sha512_state);
}

// Whether every byte of n at p is zero.
static int all_zero(const void *p, size_t n) {
    const uint8_t *bytes = p;
    uint8_t any = 0;
    for (size_t i = 0; i < n; i++) {
        any |= bytes[i];
    }
    return any == 0;
}

// RFC 6234's rows: the one-shot call where the message is not repeated,
// and the stream with one update for each repeat. Then the final must have
// wiped the state.
static void sha2_vectors_hold(uint32_t cpu) {
    for (size_t i = 0; i < COUNT(sha2_vectors); i++) {
        uint8_t algorithm = sha2_vectors[i].algorithm;
        uint8_t digest[CH_SHA512_LEN];
        if (sha2_vectors[i].repeat_count == 1) {
            expect(sha2_hash(algorithm, cpu, sha2_vectors[i].message, sha2_vectors[i].message_len,
                             digest),
                   CH_OK, "a one-shot SHA-2 call runs");
            expect_bytes(digest, sha2_vectors[i].digest, sha2_vectors[i].digest_len,
                         "an RFC 6234 vector, one-shot");
        }
        sha2_state s;
        memset(&s, 0x5a, sizeof s);
        expect(sha2_init(&s, algorithm, cpu), CH_OK, "a SHA-2 init runs");
        for (size_t r = 0; r < sha2_vectors[i].repeat_count; r++) {
            sha2_update(&s, algorithm, sha2_vectors[i].message, sha2_vectors[i].message_len);
        }
        sha2_final(&s, algorithm, digest);
        expect_bytes(digest, sha2_vectors[i].digest, sha2_vectors[i].digest_len,
                     "an RFC 6234 vector, streamed");
        expect(all_zero(&s, state_len(algorithm)), 1, "a final wipes its whole state");
    }
}

// The lengths each split stream adds in turn: each side of a block of 64
// and of 128 bytes, and pieces that straddle them.
static const size_t split_lengths[] = {0, 1, 3, 60, 4, 63, 64, 65, 127, 128, 129, 2, 200};
#define SPLIT_MESSAGE_LEN 1200

// A stream fed in uneven pieces, and one fed a byte at a time, give the
// one-shot digest of the same bytes, under each hash.
static void sha2_splits_hold(uint32_t cpu) {
    static uint8_t message[SPLIT_MESSAGE_LEN];
    for (size_t i = 0; i < sizeof message; i++) {
        message[i] = (uint8_t)(i * 13 + 7);
    }
    static const uint8_t algorithms[] = {CH_HASH_ALGORITHM_SHA256, CH_HASH_ALGORITHM_SHA384,
                                         CH_HASH_ALGORITHM_SHA512};
    for (size_t a = 0; a < COUNT(algorithms); a++) {
        uint8_t want[CH_SHA512_LEN];
        expect(sha2_hash(algorithms[a], cpu, message, sizeof message, want), CH_OK,
               "a one-shot SHA-2 call runs");
        sha2_state pieces;
        sha2_state bytes;
        expect(sha2_init(&pieces, algorithms[a], cpu), CH_OK, "a SHA-2 init runs");
        expect(sha2_init(&bytes, algorithms[a], cpu), CH_OK, "a SHA-2 init runs");
        size_t at = 0;
        for (size_t i = 0; at < sizeof message; i = (i + 1) % COUNT(split_lengths)) {
            size_t n =
                split_lengths[i] < sizeof message - at ? split_lengths[i] : sizeof message - at;
            sha2_update(&pieces, algorithms[a], message + at, n);
            at += n;
        }
        for (size_t j = 0; j < sizeof message; j++) {
            sha2_update(&bytes, algorithms[a], message + j, 1);
        }
        uint8_t got[CH_SHA512_LEN];
        sha2_final(&pieces, algorithms[a], got);
        expect_bytes(got, want, digest_len(algorithms[a]),
                     "a stream in uneven pieces is the one-shot digest");
        sha2_final(&bytes, algorithms[a], got);
        expect_bytes(got, want, digest_len(algorithms[a]),
                     "a stream a byte at a time is the one-shot digest");
    }
}

// RFC 4231's cases under each hash, and an empty key and message from
// NULL pointers.
static void hmac_vectors_hold(uint32_t cpu) {
    for (size_t i = 0; i < COUNT(hmac_vectors); i++) {
        uint8_t tag[CH_SHA512_LEN];
        uint8_t algorithm = hmac_vectors[i].algorithm;
        expect(ch_hmac(cpu, algorithm, hmac_vectors[i].key, hmac_vectors[i].key_len,
                       hmac_vectors[i].data, hmac_vectors[i].data_len, tag, digest_len(algorithm)),
               CH_OK, "an HMAC runs");
        expect_bytes(tag, hmac_vectors[i].tag, hmac_vectors[i].tag_len, "an RFC 4231 vector");
    }
    uint8_t from_null[CH_SHA512_LEN];
    uint8_t from_empty[CH_SHA512_LEN];
    static const uint8_t empty[1] = {0};
    expect(ch_hmac(cpu, CH_HASH_ALGORITHM_SHA512, NULL, 0, NULL, 0, from_null, CH_SHA512_LEN),
           CH_OK, "an HMAC of NULL pointers runs");
    expect(ch_hmac(cpu, CH_HASH_ALGORITHM_SHA512, empty, 0, empty, 0, from_empty, CH_SHA512_LEN),
           CH_OK, "an HMAC of empty inputs runs");
    expect_bytes(from_null, from_empty, CH_SHA512_LEN, "NULL with a length of 0 is empty");
}

// RFC 5869's cases and Python's SHA-384 and SHA-512 rows: Extract, then
// Expand from the PRK the row prints. An empty salt, as NULL, is the
// RFC's HashLen zero bytes.
static void hkdf_vectors_hold(uint32_t cpu) {
    for (size_t i = 0; i < COUNT(hkdf_vectors); i++) {
        uint8_t prk[CH_SHA512_LEN];
        uint8_t okm[256];
        uint8_t algorithm = hkdf_vectors[i].algorithm;
        const uint8_t *salt = hkdf_vectors[i].salt_len != 0 ? hkdf_vectors[i].salt : NULL;
        expect(ch_hkdf_extract(cpu, algorithm, salt, hkdf_vectors[i].salt_len, hkdf_vectors[i].ikm,
                               hkdf_vectors[i].ikm_len, prk, hkdf_vectors[i].prk_len),
               CH_OK, "an Extract runs");
        expect_bytes(prk, hkdf_vectors[i].prk, hkdf_vectors[i].prk_len, "an HKDF-Extract vector");
        expect(ch_hkdf_expand(cpu, algorithm, hkdf_vectors[i].prk, hkdf_vectors[i].prk_len,
                              hkdf_vectors[i].info, hkdf_vectors[i].info_len, okm,
                              hkdf_vectors[i].okm_len),
               CH_OK, "an Expand runs");
        expect_bytes(okm, hkdf_vectors[i].okm, hkdf_vectors[i].okm_len, "an HKDF-Expand vector");
        static const uint8_t zeros[CH_SHA512_LEN] = {0};
        uint8_t zero_salt_prk[CH_SHA512_LEN];
        expect(ch_hkdf_extract(cpu, algorithm, zeros, hkdf_vectors[i].prk_len, hkdf_vectors[i].ikm,
                               hkdf_vectors[i].ikm_len, zero_salt_prk, hkdf_vectors[i].prk_len),
               CH_OK, "an Extract under HashLen zero bytes runs");
        uint8_t empty_salt_prk[CH_SHA512_LEN];
        expect(ch_hkdf_extract(cpu, algorithm, NULL, 0, hkdf_vectors[i].ikm,
                               hkdf_vectors[i].ikm_len, empty_salt_prk, hkdf_vectors[i].prk_len),
               CH_OK, "an Extract under no salt runs");
        expect_bytes(zero_salt_prk, empty_salt_prk, hkdf_vectors[i].prk_len,
                     "no salt is HashLen zero bytes (RFC 5869 section 2.2)");
    }
}

// The squeeze lengths of the split SHAKE stream, which add to SHAKE_OUT_LEN.
static const size_t squeeze_lengths[] = {1, 7, 160, 1, 167, 64};

// SHAKE as a stream: the message absorbed in two pieces, then squeezed in
// uneven pieces, gives the one-shot output, and the wipe leaves zeros.
static void shake_stream_holds(uint32_t cpu, int shake256, size_t row, const uint8_t *want) {
    ch_shake_state s;
    memset(&s, 0x5a, sizeof s);
    int rc = shake256 ? ch_shake256_init(&s, cpu) : ch_shake128_init(&s, cpu);
    expect(rc, CH_OK, "a SHAKE init runs");
    size_t half = sponge_vectors[row].message_len / 2;
    ch_shake_absorb(&s, sponge_vectors[row].message, half);
    ch_shake_absorb(&s, sponge_vectors[row].message + half, sponge_vectors[row].message_len - half);
    uint8_t out[SHAKE_OUT_LEN];
    size_t at = 0;
    ch_shake_squeeze(&s, out, 0);
    for (size_t i = 0; i < COUNT(squeeze_lengths); i++) {
        ch_shake_squeeze(&s, out + at, squeeze_lengths[i]);
        at += squeeze_lengths[i];
    }
    expect((int)at, SHAKE_OUT_LEN, "the squeezes cover the output");
    expect_bytes(out, want, SHAKE_OUT_LEN, "a SHAKE stream is hashlib's output");
    ch_shake_wipe(&s);
    expect(all_zero(&s, sizeof s), 1, "a SHAKE wipe leaves zeros");
}

static void sponge_vectors_hold(uint32_t cpu) {
    for (size_t i = 0; i < COUNT(sponge_vectors); i++) {
        const uint8_t *m = sponge_vectors[i].message;
        size_t n = sponge_vectors[i].message_len;
        uint8_t digest[CH_SHA3_512_LEN];
        expect(ch_sha3_256_hash(cpu, m, n, digest), CH_OK, "SHA3-256 runs");
        expect_bytes(digest, sponge_vectors[i].sha3_256, CH_SHA3_256_LEN, "a SHA3-256 vector");
        expect(ch_sha3_512_hash(cpu, m, n, digest), CH_OK, "SHA3-512 runs");
        expect_bytes(digest, sponge_vectors[i].sha3_512, CH_SHA3_512_LEN, "a SHA3-512 vector");
        uint8_t out[SHAKE_OUT_LEN];
        expect(ch_shake128_hash(cpu, m, n, out, sizeof out), CH_OK, "SHAKE128 runs");
        expect_bytes(out, sponge_vectors[i].shake128, sizeof out, "a SHAKE128 vector");
        expect(ch_shake256_hash(cpu, m, n, out, sizeof out), CH_OK, "SHAKE256 runs");
        expect_bytes(out, sponge_vectors[i].shake256, sizeof out, "a SHAKE256 vector");
        shake_stream_holds(cpu, 0, i, sponge_vectors[i].shake128);
        shake_stream_holds(cpu, 1, i, sponge_vectors[i].shake256);
    }
}

// Every call that takes a CPU value refuses each value test_cpu.h lists as
// refused, and writes nothing to its output.
static void cpu_refusals_hold(uint32_t cpu) {
    uint8_t out[CH_SHA512_LEN];
    memset(out, 0x5a, sizeof out);
    sha2_state s;
    ch_shake_state shake;
    expect(sha2_init(&s, CH_HASH_ALGORITHM_SHA256, cpu), CH_EINVAL, "SHA-256 init refuses");
    expect(sha2_init(&s, CH_HASH_ALGORITHM_SHA384, cpu), CH_EINVAL, "SHA-384 init refuses");
    expect(sha2_init(&s, CH_HASH_ALGORITHM_SHA512, cpu), CH_EINVAL, "SHA-512 init refuses");
    expect(ch_shake128_init(&shake, cpu), CH_EINVAL, "SHAKE128 init refuses");
    expect(ch_shake256_init(&shake, cpu), CH_EINVAL, "SHAKE256 init refuses");
    expect(ch_sha256_hash(cpu, NULL, 0, out), CH_EINVAL, "SHA-256 refuses");
    expect(ch_sha384_hash(cpu, NULL, 0, out), CH_EINVAL, "SHA-384 refuses");
    expect(ch_sha512_hash(cpu, NULL, 0, out), CH_EINVAL, "SHA-512 refuses");
    expect(ch_sha3_256_hash(cpu, NULL, 0, out), CH_EINVAL, "SHA3-256 refuses");
    expect(ch_sha3_512_hash(cpu, NULL, 0, out), CH_EINVAL, "SHA3-512 refuses");
    expect(ch_shake128_hash(cpu, NULL, 0, out, sizeof out), CH_EINVAL, "SHAKE128 refuses");
    expect(ch_shake256_hash(cpu, NULL, 0, out, sizeof out), CH_EINVAL, "SHAKE256 refuses");
    expect(ch_hmac(cpu, CH_HASH_ALGORITHM_SHA256, NULL, 0, NULL, 0, out, CH_SHA256_LEN), CH_EINVAL,
           "HMAC refuses");
    expect(ch_hkdf_extract(cpu, CH_HASH_ALGORITHM_SHA256, NULL, 0, NULL, 0, out, CH_SHA256_LEN),
           CH_EINVAL, "Extract refuses");
    expect(ch_hkdf_expand(cpu, CH_HASH_ALGORITHM_SHA256, out, CH_SHA256_LEN, NULL, 0, out, 1),
           CH_EINVAL, "Expand refuses");
    for (size_t i = 0; i < sizeof out; i++) {
        expect(out[i], 0x5a, "a refused call writes nothing");
    }
}

// The refusals of ch_hmac, ch_hkdf_extract and ch_hkdf_expand that do not
// read the CPU value, each beside the edge value the call takes.
static void hmac_refusals_hold(uint32_t cpu) {
    uint8_t out[CH_SHA512_LEN];
    memset(out, 0x5a, sizeof out);
    expect(ch_hmac(cpu, 0, NULL, 0, NULL, 0, out, CH_SHA256_LEN), CH_EINVAL,
           "HMAC refuses algorithm 0");
    expect(ch_hmac(cpu, CH_HASH_ALGORITHM_SHA512 + 1, NULL, 0, NULL, 0, out, CH_SHA512_LEN),
           CH_EINVAL, "HMAC refuses an algorithm past SHA-512");
    expect(ch_hmac(cpu, CH_HASH_ALGORITHM_SHA384, NULL, 0, NULL, 0, out, CH_SHA512_LEN), CH_EINVAL,
           "HMAC refuses an out_len other than the digest's");
    expect(ch_hkdf_extract(cpu, CH_HASH_ALGORITHM_SHA512, NULL, 0, NULL, 0, out, CH_SHA384_LEN),
           CH_EINVAL, "Extract refuses a prk_len other than the digest's");
    for (size_t i = 0; i < sizeof out; i++) {
        expect(out[i], 0x5a, "a refused call writes nothing");
    }
}

// ch_hkdf_expand's bounds: the last value each takes, and the first it
// refuses, which writes nothing.
static void expand_bounds_hold(uint32_t cpu) {
    static uint8_t okm[CH_HKDF_EXPAND_LEN_MAX(CH_SHA512_LEN) + 1];
    static uint8_t info[CH_HKDF_INFO_LEN_MAX + 1];
    uint8_t prk[CH_SHA512_LEN] = {1};
    memset(okm, 0x5a, sizeof okm);
    size_t longest = CH_HKDF_EXPAND_LEN_MAX(CH_SHA512_LEN);
    expect(ch_hkdf_expand(cpu, CH_HASH_ALGORITHM_SHA512, prk, CH_SHA512_LEN, NULL, 0, okm, 0),
           CH_EINVAL, "Expand refuses an out_len of 0");
    expect(ch_hkdf_expand(cpu, CH_HASH_ALGORITHM_SHA512, prk, CH_SHA512_LEN, NULL, 0, okm,
                          longest + 1),
           CH_EINVAL, "Expand refuses 255 blocks and one byte");
    expect(ch_hkdf_expand(cpu, CH_HASH_ALGORITHM_SHA512, prk, CH_SHA384_LEN, NULL, 0, okm, 1),
           CH_EINVAL, "Expand refuses a prk_len other than the digest's");
    expect(ch_hkdf_expand(cpu, CH_HASH_ALGORITHM_SHA512, prk, CH_SHA512_LEN, info,
                          CH_HKDF_INFO_LEN_MAX + 1, okm, 1),
           CH_EINVAL, "Expand refuses an info past CH_HKDF_INFO_LEN_MAX");
    expect(okm[0], 0x5a, "a refused Expand writes nothing");
    expect(ch_hkdf_expand(cpu, CH_HASH_ALGORITHM_SHA512, prk, CH_SHA512_LEN, info,
                          CH_HKDF_INFO_LEN_MAX, okm, longest),
           CH_OK, "Expand takes the longest info and 255 blocks");
    expect(okm[longest], 0x5a, "Expand writes no byte past out_len");
    // A shorter output is the longer one's first bytes.
    uint8_t first[CH_SHA512_LEN + 1];
    expect(ch_hkdf_expand(cpu, CH_HASH_ALGORITHM_SHA512, prk, CH_SHA512_LEN, info,
                          CH_HKDF_INFO_LEN_MAX, first, sizeof first),
           CH_OK, "a shorter Expand runs");
    expect_bytes(first, okm, sizeof first, "a shorter Expand is a prefix");
}

static void run_under(uint32_t cpu) {
    sha2_vectors_hold(cpu);
    sha2_splits_hold(cpu);
    hmac_vectors_hold(cpu);
    hkdf_vectors_hold(cpu);
    sponge_vectors_hold(cpu);
    hmac_refusals_hold(cpu);
    expand_bounds_hold(cpu);
}

int main(void) {
    uint32_t host = hash_host_cpu();
    run_under(CH_CPU_PROBED);
    run_under(host);
    for (size_t i = 0; i < TEST_CPU_VALUES; i++) {
        if (!test_cpu_taken(i)) {
            cpu_refusals_hold(test_cpu_values[i]);
        }
    }
    if (failures != 0) {
        printf("hash: %d failures\n", failures);
        return 1;
    }
    printf("hash: %zu SHA-2, %zu HMAC, %zu HKDF and %zu sponge vectors under CH_CPU_PROBED and "
           "under 0x%x, the stream under uneven splits, and every refusal hash.h states\n",
           COUNT(sha2_vectors), COUNT(hmac_vectors), COUNT(hkdf_vectors), COUNT(sponge_vectors),
           (unsigned)host);
    return 0;
}
