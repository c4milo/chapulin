// bin/hash_dispatch_test: which path each of hash.h's calls takes under
// the CPU value it was given (docs/decisions.md 246). The two paths of a
// hash write the same bytes, so no vector shows which ran:
// test/hash_runtime_count.c and test/hash_runtime_sha3_count.c count the
// calls into each, and run every one on the portable code, so the binary
// runs no hash instruction and gives one verdict on every CPU of its
// architecture (test/hash_runtime_count.h).
//
// Each row is one use of the calls: a stream, a one-shot call, an HMAC or
// an HKDF step. It runs under CH_CPU_PROBED alone and under the bit of
// the hash it runs: CH_CPU_CONSTANT_TIME_SHA256 for SHA-256; for SHA-384
// and SHA-512 CH_CPU_AVX2 on x86-64 and CH_CPU_CONSTANT_TIME_SHA512 on
// arm64; for SHA-3 and SHAKE CH_CPU_BMI1 with CH_CPU_BMI2_ADX on x86-64
// and CH_CPU_CONSTANT_TIME_SHA3 on arm64 (sha3.h). Under the bit every
// call the row makes into that hash must run on the instructions, and
// none on the portable code; under CH_CPU_PROBED the reverse. A stream's
// init alone takes the value, so a stream that kept another value than
// its init took fails its row.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "hash.h"
#include "hash_runtime_count.h"

#if !defined(CH_CPU_RUNTIME) || !defined(CH_HASH)
#error "bin/hash_dispatch_test is a host object with CH_HASH: -DCH_CPU_RUNTIME -DCH_HASH"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#define COUNT(a) (sizeof(a) / sizeof(a)[0])

// The hash a row runs, and so the counters it reads.
typedef enum { RUNS_SHA256, RUNS_SHA512, RUNS_SHA3 } hash_kind;

// The bit of each hash, on this architecture.
#ifdef __x86_64__
#define SHA512_BIT CH_CPU_AVX2
#define SHA3_BIT (CH_CPU_BMI1 | CH_CPU_BMI2_ADX)
#else
#define SHA512_BIT CH_CPU_CONSTANT_TIME_SHA512
#define SHA3_BIT CH_CPU_CONSTANT_TIME_SHA3
#endif

// Whether this object holds a SHA-3 copy on instructions: every x86-64
// host object, and an arm64 one that clang compiled (sha3.h).
#if defined(__x86_64__) || defined(CH_KECCAK_INSTRUCTIONS)
#define SHA3_HAS_COPY 1
#else
#define SHA3_HAS_COPY 0
#endif

static const uint8_t message[300] = {1, 2, 3};
static const uint8_t key[200] = {4, 5, 6};

static void sha256_stream(uint32_t cpu) {
    ch_sha256_state s;
    uint8_t out[CH_SHA256_LEN];
    if (ch_sha256_init(&s, cpu) != CH_OK) {
        abort();
    }
    ch_sha256_update(&s, message, 70);
    ch_sha256_update(&s, message + 70, 130);
    ch_sha256_final(&s, out);
}

static void sha384_stream(uint32_t cpu) {
    ch_sha384_state s;
    uint8_t out[CH_SHA384_LEN];
    if (ch_sha384_init(&s, cpu) != CH_OK) {
        abort();
    }
    ch_sha384_update(&s, message, 130);
    ch_sha384_update(&s, message + 130, 170);
    ch_sha384_final(&s, out);
}

static void sha512_stream(uint32_t cpu) {
    ch_sha512_state s;
    uint8_t out[CH_SHA512_LEN];
    if (ch_sha512_init(&s, cpu) != CH_OK) {
        abort();
    }
    ch_sha512_update(&s, message, 1);
    ch_sha512_update(&s, message + 1, 299);
    ch_sha512_final(&s, out);
}

static void sha2_one_shots(uint32_t cpu) {
    uint8_t out[CH_SHA512_LEN];
    if (ch_sha256_hash(cpu, message, sizeof message, out) != CH_OK) {
        abort();
    }
}

static void sha512_one_shots(uint32_t cpu) {
    uint8_t out[CH_SHA512_LEN];
    if (ch_sha384_hash(cpu, message, sizeof message, out) != CH_OK ||
        ch_sha512_hash(cpu, message, sizeof message, out) != CH_OK) {
        abort();
    }
}

static void sha3_one_shots(uint32_t cpu) {
    uint8_t out[CH_SHA3_512_LEN];
    if (ch_sha3_256_hash(cpu, message, sizeof message, out) != CH_OK ||
        ch_sha3_512_hash(cpu, message, sizeof message, out) != CH_OK ||
        ch_shake128_hash(cpu, message, sizeof message, out, sizeof out) != CH_OK ||
        ch_shake256_hash(cpu, message, sizeof message, out, sizeof out) != CH_OK) {
        abort();
    }
}

static void shake_stream(uint32_t cpu) {
    ch_shake_state s;
    uint8_t out[300];
    if (ch_shake128_init(&s, cpu) != CH_OK) {
        abort();
    }
    ch_shake_absorb(&s, message, 100);
    ch_shake_absorb(&s, message + 100, 200);
    ch_shake_squeeze(&s, out, 10);
    ch_shake_squeeze(&s, out + 10, 290);
    ch_shake_wipe(&s);
}

static void hmac_of(uint32_t cpu, uint8_t algorithm, size_t len) {
    uint8_t out[CH_SHA512_LEN];
    if (ch_hmac(cpu, algorithm, key, sizeof key, message, sizeof message, out, len) != CH_OK) {
        abort();
    }
}

static void hmac_sha256(uint32_t cpu) {
    hmac_of(cpu, CH_HASH_ALGORITHM_SHA256, CH_SHA256_LEN);
}

static void hmac_sha384(uint32_t cpu) {
    hmac_of(cpu, CH_HASH_ALGORITHM_SHA384, CH_SHA384_LEN);
}

static void hmac_sha512(uint32_t cpu) {
    hmac_of(cpu, CH_HASH_ALGORITHM_SHA512, CH_SHA512_LEN);
}

static void hkdf_of(uint32_t cpu, uint8_t algorithm, size_t len) {
    uint8_t prk[CH_SHA512_LEN];
    uint8_t okm[200];
    if (ch_hkdf_extract(cpu, algorithm, key, 20, message, 40, prk, len) != CH_OK ||
        ch_hkdf_expand(cpu, algorithm, prk, len, message, 30, okm, sizeof okm) != CH_OK) {
        abort();
    }
}

static void hkdf_sha256(uint32_t cpu) {
    hkdf_of(cpu, CH_HASH_ALGORITHM_SHA256, CH_SHA256_LEN);
}

static void hkdf_sha384(uint32_t cpu) {
    hkdf_of(cpu, CH_HASH_ALGORITHM_SHA384, CH_SHA384_LEN);
}

static void hkdf_sha512(uint32_t cpu) {
    hkdf_of(cpu, CH_HASH_ALGORITHM_SHA512, CH_SHA512_LEN);
}

static const struct {
    const char *name;
    void (*run)(uint32_t cpu);
    hash_kind kind;
} rows[] = {
    {"a SHA-256 stream",                       sha256_stream,    RUNS_SHA256},
    {"a SHA-384 stream",                       sha384_stream,    RUNS_SHA512},
    {"a SHA-512 stream",                       sha512_stream,    RUNS_SHA512},
    {"SHA-256 over a whole input",             sha2_one_shots,   RUNS_SHA256},
    {"SHA-384 and SHA-512 over a whole input", sha512_one_shots, RUNS_SHA512},
    {"SHA-3 and SHAKE over a whole input",     sha3_one_shots,   RUNS_SHA3  },
    {"a SHAKE128 stream",                      shake_stream,     RUNS_SHA3  },
    {"HMAC-SHA-256",                           hmac_sha256,      RUNS_SHA256},
    {"HMAC-SHA-384",                           hmac_sha384,      RUNS_SHA512},
    {"HMAC-SHA-512",                           hmac_sha512,      RUNS_SHA512},
    {"HKDF-SHA-256",                           hkdf_sha256,      RUNS_SHA256},
    {"HKDF-SHA-384",                           hkdf_sha384,      RUNS_SHA512},
    {"HKDF-SHA-512",                           hkdf_sha512,      RUNS_SHA512},
};

static unsigned long total(const hash_calls *calls) {
    return calls->updates + calls->finals + calls->whole_messages;
}

static void zero_counts(void) {
    memset(&sha256_portable_calls, 0, sizeof sha256_portable_calls);
    memset(&sha256_hw_calls, 0, sizeof sha256_hw_calls);
    memset(&sha512_c_calls, 0, sizeof sha512_c_calls);
    memset(&sha512_hw_calls, 0, sizeof sha512_hw_calls);
    memset(&sha3_portable_calls, 0, sizeof sha3_portable_calls);
    memset(&sha3_hw_calls, 0, sizeof sha3_hw_calls);
}

// The calls the row made into the portable code of its hash, and into the
// copy on the instructions, and the bit that copy takes.
static void counts_of(hash_kind kind, unsigned long *portable, unsigned long *hw, uint32_t *bit) {
    if (kind == RUNS_SHA256) {
        *portable = total(&sha256_portable_calls);
        *hw = total(&sha256_hw_calls);
        *bit = CH_CPU_CONSTANT_TIME_SHA256;
    } else if (kind == RUNS_SHA512) {
        *portable = total(&sha512_c_calls);
        *hw = total(&sha512_hw_calls);
        *bit = SHA512_BIT;
    } else {
        *portable = total(&sha3_portable_calls);
        *hw = total(&sha3_hw_calls);
        *bit = SHA3_BIT;
    }
}

// Runs row i under CH_CPU_PROBED and under its hash's bit, and returns the
// failures.
static int row_holds(size_t i) {
    int failures = 0;
    for (int with_bit = 0; with_bit <= 1; with_bit++) {
        unsigned long portable = 0;
        unsigned long hw = 0;
        uint32_t bit = 0;
        counts_of(rows[i].kind, &portable, &hw, &bit);
        uint32_t cpu = CH_CPU_PROBED | (with_bit ? bit : 0);
        zero_counts();
        rows[i].run(cpu);
        counts_of(rows[i].kind, &portable, &hw, &bit);
        int on_hw = with_bit && (rows[i].kind != RUNS_SHA3 || SHA3_HAS_COPY);
        if (on_hw ? (hw == 0 || portable != 0) : (portable == 0 || hw != 0)) {
            printf("FAIL hash dispatch: %s under 0x%x: %lu calls on the portable code, %lu on "
                   "the instructions\n",
                   rows[i].name, (unsigned)cpu, portable, hw);
            failures++;
        }
    }
    return failures;
}

int main(void) {
    int failures = 0;
    for (size_t i = 0; i < COUNT(rows); i++) {
        failures += row_holds(i);
    }
    if (failures != 0) {
        return 1;
    }
    printf("hash dispatch: %zu rows each run every hash call on the path its CPU value names, and "
           "a stream on the value its init took\n",
           COUNT(rows));
    return 0;
}
