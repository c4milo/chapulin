// Times chapulin's two AEADs per byte on the machine that runs it:
// ChaCha20-Poly1305 (aead.c) and AES-128-GCM (quic_gcm.c), each whole and
// in its two halves, plus the carry-less multiply GHASH prototype in
// bench/ghash_clmul.c. bench/aead.sh builds it once per AES and multiply
// choice and writes the rows to bench/results-aead-<arch>.csv.
//
// Each argument names a group of rows to run:
//
//   chacha20    chacha20_xor alone
//   chachapoly  aead_seal, aead_open, and Poly1305 alone
//   gcm         gcm_seal, gcm_open, and its two halves: counter mode and
//               gcm_ghash
//   clmul       checks the prototype GHASH and the seal built on it
//               against quic_gcm.c, then times both
//
// --quick before the groups takes three short samples per row, for a
// build that only has to show the binary runs, such as an emulated one.
//
// Method. One row times one operation over one payload size. It doubles
// the repetition count until one sample takes SAMPLE_NS, which also warms
// the caches and the branch predictors, runs WARMUP_SAMPLES more samples
// and drops them, then keeps SAMPLES samples. It prints the median
// nanoseconds per payload byte, the MB/s that median gives (10^6 bytes),
// and the spread between the 25th and 75th percentile as a percent of
// the median.
//
// The clock is CLOCK_MONOTONIC_RAW where the platform defines it, and
// CLOCK_MONOTONIC elsewhere. On macOS the first steps every 41 ns and the
// second every microsecond. It is read before and after each sample and
// nowhere inside one, and no sample does I/O. Every operation is a call
// into another translation unit, and each output byte the rows read is
// added into a volatile, so the compiler cannot drop the work.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aead.h"
#include "aead_gcm.h"
#include "ch_assert.h"
#include "quic_aes_key.h"

#define SAMPLE_NS 2000000.0 // 2 ms per sample
#define SAMPLES 101         // odd, so the median is one sample
#define WARMUP_SAMPLES 10
#define QUICK_SAMPLE_NS 100000.0
#define QUICK_SAMPLES 3
#define MAX_PAYLOAD 16384 // one full TLS record, RFC 8446 §5.1
#define AAD_LEN 16        // both AEADs pad associated data to 16 bytes
#define CHECK_TRIALS 2000

// The payload sizes: a short packet; 1200 bytes, the smallest datagram
// that may carry a QUIC Initial packet (RFC 9000 §14.1); 1350 bytes, a
// packet between that floor and a 1500-byte Ethernet MTU; and a full TLS
// record.
static const size_t PAYLOAD_SIZES[] = {64, 1200, 1350, MAX_PAYLOAD};
#define PAYLOAD_SIZE_COUNT (sizeof PAYLOAD_SIZES / sizeof PAYLOAD_SIZES[0])

#ifdef CH_AES_HW
#define BUILD_AES "AES=hw"
#else
#define BUILD_AES "AES=soft"
#endif
#ifdef CH_NATIVE_WIDEMUL
#define BUILD_LABEL BUILD_AES " CH_NATIVE_WIDEMUL"
#else
#define BUILD_LABEL BUILD_AES
#endif

// The library's one platform hook this link can call. Nothing here trips
// an assertion, so reaching it is a bug in the bench.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ch_assert: %s at %s:%d\n", cond, file, line);
    exit(134);
}

static uint8_t input[MAX_PAYLOAD];
static uint8_t output[MAX_PAYLOAD];
static uint8_t sealed[MAX_PAYLOAD];
static uint8_t sealed_tag[AEAD_TAG];
static uint8_t tag[AEAD_TAG];
static uint8_t aad[AAD_LEN];
static uint8_t chacha_key[AEAD_KEY];
static uint8_t nonce[AEAD_NONCE];
static aes_public_key aes_key;
static volatile uint8_t sink;

static double sample_ns = SAMPLE_NS;
static size_t sample_count = SAMPLES;
static size_t warmup_count = WARMUP_SAMPLES;

// xorshift64 from a fixed seed, so every run times the same bytes.
static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

static uint64_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void fill_random(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)rng_next();
    }
}

static void fail(const char *what) {
    (void)fprintf(stderr, "bench/aead: %s\n", what);
    exit(1);
}

#ifdef CLOCK_MONOTONIC_RAW
#define BENCH_CLOCK CLOCK_MONOTONIC_RAW
#else
#define BENCH_CLOCK CLOCK_MONOTONIC
#endif

static double now_ns(void) {
    struct timespec t;
    if (clock_gettime(BENCH_CLOCK, &t) != 0) {
        fail("clock_gettime failed");
    }
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static void consume(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        sink = (uint8_t)(sink + p[i]);
    }
}

static void prepare_nothing(size_t n) {
    (void)n;
}

static void run_chacha20(size_t n) {
    chacha20_xor(chacha_key, nonce, 1, input, output, n);
    consume(&output[n - 1], 1);
}

static void run_poly1305(size_t n) {
    poly1305 state;
    poly1305_init(&state, chacha_key);
    poly1305_update(&state, input, n);
    poly1305_final(&state, tag);
    consume(tag, sizeof tag);
}

static void run_chachapoly_seal(size_t n) {
    aead_seal(chacha_key, nonce, aad, AAD_LEN, input, n, output, tag);
    consume(tag, sizeof tag);
}

static void prepare_chachapoly_open(size_t n) {
    aead_seal(chacha_key, nonce, aad, AAD_LEN, input, n, sealed, sealed_tag);
}

static void run_chachapoly_open(size_t n) {
    if (!aead_open(chacha_key, nonce, aad, AAD_LEN, sealed, n, sealed_tag, output)) {
        fail("aead_open rejected its own seal");
    }
    consume(&output[n - 1], 1);
}

static void run_gcm_seal(size_t n) {
    gcm_seal(&aes_key, nonce, aad, AAD_LEN, input, n, output, tag);
    consume(tag, sizeof tag);
}

static void prepare_gcm_open(size_t n) {
    gcm_seal(&aes_key, nonce, aad, AAD_LEN, input, n, sealed, sealed_tag);
}

static void run_gcm_open(size_t n) {
    if (!gcm_open(&aes_key, nonce, aad, AAD_LEN, sealed, n, sealed_tag, output)) {
        fail("gcm_open rejected its own seal");
    }
    consume(&output[n - 1], 1);
}

static void run_gcm_counter_mode(size_t n) {
    bench_gcm_counter_mode(&aes_key, nonce, input, n, output);
    consume(&output[n - 1], 1);
}

// The same associated data and length block gcm_seal hashes, so this
// row and the counter-mode row split one seal.
static void run_ghash(size_t n) {
    gcm_ghash(&aes_key, aad, AAD_LEN, input, n, tag);
    consume(tag, sizeof tag);
}

#ifdef GHASH_CLMUL_INSTRUCTION
static void run_ghash_clmul(size_t n) {
    bench_ghash_clmul(&aes_key, aad, AAD_LEN, input, n, tag);
    consume(tag, sizeof tag);
}

static void run_gcm_seal_clmul(size_t n) {
    bench_gcm_seal_clmul(&aes_key, nonce, aad, AAD_LEN, input, n, output, tag);
    consume(tag, sizeof tag);
}
#endif

typedef struct {
    const char *name;
    void (*prepare)(size_t n); // untimed setup, such as the seal an open reads
    void (*run)(size_t n);     // one timed operation over n payload bytes
} bench_row;

static const bench_row CHACHA20_ROWS[] = {
    {"chacha20", prepare_nothing, run_chacha20},
};

static const bench_row CHACHAPOLY_ROWS[] = {
    {"chacha20_poly1305_seal", prepare_nothing,         run_chachapoly_seal},
    {"chacha20_poly1305_open", prepare_chachapoly_open, run_chachapoly_open},
    {"poly1305",               prepare_nothing,         run_poly1305       },
};

static const bench_row GCM_ROWS[] = {
    {"aes128_gcm_seal", prepare_nothing,  run_gcm_seal        },
    {"aes128_gcm_open", prepare_gcm_open, run_gcm_open        },
    {"aes128_ctr",      prepare_nothing,  run_gcm_counter_mode},
    {"ghash",           prepare_nothing,  run_ghash           },
};

#ifdef GHASH_CLMUL_INSTRUCTION
static const bench_row CLMUL_ROWS[] = {
    {"ghash_clmul_prototype",           prepare_nothing, run_ghash_clmul   },
    {"aes128_gcm_seal_clmul_prototype", prepare_nothing, run_gcm_seal_clmul},
};
#endif

static double time_repetitions(const bench_row *row, size_t n, size_t repetitions) {
    double start = now_ns();
    for (size_t i = 0; i < repetitions; i++) {
        row->run(n);
    }
    return now_ns() - start;
}

static int compare_doubles(const void *a, const void *b) {
    double x = *(const double *)a;
    double y = *(const double *)b;
    return (x > y) - (x < y);
}

static void measure(const bench_row *row, size_t n) {
    double per_byte[SAMPLES];
    row->prepare(n);
    size_t repetitions = 1;
    while (time_repetitions(row, n, repetitions) < sample_ns) {
        repetitions *= 2;
    }
    for (size_t s = 0; s < warmup_count; s++) {
        time_repetitions(row, n, repetitions);
    }
    for (size_t s = 0; s < sample_count; s++) {
        per_byte[s] = time_repetitions(row, n, repetitions) / ((double)repetitions * (double)n);
    }
    qsort(per_byte, sample_count, sizeof per_byte[0], compare_doubles);
    double median = per_byte[sample_count / 2];
    double spread = per_byte[(3 * sample_count) / 4] - per_byte[sample_count / 4];
    printf("%s,%s,%zu,%.4f,%.1f,%.1f\n", row->name, BUILD_LABEL, n, median, 1000.0 / median,
           100.0 * spread / median);
    (void)fflush(stdout);
}

static void measure_group(const bench_row *rows, size_t row_count) {
    for (size_t r = 0; r < row_count; r++) {
        for (size_t s = 0; s < PAYLOAD_SIZE_COUNT; s++) {
            measure(&rows[r], PAYLOAD_SIZES[s]);
        }
    }
}

#ifdef GHASH_CLMUL_INSTRUCTION
// One trial: a fresh Initial key from a random connection ID, random
// associated data and payload of the given lengths, and both GHASHes and
// both seals over them. Returns 1 when every byte agrees.
static int clmul_agrees(size_t aad_len, size_t n) {
    uint8_t dcid[8];
    fill_random(dcid, sizeof dcid);
    if (aes_public_key_initial(&aes_key, dcid, sizeof dcid, CH_QUIC_ENDPOINT_CLIENT) != CH_OK) {
        fail("aes_public_key_initial failed");
    }
    uint8_t check_aad[64];
    fill_random(check_aad, aad_len);
    fill_random(input, n);
    uint8_t want[AES_BLOCK];
    uint8_t got[AES_BLOCK];
    gcm_ghash(&aes_key, check_aad, aad_len, input, n, want);
    bench_ghash_clmul(&aes_key, check_aad, aad_len, input, n, got);
    int same = memcmp(want, got, AES_BLOCK) == 0;
    gcm_seal(&aes_key, nonce, check_aad, aad_len, input, n, sealed, want);
    bench_gcm_seal_clmul(&aes_key, nonce, check_aad, aad_len, input, n, output, got);
    same = same && memcmp(want, got, GCM_TAG) == 0 && memcmp(sealed, output, n) == 0;
    return same;
}

// The prototype is timed only once it computes quic_gcm.c's answer:
// every associated-data length from 0 to 64 against every payload length
// from 0 to 48, which covers each partial block, then random lengths up
// to MAX_PAYLOAD.
static void check_clmul(void) {
    size_t trials = 0;
    for (size_t aad_len = 0; aad_len <= 64; aad_len++) {
        for (size_t n = 0; n <= 48; n++) {
            if (!clmul_agrees(aad_len, n)) {
                fail("the prototype GHASH differs from gcm_ghash");
            }
            trials++;
        }
    }
    for (size_t i = 0; i < CHECK_TRIALS; i++) {
        if (!clmul_agrees((size_t)(rng_next() % 65), (size_t)(rng_next() % (MAX_PAYLOAD + 1)))) {
            fail("the prototype GHASH differs from gcm_ghash");
        }
        trials++;
    }
    (void)fprintf(stderr,
                  "bench/aead: %s GHASH prototype matches gcm_ghash and gcm_seal on %zu inputs\n",
                  GHASH_CLMUL_INSTRUCTION, trials);
}
#endif

static void set_up(void) {
    fill_random(input, sizeof input);
    fill_random(aad, sizeof aad);
    fill_random(chacha_key, sizeof chacha_key);
    fill_random(nonce, sizeof nonce);
    uint8_t dcid[8];
    fill_random(dcid, sizeof dcid);
    if (aes_public_key_initial(&aes_key, dcid, sizeof dcid, CH_QUIC_ENDPOINT_CLIENT) != CH_OK) {
        fail("aes_public_key_initial failed");
    }
}

// Runs one named group. Returns 0 when the name is not a group.
static int run_group(const char *name) {
    if (strcmp(name, "chacha20") == 0) {
        measure_group(CHACHA20_ROWS, sizeof CHACHA20_ROWS / sizeof CHACHA20_ROWS[0]);
    } else if (strcmp(name, "chachapoly") == 0) {
        measure_group(CHACHAPOLY_ROWS, sizeof CHACHAPOLY_ROWS / sizeof CHACHAPOLY_ROWS[0]);
    } else if (strcmp(name, "gcm") == 0) {
        measure_group(GCM_ROWS, sizeof GCM_ROWS / sizeof GCM_ROWS[0]);
    } else if (strcmp(name, "clmul") == 0) {
#ifdef GHASH_CLMUL_INSTRUCTION
        check_clmul();
        set_up();
        measure_group(CLMUL_ROWS, sizeof CLMUL_ROWS / sizeof CLMUL_ROWS[0]);
#else
        fail("clmul: this build targets neither PMULL nor PCLMULQDQ");
#endif
    } else {
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    int first = 1;
    if (argc > 1 && strcmp(argv[1], "--quick") == 0) {
        sample_ns = QUICK_SAMPLE_NS;
        sample_count = QUICK_SAMPLES;
        warmup_count = 0;
        first = 2;
    }
    if (first >= argc) {
        (void)fprintf(stderr, "usage: %s [--quick] chacha20|chachapoly|gcm|clmul...\n", argv[0]);
        return 2;
    }
    set_up();
    for (int i = first; i < argc; i++) {
        if (!run_group(argv[i])) {
            (void)fprintf(stderr, "bench/aead: no group named %s\n", argv[i]);
            return 2;
        }
    }
    return 0;
}
