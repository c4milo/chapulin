// Times the primitives chapulin ships, each through the call the rest of
// the tree makes, on the machine that runs it. bench/primitives.sh builds
// it and writes the rows to bench/results-primitives-<arch>.csv. The
// method is in this file; the rows are in primitives_symmetric.c,
// primitives_public_key.c and primitives_handshake.c.
//
// Usage: primitives [--quick] [--runs N] group...
//
// Method. One row times one operation at one size. It doubles the
// repetition count until one sample takes SAMPLE_NS, which also warms the
// caches and the branch predictors, runs WARMUP_SAMPLES more samples and
// drops them, then keeps BENCH_SAMPLES samples and takes their median. An
// operation slower than SAMPLE_NS runs once per sample, and one so slow
// that BENCH_SAMPLES of it would pass ROW_BUDGET_NS takes as many samples
// as fit in that budget, but never fewer than SLOW_SAMPLES_MIN, after one
// warm-up sample. The whole set of groups runs --runs times in turn, 3 by
// default, so a burst of load on a shared machine lands in one run of a
// row rather than in all of them. Each row prints the median over the
// runs, the samples one run took, the largest spread between the 25th
// and 75th percentile inside one run, and the spread between the fastest
// and the slowest run.
//
// The clock is CLOCK_MONOTONIC_RAW where the platform defines it, and
// CLOCK_MONOTONIC elsewhere. It is read before and after each sample and
// nowhere inside one, and no sample does I/O. Every operation is a call
// into another translation unit, and bench_consume adds output bytes into
// a volatile, so the compiler cannot drop the work.
//
// --quick takes three short samples per row and one run, for a build
// that only has to show the program runs, such as an emulated one.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <pthread.h>
#endif

#include "ch_assert.h"
#include "drbg.h"
#include "primitives.h"

#define SAMPLE_NS 2000000.0 // 2 ms per sample
#define WARMUP_SAMPLES 10
#define ROW_BUDGET_NS 1e9 // 1 s of samples per row and run, past which a row takes fewer
#define SLOW_SAMPLES_MIN 11
#define QUICK_SAMPLE_NS 100000.0
#define QUICK_SAMPLES 3
#define RUNS_DEFAULT 3
#define RUNS_MAX 9
#define RESULTS_MAX 160

// bench/primitives.sh changes one build choice at a time from the default, so
// no build here defines both.
#if defined(CH_NATIVE_WIDEMUL) && defined(CH_X25519_WIDE)
#error "bench/primitives.sh times CH_NATIVE_WIDEMUL and X25519=wide one at a time"
#elif defined(CH_NATIVE_WIDEMUL)
const char *const BENCH_BUILD = "CH_NATIVE_WIDEMUL";
#elif defined(CH_X25519_WIDE)
const char *const BENCH_BUILD = "X25519=wide";
#else
const char *const BENCH_BUILD = "default";
#endif

// The library's one platform hook besides entropy. Nothing here trips an
// assertion, so reaching it is a bug in the bench.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ch_assert: %s at %s:%d\n", cond, file, line);
    exit(134);
}

static volatile uint8_t sink;
static double sample_ns = SAMPLE_NS;
static size_t sample_count = BENCH_SAMPLES;
static size_t warmup_count = WARMUP_SAMPLES;

// xorshift64 from a fixed seed, so every invocation fills the same bytes.
static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

void bench_fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        p[i] = (uint8_t)rng_state;
    }
}

void bench_fail(const char *what) {
    (void)fprintf(stderr, "bench/primitives: %s\n", what);
    exit(1);
}

void bench_consume(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        sink = (uint8_t)(sink + p[i]);
    }
}

size_t bench_sample_count(double one_sample_ns) {
    if (one_sample_ns * (double)sample_count <= ROW_BUDGET_NS) {
        return sample_count;
    }
    size_t count = (size_t)(ROW_BUDGET_NS / one_sample_ns) | 1; // odd, so the median is one sample
    return count < SLOW_SAMPLES_MIN ? SLOW_SAMPLES_MIN : count;
}

size_t bench_warmup_count(double one_sample_ns) {
    return bench_sample_count(one_sample_ns) < sample_count && warmup_count > 0 ? 1 : warmup_count;
}

#ifdef CLOCK_MONOTONIC_RAW
#define BENCH_CLOCK CLOCK_MONOTONIC_RAW
#else
#define BENCH_CLOCK CLOCK_MONOTONIC
#endif

double bench_now_ns(void) {
    struct timespec t;
    if (clock_gettime(BENCH_CLOCK, &t) != 0) {
        bench_fail("clock_gettime failed");
    }
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static int compare_doubles(const void *a, const void *b) {
    double x = *(const double *)a;
    double y = *(const double *)b;
    return (x > y) - (x < y);
}

bench_stat bench_stat_of(double *samples, size_t count) {
    qsort(samples, count, sizeof samples[0], compare_doubles);
    bench_stat s;
    s.median = samples[count / 2];
    s.iqr_pct = 100.0 * (samples[(3 * count) / 4] - samples[count / 4]) / s.median;
    return s;
}

// One row and size across every run.
typedef struct {
    const char *name;
    const char *unit;
    size_t bytes;
    size_t sample_count;
    size_t run_count;
    double median[RUNS_MAX];
    double iqr_pct[RUNS_MAX];
} result;

static result results[RESULTS_MAX];
static size_t result_count;

void bench_record(const char *name, const char *unit, size_t bytes, size_t count, bench_stat s) {
    result *r = NULL;
    for (size_t i = 0; i < result_count; i++) {
        if (strcmp(results[i].name, name) == 0 && results[i].bytes == bytes) {
            r = &results[i];
        }
    }
    if (r == NULL) {
        if (result_count == RESULTS_MAX) {
            bench_fail("more rows than RESULTS_MAX");
        }
        r = &results[result_count++];
        r->name = name;
        r->unit = unit;
        r->bytes = bytes;
        r->sample_count = count;
    }
    if (count < r->sample_count) {
        r->sample_count = count;
    }
    r->median[r->run_count] = s.median;
    r->iqr_pct[r->run_count] = s.iqr_pct;
    r->run_count++;
}

// The CSV columns: primitive, build, unit, bytes, ns (per byte or per
// operation: the median over the runs of each run's median), per_second
// (10^6 bytes, or operations, per second at that median), samples (the
// fewest one run took), iqr_pct and run_spread_pct.
static void print_result(const result *r) {
    double sorted[RUNS_MAX];
    double iqr_max = 0.0;
    for (size_t i = 0; i < r->run_count; i++) {
        sorted[i] = r->median[i];
        if (r->iqr_pct[i] > iqr_max) {
            iqr_max = r->iqr_pct[i];
        }
    }
    qsort(sorted, r->run_count, sizeof sorted[0], compare_doubles);
    double median = sorted[r->run_count / 2];
    if (r->run_count % 2 == 0) {
        median = (sorted[r->run_count / 2 - 1] + median) / 2.0;
    }
    double spread = 100.0 * (sorted[r->run_count - 1] - sorted[0]) / median;
    int per_byte = strcmp(r->unit, "byte") == 0;
    double per_second = per_byte ? 1000.0 / median : 1e9 / median;
    printf("%s,%s,%s,%zu,%.4f,%.1f,%zu,%.1f,%.1f\n", r->name, BENCH_BUILD, r->unit, r->bytes,
           median, per_second, r->sample_count, iqr_max, spread);
}

static double time_repetitions(const bench_row *row, size_t n, size_t repetitions) {
    double start = bench_now_ns();
    for (size_t i = 0; i < repetitions; i++) {
        row->run(n);
    }
    return bench_now_ns() - start;
}

static void measure_row(const bench_row *row, size_t n) {
    double samples[BENCH_SAMPLES];
    row->prepare(n);
    size_t repetitions = 1;
    double first = time_repetitions(row, n, repetitions);
    while (first < sample_ns) {
        repetitions *= 2;
        first = time_repetitions(row, n, repetitions);
    }
    size_t count = bench_sample_count(first);
    for (size_t s = 0; s < bench_warmup_count(first); s++) {
        (void)time_repetitions(row, n, repetitions);
    }
    double divisor = (double)repetitions;
    if (strcmp(row->unit, "byte") == 0) {
        divisor *= (double)n;
    }
    for (size_t s = 0; s < count; s++) {
        samples[s] = time_repetitions(row, n, repetitions) / divisor;
    }
    bench_record(row->name, row->unit, n, count, bench_stat_of(samples, count));
}

static void measure_group(const bench_group *g) {
    if (g->rows == NULL) {
        g->measure();
        return;
    }
    for (size_t r = 0; r < g->row_count; r++) {
        for (size_t s = 0; s < g->rows[r].size_count; s++) {
            measure_row(&g->rows[r], g->rows[r].sizes[s]);
        }
    }
}

#ifdef BENCH_HANDSHAKE_PROGRAM
static const bench_group *const GROUPS[] = {&BENCH_HANDSHAKE};
#else
static const bench_group *const GROUPS[] = {&BENCH_HASH,   &BENCH_CIPHER,     &BENCH_AEAD,
                                            &BENCH_VERIFY, &BENCH_SECRET_KEY, &BENCH_X25519};
#endif
#define GROUP_COUNT (sizeof GROUPS / sizeof GROUPS[0])

static const bench_group *find_group(const char *name) {
    for (size_t i = 0; i < GROUP_COUNT; i++) {
        if (strcmp(GROUPS[i]->name, name) == 0) {
            return GROUPS[i];
        }
    }
    return NULL;
}

static void usage(const char *program) {
    (void)fprintf(stderr, "usage: %s [--quick] [--runs N] group...\ngroups:", program);
    for (size_t i = 0; i < GROUP_COUNT; i++) {
        (void)fprintf(stderr, " %s", GROUPS[i]->name);
    }
    (void)fprintf(stderr, "\n");
    exit(2);
}

// Reads the options; returns the index of the first group name.
static int read_options(int argc, char **argv, size_t *runs) {
    int i = 1;
    for (; i < argc && strncmp(argv[i], "--", 2) == 0; i++) {
        if (strcmp(argv[i], "--quick") == 0) {
            sample_ns = QUICK_SAMPLE_NS;
            sample_count = QUICK_SAMPLES;
            warmup_count = 0;
            *runs = 1;
        } else if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc) {
            *runs = (size_t)strtoul(argv[++i], NULL, 10);
            if (*runs == 0 || *runs > RUNS_MAX) {
                usage(argv[0]);
            }
        } else {
            usage(argv[0]);
        }
    }
    if (i >= argc) {
        usage(argv[0]);
    }
    return i;
}

int main(int argc, char **argv) {
#ifdef __APPLE__
    // User-interactive is the class macOS places on performance cores
    // first. An Apple silicon part also has efficiency cores, which run
    // the same code slower, and a sample taken on one would read as noise.
    (void)pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
    size_t runs = RUNS_DEFAULT;
    int first = read_options(argc, argv, &runs);
    for (int i = first; i < argc; i++) {
        if (find_group(argv[i]) == NULL) {
            (void)fprintf(stderr, "bench/primitives: no group named %s\n", argv[i]);
            usage(argv[0]);
        }
    }
    // The DRBG is ch_rand_bytes for every call that draws, seeded with a
    // fixed value so every invocation draws the same stream.
    uint8_t seed[32];
    bench_fill(seed, sizeof seed);
    ch_drbg_seed(seed, sizeof seed);
    for (size_t run = 0; run < runs; run++) {
        double load[1] = {0.0};
        (void)getloadavg(load, 1);
        printf("# %s run %zu of %zu: 1-minute load average %.2f at its start\n", BENCH_BUILD,
               run + 1, runs, load[0]);
        (void)fflush(stdout);
        for (int i = first; i < argc; i++) {
            measure_group(find_group(argv[i]));
        }
    }
    for (size_t i = 0; i < result_count; i++) {
        print_result(&results[i]);
    }
    return 0;
}
