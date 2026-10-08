// Times the primitives chapulin ships, each through the call the rest of
// the tree makes, on the machine that runs it. bench/primitives.sh builds
// it, runs it and writes
// bench/results-primitives-<os>-<arch>-<compiler>.csv. The method is in
// this file; the rows are in primitives_symmetric.c,
// primitives_public_key.c and primitives_handshake.c.
//
// Usage: primitives [--quick] --cpu VALUE group...
//
// --cpu is the ch_cfg.cpu value every row runs under, such as 0x7. The
// timed programs are host objects, which hold every path, and the value
// picks among them as a session's does (primitives.h). A device object's
// program, which bench/primitives.sh builds to count calls, has no such
// field and takes no --cpu.
//
// Method. One invocation is one run: it times every row of the groups it
// is given once and prints each row as it ends. bench/primitives.sh runs
// the programs several times in turn, with OpenSSL's rows between them, and
// takes each row's median over those runs, so a burst of load on a shared
// machine lands in one run of a row rather than in all of them.
//
// One row times one operation at one size. It doubles the repetition
// count until one sample takes SAMPLE_NS, which also warms the caches and
// the branch predictors, runs WARMUP_SAMPLES more samples and drops them,
// then keeps BENCH_SAMPLES samples and prints their median and the spread
// between their 25th and 75th percentiles. An operation slower than
// SAMPLE_NS runs once per sample, and one so slow that BENCH_SAMPLES of it
// would pass ROW_BUDGET_NS takes as many samples as fit in that budget,
// but never fewer than SLOW_SAMPLES_MIN, after one warm-up sample.
//
// The clock is the thread's CPU time, CLOCK_THREAD_CPUTIME_ID, read before
// and after each sample and nowhere inside one. It counts the time this
// thread ran, so the time a loaded machine gave to other work is in no
// sample. `openssl speed`, whose rows the script puts beside these, divides
// by its process's user CPU time, so both sides count the same thing. On
// macOS the clock steps every 42 ns, and a sample spans 2 ms. No sample
// does I/O. Every operation is a call into another translation unit, and
// bench_consume adds output bytes into a volatile, so the compiler cannot
// drop the work.
//
// Each row also prints the instructions one operation retired, where the
// system counts them for a program: the count over the kept samples,
// divided by the operations they ran. macOS reports it through
// proc_pid_rusage, which `/usr/bin/time -l` prints as "instructions
// retired". A count does not move with the machine's load, so it shows
// what a change did to a row on a machine too loaded to time it.
//
// --quick takes three short samples per row, for a build that only has to
// show the program runs, such as an emulated one.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <libproc.h>
#include <pthread.h>
#include <unistd.h>
#endif

#include "ch_assert.h"
#include "drbg.h"
#include "primitives.h"

#define SAMPLE_NS 2000000.0 // 2 ms per sample
#define WARMUP_SAMPLES 10
#define ROW_BUDGET_NS 1e9 // 1 s of samples per row, past which a row takes fewer
#define SLOW_SAMPLES_MIN 11
#define QUICK_SAMPLE_NS 100000.0
#define QUICK_SAMPLES 3

// The build column: the ch_cfg.cpu value the rows ran under.
#ifdef CH_CPU_RUNTIME
uint32_t bench_cpu;
#endif
static char build_label[32] = "device object";

// The library's one platform hook besides entropy. Nothing here trips an
// assertion, so a call to it is a bug in the bench.
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

double bench_now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t) != 0) {
        bench_fail("clock_gettime failed");
    }
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

uint64_t bench_instructions(void) {
#ifdef __APPLE__
    struct rusage_info_v4 info;
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V4, (rusage_info_t *)&info) == 0) {
        return info.ri_instructions;
    }
#endif
    return 0;
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

// One row of this run: primitive, build, unit, bytes, ns (per byte or per
// operation, the median of the samples), samples, iqr_pct and
// instructions (per byte or per operation, empty where the system gives no
// count). bench/primitives.sh takes each row's median over its runs.
void bench_print(const char *name, const char *unit, size_t bytes, size_t count, bench_stat s,
                 double instructions) {
    printf("%s,%s,%s,%zu,%.4f,%zu,%.1f,", name, build_label, unit, bytes, s.median, count,
           s.iqr_pct);
    if (instructions > 0.0) {
        printf("%.*f", strcmp(unit, "byte") == 0 ? 2 : 0, instructions);
    }
    printf("\n");
    (void)fflush(stdout);
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
    uint64_t instructions = bench_instructions();
    for (size_t s = 0; s < count; s++) {
        samples[s] = time_repetitions(row, n, repetitions) / divisor;
    }
    instructions = bench_instructions() - instructions;
    bench_print(row->name, row->unit, n, count, bench_stat_of(samples, count),
                (double)instructions / ((double)count * divisor));
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
static const bench_group *const GROUPS[] = {&BENCH_HASH, &BENCH_CIPHER, &BENCH_AEAD, &BENCH_VERIFY,
                                            &BENCH_SECRET_KEY};
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

#ifdef CH_CPU_RUNTIME
#define USAGE_OPTIONS "[--quick] --cpu VALUE"
#else
#define USAGE_OPTIONS "[--quick]"
#endif

static void usage(const char *program) {
    (void)fprintf(stderr, "usage: %s " USAGE_OPTIONS " group...\ngroups:", program);
    for (size_t i = 0; i < GROUP_COUNT; i++) {
        (void)fprintf(stderr, " %s", GROUPS[i]->name);
    }
    (void)fprintf(stderr, "\n");
    exit(2);
}

// Reads the options; returns the index of the first group name. A host
// object's program requires --cpu, because no row has a path to run
// without the value.
static int read_options(int argc, char **argv) {
#ifdef CH_CPU_RUNTIME
    int cpu_given = 0;
#else
    int cpu_given = 1; // a device object has no ch_cfg.cpu to be given
#endif
    int i = 1;
    for (; i < argc && strncmp(argv[i], "--", 2) == 0; i++) {
        if (strcmp(argv[i], "--quick") == 0) {
            sample_ns = QUICK_SAMPLE_NS;
            sample_count = QUICK_SAMPLES;
            warmup_count = 0;
#ifdef CH_CPU_RUNTIME
        } else if (strcmp(argv[i], "--cpu") == 0 && i + 1 < argc) {
            bench_cpu = (uint32_t)strtoul(argv[++i], NULL, 0);
            (void)snprintf(build_label, sizeof build_label, "ch_cfg.cpu 0x%x", (unsigned)bench_cpu);
            cpu_given = 1;
#endif
        } else {
            usage(argv[0]);
        }
    }
    if (i >= argc || !cpu_given) {
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
    int first = read_options(argc, argv);
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
    for (int i = first; i < argc; i++) {
        measure_group(find_group(argv[i]));
    }
    return 0;
}
