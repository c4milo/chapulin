// Times one TLS record's protection on the machine that runs it, split into
// the stages that make it up, for https://github.com/c4milo/chapulin/issues/184
// (AES-GCM) and https://github.com/c4milo/chapulin/issues/181
// (ChaCha20-Poly1305). bench/record.sh builds it with the flags of a
// SUITE=aesgcm host object and writes its rows to
// bench/results-record-<os>-<arch>-<compiler>.csv, and docs/performance.md,
// "Where a record's time goes", reads them.
//
// Each argument names one AEAD: aes128gcm and aes256gcm run the AEADs of
// TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384 on the AES
// instructions, and chacha20poly1305 runs TLS_CHACHA20_POLY1305_SHA256's.
// --quick before them takes one short run per row, for a build that only
// has to show the binary runs, such as an emulated one.
//
// What a row times. bench/record_rows.c defines one function per row and
// says what each calls. The whole rows call the library's own objects:
// rec_seal and rec_open, and the AEAD entries record.c calls. The stage
// rows call the library's functions where they are external, and entries
// in the stage sources bench/record_stages.h lists where a stage is
// static. Two stages have no function of their own: the last partial
// block of gcm.c's counter_mode, which is counter_mode less the whole
// blocks it hands the AES instructions, and the exclusive-or in
// chacha20_xor's loop. Each is a difference of two timed rows, which
// record_rows.c lists. Each check line prints a whole and the sum of its
// parts.
//
// Method, after pepegrillo's docs/performance.md
// (https://github.com/c4milo/pepegrillo/blob/main/docs/performance.md):
//
// - A warm-up pass runs every row unmeasured. It also fixes each row's
//   batch: the operation count doubles until one batch takes BATCH_NS.
// - RUNS runs follow. Each run passes SAMPLES times over every row, timing
//   one batch of each row per pass, so the rows are interleaved batch by
//   batch; the row's figure for that run is the median of its batches. A
//   median ignores the batches the scheduler interrupted.
// - A row's figure is the median of its run figures, and its spread is the
//   slowest run less the fastest, as a percent of that median. It also
//   prints the batches at the 10th and the 90th percentile over every
//   run, because some rows' batches fall into two groups whose median
//   moves from one run to the next.
// - An open destroys the record it opens, so each open first copies the
//   sealed record back into the buffer, as ch_read's socket read would
//   write it there, and its figure in each run is less the refill row's.
// - Setup stays out of every batch: bench_prepare keys the state and seals
//   the record before each pass over a record size, and bench_reset_batch
//   sets the sequence numbers back before each batch.
//
// The clock is CLOCK_MONOTONIC_RAW where the platform defines it, read
// before and after each batch and nowhere inside one. On macOS it steps
// every 41 ns, and a batch spans at least 24,000 steps. On macOS the
// process asks for the user-interactive quality-of-service class, which
// macOS places on the performance cores first.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <pthread.h>
#endif

#include "ch_assert.h"
#include "record_rows.h"

#define RUNS 5
#define SAMPLES 15            // batches per row per run; odd, so the median is one batch
#define BATCH_NS 1000000.0    // 1 ms
#define QUICK_BATCH_NS 1000.0 // one operation or a few, for --quick
#define MAX_ROWS 32

// The build column: the widening multiply the rows run on, which the
// answer BENCH_WIDEMUL picks in the host object (record_stages.h), under
// CHACHA=vector the ChaCha20 path before it, and before that the x86-64
// kernels when bench/record.sh routes the build's calls to them.
#if defined(TEST_ROUTE_AVX2) && defined(TEST_ROUTE_VAES)
#define KERNEL_LABEL "AVX2+VAES "
#else
#define KERNEL_LABEL ""
#endif
#ifdef CH_CHACHA_VECTOR
#define CHACHA_LABEL KERNEL_LABEL "CHACHA=vector "
#else
#define CHACHA_LABEL KERNEL_LABEL ""
#endif
#ifdef BENCH_WIDEMUL_NATIVE
#define BUILD_LABEL CHACHA_LABEL "WIDEMUL=native"
#else
#define BUILD_LABEL CHACHA_LABEL "WIDEMUL=decomposed"
#endif

// The library's one platform hook this link can call. Nothing here trips
// an assertion, so a call to it is a bug in the bench.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ch_assert: %s at %s:%d\n", cond, file, line);
    exit(134);
}

static bench_state state;

// One timed row at one size: its batch, and each batch's time per
// operation in each run, in nanoseconds.
typedef struct {
    size_t repetitions;
    double batch_ns[RUNS][SAMPLES];
} bench_cell;

static bench_cell cells[BENCH_GROUP_COUNT][MAX_ROWS][BENCH_SIZE_COUNT];

static double batch_ns = BATCH_NS;
static size_t run_count = RUNS;
static size_t sample_count = SAMPLES;

#ifdef CLOCK_MONOTONIC_RAW
#define BENCH_CLOCK CLOCK_MONOTONIC_RAW
#else
#define BENCH_CLOCK CLOCK_MONOTONIC
#endif

static void fail(const char *what, const char *name) {
    (void)fprintf(stderr, "bench/record: %s%s\n", what, name);
    exit(1);
}

static double now_ns(void) {
    struct timespec t;
    if (clock_gettime(BENCH_CLOCK, &t) != 0) {
        fail("clock_gettime failed", "");
    }
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static int compare_doubles(const void *a, const void *b) {
    double x = *(const double *)a;
    double y = *(const double *)b;
    return (x > y) - (x < y);
}

static double median(double *values, size_t n) {
    qsort(values, n, sizeof values[0], compare_doubles);
    return n % 2 == 1 ? values[n / 2] : (values[n / 2 - 1] + values[n / 2]) / 2;
}

// Whether a row with these sizes runs at size index s. A fixed row runs
// once, at index 0.
static int runs_at(unsigned sizes, size_t s) {
    if (sizes == BENCH_SIZES_FIXED) {
        return s == 0;
    }
    return (sizes >> s) & 1U;
}

// The index of the timed row named stage, or -1.
static int timed_row(const bench_group *group, const char *stage) {
    for (size_t r = 0; r < group->row_count; r++) {
        if (strcmp(group->rows[r].stage, stage) == 0) {
            return (int)r;
        }
    }
    return -1;
}

static const bench_difference *difference_named(const bench_group *group, const char *stage) {
    for (size_t d = 0; d < group->difference_count; d++) {
        if (strcmp(group->differences[d].stage, stage) == 0) {
            return &group->differences[d];
        }
    }
    fail("no row named ", stage);
    return NULL;
}

// The sizes the row named stage runs at; a difference runs where its
// first row does.
static unsigned sizes_of(const bench_group *group, const char *stage) {
    int r = timed_row(group, stage);
    if (r >= 0) {
        return group->rows[r].sizes;
    }
    return sizes_of(group, difference_named(group, stage)->from);
}

static double time_batch(const bench_row *row, size_t repetitions) {
    bench_state *b = &state;
    bench_reset_batch(b);
    double start = now_ns();
    for (size_t i = 0; i < repetitions; i++) {
        row->run(b);
    }
    return now_ns() - start;
}

static void warm_up(size_t g, size_t s) {
    const bench_group *group = &bench_groups[g];
    for (size_t r = 0; r < group->row_count; r++) {
        const bench_row *row = &group->rows[r];
        if (!runs_at(row->sizes, s)) {
            continue;
        }
        size_t repetitions = 1;
        while (time_batch(row, repetitions) < batch_ns) {
            repetitions *= 2;
        }
        (void)time_batch(row, repetitions);
        cells[g][r][s].repetitions = repetitions;
    }
}

// One run at one size: sample_count passes over every row, one batch of
// each per pass, so each row's batches spread across the whole run.
static void measure_run(size_t g, size_t s, size_t run) {
    const bench_group *group = &bench_groups[g];
    for (size_t i = 0; i < sample_count; i++) {
        for (size_t r = 0; r < group->row_count; r++) {
            if (!runs_at(group->rows[r].sizes, s)) {
                continue;
            }
            bench_cell *cell = &cells[g][r][s];
            cell->batch_ns[run][i] =
                time_batch(&group->rows[r], cell->repetitions) / (double)cell->repetitions;
        }
    }
}

static const bench_cell *cell_of(size_t g, int r, size_t s) {
    return &cells[g][r][bench_groups[g].rows[r].sizes == BENCH_SIZES_FIXED ? 0 : s];
}

// The figure of the row named stage in one run at size index s: for a
// timed row the median of its batches, less the refill row's figure when
// it refills; for a difference the figure of its first row less its
// second's.
static double run_figure(size_t g, const char *stage, size_t s, size_t run) {
    const bench_group *group = &bench_groups[g];
    int r = timed_row(group, stage);
    if (r < 0) {
        const bench_difference *d = difference_named(group, stage);
        return run_figure(g, d->from, s, run) - run_figure(g, d->minus, s, run);
    }
    double batches[SAMPLES];
    memcpy(batches, cell_of(g, r, s)->batch_ns[run], sizeof batches);
    double value = median(batches, sample_count);
    if (group->rows[r].refills) {
        value -= run_figure(g, "refill", s, run);
    }
    return value;
}

// The batches of timed row r at the 10th and the 90th percentile, nearest
// rank, over every run, each less the refill row's figure in its run when
// the row refills. A row whose batches fall into two groups shows both.
static void percentiles(size_t g, int r, size_t s, double *p10, double *p90) {
    double values[RUNS * SAMPLES];
    size_t n = 0;
    for (size_t run = 0; run < run_count; run++) {
        double less = bench_groups[g].rows[r].refills ? run_figure(g, "refill", s, run) : 0;
        for (size_t i = 0; i < sample_count; i++) {
            values[n++] = cell_of(g, r, s)->batch_ns[run][i] - less;
        }
    }
    qsort(values, n, sizeof values[0], compare_doubles);
    *p10 = values[(n - 1) / 10];
    *p90 = values[9 * (n - 1) / 10];
}

// The median of a row's run figures, and their spread as a percent of it.
static double figure(size_t g, const char *stage, size_t s, double *spread_pct) {
    double values[RUNS];
    for (size_t run = 0; run < run_count; run++) {
        values[run] = run_figure(g, stage, s, run);
    }
    double mid = median(values, run_count);
    if (spread_pct != NULL) {
        *spread_pct = 100.0 * (values[run_count - 1] - values[0]) / mid;
    }
    return mid;
}

// One CSV row. A fixed row has no bytes to divide by and a difference no
// batches of its own, so those cells stay empty.
static void print_row(size_t g, const char *stage, size_t s, int timed) {
    const bench_group *group = &bench_groups[g];
    int fixed = sizes_of(group, stage) == BENCH_SIZES_FIXED;
    size_t bytes = fixed ? 0 : bench_record_sizes[s];
    double spread = 0;
    double ns = figure(g, stage, s, &spread);
    char per_byte[64] = ",";
    char batches[64] = ",";
    if (!fixed) {
        (void)snprintf(per_byte, sizeof per_byte, "%.4f,%.1f", ns / (double)bytes,
                       1000.0 * (double)bytes / ns);
    }
    if (timed) {
        double p10 = 0;
        double p90 = 0;
        percentiles(g, timed_row(group, stage), s, &p10, &p90);
        (void)snprintf(batches, sizeof batches, "%.1f,%.1f", p10, p90);
    }
    printf("%s,%s,%s,%zu,%.1f,%s,%.1f,%s\n", group->name, BUILD_LABEL, stage, bytes, ns, per_byte,
           spread, batches);
}

// Each check as a comment line: the whole, the sum of its parts, and the
// difference as a percent of the whole, at the sizes the whole runs at.
static void print_checks(size_t g, size_t s) {
    const bench_group *group = &bench_groups[g];
    for (size_t c = 0; c < group->check_count; c++) {
        const bench_check *check = &group->checks[c];
        if (!runs_at(sizes_of(group, check->whole), s)) {
            continue;
        }
        double whole = figure(g, check->whole, s, NULL);
        double sum = 0;
        printf("# check,%s,%s,%zu,%s =", group->name, BUILD_LABEL, bench_record_sizes[s],
               check->whole);
        for (size_t i = 0; i < BENCH_CHECK_PARTS && check->parts[i] != NULL; i++) {
            sum += figure(g, check->parts[i], s, NULL);
            printf("%s%s", i == 0 ? " " : " + ", check->parts[i]);
        }
        printf(",%.1f,%.1f,%+.1f%%\n", whole, sum, 100.0 * (sum - whole) / whole);
    }
}

static void print_group(size_t g, size_t s) {
    const bench_group *group = &bench_groups[g];
    for (size_t r = 0; r < group->row_count; r++) {
        if (runs_at(group->rows[r].sizes, s)) {
            print_row(g, group->rows[r].stage, s, 1);
        }
    }
    for (size_t d = 0; d < group->difference_count; d++) {
        if (runs_at(sizes_of(group, group->differences[d].stage), s)) {
            print_row(g, group->differences[d].stage, s, 0);
        }
    }
    print_checks(g, s);
}

// The group each argument names, or -1 for a name that is not one.
static int group_named(const char *name) {
    for (size_t g = 0; g < BENCH_GROUP_COUNT; g++) {
        if (strcmp(name, bench_groups[g].name) == 0) {
            return (int)g;
        }
    }
    return -1;
}

int main(int argc, char **argv) {
    int first = 1;
    if (argc > 1 && strcmp(argv[1], "--quick") == 0) {
        batch_ns = QUICK_BATCH_NS;
        run_count = 1;
        sample_count = 1;
        first = 2;
    }
    if (first >= argc) {
        (void)fprintf(stderr, "usage: %s [--quick] aes128gcm|aes256gcm|chacha20poly1305...\n",
                      argv[0]);
        return 2;
    }
    int chosen[BENCH_GROUP_COUNT] = {0};
    for (int i = first; i < argc; i++) {
        int g = group_named(argv[i]);
        if (g < 0) {
            fail("no AEAD named ", argv[i]);
        }
        chosen[g] = 1;
    }
    for (size_t g = 0; g < BENCH_GROUP_COUNT; g++) {
        if (bench_groups[g].row_count > MAX_ROWS) {
            fail("more rows than MAX_ROWS in ", bench_groups[g].name);
        }
    }
#ifdef __APPLE__
    (void)pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
    for (size_t g = 0; g < BENCH_GROUP_COUNT; g++) {
        for (size_t s = 0; chosen[g] && s < BENCH_SIZE_COUNT; s++) {
            bench_prepare(&state, bench_groups[g].aead, bench_record_sizes[s]);
            warm_up(g, s);
        }
    }
    for (size_t run = 0; run < run_count; run++) {
        for (size_t g = 0; g < BENCH_GROUP_COUNT; g++) {
            for (size_t s = 0; chosen[g] && s < BENCH_SIZE_COUNT; s++) {
                bench_prepare(&state, bench_groups[g].aead, bench_record_sizes[s]);
                measure_run(g, s, run);
            }
        }
    }
    for (size_t g = 0; g < BENCH_GROUP_COUNT; g++) {
        for (size_t s = 0; chosen[g] && s < BENCH_SIZE_COUNT; s++) {
            print_group(g, s);
        }
    }
    return 0;
}
