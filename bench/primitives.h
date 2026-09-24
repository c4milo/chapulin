// The measurement method bench/primitives.c implements, and the row
// tables the files beside it hand to it. bench/primitives.sh builds two
// programs from these files: one times the primitives
// (primitives_symmetric.c, primitives_public_key.c), and one times whole
// handshakes between this tree's client and server
// (primitives_handshake.c). None of this is library code.
#ifndef CH_BENCH_PRIMITIVES_H
#define CH_BENCH_PRIMITIVES_H

#include <stddef.h>
#include <stdint.h>

// One timed operation. A row whose unit is "byte" runs once per payload
// size in sizes and reports nanoseconds per payload byte. A row whose
// unit is "op" runs once per entry in sizes as well, and reports
// nanoseconds per call; its sizes hold the one byte count the call
// takes, such as the 32 bytes HKDF-Expand-Label writes, or 0 where the
// call takes fixed-size inputs.
typedef struct {
    const char *name;
    const char *unit;
    const size_t *sizes;
    size_t size_count;
    void (*prepare)(size_t n); // untimed setup and checks, before the samples
    void (*run)(size_t n);     // the timed operation
} bench_row;

// A named set of rows, or, when rows is NULL, a group that takes its own
// samples through measure and hands them to bench_record.
typedef struct {
    const char *name;
    const bench_row *rows;
    size_t row_count;
    void (*measure)(void);
} bench_group;

// The groups each program carries, defined in the file that owns them.
extern const bench_group BENCH_HASH;
extern const bench_group BENCH_CIPHER;
extern const bench_group BENCH_AEAD;
extern const bench_group BENCH_VERIFY;
extern const bench_group BENCH_SECRET_KEY;
extern const bench_group BENCH_X25519;
extern const bench_group BENCH_HANDSHAKE;

// The build this program was compiled as, for the CSV's build column.
extern const char *const BENCH_BUILD;

// Nanoseconds from a monotonic clock.
double bench_now_ns(void);

// The median of count samples and the spread between their 25th and
// 75th percentiles, as a percent of the median. Sorts samples in place.
typedef struct {
    double median;
    double iqr_pct;
} bench_stat;
bench_stat bench_stat_of(double *samples, size_t count);

// How many samples a measurement takes, and how many it drops first,
// given how long one sample took: BENCH_SAMPLES and 10, fewer for an
// operation too slow to fit that many in bench/primitives.c's per-row
// budget, and fewer under --quick. BENCH_SAMPLES is odd, so the median
// is one sample.
#define BENCH_SAMPLES 101
size_t bench_sample_count(double one_sample_ns);
size_t bench_warmup_count(double one_sample_ns);

// Stores one run's result for one row and size, from count samples.
// main prints every row once all runs are done, with the median over the
// runs.
void bench_record(const char *name, const char *unit, size_t bytes, size_t count, bench_stat s);

// Adds bytes into a volatile, so the compiler cannot drop the work that
// wrote them.
void bench_consume(const uint8_t *p, size_t n);

// Prints what failed and exits 1.
void bench_fail(const char *what);

// Fills p from a fixed-seed xorshift64, so every run times the same bytes.
void bench_fill(uint8_t *p, size_t n);

#endif
