// Times the connected read and write of a TLS session through the calls
// that copy and through the calls that work in place, for the chart of
// docs/performance.md, "Reads and writes in place" (docs/decisions.md 247
// and 248). bench/inplace.sh builds it twice from one tree:
//
// - over a TRANSPORT=tcp-blocking object, with -DBENCH_COPY: ch_write over a
//   send that copies each record into the caller's output, and ch_read over
//   a recv that copies each record in from the caller's input, then the
//   plaintext out, as the Zig API's callbacks did before the two entries;
// - over a TRANSPORT=tcp-nonblocking object: ch_seal_in_place over the
//   plaintext where the caller wrote it, and ch_read_in_place over each
//   record where it lies.
//
// Both objects are TRUST=webpki SUITE=aesgcm TX_RECORD=16384, as colibri
// builds them, so a record carries up to 16 KiB. A row is one direction,
// one AEAD and one size of plaintext:
//
// - write: WRITE_CALLS calls of that many bytes, one record each up to
//   16 KiB and four records at 64 KiB; the figure is per call;
// - read: READ_RECORDS records of that many bytes, one a call; the figure
//   is per record.
//
// The session is connected by hand, with no handshake: the state, the keys
// of one secret in both directions, the suite and the peer's limit. A
// handshake runs the same code on both paths. Before each sample the
// session is connected again and, for a read, the records are sealed under
// the same secret, outside the clock. A socket writes the records into the
// caller's memory in both designs, so neither figure holds that write. A
// seal in place destroys the plaintext, and the next call seals the bytes
// it finds there, which takes the same time.
//
// Method, after pepegrillo's docs/performance.md: warm-up passes run every
// row unmeasured for WARM_UP_NS, so a short run does not time a core that
// was idle before it. SAMPLES passes follow, each timing one sample of every row
// in turn, so the rows interleave. A row's figure is the median of its
// samples, and bench/inplace.sh runs the two builds in turns and takes the
// median of their figures. The clock is CLOCK_MONOTONIC_RAW where the
// platform defines it, read before and after each sample.
//
// --samples N takes N samples a row, at most SAMPLES, and --quick three,
// for a build that only has to show that the binary runs. bench/inplace.sh
// runs the program at many stack positions, each with fewer samples.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ch_assert.h"
#include "record.h"
#include "session_convert.h"
#include "suite.h"
#include "tls.h"
#ifndef BENCH_COPY
#include "tcp_nonblocking.h"
#include "tcp_nonblocking_session.h"
#endif

#ifndef BENCH_CPU
#error "bench/inplace.sh passes -DBENCH_CPU, the ch_cfg.cpu value the rows run under"
#endif

#define SAMPLES 201
#define QUICK_SAMPLES 3
#define WARM_UP_NS 100e6
// The most warm-up passes, which bound the loop on a clock that stalls.
#define WARM_UP_PASSES_MAX 10000
#define READ_RECORDS 64
#define WRITE_CALLS 16
#define RECORD_MAX 16384
#define WRITE_MAX (4 * RECORD_MAX)
// The receive buffer each session's cfg.buf_len names, colibri's 20 KiB.
// The copying read takes each record into it.
#define RECEIVE_LEN 20480
#define SECRET_LEN 48
#define SECRET_BYTE 7

#ifdef BENCH_COPY
#define BENCH_PATH "copy"
typedef ch_tls_priv bench_session;
static ch_tls_priv *session_tls(bench_session *s) {
    return s;
}
#else
#define BENCH_PATH "in_place"
typedef ch_tcp_priv bench_session;
static ch_tls_priv *session_tls(bench_session *s) {
    return &s->t;
}
#endif

typedef struct {
    const char *name;
    uint16_t suite;
} bench_aead;

static const bench_aead AEADS[] = {
    {"aes128gcm",        SUITE_AES_128_GCM_SHA256      },
    {"aes256gcm",        SUITE_AES_256_GCM_SHA384      },
    {"chacha20poly1305", SUITE_CHACHA20_POLY1305_SHA256},
};
#define AEAD_COUNT (sizeof AEADS / sizeof AEADS[0])

static const size_t READ_SIZES[] = {100, 1024, 4096, RECORD_MAX};
static const size_t WRITE_SIZES[] = {100, 1024, 4096, RECORD_MAX, WRITE_MAX};
#define READ_SIZE_COUNT (sizeof READ_SIZES / sizeof READ_SIZES[0])
#define WRITE_SIZE_COUNT (sizeof WRITE_SIZES / sizeof WRITE_SIZES[0])
#define ROW_COUNT (AEAD_COUNT * (READ_SIZE_COUNT + WRITE_SIZE_COUNT))

typedef struct {
    int write;
    const bench_aead *aead;
    size_t bytes;
    double samples[SAMPLES];
} bench_row;

static bench_row rows[ROW_COUNT];
static bench_session session;
static uint8_t secret[SECRET_LEN];
static uint8_t plaintext[WRITE_MAX];
// The sealed records a read opens, as a socket wrote them.
static uint8_t wire[READ_RECORDS * (RECORD_MAX + REC_OVERHEAD)];
static size_t wire_len;
// The caller's output: the records a write sealed, and a KeyUpdate's room.
static uint8_t out[WRITE_MAX + (WRITE_MAX / RECORD_MAX + 1) * REC_OVERHEAD];
#ifndef BENCH_COPY
// The side buffer a KeyUpdate would go into. No row owes one.
static uint8_t side[CH_KEY_UPDATE_RECORD_LEN];
#endif
#ifdef BENCH_COPY
static uint8_t receive_buf[RECEIVE_LEN];
static uint8_t read_out[RECORD_MAX];
static size_t out_len;
static size_t feed_offset;
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "inplace bench: CH_ASSERT(%s) failed at %s:%d\n", cond, file, line);
    abort();
}

// RAND=extern's entropy hook. No timed call draws randomness.
void ch_rand_bytes(uint8_t *p, size_t n) {
    memset(p, 1, n);
}

static noreturn void fail(const char *what, const bench_row *row) {
    (void)fprintf(stderr, "inplace bench: %s, %s %s %zu bytes\n", what,
                  row->write ? "write" : "read", row->aead->name, row->bytes);
    exit(1);
}

static double now_ns(void) {
    struct timespec ts;
#ifdef CLOCK_MONOTONIC_RAW
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

#ifdef BENCH_COPY
// The send of the Zig API before entry 248: each record copied into the
// caller's output.
static int send_copy(void *io, const uint8_t *p, size_t n) {
    (void)io;
    memcpy(out + out_len, p, n);
    out_len += n;
    return (int)n;
}

// The recv of the Zig API before entry 247: the bytes the caller holds,
// copied into cfg.buf as the session asks for them.
static int recv_copy(void *io, uint8_t *p, size_t n) {
    (void)io;
    size_t left = wire_len - feed_offset;
    size_t take = n < left ? n : left;
    memcpy(p, wire + feed_offset, take);
    feed_offset += take;
    return (int)take;
}
#endif

// A connected session under the row's AEAD, at sequence number 0 in both
// directions.
static void connect_session(const bench_row *row) {
    memset(&session, 0, sizeof session);
    ch_tls_priv *t = session_tls(&session);
    t->cfg.buf_len = RECEIVE_LEN;
#ifdef BENCH_COPY
    t->cfg.buf = receive_buf;
    t->cfg.send = send_copy;
    t->cfg.recv = recv_copy;
#endif
    t->cfg.cpu = BENCH_CPU;
    t->rd.cpu = BENCH_CPU;
    t->wr.cpu = BENCH_CPU;
    t->state = CH_ST_CONNECTED;
    t->keys = 1;
    t->limit_sent = 1;
    t->suite = row->aead->suite;
    t->peer_limit = RECORD_MAX;
    rec_dir_init_suite(&t->wr, secret, row->aead->suite);
    rec_dir_init_suite(&t->rd, secret, row->aead->suite);
}

// READ_RECORDS records of the row's size, sealed under the secret from
// sequence number 0, as the peer sent them.
static void seal_records(const bench_row *row) {
    rec_dir peer;
    memset(&peer, 0, sizeof peer);
    peer.cpu = BENCH_CPU;
    rec_dir_init_suite(&peer, secret, row->aead->suite);
    wire_len = 0;
    for (size_t i = 0; i < READ_RECORDS; i++) {
        size_t len = 0;
        if (rec_seal(&peer, REC_APPDATA, plaintext, row->bytes, wire + wire_len,
                     sizeof wire - wire_len, &len) != 0) {
            fail("rec_seal refused a record", row);
        }
        wire_len += len;
    }
}

#ifdef BENCH_COPY
static double read_sample(const bench_row *row) {
    ch_tls *t = tls_public(session_tls(&session));
    feed_offset = 0;
    double start = now_ns();
    for (size_t i = 0; i < READ_RECORDS; i++) {
        if (ch_read(t, read_out, sizeof read_out) != (int)row->bytes) {
            fail("ch_read did not return the record's plaintext", row);
        }
    }
    return (now_ns() - start) / READ_RECORDS;
}

static double write_sample(const bench_row *row) {
    ch_tls *t = tls_public(session_tls(&session));
    double start = now_ns();
    for (size_t i = 0; i < WRITE_CALLS; i++) {
        out_len = 0;
        if (ch_write(t, plaintext, row->bytes) != CH_OK) {
            fail("ch_write refused the write", row);
        }
    }
    return (now_ns() - start) / WRITE_CALLS;
}
#else
static double read_sample(const bench_row *row) {
    ch_tls *t = tls_public(session_tls(&session));
    uint8_t reply[CH_ALERT_RECORD_LEN];
    size_t offset = 0;
    double start = now_ns();
    for (size_t i = 0; i < READ_RECORDS; i++) {
        ch_read_result result;
        if (ch_read_in_place(t, wire + offset, wire_len - offset, reply, sizeof reply, &result) !=
                CH_OK ||
            result.pt_len != row->bytes) {
            fail("ch_read_in_place did not open the record", row);
        }
        offset += result.consumed;
    }
    return (now_ns() - start) / READ_RECORDS;
}

static double write_sample(const bench_row *row) {
    ch_tls *t = tls_public(session_tls(&session));
    double start = now_ns();
    for (size_t i = 0; i < WRITE_CALLS; i++) {
        ch_seal_result result;
        if (ch_seal_in_place(t, out, sizeof out, row->bytes, side, sizeof side, &result) != CH_OK ||
            result.side_len != 0) {
            fail("ch_seal_in_place did not seal the write alone", row);
        }
    }
    return (now_ns() - start) / WRITE_CALLS;
}
#endif

// One sample of the row, its setup outside the clock.
static double sample(const bench_row *row) {
    connect_session(row);
    if (!row->write) {
        seal_records(row);
        return read_sample(row);
    }
#ifndef BENCH_COPY
    memcpy(out + REC_HDR, plaintext, row->bytes);
#endif
    return write_sample(row);
}

static size_t fill_rows(void) {
    size_t count = 0;
    for (size_t a = 0; a < AEAD_COUNT; a++) {
        for (size_t s = 0; s < READ_SIZE_COUNT; s++) {
            rows[count++] = (bench_row){.write = 0, .aead = &AEADS[a], .bytes = READ_SIZES[s]};
        }
        for (size_t s = 0; s < WRITE_SIZE_COUNT; s++) {
            rows[count++] = (bench_row){.write = 1, .aead = &AEADS[a], .bytes = WRITE_SIZES[s]};
        }
    }
    CH_ASSERT(count == ROW_COUNT);
    return count;
}

static int compare_doubles(const void *a, const void *b) {
    double x = *(const double *)a;
    double y = *(const double *)b;
    return (x > y) - (x < y);
}

static double median(double *values, size_t n) {
    qsort(values, n, sizeof values[0], compare_doubles);
    return n % 2 ? values[n / 2] : (values[n / 2 - 1] + values[n / 2]) / 2;
}

// The sample count the arguments name, or 0 for arguments the program
// does not take.
static size_t samples_of(int argc, char **argv) {
    if (argc == 1) {
        return SAMPLES;
    }
    if (argc == 2 && strcmp(argv[1], "--quick") == 0) {
        return QUICK_SAMPLES;
    }
    if (argc == 3 && strcmp(argv[1], "--samples") == 0) {
        char *end = NULL;
        unsigned long n = strtoul(argv[2], &end, 10);
        if (end != argv[2] && *end == '\0' && n >= 1 && n <= SAMPLES) {
            return (size_t)n;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    size_t samples = samples_of(argc, argv);
    if (samples == 0) {
        (void)fprintf(stderr, "usage: %s [--quick | --samples N], N from 1 to %d\n", argv[0],
                      SAMPLES);
        return 2;
    }
    memset(secret, SECRET_BYTE, sizeof secret);
    for (size_t i = 0; i < sizeof plaintext; i++) {
        plaintext[i] = (uint8_t)i;
    }
    size_t count = fill_rows();
    double warm_until = now_ns() + WARM_UP_NS;
    for (size_t pass = 0; pass < WARM_UP_PASSES_MAX && now_ns() < warm_until; pass++) {
        for (size_t r = 0; r < count; r++) {
            (void)sample(&rows[r]);
        }
    }
    for (size_t k = 0; k < samples; k++) {
        for (size_t r = 0; r < count; r++) {
            rows[r].samples[k] = sample(&rows[r]);
        }
    }
    for (size_t r = 0; r < count; r++) {
        printf("%s,%s,%s,%zu,0x%x,%.1f\n", BENCH_PATH, rows[r].write ? "write" : "read",
               rows[r].aead->name, rows[r].bytes, (unsigned)BENCH_CPU,
               median(rows[r].samples, samples));
    }
    return 0;
}
