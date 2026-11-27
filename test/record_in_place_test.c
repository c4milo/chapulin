// Every AEAD path opens a record in place. ch_read_in_place opens each
// record of the caller's input with its plaintext over its ciphertext,
// REC_HDR bytes after the record's start (tcp_read.c, docs/decisions.md
// 247), so rec_open runs there with pt == rec + REC_HDR, a shape no record
// opened in before. This binary seals records under each suite and under
// each ch_cfg.cpu value that picks another kernel, at lengths on both sides
// of each kernel's threshold, and requires each open in place to give the
// plaintext the seal took.
//
// It holds the other half of the rule too: a record whose tag fails
// releases no plaintext. AES-GCM and the one-pass ChaCha20-Poly1305 kernels
// write the plaintext before they compare the tag, so the bytes they leave
// must be zeros; the two-pass ChaCha20-Poly1305 open writes nothing, so the
// bytes must be the ciphertext still. Either answer is a refusal that
// released nothing, and ch_read_in_place then wipes the whole record.
//
// Which kernel a value and a length pick is the dispatch rule that
// bin/x86_kernels_test and bin/aes_runtime_test count. This binary runs
// each value the host's CPU holds, so a machine without AVX-512 runs the
// rows without it.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "cpu.h"
#include "ct.h"
#include "record.h"
#include "suite.h"
#include "test_cpu.h"
#ifdef __x86_64__
#include "x86_kernels_cpu.h"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures = 0;
static size_t cases = 0;

// The plaintext lengths: both sides of 16, the AEAD block, and of the
// thresholds of the vector kernels (aead_avx2.h, aead_avx512.h,
// poly1305.h), and one record of CH_TX_PT's largest value.
static const size_t lengths[] = {0,    1,    15,   16,   17,   63,   64,    65,   255,
                                 256,  257,  511,  512,  513,  1023, 1024,  1025, 2047,
                                 2048, 2049, 4095, 4096, 8191, 8192, 16383, 16384};
#define LENGTHS (sizeof lengths / sizeof lengths[0])

static const uint16_t suites[] = {SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_128_GCM_SHA256,
                                  SUITE_AES_256_GCM_SHA384};
#define SUITES (sizeof suites / sizeof suites[0])

// The values that pick another path. The AES bit names AES-GCM's
// instructions, and a traffic key runs on them alone, so an AES-GCM row
// takes it (record.h).
#ifdef __x86_64__
static const uint32_t values[] = {
    CH_CPU_PROBED,
    CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY,
    CH_CPU_PROBED | CH_CPU_AVX2,
    CH_CPU_PROBED | CH_CPU_AVX2 | CH_CPU_CONSTANT_TIME_MULTIPLY,
    CH_CPU_PROBED | CH_CPU_AVX2 | CH_CPU_CONSTANT_TIME_MULTIPLY | CH_CPU_AVX512_IFMA,
    CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_MULTIPLY,
    CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_MULTIPLY | CH_CPU_VAES,
    CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_MULTIPLY | CH_CPU_VAES |
        CH_CPU_AVX512,
};
#else
static const uint32_t values[] = {
    CH_CPU_PROBED,
    CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY,
    CH_CPU_PROBED | CH_CPU_SVE2,
    CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_MULTIPLY,
    CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_SHA3,
    CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_EOR3,
};
#endif
#define VALUES (sizeof values / sizeof values[0])

// Whether this CPU holds every instruction value names. A row of a value
// it does not hold would fault, so the row is skipped.
static int held(uint32_t value) {
    if (test_cpu_absent_hash_bits(value) != 0 || test_cpu_absent_sve2_bit(value) != 0) {
        return 0;
    }
#ifdef __x86_64__
    if (test_cpu_absent_avx2_bit(value) != 0 || test_cpu_absent_ifma_bit(value) != 0 ||
        test_cpu_absent_avx512_bit(value) != 0) {
        return 0;
    }
    if ((value & CH_CPU_VAES) != 0 && !x86_cpu_has_vaes()) {
        return 0;
    }
#endif
    return 1;
}

// Whether n bytes at p are all zero.
static int all_zero(const uint8_t *p, size_t n) {
    uint8_t any = 0;
    for (size_t i = 0; i < n; i++) {
        any |= p[i];
    }
    return any == 0;
}

static void fail(const char *what, uint16_t suite, uint32_t value, size_t n) {
    failures++;
    (void)fprintf(stderr, "FAIL %s: suite 0x%04x, cpu 0x%x, %zu bytes\n", what, suite, value, n);
}

// A direction keyed with secret under suite, on the path value names.
static void keyed(rec_dir *d, uint16_t suite, uint32_t value, const uint8_t *secret) {
    memset(d, 0, sizeof *d);
    d->cpu = value;
    rec_dir_init_suite(d, secret, suite);
}

#define RECORD_MAX (REC_HDR + 16384 + 1 + AEAD_TAG)
static uint8_t plaintext[16384];
static uint8_t sealed[RECORD_MAX];
static uint8_t opened[RECORD_MAX];

// One record: sealed out of place, opened in place, then opened in place
// once more with one bit of its tag flipped.
static void one_case(uint16_t suite, uint32_t value, size_t n, const uint8_t *secret) {
    rec_dir writer;
    rec_dir reader;
    keyed(&writer, suite, value, secret);
    size_t record_len = 0;
    if (rec_seal(&writer, REC_APPDATA, plaintext, n, sealed, sizeof sealed, &record_len) != 0) {
        fail("the seal refused", suite, value, n);
        return;
    }
    cases++;
    size_t pt_len = 0;
    uint8_t type = 0;
    memcpy(opened, sealed, record_len);
    keyed(&reader, suite, value, secret);
    int rc = rec_open(&reader, opened, record_len, opened + REC_HDR, record_len - REC_HDR, &pt_len,
                      &type);
    if (rc != 0 || pt_len != n || type != REC_APPDATA ||
        memcmp(opened + REC_HDR, plaintext, n) != 0) {
        fail("the open in place did not give the plaintext", suite, value, n);
    }
    memcpy(opened, sealed, record_len);
    opened[record_len - 1] ^= 1;
    keyed(&reader, suite, value, secret);
    size_t body = record_len - REC_HDR - AEAD_TAG;
    rc = rec_open(&reader, opened, record_len, opened + REC_HDR, record_len - REC_HDR, &pt_len,
                  &type);
    int nothing_written = memcmp(opened + REC_HDR, sealed + REC_HDR, body) == 0;
    if (rc == 0 || !(nothing_written || all_zero(opened + REC_HDR, body))) {
        fail("an open in place with a wrong tag released plaintext", suite, value, n);
    }
    ct_wipe(&writer, sizeof writer);
    ct_wipe(&reader, sizeof reader);
}

int main(void) {
    for (size_t i = 0; i < sizeof plaintext; i++) {
        plaintext[i] = (uint8_t)(i * 131U + 7U);
    }
    uint8_t secret[SHA384_LEN];
    for (size_t i = 0; i < sizeof secret; i++) {
        secret[i] = (uint8_t)(i + 1U);
    }
    size_t rows = 0;
    for (size_t v = 0; v < VALUES; v++) {
        if (!held(values[v])) {
            continue;
        }
        rows++;
        for (size_t s = 0; s < SUITES; s++) {
            int aes = suite_runs_aes_gcm(suites[s]);
            if (aes && (values[v] & CH_CPU_CONSTANT_TIME_AES) == 0) {
                continue; // a traffic key runs on the AES instructions alone (record.h)
            }
            for (size_t l = 0; l < LENGTHS; l++) {
                one_case(suites[s], values[v], lengths[l], secret);
            }
        }
    }
    if (failures != 0 || rows == 0) {
        (void)fprintf(stderr, "record_in_place: %d failures over %zu CPU values\n", failures, rows);
        return 1;
    }
    (void)printf("record_in_place: %zu records opened in place under %zu CPU values, each giving"
                 " its plaintext, and each with a wrong tag releasing none\n",
                 cases, rows);
    return 0;
}
