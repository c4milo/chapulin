// bin/x86_kernels_test's SHA-512 rows. test/x86_kernels_test.c alone
// includes this file, on x86-64, after it defines CHECK and failures.
//
// sha512.h's entries that take a session's ch_cfg.cpu run sha512_hw.c's
// calls where the value holds CH_CPU_AVX2, and on x86-64 that file is
// sha512.c's first arm compiled once more over sha512_avx2.c's kernel
// (docs/decisions.md 128). hkdf.h's entries pick hkdf_hw.c's copy by the
// same bit at SHA-384's hash length, and a record direction keys itself
// through them with its own cpu. Every other call compresses on
// sha512_compress_blocks.c. The binary links sha512_hw.c itself, so these
// rows run its framing, and two stand-ins count the compression calls
// under it: test/x86_kernels_count.c counts sha512_avx2_compress_blocks and
// runs each call on sha512_compress_blocks, and
// test/hash_runtime_compress_count.c counts that function.
//
// Each row runs first under CH_CPU_PROBED alone, where every compression
// call it makes is sha512_compress_blocks's, and that count is the row's.
// Under the value the row must then make every one of those calls on the
// kernel where the value holds CH_CPU_AVX2 and none anywhere else, and
// write the same bytes. A row that runs SHA-256 makes no such call under
// any value.
#ifndef CH_TEST_X86_KERNELS_SHA512_H
#define CH_TEST_X86_KERNELS_SHA512_H

#include <stdio.h>
#include <string.h>

#include "hash_runtime_count.h"
#include "hkdf.h"
#include "record.h"
#include "sha512.h"
#include "suite.h"
#include "x86_kernels_count.h"

#define SHA512_ROW_INPUT ((size_t)300)
#define SHA512_ROW_KEY ((size_t)40)
#define SHA512_ROW_OUTPUT ((size_t)160)

static uint8_t sha512_row_input[SHA512_ROW_INPUT];
static uint8_t sha512_row_key[SHA512_ROW_KEY];
// The hash length and the suite the rows that take one run at.
static size_t sha512_row_hash_len;
static uint16_t sha512_row_suite;

// What a value names, written here apart from sha512.h's
// sha512_on_instructions so that a wrong predicate fails a row.
static unsigned long names_sha512_avx2(uint32_t cpu) {
    return (cpu & CH_CPU_AVX2) != 0 ? 1 : 0;
}

// One call that takes a session's ch_cfg.cpu and writes into out.
typedef struct {
    const char *name;
    void (*call)(uint32_t cpu, uint8_t out[SHA512_ROW_OUTPUT]);
} sha512_row;

static void sha512_row_whole_message384(uint32_t cpu, uint8_t out[SHA512_ROW_OUTPUT]) {
    sha384_of_cpu(cpu, sha512_row_input, SHA512_ROW_INPUT, out);
}

static void sha512_row_whole_message512(uint32_t cpu, uint8_t out[SHA512_ROW_OUTPUT]) {
    sha512_of_cpu(cpu, sha512_row_input, SHA512_ROW_INPUT, out);
}

// Three updates and a final: the second update fills the block the first
// left in the context.
static void sha512_row_streamed(uint32_t cpu, uint8_t out[SHA512_ROW_OUTPUT]) {
    sha512 s;
    sha384_init(&s);
    sha512_update_cpu(cpu, &s, sha512_row_input, 70);
    sha512_update_cpu(cpu, &s, sha512_row_input + 70, 130);
    sha512_update_cpu(cpu, &s, sha512_row_input + 200, SHA512_ROW_INPUT - 200);
    sha384_final_cpu(cpu, &s, out);
    sha512_init(&s);
    sha512_update_cpu(cpu, &s, sha512_row_input, SHA512_ROW_INPUT);
    sha512_final_cpu(cpu, &s, out + SHA384_LEN);
}

static void sha512_row_hmac(uint32_t cpu, uint8_t out[SHA512_ROW_OUTPUT]) {
    hmac_cpu(cpu, sha512_row_hash_len, sha512_row_key, SHA512_ROW_KEY, sha512_row_input,
             SHA512_ROW_INPUT, out);
}

static void sha512_row_hkdf(uint32_t cpu, uint8_t out[SHA512_ROW_OUTPUT]) {
    uint8_t pseudorandom_key[HKDF_HASH_MAX];
    hkdf_extract_cpu(cpu, sha512_row_hash_len, sha512_row_key, SHA512_ROW_KEY, sha512_row_input,
                     SHA512_ROW_INPUT, pseudorandom_key);
    hkdf_expand_label_cpu(cpu, sha512_row_hash_len, pseudorandom_key, "c hs traffic",
                          sha512_row_input, sha512_row_hash_len, out, sha512_row_hash_len);
}

// A record direction, which reads its own cpu: keyed under sha512_row_suite,
// then rekeyed as KeyUpdate rekeys it.
static void sha512_row_record_direction(uint32_t cpu, uint8_t out[SHA512_ROW_OUTPUT]) {
    uint8_t traffic_secret[HKDF_HASH_MAX];
    memcpy(traffic_secret, sha512_row_input, sizeof traffic_secret);
    rec_dir d;
    memset(&d, 0, sizeof d);
    d.cpu = cpu;
    rec_dir_init_suite(&d, traffic_secret, sha512_row_suite);
    memcpy(out, d.key, sizeof d.key);
    memcpy(out + sizeof d.key, d.iv, sizeof d.iv);
    rec_dir_update(traffic_secret, &d);
    memcpy(out + 64, d.key, sizeof d.key);
    memcpy(out + 64 + sizeof d.key, d.iv, sizeof d.iv);
}

// The row under cpu, against the same row under CH_CPU_PROBED alone.
// runs_sha512 says whether the row hashes with SHA-512 or SHA-384 at all:
// such a row must make a compression call, so a row that made none does
// not pass with nothing counted.
static void check_sha512_row(const sha512_row *row, uint32_t cpu, int runs_sha512) {
    uint8_t want[SHA512_ROW_OUTPUT];
    uint8_t got[SHA512_ROW_OUTPUT];
    memset(want, 0, sizeof want);
    memset(got, 0, sizeof got);
    sha512_compress_blocks_calls = 0;
    x86_sha512_avx2_calls = 0;
    row->call(CH_CPU_PROBED, want);
    unsigned long counted = sha512_compress_blocks_calls;
    unsigned long probed_alone_on_kernel = x86_sha512_avx2_calls;

    sha512_compress_blocks_calls = 0;
    x86_sha512_avx2_calls = 0;
    row->call(cpu, got);
    // The stand-in for the kernel runs each call on sha512_compress_blocks,
    // so that function's count is every compression call of the row.
    int calls_ok = probed_alone_on_kernel == 0 && sha512_compress_blocks_calls == counted &&
                   x86_sha512_avx2_calls == counted * names_sha512_avx2(cpu) &&
                   (counted != 0) == (runs_sha512 != 0);
    CHECK(calls_ok);
    CHECK(memcmp(got, want, sizeof want) == 0);
    if (!calls_ok) {
        (void)fprintf(stderr,
                      "calls: %s at hash length %zu, suite 0x%04x: %lu compression calls under "
                      "CH_CPU_PROBED alone, %lu of them on the kernel, and %lu under the value, "
                      "%lu of them on the kernel\n",
                      row->name, sha512_row_hash_len, (unsigned)sha512_row_suite, counted,
                      probed_alone_on_kernel, sha512_compress_blocks_calls, x86_sha512_avx2_calls);
    }
}

// The calls that take no value compress on sha512_compress_blocks.c,
// whatever a session states.
static void check_sha512_plain_names(void) {
    uint8_t out[SHA512_ROW_OUTPUT];
    sha512 s;
    sha512_compress_blocks_calls = 0;
    x86_sha512_avx2_calls = 0;
    sha384_of(sha512_row_input, SHA512_ROW_INPUT, out);
    sha512_init(&s);
    sha512_update(&s, sha512_row_input, SHA512_ROW_INPUT);
    sha512_final(&s, out);
    hmac(SHA384_LEN, sha512_row_key, SHA512_ROW_KEY, sha512_row_input, SHA512_ROW_INPUT, out);
    CHECK(sha512_compress_blocks_calls != 0 && x86_sha512_avx2_calls == 0);
}

static void check_sha512(uint32_t cpu) {
    static const sha512_row fixed_rows[] = {
        {"sha384_of_cpu",                                                sha512_row_whole_message384},
        {"sha512_of_cpu",                                                sha512_row_whole_message512},
        {"sha512_update_cpu with sha384_final_cpu and sha512_final_cpu", sha512_row_streamed        },
    };
    static const sha512_row hash_rows[] = {
        {"hmac_cpu",                                   sha512_row_hmac},
        {"hkdf_extract_cpu and hkdf_expand_label_cpu", sha512_row_hkdf},
    };
    static const sha512_row direction_row = {"a record direction", sha512_row_record_direction};
    static const size_t hash_lens[] = {SHA256_LEN, SHA384_LEN};
    static const uint16_t suites[] = {SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_128_GCM_SHA256,
                                      SUITE_AES_256_GCM_SHA384};
    for (size_t i = 0; i < SHA512_ROW_INPUT; i++) {
        sha512_row_input[i] = (uint8_t)(0x5a + 11 * i);
    }
    for (size_t i = 0; i < SHA512_ROW_KEY; i++) {
        sha512_row_key[i] = (uint8_t)(0x21 + 3 * i);
    }
    sha512_row_hash_len = 0;
    sha512_row_suite = 0;
    check_sha512_plain_names();
    for (size_t i = 0; i < sizeof fixed_rows / sizeof fixed_rows[0]; i++) {
        check_sha512_row(&fixed_rows[i], cpu, 1);
    }
    for (size_t h = 0; h < sizeof hash_lens / sizeof hash_lens[0]; h++) {
        sha512_row_hash_len = hash_lens[h];
        for (size_t i = 0; i < sizeof hash_rows / sizeof hash_rows[0]; i++) {
            check_sha512_row(&hash_rows[i], cpu, hash_lens[h] == SHA384_LEN);
        }
    }
    sha512_row_hash_len = 0;
    for (size_t s = 0; s < sizeof suites / sizeof suites[0]; s++) {
        sha512_row_suite = suites[s];
        check_sha512_row(&direction_row, cpu, suites[s] == SUITE_AES_256_GCM_SHA384);
    }
    sha512_row_suite = 0;
}

#endif
