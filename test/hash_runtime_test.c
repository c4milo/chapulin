// bin/hash_runtime_test: which SHA-256 a host object's hash calls run under
// each ch_cfg.cpu value (docs/decisions.md 93). sha256.h's
// sha256_on_instructions picks sha256_hw.c's code where the value holds
// CH_CPU_CONSTANT_TIME_SHA256, and hkdf.h's hash_on_instructions picks the
// copies hkdf_hw.c and keysched_hw.c hold where the hash a call runs is
// SHA-256 and the value holds that bit. The two paths compute the same
// bytes, so no vector can tell which ran: test/hash_runtime_count.c counts
// the calls into each instead, and runs both on sha256.c's code, so this
// binary runs no hash instruction and gives the same verdict on every CPU.
//
// Every row runs under each of the 128 values the seven bits beside
// CH_CPU_PROBED make, and under 0, which a wiped record direction holds. A
// row is one call that takes a session's value. It runs first under
// CH_CPU_PROBED alone, which names no instruction, and that run's calls
// into sha256.c are the row's count. Under the value, the row must then:
//
//   - make every one of those calls on the instructions where the value
//     holds the SHA-256 bit, and none on sha256.c;
//   - make every one on sha256.c where it does not, and none on the
//     instructions;
//   - write the same bytes either way.
//
// So a predicate that reads another bit fails under the values that hold
// one bit and not the other, an entry that leaves a call on the other path
// fails its count, and a copy that calls sha256.c under its own name fails
// it too. A row that runs SHA-384 makes no SHA-256 call under any value.
//
// The rows: sha256.h's three entries; hkdf.h's five and keysched.h's, at
// each hash length the build holds; transcript.h's two; a record
// direction's keying and its KeyUpdate, which read the direction's cpu,
// under each suite; and in a QUIC build a level's keys, their update and
// an Initial packet. The Makefile builds the file twice: as a QUIC object
// with the suites, and as a TCP object with the exporter, whose two entries
// a QUIC object does not hold.
//
// One row computes more than hashes: the Initial packet's seal runs
// AES-128-GCM, on the path the value's AES and VAES bits pick. That row
// clears the bits that pick an AES or ChaCha20 path, so no row runs an
// instruction a CPU may lack, and test/aes-runtime-qemu.sh runs both
// binaries on a CPU model without any of them.
//
// What the instructions compute is held elsewhere: bin/sha2_equiv_test
// calls them against the portable code, and bin/unit_host and the
// Wycheproof host leg run the published vectors on them where the CPU has
// them.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "hash_runtime_count.h"
#include "hkdf.h"
#include "keysched.h"
#include "record.h"
#include "sha256.h"
#include "suite.h"
#include "transcript.h"
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#include "quic_initial.h"
#include "quic_keys.h"
#endif

#if !defined(CH_CPU_RUNTIME) || !defined(CH_SUITE_AES_GCM)
#error "bin/hash_runtime_test is a host object with the suites: -DCH_CPU_RUNTIME -DCH_SUITE_AES_GCM"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

#define INPUT ((size_t)300)
#define KEY ((size_t)100)
#define OUTPUT ((size_t)256)

// Where in output a call that writes two or three secrets writes its second
// and its third.
#define SECOND ((size_t)HKDF_HASH_MAX)
#define THIRD ((size_t)(2 * HKDF_HASH_MAX))

// What every row reads: a message, a key longer than a SHA-256 block, which
// HMAC hashes before it uses it, a pseudorandom key of the longest hash,
// which is RFC 5869's name for the secret HKDF-Expand takes, and a
// transcript hash of that length.
static uint8_t input[INPUT];
static uint8_t key[KEY];
static uint8_t pseudorandom_key[HKDF_HASH_MAX];
static uint8_t transcript_hash[HKDF_HASH_MAX];
// What a row writes, which must be the same bytes on either path.
static uint8_t output[OUTPUT];
// The hash length and the suite the rows that take one run at.
static size_t row_hash_len;
static uint16_t row_suite;

static void fill(uint8_t *p, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(seed + 7 * i);
    }
}

// What a value names, written here apart from the library's predicates so
// that a wrong predicate fails a row.
static int names_sha256(uint32_t cpu) {
    return (cpu & CH_CPU_CONSTANT_TIME_SHA256) != 0;
}

static void reset_calls(void) {
    memset(&sha256_portable_calls, 0, sizeof sha256_portable_calls);
    memset(&sha256_hw_calls, 0, sizeof sha256_hw_calls);
}

static int same_calls(const hash_calls *a, const hash_calls *b) {
    return a->updates == b->updates && a->finals == b->finals &&
           a->whole_messages == b->whole_messages;
}

static int no_calls(const hash_calls *a) {
    static const hash_calls none = {0, 0, 0};
    return same_calls(a, &none);
}

// One call that takes a session's ch_cfg.cpu, and writes what it computed
// into output.
typedef struct {
    const char *name;
    void (*call)(uint32_t cpu);
} row;

// The row under cpu, against the same row under CH_CPU_PROBED alone.
static void check_row(const row *r, uint32_t cpu) {
    uint8_t want[OUTPUT];
    memset(output, 0, sizeof output);
    reset_calls();
    r->call(CH_CPU_PROBED);
    hash_calls counted = sha256_portable_calls;
    int probed_alone_ok = no_calls(&sha256_hw_calls);
    memcpy(want, output, sizeof want);

    memset(output, 0, sizeof output);
    reset_calls();
    r->call(cpu);
    const hash_calls *taken = names_sha256(cpu) ? &sha256_hw_calls : &sha256_portable_calls;
    const hash_calls *left = names_sha256(cpu) ? &sha256_portable_calls : &sha256_hw_calls;
    int paths_ok = same_calls(taken, &counted) && no_calls(left);
    int bytes_ok = memcmp(output, want, sizeof want) == 0;
    CHECK(probed_alone_ok);
    CHECK(paths_ok);
    CHECK(bytes_ok);
    if (!probed_alone_ok || !paths_ok || !bytes_ok) {
        (void)fprintf(stderr,
                      "hash runtime: %s at hash length %zu, suite 0x%04x, under ch_cfg.cpu 0x%x: "
                      "sha256.c took %lu updates, %lu finals and %lu whole messages, and the "
                      "instructions %lu, %lu and %lu; CH_CPU_PROBED alone gave sha256.c %lu, %lu "
                      "and %lu\n",
                      r->name, row_hash_len, (unsigned)row_suite, (unsigned)cpu,
                      sha256_portable_calls.updates, sha256_portable_calls.finals,
                      sha256_portable_calls.whole_messages, sha256_hw_calls.updates,
                      sha256_hw_calls.finals, sha256_hw_calls.whole_messages, counted.updates,
                      counted.finals, counted.whole_messages);
    }
}

// sha256.h's entries.
static void row_sha256_update_final(uint32_t cpu) {
    sha256 s;
    sha256_init(&s);
    sha256_update_cpu(cpu, &s, input, 70);
    sha256_update_cpu(cpu, &s, input + 70, INPUT - 70);
    sha256_final_cpu(cpu, &s, output);
}

static void row_sha256_of(uint32_t cpu) {
    sha256_of_cpu(cpu, input, INPUT, output);
}

// The calls that take no value run sha256.c, whatever a session states.
static void check_plain_names(void) {
    sha256 s;
    reset_calls();
    sha256_init(&s);
    sha256_update(&s, input, INPUT);
    sha256_final(&s, output);
    sha256_of(input, INPUT, output);
    hmac_sha256(key, KEY, input, INPUT, output);
    hkdf_expand_label(SHA256_LEN, pseudorandom_key, "key", NULL, 0, output, 32);
    ks_verify_data(SHA256_LEN, pseudorandom_key, transcript_hash, output);
    CHECK(no_calls(&sha256_hw_calls));
    CHECK(!no_calls(&sha256_portable_calls));
}

// hkdf.h's entries. hmac_sha256_cpu runs SHA-256 at every hash length.
static void row_hmac_sha256(uint32_t cpu) {
    hmac_sha256_cpu(cpu, key, KEY, input, INPUT, output);
}

static void row_hmac(uint32_t cpu) {
    hmac_cpu(cpu, row_hash_len, key, KEY, input, INPUT, output);
}

static void row_hkdf_extract(uint32_t cpu) {
    hkdf_extract_cpu(cpu, row_hash_len, key, KEY, input, INPUT, output);
}

static void row_hkdf_expand(uint32_t cpu) {
    hkdf_expand_cpu(cpu, row_hash_len, pseudorandom_key, input, 20, output, 3 * row_hash_len + 5);
}

static void row_hkdf_expand_label(uint32_t cpu) {
    hkdf_expand_label_cpu(cpu, row_hash_len, pseudorandom_key, "c hs traffic", transcript_hash,
                          row_hash_len, output, row_hash_len);
}

// keysched.h's entries.
static void row_ks_early(uint32_t cpu) {
    ks_early_cpu(cpu, row_hash_len, key, KEY, 1, output, output + SECOND);
}

static void row_ks_verify_data(uint32_t cpu) {
    ks_verify_data_cpu(cpu, row_hash_len, pseudorandom_key, transcript_hash, output);
}

static void row_ks_handshake(uint32_t cpu) {
    ks_handshake_cpu(cpu, row_hash_len, pseudorandom_key, key, 32, transcript_hash, output,
                     output + SECOND, output + THIRD);
}

static void row_ks_master(uint32_t cpu) {
    ks_master_cpu(cpu, row_hash_len, pseudorandom_key, transcript_hash, output, output + SECOND,
                  output + THIRD);
}

static void row_ks_res_master(uint32_t cpu) {
    ks_res_master_cpu(cpu, row_hash_len, pseudorandom_key, transcript_hash, output);
}

static void row_ks_res_psk(uint32_t cpu) {
    ks_res_psk_cpu(cpu, row_hash_len, pseudorandom_key, key, 8, output);
}

#ifdef CH_EXPORTER
static void row_ks_exp_master(uint32_t cpu) {
    ks_exp_master_cpu(cpu, row_hash_len, pseudorandom_key, transcript_hash, output);
}

static void row_ks_exporter(uint32_t cpu) {
    ks_exporter_cpu(cpu, row_hash_len, pseudorandom_key, "EXPORTER-test", input, INPUT, output, 80);
}
#endif

// transcript.h's entries. A build with SHA-384 hashes the transcript with
// both hashes, so the update runs SHA-256 at either hash length, and the
// digest runs the one hash_len names.
static void row_transcript(uint32_t cpu) {
    ch_transcript t;
    transcript_init(&t);
    transcript_update_cpu(cpu, &t, input, 100);
    transcript_hash_after_cpu(cpu, &t, row_hash_len, input + 100, 50, output);
}

// A record direction, which reads its own cpu: keyed under row_suite, then
// rekeyed as KeyUpdate rekeys it.
static void row_record_direction(uint32_t cpu) {
    uint8_t traffic_secret[HKDF_HASH_MAX];
    memcpy(traffic_secret, pseudorandom_key, sizeof traffic_secret);
    rec_dir d;
    memset(&d, 0, sizeof d);
    d.cpu = cpu;
    rec_dir_init_suite(&d, traffic_secret, row_suite);
    memcpy(output, d.key, sizeof d.key);
    memcpy(output + sizeof d.key, d.iv, sizeof d.iv);
    rec_dir_update(traffic_secret, &d);
    memcpy(output + 64, d.key, sizeof d.key);
    memcpy(output + 64 + sizeof d.key, d.iv, sizeof d.iv);
    memcpy(output + 128, traffic_secret, sizeof traffic_secret);
    CHECK(d.cpu == cpu);
}

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
// One level's packet protection keys and header protection key under
// row_suite, and the key update.
static void row_quic_keys(uint32_t cpu) {
    uint8_t traffic_secret[HKDF_HASH_MAX];
    memcpy(traffic_secret, pseudorandom_key, sizeof traffic_secret);
    quic_keys k;
    quic_hp_key h;
    memset(&k, 0, sizeof k);
    memset(&h, 0, sizeof h);
    quic_keys_init_suite(cpu, &k, CH_QUIC_VERSION_1, traffic_secret, row_suite);
    quic_hp_key_init_suite(cpu, &h, CH_QUIC_VERSION_1, traffic_secret, row_suite);
    memcpy(output, k.key, sizeof k.key);
    memcpy(output + sizeof k.key, k.iv, sizeof k.iv);
    memcpy(output + 64, h.key, sizeof h.key);
    quic_keys_update(cpu, traffic_secret, &k, CH_QUIC_VERSION_1);
    memcpy(output + 128, k.key, sizeof k.key);
    memcpy(output + 128 + sizeof k.key, k.iv, sizeof k.iv);
    memcpy(output + 192, traffic_secret, sizeof traffic_secret);
}

// One Initial packet a client seals, whose keys RFC 9001 §5.2 derives with
// HKDF over SHA-256 whatever suite the session runs. The seal then runs
// AES-128-GCM: on the AES instructions under the value's AES bit, and on
// the 256-bit kernels under its VAES bit as well. A CPU without those
// faults on them, so the row clears the three bits that pick an AES or
// ChaCha20 path, and the packet is sealed on the table and the portable
// multiply, which every CPU runs. The value keeps every bit a hash call
// reads.
static void row_quic_initial(uint32_t cpu) {
    static const uint8_t dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    static const uint8_t hdr[20] = {0xc1, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0,
                                    0x3e, 0x51, 0x57, 0x08, 0x00, 0x00, 0x40, 0x42, 0x00, 0x07};
    uint32_t no_cipher_bits =
        cpu & ~(uint32_t)(CH_CPU_CONSTANT_TIME_AES | CH_CPU_AVX2 | CH_CPU_VAES);
    size_t pkt_len = 0;
    CHECK(quic_initial_seal(no_cipher_bits, CH_QUIC_ENDPOINT_CLIENT, CH_QUIC_VERSION_1, dcid,
                            sizeof dcid, 7, 2, hdr, sizeof hdr, input, 48, output, sizeof output,
                            &pkt_len) == CH_OK);
}
#endif

// The rows that take no hash length and no suite.
static const row fixed_rows[] = {
    {"sha256_update_cpu and sha256_final_cpu", row_sha256_update_final},
    {"sha256_of_cpu",                          row_sha256_of          },
    {"hmac_sha256_cpu",                        row_hmac_sha256        },
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    {"quic_initial_seal",                      row_quic_initial       },
#endif
};

// The rows that run the hash row_hash_len names.
static const row hash_rows[] = {
    {"hmac_cpu",              row_hmac             },
    {"hkdf_extract_cpu",      row_hkdf_extract     },
    {"hkdf_expand_cpu",       row_hkdf_expand      },
    {"hkdf_expand_label_cpu", row_hkdf_expand_label},
    {"ks_early_cpu",          row_ks_early         },
    {"ks_verify_data_cpu",    row_ks_verify_data   },
    {"ks_handshake_cpu",      row_ks_handshake     },
    {"ks_master_cpu",         row_ks_master        },
    {"ks_res_master_cpu",     row_ks_res_master    },
    {"ks_res_psk_cpu",        row_ks_res_psk       },
#ifdef CH_EXPORTER
    {"ks_exp_master_cpu",     row_ks_exp_master    },
    {"ks_exporter_cpu",       row_ks_exporter      },
#endif
    {"the transcript",        row_transcript       },
};

// The rows that run under the suite row_suite names.
static const row suite_rows[] = {
    {"a record direction",  row_record_direction},
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    {"a QUIC level's keys", row_quic_keys       },
#endif
};

#define COUNT(a) (sizeof(a) / sizeof(a)[0])

static void check_value(uint32_t cpu) {
    static const size_t hash_lens[] = {SHA256_LEN, SHA384_LEN};
    static const uint16_t suites[] = {SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_128_GCM_SHA256,
                                      SUITE_AES_256_GCM_SHA384};
    row_hash_len = 0;
    row_suite = 0;
    for (size_t i = 0; i < COUNT(fixed_rows); i++) {
        check_row(&fixed_rows[i], cpu);
    }
    for (size_t h = 0; h < COUNT(hash_lens); h++) {
        row_hash_len = hash_lens[h];
        for (size_t i = 0; i < COUNT(hash_rows); i++) {
            check_row(&hash_rows[i], cpu);
        }
    }
    row_hash_len = 0;
    for (size_t s = 0; s < COUNT(suites); s++) {
        row_suite = suites[s];
        for (size_t i = 0; i < COUNT(suite_rows); i++) {
            check_row(&suite_rows[i], cpu);
        }
    }
}

int main(void) {
    fill(input, sizeof input, 0x99);
    fill(key, sizeof key, 0x11);
    fill(pseudorandom_key, sizeof pseudorandom_key, 0x44);
    fill(transcript_hash, sizeof transcript_hash, 0x55);
    check_plain_names();
    // The seven bits beside CH_CPU_PROBED are 0x02 to 0x80, so the 128
    // values are the probe's bit and each of 0 to 127 shifted up one.
    for (uint32_t bits = 0; bits < 128 && failures == 0; bits++) {
        check_value(CH_CPU_PROBED | (bits << 1));
    }
    check_value(0);
    if (failures == 0) {
        (void)printf("hash runtime: under each of 129 ch_cfg.cpu values, every SHA-256 call of "
                     "every row ran on the instructions where CH_CPU_CONSTANT_TIME_SHA256 was "
                     "set, and on sha256.c anywhere else\n");
    }
    return failures != 0;
}
