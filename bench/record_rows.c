// The rows bench/record.c times, for bench/record.c only. record_rows.h
// states the types; this file sets up the state and defines one function
// per row. Every function makes the call the record layer makes, on the
// buffer shape it makes it on: rec_seal copies the caller's plaintext into
// the record and seals it in place, and rec_open opens it in place, with
// the plaintext REC_HDR bytes before the ciphertext (record.h). The rows
// named in_place run the first shape and the rows named shifted the
// second, because a compiler may emit a different loop when the input and
// the output overlap.
#include "record_rows.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ct.h"
#include "gcm.h"
#include "ghash_hw.h"
#include "record_stages.h"
#include "suite.h"

#if !defined(CH_SUITE_AES_GCM) || !defined(CH_AES_HW)
#error                                                                                             \
    "bench/record.c times the AES-GCM suites on the AES instructions: build it as bench/record.sh does"
#endif

const size_t bench_record_sizes[BENCH_SIZE_COUNT] = {1024, 16384, BENCH_MAX_PLAINTEXT};

volatile uint8_t bench_sink;

static void consume(uint8_t byte) {
    bench_sink = (uint8_t)(bench_sink + byte);
}

static void fail(const char *what) {
    (void)fprintf(stderr, "bench/record: %s\n", what);
    exit(1);
}

// xorshift64 from a fixed seed, so every invocation draws the same bytes.
static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

static void fill_random(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        p[i] = (uint8_t)rng_state;
    }
}

static uint16_t suite_of(bench_aead aead) {
    if (aead == BENCH_AES_128_GCM) {
        return SUITE_AES_128_GCM_SHA256;
    }
    return aead == BENCH_AES_256_GCM ? SUITE_AES_256_GCM_SHA384 : SUITE_CHACHA20_POLY1305_SHA256;
}

// Seals the record at sequence number 0 into b->sealed. rec_seal writes it
// where a record can carry the plaintext; past 16 KiB, where rec_seal
// refuses, the AEAD seals the same layout directly, for the AEAD rows alone.
static void seal_record(bench_state *b) {
    rec_dir d = b->wr;
    size_t out_len = 0;
    if (b->plaintext_len <= 0x4000) {
        if (rec_seal(&d, REC_APPDATA, b->app, b->plaintext_len, b->sealed, sizeof b->sealed,
                     &out_len) != 0 ||
            out_len != b->record_len) {
            fail("rec_seal refused the record every open reads");
        }
        return;
    }
    const uint8_t header[REC_HDR] = {REC_APPDATA, 0x03, 0x03, 0, 0};
    uint8_t *body = b->sealed + REC_HDR;
    memcpy(b->sealed, header, REC_HDR);
    memcpy(body, b->app, b->plaintext_len);
    body[b->plaintext_len] = REC_APPDATA;
    if (b->aead == BENCH_CHACHA20_POLY1305) {
        aead_seal(b->wr.key, b->nonce, b->sealed, REC_HDR, body, b->len, body, body + b->len);
    } else {
        gcm_traffic_seal(&b->key, b->nonce, b->sealed, REC_HDR, body, b->len, body, body + b->len);
    }
}

void bench_prepare(bench_state *b, bench_aead aead, size_t plaintext_len) {
    uint16_t suite = suite_of(aead);
    uint8_t secret[SHA384_LEN];
    fill_random(secret, sizeof secret);
    b->aead = aead;
    b->plaintext_len = plaintext_len;
    b->len = plaintext_len + 1;
    b->record_len = REC_HDR + b->len + AEAD_TAG;
    b->aes_blocks = (b->len + AES_BLOCK - 1) / AES_BLOCK;
    rec_dir_init_suite(&b->wr, secret, suite);
    b->rd = b->wr;
    memcpy(b->nonce, b->wr.iv, AEAD_NONCE); // the IV is the nonce at sequence number 0
    fill_random(b->app, plaintext_len);
    fill_random(b->counter, sizeof b->counter);
    fill_random(b->poly_key, sizeof b->poly_key);
    if (aead != BENCH_CHACHA20_POLY1305) {
        static const uint8_t zero[AES_BLOCK] = {0};
        aes_traffic_key_init(&b->key, b->wr.key, suite_key_len(suite));
        aes_encrypt_schedule(&b->key.key, zero, b->subkey);
    }
    seal_record(b);
    memcpy(b->stub_rec, b->sealed, b->record_len);
}

void bench_reset_batch(bench_state *b) {
    b->wr.seq = 0;
    b->rd.seq = 0;
}

// What ch_read's socket read does before each record: the sealed record
// is written into the buffer rec_open opens in place. Each open row runs it first
// and subtracts this row's figure.
static void refill(bench_state *b) {
    memcpy(b->rec, b->sealed, b->record_len);
    b->rd.seq = 0;
}

static void run_refill(bench_state *b) {
    refill(b);
    consume(b->rec[b->record_len - 1]);
}

static void run_rec_seal(bench_state *b) {
    size_t out_len = 0;
    if (rec_seal(&b->wr, REC_APPDATA, b->app, b->plaintext_len, b->rec, sizeof b->rec, &out_len) !=
        0) {
        fail("rec_seal refused a record");
    }
    consume(b->rec[out_len - 1]);
}

static void run_rec_open(bench_state *b) {
    refill(b);
    size_t pt_len = 0;
    uint8_t type = 0;
    if (rec_open(&b->rd, b->rec, b->record_len, b->rec, sizeof b->rec, &pt_len, &type) != 0) {
        fail("rec_open rejected its own record");
    }
    consume(type);
}

static void run_rec_seal_without_aead(bench_state *b) {
    size_t out_len = 0;
    if (bench_rec_seal_without_aead(&b->wr, REC_APPDATA, b->app, b->plaintext_len, b->rec,
                                    sizeof b->rec, &out_len) != 0) {
        fail("the record layer without its AEAD refused a record");
    }
    consume(b->rec[out_len - 1]);
}

// The stubbed open writes nothing, so stub_rec keeps its bytes and needs
// no refill.
static void run_rec_open_without_aead(bench_state *b) {
    size_t pt_len = 0;
    uint8_t type = 0;
    if (bench_rec_open_without_aead(&b->rd, b->stub_rec, b->record_len, b->stub_rec,
                                    sizeof b->stub_rec, &pt_len, &type) != 0) {
        fail("the record layer without its AEAD rejected a record");
    }
    consume(type);
}

static void run_key_expansion(bench_state *b) {
    aes_traffic_key_init(&b->scratch, b->wr.key, suite_key_len(suite_of(b->aead)));
    consume(b->scratch.key.round_keys[0]);
}

static void run_key_wipe(bench_state *b) {
    ct_wipe(&b->scratch, sizeof b->scratch);
    consume(b->scratch.key.round_keys[0]);
}

static void run_gcm_seal(bench_state *b) {
    uint8_t *body = b->rec + REC_HDR;
    gcm_traffic_seal(&b->key, b->nonce, b->rec, REC_HDR, body, b->len, body, body + b->len);
    consume(body[b->len]);
}

static void run_gcm_open(bench_state *b) {
    refill(b);
    uint8_t *body = b->rec + REC_HDR;
    if (!gcm_traffic_open(&b->key, b->nonce, b->rec, REC_HDR, body, b->len, body + b->len,
                          b->rec)) {
        fail("gcm_traffic_open rejected its own record");
    }
    consume(b->rec[0]);
}

static void run_counter_mode_in_place(bench_state *b) {
    uint8_t *body = b->rec + REC_HDR;
    bench_gcm_counter_mode(&b->key, b->nonce, body, b->len, body);
    consume(body[b->len - 1]);
}

static void run_counter_mode_shifted(bench_state *b) {
    bench_gcm_counter_mode(&b->key, b->nonce, b->rec + REC_HDR, b->len, b->rec);
    consume(b->rec[b->len - 1]);
}

// The forward cipher alone, once per block counter_mode runs, on one
// counter block: the timing reads no value of it.
static void run_aes_blocks(bench_state *b) {
    for (size_t i = 0; i < b->aes_blocks; i++) {
        aes_encrypt_schedule(&b->key.key, b->counter, b->keystream);
    }
    consume(b->keystream[0]);
}

static void run_counter_mode_without_aes_in_place(bench_state *b) {
    uint8_t *body = b->rec + REC_HDR;
    bench_gcm_counter_mode_without_aes(&b->key, b->nonce, body, b->len, body);
    consume(body[b->len - 1]);
}

static void run_counter_mode_without_aes_shifted(bench_state *b) {
    bench_gcm_counter_mode_without_aes(&b->key, b->nonce, b->rec + REC_HDR, b->len, b->rec);
    consume(b->rec[b->len - 1]);
}

// The 16-byte wipe aes_hw.c's cipher runs after each block, alone, as often
// as counter_mode runs the cipher. aes_blocks includes it.
static void run_block_wipes(bench_state *b) {
    for (size_t i = 0; i < b->aes_blocks; i++) {
        ct_wipe(b->keystream, AES_BLOCK);
    }
    consume(b->keystream[0]);
}

// The stub's own calls, which the two rows above make once per block.
static void run_stub_cipher_calls(bench_state *b) {
    for (size_t i = 0; i < b->aes_blocks; i++) {
        bench_stub_encrypt_schedule(&b->key.key, b->counter, b->keystream);
    }
    consume(b->keystream[0]);
}

static void run_compute_tag(bench_state *b) {
    bench_gcm_compute_tag(&b->key, b->nonce, b->rec, REC_HDR, b->rec + REC_HDR, b->len, b->tag);
    consume(b->tag[0]);
}

static void run_ghash_data(bench_state *b) {
    gcm_hash_data_hw(b->acc, b->subkey, b->rec + REC_HDR, b->len);
    consume(b->acc[0]);
}

static void run_compute_tag_fixed(bench_state *b) {
    bench_gcm_compute_tag(&b->key, b->nonce, b->rec, REC_HDR, b->rec + REC_HDR, 0, b->tag);
    consume(b->tag[0]);
}

static void run_chacha_seal(bench_state *b) {
    uint8_t *body = b->rec + REC_HDR;
    aead_seal(b->wr.key, b->nonce, b->rec, REC_HDR, body, b->len, body, body + b->len);
    consume(body[b->len]);
}

static void run_chacha_open(bench_state *b) {
    refill(b);
    uint8_t *body = b->rec + REC_HDR;
    if (!aead_open(b->wr.key, b->nonce, b->rec, REC_HDR, body, b->len, body + b->len, b->rec)) {
        fail("aead_open rejected its own record");
    }
    consume(b->rec[0]);
}

// aead_seal's cipher half: counter 1 is the first data block, RFC 8439
// §2.8.
static void run_chacha20_xor_in_place(bench_state *b) {
    uint8_t *body = b->rec + REC_HDR;
    chacha20_xor(b->wr.key, b->nonce, 1, body, body, b->len);
    consume(body[b->len - 1]);
}

static void run_chacha20_xor_shifted(bench_state *b) {
    chacha20_xor(b->wr.key, b->nonce, 1, b->rec + REC_HDR, b->rec, b->len);
    consume(b->rec[b->len - 1]);
}

// The keystream alone: chacha20.c's block function, or under CHACHA=vector
// chacha20_vector.c's four blocks at a time, as chacha20_xor calls it.
static void run_chacha20_blocks(bench_state *b) {
#ifdef CH_CHACHA_VECTOR
    bench_chacha20_vector_blocks(b->wr.key, b->nonce, 1, b->len, b->keystream);
#else
    bench_chacha20_blocks(b->wr.key, b->nonce, 1, b->len, b->keystream);
#endif
    consume(b->keystream[0]);
}

static void run_mac(bench_state *b) {
    bench_aead_mac(b->wr.key, b->nonce, b->rec, REC_HDR, b->rec + REC_HDR, b->len, b->tag);
    consume(b->tag[0]);
}

// Poly1305 over the ciphertext alone, from a fresh state, as mac runs it.
static void run_poly1305_data(bench_state *b) {
    poly1305_init(&b->poly, b->poly_key);
    poly1305_update(&b->poly, b->rec + REC_HDR, b->len);
    consume((uint8_t)b->poly.h[0]);
}

static void run_mac_fixed(bench_state *b) {
    bench_aead_mac(b->wr.key, b->nonce, b->rec, REC_HDR, b->rec + REC_HDR, 0, b->tag);
    consume(b->tag[0]);
}

// Short names for the size sets, so each row fits one line.
#define RECORD BENCH_SIZES_RECORD
#define ALL BENCH_SIZES_ALL
#define FIXED BENCH_SIZES_FIXED

// The AES-GCM rows, for both key sizes, in the order a run times them.
static const bench_row AES_ROWS[] = {
    {"rec_seal",                          RECORD, run_rec_seal,                          0},
    {"refill",                            ALL,    run_refill,                            0},
    {"rec_open",                          RECORD, run_rec_open,                          1},
    {"rec_seal_without_aead",             RECORD, run_rec_seal_without_aead,             0},
    {"rec_open_without_aead",             RECORD, run_rec_open_without_aead,             0},
    {"key_expansion",                     FIXED,  run_key_expansion,                     0},
    {"key_wipe",                          FIXED,  run_key_wipe,                          0},
    {"aead_seal",                         ALL,    run_gcm_seal,                          0},
    {"aead_open",                         ALL,    run_gcm_open,                          1},
    {"counter_mode_in_place",             ALL,    run_counter_mode_in_place,             0},
    {"counter_mode_shifted",              ALL,    run_counter_mode_shifted,              0},
    {"aes_blocks",                        ALL,    run_aes_blocks,                        0},
    {"block_wipes",                       ALL,    run_block_wipes,                       0},
    {"counter_mode_without_aes_in_place", ALL,    run_counter_mode_without_aes_in_place, 0},
    {"counter_mode_without_aes_shifted",  ALL,    run_counter_mode_without_aes_shifted,  0},
    {"stub_cipher_calls",                 ALL,    run_stub_cipher_calls,                 0},
    {"compute_tag",                       ALL,    run_compute_tag,                       0},
    {"ghash_data",                        ALL,    run_ghash_data,                        0},
    {"compute_tag_fixed",                 FIXED,  run_compute_tag_fixed,                 0},
};

// counter_mode less its cipher, less the stub's own calls: the counter
// increments and the keystream exclusive-or, in each shape.
static const bench_difference AES_DIFFERENCES[] = {
    {"xor_and_increments_in_place", "counter_mode_without_aes_in_place", "stub_cipher_calls"},
    {"xor_and_increments_shifted",  "counter_mode_without_aes_shifted",  "stub_cipher_calls"},
};

// Each whole against its parts. The seal's four stages are the AES
// rounds, the exclusive-or with the counter increments, GHASH over the
// ciphertext and the tag's fixed work; the open runs the same four with
// the exclusive-or in its own shape.
static const bench_check AES_CHECKS[] = {
    {"aead_seal",             {"aes_blocks", "xor_and_increments_in_place", "ghash_data", "compute_tag_fixed"}},
    {"aead_open",             {"aes_blocks", "xor_and_increments_shifted", "ghash_data", "compute_tag_fixed"} },
    {"counter_mode_in_place", {"aes_blocks", "xor_and_increments_in_place", NULL}                             },
    {"counter_mode_shifted",  {"aes_blocks", "xor_and_increments_shifted", NULL}                              },
    {"compute_tag",           {"ghash_data", "compute_tag_fixed", NULL}                                       },
    {"rec_seal",              {"rec_seal_without_aead", "aead_seal", NULL}                                    },
    {"rec_open",              {"rec_open_without_aead", "aead_open", NULL}                                    },
};

// The ChaCha20-Poly1305 rows.
static const bench_row CHACHA_ROWS[] = {
    {"rec_seal",              RECORD, run_rec_seal,              0},
    {"refill",                ALL,    run_refill,                0},
    {"rec_open",              RECORD, run_rec_open,              1},
    {"rec_seal_without_aead", RECORD, run_rec_seal_without_aead, 0},
    {"rec_open_without_aead", RECORD, run_rec_open_without_aead, 0},
    {"aead_seal",             ALL,    run_chacha_seal,           0},
    {"aead_open",             ALL,    run_chacha_open,           1},
    {"chacha20_xor_in_place", ALL,    run_chacha20_xor_in_place, 0},
    {"chacha20_xor_shifted",  ALL,    run_chacha20_xor_shifted,  0},
    {"chacha20_blocks",       ALL,    run_chacha20_blocks,       0},
    {"mac",                   ALL,    run_mac,                   0},
    {"poly1305_data",         ALL,    run_poly1305_data,         0},
    {"mac_fixed",             FIXED,  run_mac_fixed,             0},
};

// chacha20.c's block is static and its exclusive-or sits in chacha20_xor's
// loop after each call to it, so no stub can take the block's place. The
// exclusive-or, its loads and stores and the loop are chacha20_xor less
// the block function, both timed.
static const bench_difference CHACHA_DIFFERENCES[] = {
    {"xor_rest_in_place", "chacha20_xor_in_place", "chacha20_blocks"},
    {"xor_rest_shifted",  "chacha20_xor_shifted",  "chacha20_blocks"},
};

static const bench_check CHACHA_CHECKS[] = {
    {"aead_seal", {"chacha20_xor_in_place", "poly1305_data", "mac_fixed", NULL}},
    {"aead_open", {"chacha20_xor_shifted", "poly1305_data", "mac_fixed", NULL} },
    {"mac",       {"poly1305_data", "mac_fixed", NULL}                         },
    {"rec_seal",  {"rec_seal_without_aead", "aead_seal", NULL}                 },
    {"rec_open",  {"rec_open_without_aead", "aead_open", NULL}                 },
};

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

// One group: its name, its AEAD and its three tables with their lengths.
#define GROUP(name, aead, rows, differences, checks)                                               \
    {name, aead, rows, COUNT(rows), differences, COUNT(differences), checks, COUNT(checks)}

const bench_group bench_groups[BENCH_GROUP_COUNT] = {
    GROUP("aes128gcm", BENCH_AES_128_GCM, AES_ROWS, AES_DIFFERENCES, AES_CHECKS),
    GROUP("aes256gcm", BENCH_AES_256_GCM, AES_ROWS, AES_DIFFERENCES, AES_CHECKS),
    GROUP("chacha20poly1305", BENCH_CHACHA20_POLY1305, CHACHA_ROWS, CHACHA_DIFFERENCES,
          CHACHA_CHECKS),
};
