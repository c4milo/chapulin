// The rows bench/record.c times: the one state every row runs on, the call
// that sets it up for one AEAD and one record size, and each AEAD's rows
// and the sums the bench checks them against. bench/record_rows.c defines
// them. None of this is library code.
#ifndef CH_BENCH_RECORD_ROWS_H
#define CH_BENCH_RECORD_ROWS_H

#include <stddef.h>
#include <stdint.h>

#include "aes_traffic_key.h"
#include "poly1305.h"
#include "record.h"

// The record sizes, as the plaintext bytes ch_write hands rec_seal: 1 KiB,
// 16 KiB, the most RFC 9846 §5.1 lets a record carry, and 64 KiB, which no
// record carries and only the AEAD rows run at, to show whether the cost
// per byte moves past a record's size.
#define BENCH_SIZE_COUNT 3
#define BENCH_MAX_PLAINTEXT 65536
extern const size_t bench_record_sizes[BENCH_SIZE_COUNT];

// The largest record: the header, the plaintext and its content type byte,
// and the tag.
#define BENCH_RECORD_CAP (REC_HDR + BENCH_MAX_PLAINTEXT + 1 + AEAD_TAG)

typedef enum {
    BENCH_AES_128_GCM,
    BENCH_AES_256_GCM,
    BENCH_CHACHA20_POLY1305,
} bench_aead;

// Everything a row reads and writes, in one object the rows access through
// a pointer, set up by bench_prepare before each pass over a record size.
typedef struct {
    bench_aead aead;
    size_t plaintext_len; // the record's plaintext bytes
    size_t len;           // plaintext_len + 1: the TLSInnerPlaintext the AEAD seals
    size_t record_len;    // REC_HDR + len + AEAD_TAG
    size_t whole_blocks;  // the whole blocks of len bytes, which counter_mode runs eight a pass
    rec_dir wr;           // the direction rec_seal seals under
    rec_dir rd;           // the direction rec_open opens under, keyed as wr
    aes_traffic_key key;  // wr's AES key, expanded once for the AEAD rows
    aes_traffic_key scratch;
    uint8_t nonce[AEAD_NONCE]; // wr's nonce at sequence number 0
    uint8_t subkey[AES_BLOCK]; // GHASH's hash subkey under key
    uint8_t acc[AES_BLOCK];
    uint8_t counter[AES_BLOCK];
    uint8_t keystream[16 * CHACHA20_BLOCK]; // one pass of the widest ChaCha20 path
    uint8_t tag[AEAD_TAG];
    uint8_t poly_key[POLY1305_KEY];
    poly1305 poly;
    uint8_t app[BENCH_MAX_PLAINTEXT]; // the caller's plaintext
    // The record buffer every row seals and opens in. It starts on a
    // 64-byte boundary, so the ciphertext starts REC_HDR bytes past one.
    _Alignas(64) uint8_t rec[BENCH_RECORD_CAP];
    uint8_t sealed[BENCH_RECORD_CAP];   // the record at sequence number 0
    uint8_t stub_rec[BENCH_RECORD_CAP]; // the same, for the open with no AEAD
} bench_state;

// Keys b for aead, fills the plaintext, and seals the record every open
// reads. Nothing it does is timed.
void bench_prepare(bench_state *b, bench_aead aead, size_t plaintext_len);

// Sets both sequence numbers back to 0 before a batch, so no seal in a
// batch takes a sequence number at the AES-GCM record limit, which rec_seal
// refuses.
void bench_reset_batch(bench_state *b);

// Which record sizes a row runs at, one bit per entry of
// bench_record_sizes: the two a TLS record can carry, or all three.
// BENCH_SIZES_FIXED marks a row whose cost does not depend on the size,
// run once per AEAD.
#define BENCH_SIZES_RECORD 0x3u
#define BENCH_SIZES_ALL 0x7u
#define BENCH_SIZES_FIXED 0x8u

// One timed row: run is one operation. A row that refills the record
// before each operation has the refill row's figure from the same run
// taken off its own.
typedef struct {
    const char *stage;
    unsigned sizes;
    void (*run)(bench_state *b);
    int refills;
} bench_row;

// A row computed from two timed rows, at the sizes the first runs at: the
// figure of from less the figure of minus, in the same run.
typedef struct {
    const char *stage;
    const char *from;
    const char *minus;
} bench_difference;

// A sum the bench checks: the row named whole against the sum of the rows
// in parts, which ends at the first NULL.
#define BENCH_CHECK_PARTS 4
typedef struct {
    const char *whole;
    const char *parts[BENCH_CHECK_PARTS];
} bench_check;

typedef struct {
    const char *name;
    bench_aead aead;
    const bench_row *rows;
    size_t row_count;
    const bench_difference *differences;
    size_t difference_count;
    const bench_check *checks;
    size_t check_count;
} bench_group;

#define BENCH_GROUP_COUNT 3
extern const bench_group bench_groups[BENCH_GROUP_COUNT];

// The byte every operation adds into a volatile, so no call is dropped.
extern volatile uint8_t bench_sink;

#endif
