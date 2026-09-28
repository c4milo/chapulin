// ch_writable_len differential section: tls_write.c's ch_writable_len
// against spec/lean/Spec/TlsWrite.lean's writableLen. Lean proves that
// every sum and product in that model is below 2^w for a cap below 2^w, at
// every width w of 15 bits or more, and these rows compare the model with
// the C, so that the proof is about the code that ships.
//
// Each row sets one ch_tls's peer_limit, and in a -DCH_SUITE_AES_GCM build
// its write key's suite and sequence number, which is all ch_writable_len
// reads (tls.h). It sends the spec the limit and the room those fields
// give:
//
//   - the limit is peer_limit, or CH_TX_PT for a peer_limit above it
//     (record_plaintext_max);
//   - the room is SIZE_MAX for a ChaCha20-Poly1305 key, and for a build
//     without -DCH_SUITE_AES_GCM, which has no room
//     (Spec.TlsWrite.writableLen_of_cap_le_room). Under AES-GCM a row
//     picks the room and sets the sequence number to
//     REC_AES_GCM_RECORDS_MAX - 1 less the room, or to that number and past
//     it for a room of 0 (records_before_key_update).
//
// The limits are 0, 1, 63, a limit between, CH_TX_PT and the limits beside
// it, and DIFF_WRITABLE_RANDOM_LIMITS drawn at random. Each is compared at
// the caps where the first three records end and where a last record
// carries its first byte, the same caps below SIZE_MAX and after the last
// whole record SIZE_MAX holds, and DIFF_WRITABLE_RANDOM_CAPS drawn at
// random. Under AES-GCM the rooms are 0, 1, 2, 2^24 - 2, 2^24 - 1 and
// DIFF_WRITABLE_RANDOM_ROOMS drawn at random, each compared at the caps
// where the records pass the room, where the KeyUpdate record after them
// ends, and where the records after it pass REC_AES_GCM_RECORDS_MAX - 1.
//
// bin/diff runs at the default CH_TX_PT of 512. The Makefile's diff-webpki
// builds bin/diff_webpki_aes at CH_TX_PT=16384 under -DCH_SUITE_AES_GCM, so
// there the limits run up to 2^14 and fill_across_key_update runs.
//
// Included by test/diff_test.c after diff_driver.h (single translation
// unit). spec/lean/Main.lean serves the op:
//   writable_len <cap> <limit> <room>
// with every number in decimal, and answers in decimal.
#ifndef CH_DIFF_WRITABLE_LEN_H
#define CH_DIFF_WRITABLE_LEN_H

#include "record.h"
#include "suite.h"
#include "tls.h"

// Limits drawn at random from 1 to CH_TX_PT, rooms drawn at random below
// REC_AES_GCM_RECORDS_MAX, and caps drawn at random for each limit and room.
#define DIFF_WRITABLE_RANDOM_LIMITS 8
#define DIFF_WRITABLE_RANDOM_ROOMS 4
#define DIFF_WRITABLE_RANDOM_CAPS 16

static long diff_writable_rows;
static long diff_writable_aes_rows;
static long diff_writable_key_update_rows;

// The session every row asks about.
static ch_tls diff_writable_session;

// Compares ch_writable_len's answer for cap with the spec's, at the limit
// and room the session's fields give. Returns the answer.
static size_t diff_writable_row(size_t cap, size_t limit, size_t room) {
    size_t answer = ch_writable_len(&diff_writable_session, cap);
    char cmd[96];
    (void)snprintf(cmd, sizeof cmd, "writable_len %zu %zu %zu", cap, limit, room);
    char want[32];
    (void)snprintf(want, sizeof want, "%zu", answer);
    diff_writable_rows++;
    expect(cmd, want);
    return answer;
}

// A cap cut to a random number of its low bits, so every magnitude up to
// SIZE_MAX comes up.
static size_t diff_writable_random_cap(void) {
    return (size_t)(rng_next() >> rng_below(64));
}

// The caps one limit is compared at, where a record is limit +
// REC_OVERHEAD bytes: after 0 to 3 whole records, SIZE_MAX, and the last
// whole record SIZE_MAX holds, each plus 0, 1, REC_OVERHEAD - 1,
// REC_OVERHEAD, REC_OVERHEAD + 1 and a record less one byte (from SIZE_MAX,
// minus those); and DIFF_WRITABLE_RANDOM_CAPS drawn at random.
static void diff_writable_caps(size_t limit, size_t room) {
    size_t record = limit + REC_OVERHEAD;
    const size_t offsets[] = {0, 1, REC_OVERHEAD - 1, REC_OVERHEAD, REC_OVERHEAD + 1, record - 1};
    size_t last_whole = SIZE_MAX / record * record;
    for (size_t i = 0; i < sizeof offsets / sizeof offsets[0]; i++) {
        for (size_t whole = 0; whole <= 3; whole++) {
            (void)diff_writable_row(whole * record + offsets[i], limit, room);
        }
        (void)diff_writable_row(SIZE_MAX - offsets[i], limit, room);
        if (offsets[i] <= SIZE_MAX - last_whole) {
            (void)diff_writable_row(last_whole + offsets[i], limit, room);
        }
    }
    for (int i = 0; i < DIFF_WRITABLE_RANDOM_CAPS; i++) {
        (void)diff_writable_row(diff_writable_random_cap(), limit, room);
    }
}

// Sets peer_limit and compares its caps, at the limit record_plaintext_max
// answers for it.
static void diff_writable_peer_limit(uint16_t peer_limit, size_t room) {
    diff_writable_session.peer_limit = peer_limit;
    diff_writable_caps(peer_limit < CH_TX_PT ? peer_limit : CH_TX_PT, room);
}

// The limits at a room of SIZE_MAX: 0, which no connected session holds;
// 1; 63, what RFC 8449's least record_size_limit leaves; 200; CH_TX_PT and
// one below it; one above it and UINT16_MAX, which leave CH_TX_PT; and
// DIFF_WRITABLE_RANDOM_LIMITS drawn from 1 to CH_TX_PT.
static void diff_writable_limits(void) {
    const uint16_t peer_limits[] = {
        0, 1, 63, 200, CH_TX_PT - 1, CH_TX_PT, CH_TX_PT + 1, UINT16_MAX,
    };
    for (size_t i = 0; i < sizeof peer_limits / sizeof peer_limits[0]; i++) {
        diff_writable_peer_limit(peer_limits[i], SIZE_MAX);
    }
    for (int i = 0; i < DIFF_WRITABLE_RANDOM_LIMITS; i++) {
        diff_writable_peer_limit((uint16_t)(1 + rng_below(CH_TX_PT)), SIZE_MAX);
    }
}

#ifdef CH_SUITE_AES_GCM

// Compares cap under the session's AES-GCM key, and counts the row when
// the KeyUpdate record changed the answer: the answer for the same cap
// under a ChaCha20-Poly1305 key, which counts no KeyUpdate, is another.
static void diff_writable_aes_row(size_t cap, size_t limit, size_t room) {
    size_t answer = diff_writable_row(cap, limit, room);
    uint16_t suite = diff_writable_session.wr.suite;
    diff_writable_session.wr.suite = SUITE_CHACHA20_POLY1305_SHA256;
    size_t chacha_answer = ch_writable_len(&diff_writable_session, cap);
    diff_writable_session.wr.suite = suite;
    diff_writable_aes_rows++;
    diff_writable_key_update_rows += answer != chacha_answer;
}

// The caps one limit and room are compared at, where a record is limit +
// REC_OVERHEAD bytes: after room whole records, after those and the
// KeyUpdate record, and after those and REC_AES_GCM_RECORDS_MAX - 1 whole
// records under the next key, each plus 0, 1, REC_OVERHEAD,
// REC_OVERHEAD + 1, a record, and a record and REC_OVERHEAD + 1; SIZE_MAX;
// and DIFF_WRITABLE_RANDOM_CAPS drawn at random.
static void diff_writable_aes_caps(size_t limit, size_t room) {
    size_t record = limit + REC_OVERHEAD;
    size_t room_records = room * record;
    size_t key_update = room_records + CH_KEY_UPDATE_RECORD_LEN;
    size_t next_key_records = key_update + (size_t)(REC_AES_GCM_RECORDS_MAX - 1) * record;
    const size_t offsets[] = {
        0, 1, REC_OVERHEAD, REC_OVERHEAD + 1, record, record + REC_OVERHEAD + 1,
    };
    for (size_t i = 0; i < sizeof offsets / sizeof offsets[0]; i++) {
        diff_writable_aes_row(room_records + offsets[i], limit, room);
        diff_writable_aes_row(key_update + offsets[i], limit, room);
        diff_writable_aes_row(next_key_records + offsets[i], limit, room);
    }
    diff_writable_aes_row(SIZE_MAX, limit, room);
    for (int i = 0; i < DIFF_WRITABLE_RANDOM_CAPS; i++) {
        diff_writable_aes_row(diff_writable_random_cap(), limit, room);
    }
}

// Sets the write key's sequence number and compares, under AES-128-GCM and
// AES-256-GCM in turn, the limits 1, 63, 512 and CH_TX_PT and one drawn at
// random, at the room that sequence number leaves.
static void diff_writable_aes_seq(uint64_t seq, size_t room) {
    const uint16_t peer_limits[] = {1, 63, 512, CH_TX_PT, (uint16_t)(1 + rng_below(CH_TX_PT))};
    diff_writable_session.wr.seq = seq;
    for (size_t i = 0; i < sizeof peer_limits / sizeof peer_limits[0]; i++) {
        diff_writable_session.wr.suite =
            i % 2 == 0 ? SUITE_AES_128_GCM_SHA256 : SUITE_AES_256_GCM_SHA384;
        diff_writable_session.peer_limit = peer_limits[i];
        diff_writable_aes_caps(peer_limits[i], room);
    }
}

// The rooms: 0, at the sequence number of the key's KeyUpdate record, one
// past it and at UINT64_MAX; 1 and 2, the last data records; 2^24 - 2 and
// 2^24 - 1, the key's first; and DIFF_WRITABLE_RANDOM_ROOMS drawn at
// random.
static void diff_writable_aes(void) {
    const uint64_t last = REC_AES_GCM_RECORDS_MAX - 1;
    diff_writable_aes_seq(last, 0);
    diff_writable_aes_seq(last + 1, 0);
    diff_writable_aes_seq(UINT64_MAX, 0);
    const size_t rooms[] = {1, 2, REC_AES_GCM_RECORDS_MAX - 2, REC_AES_GCM_RECORDS_MAX - 1};
    for (size_t i = 0; i < sizeof rooms / sizeof rooms[0]; i++) {
        diff_writable_aes_seq(last - rooms[i], rooms[i]);
    }
    for (int i = 0; i < DIFF_WRITABLE_RANDOM_ROOMS; i++) {
        size_t room = rng_below(REC_AES_GCM_RECORDS_MAX);
        diff_writable_aes_seq(last - room, room);
    }
}

static void diff_writable_len(void) {
    // A ChaCha20-Poly1305 key at the sequence number where an AES-GCM key
    // sends its KeyUpdate: it counts none.
    diff_writable_session.wr.suite = SUITE_CHACHA20_POLY1305_SHA256;
    diff_writable_session.wr.seq = REC_AES_GCM_RECORDS_MAX - 1;
    diff_writable_limits();
    diff_writable_aes();
    (void)printf("diff: writable_len: %ld rows, %ld under an AES-GCM key, where the KeyUpdate "
                 "record changed %ld answers, C == spec\n",
                 diff_writable_rows, diff_writable_aes_rows, diff_writable_key_update_rows);
}

#else

static void diff_writable_len(void) {
    diff_writable_limits();
    (void)printf("diff: writable_len: %ld rows, C == spec; the AES-GCM rows run under "
                 "-DCH_SUITE_AES_GCM only\n",
                 diff_writable_rows);
}

#endif

#endif
