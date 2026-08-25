// SHA-3 differential section: both fixed-length digests and both XOFs
// against the Lean spec. Message and output lengths visit every sponge
// rate boundary (72, 136, 168 and neighbors) before random fill, and
// the XOF rows absorb and squeeze through split calls, so the C
// streaming context is what the oracle's one-shot answer checks.
// Included by test/diff_test.c after diff_driver.h (single translation unit).
#ifndef CH_DIFFSHA3_H
#define CH_DIFFSHA3_H

#include "sha3.h"

#define SHA3_DIFF_MSG_MAX 300
#define SHA3_DIFF_OUT_MAX 336

// The empty message, each rate boundary with its neighbors, then random.
static size_t sha3_diff_msg_len(int i) {
    static const size_t edge[] = {0, 1, 71, 72, 73, 135, 136, 137, 167, 168, 169};
    if ((size_t)i < sizeof edge / sizeof edge[0]) {
        return edge[i];
    }
    return rng_below(SHA3_DIFF_MSG_MAX + 1);
}

// Output lengths for the XOFs: one byte, the rate boundaries, a whole
// number of blocks, then random.
static size_t sha3_diff_out_len(int i) {
    static const size_t edge[] = {1, 71, 72, 73, 135, 136, 137, 167, 168, 169, 336};
    if ((size_t)i < sizeof edge / sizeof edge[0]) {
        return edge[i];
    }
    return 1 + rng_below(SHA3_DIFF_OUT_MAX);
}

static void diff_sha3_256(void) {
    for (int i = 0; i < 60; i++) {
        uint8_t msg[SHA3_DIFF_MSG_MAX];
        size_t msg_len = sha3_diff_msg_len(i);
        rng_fill(msg, msg_len);
        uint8_t out[SHA3_256_LEN];
        sha3_256(msg, msg_len, out);
        char msg_hex[2 * SHA3_DIFF_MSG_MAX + 2];
        (void)hex_encode(msg_hex, msg, msg_len);
        char want[2 * SHA3_256_LEN + 1];
        (void)hex_encode(want, out, sizeof out);
        char cmd[2 * SHA3_DIFF_MSG_MAX + 32];
        (void)snprintf(cmd, sizeof cmd, "sha3_256 %s", msg_hex);
        expect(cmd, want);
    }
}

static void diff_sha3_512(void) {
    for (int i = 0; i < 60; i++) {
        uint8_t msg[SHA3_DIFF_MSG_MAX];
        size_t msg_len = sha3_diff_msg_len(i);
        rng_fill(msg, msg_len);
        uint8_t out[SHA3_512_LEN];
        sha3_512(msg, msg_len, out);
        char msg_hex[2 * SHA3_DIFF_MSG_MAX + 2];
        (void)hex_encode(msg_hex, msg, msg_len);
        char want[2 * SHA3_512_LEN + 1];
        (void)hex_encode(want, out, sizeof out);
        char cmd[2 * SHA3_DIFF_MSG_MAX + 32];
        (void)snprintf(cmd, sizeof cmd, "sha3_512 %s", msg_hex);
        expect(cmd, want);
    }
}

// One XOF row: split the absorb and the squeeze at random points, so
// every context state the streaming API can reach answers for itself.
// The callers build the oracle command, so each op name is a literal
// format string spec_coverage.py's driven-op scan can find.
static void diff_shake_row(int is_128, const uint8_t *msg, size_t msg_len, uint8_t *out,
                           size_t out_len) {
    shake s;
    if (is_128) {
        shake128_init(&s);
    } else {
        shake256_init(&s);
    }
    size_t absorb_cut = rng_below(msg_len + 1);
    shake_absorb(&s, msg, absorb_cut);
    shake_absorb(&s, msg + absorb_cut, msg_len - absorb_cut);
    size_t squeeze_cut = rng_below(out_len + 1);
    shake_squeeze(&s, out, squeeze_cut);
    shake_squeeze(&s, out + squeeze_cut, out_len - squeeze_cut);
}

static void diff_shake128(void) {
    for (int i = 0; i < 60; i++) {
        uint8_t msg[SHA3_DIFF_MSG_MAX];
        size_t msg_len = sha3_diff_msg_len(i);
        rng_fill(msg, msg_len);
        uint8_t out[SHA3_DIFF_OUT_MAX];
        size_t out_len = sha3_diff_out_len(i);
        diff_shake_row(1, msg, msg_len, out, out_len);
        char msg_hex[2 * SHA3_DIFF_MSG_MAX + 2];
        (void)hex_encode(msg_hex, msg, msg_len);
        char want[2 * SHA3_DIFF_OUT_MAX + 2];
        (void)hex_encode(want, out, out_len);
        char cmd[2 * SHA3_DIFF_MSG_MAX + 48];
        (void)snprintf(cmd, sizeof cmd, "shake128 %s %zu", msg_hex, out_len);
        expect(cmd, want);
    }
}

static void diff_shake256(void) {
    for (int i = 0; i < 60; i++) {
        uint8_t msg[SHA3_DIFF_MSG_MAX];
        size_t msg_len = sha3_diff_msg_len(i);
        rng_fill(msg, msg_len);
        uint8_t out[SHA3_DIFF_OUT_MAX];
        size_t out_len = sha3_diff_out_len(i);
        diff_shake_row(0, msg, msg_len, out, out_len);
        char msg_hex[2 * SHA3_DIFF_MSG_MAX + 2];
        (void)hex_encode(msg_hex, msg, msg_len);
        char want[2 * SHA3_DIFF_OUT_MAX + 2];
        (void)hex_encode(want, out, out_len);
        char cmd[2 * SHA3_DIFF_MSG_MAX + 48];
        (void)snprintf(cmd, sizeof cmd, "shake256 %s %zu", msg_hex, out_len);
        expect(cmd, want);
    }
}

#endif
