// SHA-512 and SHA-384 differential section: both digests against the
// Lean spec. Message lengths visit the padding boundary (112), the block
// boundary (128) and the same two points of the second block, each with
// its neighbours, before random fill, so every pad position the C can
// take is compared at least once.
// Included by test/diff_test.c after diff_driver.h (single translation unit).
#ifndef CH_DIFFSHA512_H
#define CH_DIFFSHA512_H

#include "sha512.h"

#define SHA512_DIFF_MSG_MAX 300

// The empty message, each boundary with its neighbours, then random.
static size_t sha512_diff_msg_len(int i) {
    static const size_t edge[] = {0, 1, 111, 112, 113, 127, 128, 129, 239, 240, 241, 255, 256, 257};
    if ((size_t)i < sizeof edge / sizeof edge[0]) {
        return edge[i];
    }
    return rng_below(SHA512_DIFF_MSG_MAX + 1);
}

static void diff_sha512(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t msg[SHA512_DIFF_MSG_MAX];
        size_t msg_len = sha512_diff_msg_len(i);
        rng_fill(msg, msg_len);
        uint8_t out[SHA512_LEN];
        sha512_of(msg, msg_len, out);
        char msg_hex[2 * SHA512_DIFF_MSG_MAX + 2];
        (void)hex_encode(msg_hex, msg, msg_len);
        char want[2 * SHA512_LEN + 1];
        (void)hex_encode(want, out, sizeof out);
        char cmd[2 * SHA512_DIFF_MSG_MAX + 32];
        (void)snprintf(cmd, sizeof cmd, "sha512 %s", msg_hex);
        expect(cmd, want);
    }
}

static void diff_sha384(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t msg[SHA512_DIFF_MSG_MAX];
        size_t msg_len = sha512_diff_msg_len(i);
        rng_fill(msg, msg_len);
        uint8_t out[SHA384_LEN];
        sha384_of(msg, msg_len, out);
        char msg_hex[2 * SHA512_DIFF_MSG_MAX + 2];
        (void)hex_encode(msg_hex, msg, msg_len);
        char want[2 * SHA384_LEN + 1];
        (void)hex_encode(want, out, sizeof out);
        char cmd[2 * SHA512_DIFF_MSG_MAX + 32];
        (void)snprintf(cmd, sizeof cmd, "sha384 %s", msg_hex);
        expect(cmd, want);
    }
}

#endif
