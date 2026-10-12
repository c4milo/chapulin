// The length each SHA-512 path writes after a message, against a padding
// this file writes itself.
//
// FIPS 180-4 §5.1.2 ends a message with its length in bits as a 128-bit
// integer. A context counts bytes in total_bytes, a 64-bit word, so each
// path's finalize writes the length as two words: the upper is the top
// three bits of the byte count, and the lower is the byte count shifted
// left by three. Every other case of this binary hashes a message under
// 2^61 bytes, whose upper word is zero, so a finalize that wrote zero
// there would pass them all.
//
// No test hashes 2^61 bytes, so a case here starts a context at a byte
// count: the hash's initial value, total_bytes set to the count, and as
// many buffered bytes as the count leaves in a block. The case absorbs a
// tail on the path it holds and takes the final there. It compares the
// digest with one this file computes: the buffered bytes, the tail and the
// padding in one buffer, with the length written from a 128-bit product,
// compressed a block at a time on sha512_compress, the reference's
// compression function. So the two sides share no finalize.
//
// The counts are 2^61 - 1, 2^61 and five larger ones up to 2^64 - 4,096.
// From 2^61 - 1 the empty tail gives the last length whose upper word is
// zero, and a tail of one byte the first whose upper word is one.
//
// Included by test/sha2_equiv_sha512.h only.
#ifndef CH_SHA2_EQUIV_LENGTH512_H
#define CH_SHA2_EQUIV_LENGTH512_H

#include "ct.h"
#include "sha512_compress.h"

// The byte counts a case starts a context at. Each leaves count mod 128
// bytes buffered: 127, 0, 111, which is one byte short of where the padding
// takes a block of its own, 127, 64, 5 and 0.
static const uint64_t LENGTH512_STARTS[] = {(UINT64_C(1) << 61) - 1,     (UINT64_C(1) << 61),
                                            (UINT64_C(1) << 61) + 111,   (UINT64_C(1) << 62) - 1,
                                            (UINT64_C(3) << 61) + 64,    (UINT64_C(1) << 63) + 5,
                                            UINT64_C(0xfffffffffffff000)};
// The lengths of the tail a case absorbs, the longest of which crosses two
// block boundaries.
static const size_t LENGTH512_TAILS[] = {0, 1, 16, 17, 129, 300};
#define LENGTH512_TAIL_MAX ((size_t)300)
// The buffered bytes, the tail, the 0x80 byte, the zeros and the length:
// under one block, the tail, and under two blocks more.
#define LENGTH512_PADDED_MAX ((size_t)3 * SHA512_BLOCK + LENGTH512_TAIL_MAX)

// The digest FIPS 180-4 gives a message of start + n bytes whose state
// before its last buffered + n bytes is the hash's initial value, where
// those bytes are held[0..buffered) and tail[0..n) and buffered is
// start mod 128. The padding of §5.1.2 is written here: the 0x80 byte,
// zeros up to sixteen bytes short of a block, and the bit count, a 128-bit
// product, most significant byte first.
static void digest_from_count512(int is384, uint64_t start, const uint8_t *held,
                                 const uint8_t *tail, size_t n, uint8_t out[SHA512_LEN]) {
    uint8_t padded[LENGTH512_PADDED_MAX];
    size_t buffered = (size_t)(start % SHA512_BLOCK);
    memcpy(padded, held, buffered);
    memcpy(padded + buffered, tail, n);
    size_t len = buffered + n;
    padded[len++] = 0x80;
    while (len % SHA512_BLOCK != SHA512_BLOCK - 16) {
        padded[len++] = 0;
    }
    ct_u128 bit_count = (ct_u128)(start + n) * 8;
    for (size_t i = 0; i < 16; i++) {
        padded[len++] = (uint8_t)(bit_count >> (120 - 8 * i));
    }
    sha512 s;
    init512(is384, &s);
    for (size_t at = 0; at < len; at += SHA512_BLOCK) {
        sha512_compress(s.h, padded + at);
    }
    for (size_t i = 0; i < 8; i++) {
        for (size_t j = 0; j < 8; j++) {
            out[8 * i + j] = (uint8_t)(s.h[i] >> (56 - 8 * j));
        }
    }
}

// One case: a context that starts at start bytes absorbs n more on held and
// takes its final there.
static void compare_length512(const path512 *held, int is384, uint64_t start, size_t n) {
    uint8_t buffered_bytes[SHA512_BLOCK];
    uint8_t tail[LENGTH512_TAIL_MAX];
    rng_fill(buffered_bytes, sizeof buffered_bytes);
    rng_fill(tail, sizeof tail);

    sha512 s;
    init512(is384, &s);
    s.total_bytes = start;
    s.fill = (size_t)(start % SHA512_BLOCK);
    memcpy(s.block, buffered_bytes, s.fill);
    held->update(&s, tail, n);
    uint64_t counted = s.total_bytes;
    uint8_t got[SHA512_LEN];
    final512_on(held, is384, &s, got);
    uint8_t want[SHA512_LEN];
    digest_from_count512(is384, start, buffered_bytes, tail, n, want);
    compared++;

    if (counted != start + n || memcmp(want, got, digest_len512(is384)) != 0) {
        failures++;
        (void)fprintf(stderr,
                      "sha2 equivalence: %s: from a context that starts at 0x%016llx bytes and "
                      "absorbs %zu more, the %s digest is not the digest of FIPS 180-4's padding, "
                      "or the context counted another length\n",
                      held->name, (unsigned long long)start, n, is384 ? "SHA-384" : "SHA-512");
    }
}

// Every count with every tail, for both hashes, on one path.
static void run_length512(const path512 *held) {
    for (size_t i = 0; i < sizeof LENGTH512_STARTS / sizeof LENGTH512_STARTS[0]; i++) {
        for (size_t j = 0; j < sizeof LENGTH512_TAILS / sizeof LENGTH512_TAILS[0]; j++) {
            compare_length512(held, 0, LENGTH512_STARTS[i], LENGTH512_TAILS[j]);
            compare_length512(held, 1, LENGTH512_STARTS[i], LENGTH512_TAILS[j]);
        }
    }
}

#endif
