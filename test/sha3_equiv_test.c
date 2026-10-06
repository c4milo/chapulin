// sha3.c against FIPS 202 as the standard writes it (docs/decisions.md
// 98): the same input into both, the same output out.
//
// sha3.c writes each round out lane by lane, reads its round constants
// from a table and moves eight bytes at a time between a message and the
// lanes. proof/sha3_reference.h is the standard's algorithms step by
// step: the round as loops, the rho offsets and the round constants
// computed by the standard's rules, and a sponge that moves one byte at a
// time. This binary gives both the same input:
//
//   - the permutation alone, on the state of zeros, the state of ones,
//     each of the 1,600 states with one bit set, and random states;
//   - SHA3-256 and SHA3-512 of a message of every length from 0 to 420
//     bytes, which is past three blocks of either rate, and of random
//     longer ones;
//   - SHAKE128 and SHAKE256 with the input absorbed in pieces and the
//     output squeezed in pieces, the pieces of random lengths from 0
//     bytes up, so that a piece starts and ends at every offset of a
//     lane and of a block.
//
// This file includes sha3.c itself, so it can call the permutation,
// which sha3.c keeps static. The random values come from the seeded
// generator below, so an ordinary run replays exactly, and
// CH_SHA3_EQUIV_SEED gives a run another seed.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha3.c"

#include "proof/sha3_reference.h"

// xorshift64, as test/x25519_equiv_test.c writes it and for its reasons:
// a fixed default seed, so a mismatch reproduces bit for bit, and an
// environment variable that gives a run another one. Never time().
#define SHA3_EQUIV_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = SHA3_EQUIV_DEFAULT_SEED;

static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_SHA3_EQUIV_SEED");
    if (text != NULL) {
        char *end = NULL;
        unsigned long long value = strtoull(text, &end, 0);
        if (end != text && *end == 0 && value != 0) {
            rng_state = (uint64_t)value;
        }
    }
    return rng_state;
}

static uint64_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void rng_bytes(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)(rng_next() >> 32);
    }
}

static unsigned long comparisons = 0;
static int failures = 0;

static void expect_same(const char *what, const void *ours, const void *reference, size_t n) {
    comparisons++;
    if (memcmp(ours, reference, n) != 0) {
        failures++;
        (void)fprintf(stderr, "sha3_equiv: %s: sha3.c and the reference differ\n", what);
    }
}

static uint64_t reference_constants[24];

static void permutation(const char *what, const uint64_t state[25]) {
    uint64_t ours[25];
    uint64_t reference[25];
    memcpy(ours, state, sizeof ours);
    memcpy(reference, state, sizeof reference);
    keccak_f1600(ours);
    reference_f1600(reference, reference_constants);
    expect_same(what, ours, reference, sizeof ours);
}

static void permutations(void) {
    uint64_t state[25] = {0};
    permutation("the permutation of zeros", state);
    memset(state, 0xff, sizeof state);
    permutation("the permutation of ones", state);
    for (int bit = 0; bit < 1600; bit++) {
        memset(state, 0, sizeof state);
        state[bit / 64] = UINT64_C(1) << (bit % 64);
        permutation("the permutation of one bit", state);
    }
    for (int i = 0; i < 2000; i++) {
        for (int lane = 0; lane < 25; lane++) {
            state[lane] = rng_next();
        }
        permutation("the permutation of a random state", state);
    }
}

// A SHA-3 digest from the reference: the capacity is twice the digest's
// length, so a block is 200 bytes less that (FIPS 202 §6.1).
static void reference_digest(const uint8_t *message, size_t n, uint8_t *out, size_t out_len) {
    sha3_reference s;
    reference_init(&s, 200 - 2 * out_len);
    reference_absorb(&s, message, n);
    reference_pad(&s, 0x06);
    reference_squeeze(&s, out, out_len);
}

#define MESSAGE_MAX 6000

static void digests_of(const uint8_t *message, size_t n) {
    uint8_t ours[SHA3_512_LEN];
    uint8_t reference[SHA3_512_LEN];
    sha3_256(message, n, ours);
    reference_digest(message, n, reference, SHA3_256_LEN);
    expect_same("SHA3-256", ours, reference, SHA3_256_LEN);
    sha3_512(message, n, ours);
    reference_digest(message, n, reference, SHA3_512_LEN);
    expect_same("SHA3-512", ours, reference, SHA3_512_LEN);
}

static void digests(void) {
    static uint8_t message[MESSAGE_MAX];
    rng_bytes(message, sizeof message);
    for (size_t n = 0; n <= 420; n++) {
        digests_of(message, n);
    }
    for (int i = 0; i < 200; i++) {
        size_t n = (size_t)(rng_next() % (MESSAGE_MAX + 1));
        size_t start = (size_t)(rng_next() % (MESSAGE_MAX - n + 1));
        digests_of(message + start, n);
    }
}

// A piece's length: most are short, so that pieces start and end inside a
// lane, and some pass a block or two.
static size_t piece(size_t left) {
    uint64_t r = rng_next();
    size_t n = (size_t)((r >> 8) % ((r & 7) == 0 ? 400 : 20));
    return n > left ? left : n;
}

#define STREAM_MAX 1500

// One SHAKE, sha3.c and the reference given the same pieces. SHAKE128's
// security strength is 16 bytes and SHAKE256's is 32 (FIPS 202 §6.2).
static void stream(int is_128) {
    static uint8_t input[STREAM_MAX];
    static uint8_t our_out[STREAM_MAX];
    static uint8_t reference_out[STREAM_MAX];
    shake ours;
    sha3_reference reference;
    size_t in_len = (size_t)(rng_next() % (STREAM_MAX + 1));
    size_t out_len = (size_t)(rng_next() % (STREAM_MAX + 1));
    rng_bytes(input, in_len);
    memset(our_out, 0, sizeof our_out);
    memset(reference_out, 0, sizeof reference_out);
    if (is_128) {
        shake128_init(&ours);
        reference_init(&reference, 200 - 2 * 16);
    } else {
        shake256_init(&ours);
        reference_init(&reference, 200 - 2 * 32);
    }
    for (size_t done = 0; done < in_len;) {
        size_t n = piece(in_len - done);
        shake_absorb(&ours, input + done, n);
        reference_absorb(&reference, input + done, n);
        done += n;
    }
    reference_pad(&reference, 0x1f);
    for (size_t done = 0; done < out_len;) {
        size_t n = piece(out_len - done);
        shake_squeeze(&ours, our_out + done, n);
        reference_squeeze(&reference, reference_out + done, n);
        done += n;
        // A piece of no bytes is a call too; after one, stop one time in
        // four, so some streams end short of their length.
        if (n == 0 && (rng_next() & 3) == 0) {
            break;
        }
    }
    // The bytes each wrote, and the state each is left in. A stream that
    // squeezed nothing has not padded in sha3.c, so its state is compared
    // only once a squeeze has run.
    expect_same(is_128 ? "a SHAKE128 stream" : "a SHAKE256 stream", our_out, reference_out,
                sizeof our_out);
    if (ours.squeezing) {
        expect_same("a SHAKE state", ours.lane, reference.lane, sizeof ours.lane);
    }
}

int main(void) {
    uint64_t seed = rng_seed_from_env();
    for (unsigned round = 0; round < 24; round++) {
        reference_constants[round] = reference_round_constant(round);
    }
    permutations();
    digests();
    for (int i = 0; i < 600; i++) {
        stream(i & 1);
    }
    if (failures != 0) {
        (void)fprintf(stderr, "sha3_equiv: %d failures (seed 0x%llx)\n", failures,
                      (unsigned long long)seed);
        return 1;
    }
    printf("sha3_equiv: %lu outputs, sha3.c == FIPS 202's algorithms (seed 0x%llx)\n", comparisons,
           (unsigned long long)seed);
    return 0;
}
