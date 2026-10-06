// bin/sha3_hw_equiv_test: holds sha3_hw.c, Keccak-f[1600] on arm64's SHA-3
// instructions, to sha3.c, the portable code CBMC proves (docs/decisions.md
// 99). CBMC cannot read an intrinsic, so this binary is what holds the
// instructions to the proved code.
//
// It compares the two over
//
//   SHA3-256 and SHA3-512 of every length from 0 to EVERY_LENGTH_MAX bytes,
//     which crosses several blocks of each rate, and of two long messages;
//   SHAKE128 and SHAKE256 streams absorbed and squeezed in random pieces,
//     the same pieces on each path;
//   the same streams once more with each call on a path picked at random,
//     which sha3.h allows because the two paths keep the same state in a
//     context.
//
// At the lengths around a block's end it also compares the instructions
// with proof/sha3_reference.h, FIPS 202 as the standard writes it, so they
// answer the standard directly and not only through sha3.c. Every message
// and every output sits in a heap buffer that ends where it ends, so under
// AddressSanitizer a read or a write past one fails.
//
// test/sha3_hw_equiv_residue.h then searches the stack each kind of call
// leaves for any lane the call computed.
//
// An object holds the instructions where clang compiled it for arm64
// (CH_KECCAK_INSTRUCTIONS, cpu_cfg.h). In any other object this binary says
// so and passes, and on a CPU without the instructions it skips. Under
// CH_REQUIRE_HASH_INSTRUCTIONS=1 it fails in either case instead
// (test/hash_instructions_cpu.h), so a run that must test the instructions
// cannot pass by testing nothing.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash_instructions_cpu.h"
#include "sha3.h"

#ifndef CH_CPU_RUNTIME
#error "bin/sha3_hw_equiv_test links a host object's hash sources: -DCH_CPU_RUNTIME"
#endif

#ifndef CH_KECCAK_INSTRUCTIONS

int main(void) {
    if (hash_instructions_required()) {
        (void)fprintf(stderr,
                      "sha3 instructions equivalence: this object holds no Keccak on the "
                      "SHA-3 instructions (cpu_cfg.h), and CH_REQUIRE_HASH_INSTRUCTIONS is 1\n");
        return 1;
    }
    (void)printf("SKIP sha3 instructions equivalence: this object holds no Keccak on the SHA-3 "
                 "instructions (cpu_cfg.h)\n");
    return 0;
}

#else

#include "proof/sha3_reference.h"

// xorshift64, the generator test/sha3_equiv_test.c uses. The default seed
// is fixed, so an ordinary run replays the same cases and a mismatch
// reproduces bit for bit; CH_SHA3_HW_EQUIV_SEED sets another, and this
// binary prints the seed it used.
#define SHA3_HW_EQUIV_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = SHA3_HW_EQUIV_DEFAULT_SEED;

// Reads CH_SHA3_HW_EQUIV_SEED, if set, as the seed, and returns the seed in
// use. A value that is not a number, or zero, keeps the default: xorshift64
// is all zeroes forever from zero.
static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_SHA3_HW_EQUIV_SEED");
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
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static void rng_bytes(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)(rng_next() >> 32);
    }
}

static unsigned long compared = 0;
static int failures = 0;

static void expect_same(const char *what, size_t n_in, const void *ours, const void *theirs,
                        size_t n) {
    compared++;
    if (memcmp(ours, theirs, n) != 0) {
        failures++;
        (void)fprintf(stderr, "sha3 instructions equivalence: %s of %zu bytes differ\n", what,
                      n_in);
    }
}

// FIPS 202's 24 round constants from its shift register, computed once.
static uint64_t round_constants[24];

// The digest of n bytes by the standard's loops: rate bytes a block, and
// SHA-3's suffix and padding.
static void reference_digest(const uint8_t *message, size_t n, size_t rate, uint8_t *out,
                             size_t out_len) {
    sha3_reference s;
    reference_init(&s, rate);
    reference_absorb(&s, message, n);
    reference_pad(&s, 0x06);
    reference_squeeze(&s, out, out_len);
}

#define EVERY_LENGTH_MAX 700
#define LONG_MESSAGE_LEN 16384

// A heap buffer of n bytes, or of one where n is 0, since malloc(0) may
// return NULL. A case puts its message, or its output, in one that ends
// where the bytes end, so that under AddressSanitizer a read or a write
// past the last byte fails.
static uint8_t *exact_buffer(size_t n) {
    uint8_t *buffer = malloc(n > 0 ? n : 1);
    if (buffer == NULL) {
        (void)fprintf(stderr, "sha3 instructions equivalence: out of memory\n");
        exit(1);
    }
    return buffer;
}

// n bytes of message at an offset of n % 8 into a heap buffer that ends
// with them, so the message starts off a lane's boundary at every length
// but a multiple of eight. The caller frees *buffer.
static const uint8_t *exact_copy(const uint8_t *message, size_t n, uint8_t **buffer) {
    size_t offset = n % 8;
    *buffer = exact_buffer(offset + n);
    memcpy(*buffer + offset, message, n);
    return *buffer + offset;
}

static void digests_of(const uint8_t *message_bytes, size_t n) {
    uint8_t *buffer = NULL;
    const uint8_t *message = exact_copy(message_bytes, n, &buffer);
    uint8_t on_instructions[SHA3_512_LEN];
    uint8_t portable[SHA3_512_LEN];
    sha3_256_hw(message, n, on_instructions);
    sha3_256(message, n, portable);
    expect_same("the SHA3-256 of sha3_hw.c and of sha3.c", n, on_instructions, portable,
                SHA3_256_LEN);
    sha3_512_hw(message, n, on_instructions);
    sha3_512(message, n, portable);
    expect_same("the SHA3-512 of sha3_hw.c and of sha3.c", n, on_instructions, portable,
                SHA3_512_LEN);
    free(buffer);
}

static void digests_against_the_standard(const uint8_t *message_bytes, size_t n) {
    uint8_t *buffer = NULL;
    const uint8_t *message = exact_copy(message_bytes, n, &buffer);
    uint8_t on_instructions[SHA3_512_LEN];
    uint8_t standard[SHA3_512_LEN];
    sha3_256_hw(message, n, on_instructions);
    reference_digest(message, n, SHA3_256_RATE, standard, SHA3_256_LEN);
    expect_same("the SHA3-256 of sha3_hw.c and of FIPS 202's loops", n, on_instructions, standard,
                SHA3_256_LEN);
    sha3_512_hw(message, n, on_instructions);
    reference_digest(message, n, SHA3_512_RATE, standard, SHA3_512_LEN);
    expect_same("the SHA3-512 of sha3_hw.c and of FIPS 202's loops", n, on_instructions, standard,
                SHA3_512_LEN);
    free(buffer);
}

static void run_digests(void) {
    // One byte each side of a block's end, at one and at two blocks of each
    // rate, and the empty message.
    static const size_t around_a_block[] = {0,   1,   71,  72,  73,  135, 136, 137, 143,
                                            144, 145, 167, 168, 169, 271, 272, 273};
    static uint8_t message[LONG_MESSAGE_LEN];
    rng_bytes(message, sizeof message);
    for (size_t n = 0; n <= EVERY_LENGTH_MAX; n++) {
        digests_of(message, n);
    }
    digests_of(message, 4096);
    digests_of(message, LONG_MESSAGE_LEN);
    for (size_t i = 0; i < sizeof around_a_block / sizeof around_a_block[0]; i++) {
        digests_against_the_standard(message, around_a_block[i]);
    }
}

// A piece of at most `left` bytes: short most of the time, and one time in
// eight as long as several blocks, so pieces end inside a block, on its end
// and past it.
static size_t piece(size_t left) {
    uint64_t r = rng_next();
    size_t n = (size_t)((r >> 8) % ((r & 7) == 0 ? 400 : 20));
    return n > left ? left : n;
}

#define STREAM_MAX 1500
#define STREAM_CASES 200

static void stream_init(shake *s, int is_128, int on_instructions) {
    if (is_128) {
        if (on_instructions) {
            shake128_init_hw(s);
        } else {
            shake128_init(s);
        }
    } else if (on_instructions) {
        shake256_init_hw(s);
    } else {
        shake256_init(s);
    }
}

// One SHAKE on three contexts given the same pieces: sha3_hw.c's calls,
// sha3.c's, and each call on a path one random bit picks. The message and
// each output sit in buffers that end where they end.
static void stream(int is_128) {
    shake hw;
    shake sw;
    shake mixed;
    size_t n_in = (size_t)(rng_next() % (STREAM_MAX + 1));
    size_t n_out = (size_t)(rng_next() % (STREAM_MAX + 1));
    uint8_t *message = exact_buffer(n_in);
    uint8_t *on_instructions = exact_buffer(n_out);
    uint8_t *portable = exact_buffer(n_out);
    uint8_t *either = exact_buffer(n_out);
    rng_bytes(message, n_in);
    stream_init(&hw, is_128, 1);
    stream_init(&sw, is_128, 0);
    stream_init(&mixed, is_128, (int)(rng_next() & 1));
    for (size_t done = 0; done < n_in;) {
        size_t n = piece(n_in - done);
        shake_absorb_hw(&hw, message + done, n);
        shake_absorb(&sw, message + done, n);
        if ((rng_next() & 1) != 0) {
            shake_absorb_hw(&mixed, message + done, n);
        } else {
            shake_absorb(&mixed, message + done, n);
        }
        done += n;
    }
    for (size_t done = 0; done < n_out;) {
        size_t n = piece(n_out - done);
        shake_squeeze_hw(&hw, on_instructions + done, n);
        shake_squeeze(&sw, portable + done, n);
        if ((rng_next() & 1) != 0) {
            shake_squeeze_hw(&mixed, either + done, n);
        } else {
            shake_squeeze(&mixed, either + done, n);
        }
        done += n;
    }
    expect_same(is_128 ? "the SHAKE128 output of sha3_hw.c and of sha3.c for a message"
                       : "the SHAKE256 output of sha3_hw.c and of sha3.c for a message",
                n_in, on_instructions, portable, n_out);
    expect_same(is_128 ? "the SHAKE128 output of calls on either path and of sha3.c for a message"
                       : "the SHAKE256 output of calls on either path and of sha3.c for a message",
                n_in, either, portable, n_out);
    free(message);
    free(on_instructions);
    free(portable);
    free(either);
}

static void run_streams(void) {
    for (int i = 0; i < STREAM_CASES; i++) {
        stream(1);
        stream(0);
    }
}

#include "sha3_hw_equiv_residue.h"

int main(void) {
    if (!cpu_has_sha3_instructions()) {
        if (hash_instructions_required()) {
            (void)fprintf(stderr, "sha3 instructions equivalence: this CPU lacks the SHA-3 "
                                  "instructions, and CH_REQUIRE_HASH_INSTRUCTIONS is 1\n");
            return 1;
        }
        (void)printf("SKIP sha3 instructions equivalence: this CPU lacks the SHA-3 instructions\n");
        return 0;
    }
    uint64_t seed = rng_seed_from_env();
    for (unsigned round = 0; round < 24; round++) {
        round_constants[round] = reference_round_constant(round);
    }
    run_digests();
    run_streams();
    run_residue();
    if (failures != 0) {
        (void)fprintf(stderr, "sha3 instructions equivalence: %d failure(s), seed 0x%016llx\n",
                      failures, (unsigned long long)seed);
        return 1;
    }
    (void)printf("sha3 instructions equivalence: %lu cases agree with the portable code (seed "
                 "0x%016llx)\n",
                 compared, (unsigned long long)seed);
    return 0;
}

#endif // CH_KECCAK_INSTRUCTIONS
