// A host object's SHA-256 on the CPU's instructions against the portable
// one: the same bytes, the same context after every update and the same
// digest. This is what holds sha256_hw.c, because CBMC cannot read an
// intrinsic: proof/sha256_harness.c proves sha256.c, and this binary holds
// sha256_hw.c to that code's answer (docs/decisions.md 93). It links a host
// object's hash sources, so sha256_update is the portable call and
// sha256_update_hw the one on the instructions, and it calls each by name:
// no ch_cfg.cpu value picks between them here. bin/hash_runtime_test holds
// the entries that pick.
//
// Every case hashes the message on the portable path in one call. It then
// hashes a copy in three updates and a final, each on the path one bit of
// the case's mask names, so a context passes between the two paths at each
// call, which sha256.h's contract allows. No session does that today: every
// call that hashes one context takes the same ch_cfg.cpu, or none. The copy
// sits in a heap buffer that ends where the message ends, so under
// AddressSanitizer (make san-check) a read past it stops the binary.
//
// The inputs, in order:
//
//   - every length from 0 to LENGTH_MAX, which crosses four blocks, cut at
//     every offset below CUT_MAX and once more halfway through the rest,
//     with the paths and the alignment taken from the cut;
//   - messages of all 0x00 and all 0xff at every length a block boundary
//     is next to;
//   - RANDOM_CASES cases with a random length up to RANDOM_LENGTH_MAX,
//     cuts, alignment and paths;
//   - a 16 KiB record with its content type byte, 16,385 bytes, and
//     64 KiB;
//   - an update of no bytes from a NULL pointer, and the empty message's
//     digest, which FIPS 180-4 fixes;
//   - HMAC, HKDF and the key schedule in the copies hkdf_hw.c and
//     keysched_hw.c hold, against hkdf.c and keysched.c, over random keys,
//     messages and lengths.
//
// Beside those cases, test/sha2_equiv_residue.h looks in the stack a call
// leaves behind for the values it computed from its input: the message
// schedule, the working variables after each round and the state.
//
// FIPS 180-4's vectors are not repeated here. bin/unit runs them on the
// portable code and bin/unit_host, with the SHA-256 bit, on this path, so
// both answer the published standard directly and not only through each
// other.
//
// On a CPU without the instructions the binary skips, and fails instead
// under CH_REQUIRE_HASH_INSTRUCTIONS=1 (test/hash_instructions_cpu.h).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "hash_instructions_cpu.h"
#include "hkdf.h"
#include "keysched.h"
#include "sha256.h"

#ifndef CH_CPU_RUNTIME
#error "bin/sha2_equiv_test links a host object's hash sources: -DCH_CPU_RUNTIME"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "sha2 equivalence: CH_ASSERT(%s) failed at %s:%d\n", cond, file, line);
    exit(1);
}

// xorshift64, the generator test/chacha20_equiv_test.c uses. The default
// seed is fixed, so an ordinary run replays the same cases and a mismatch
// reproduces bit for bit; CH_SHA2_EQUIV_SEED sets another, and this binary
// prints the seed it used.
#define SHA2_EQUIV_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = SHA2_EQUIV_DEFAULT_SEED;

// Reads CH_SHA2_EQUIV_SEED, if set, as the seed, and returns the seed in
// use. A value that is not a number, or zero, keeps the default:
// xorshift64 is all zeroes forever from zero.
static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_SHA2_EQUIV_SEED");
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

static void rng_fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(rng_next() >> 56);
    }
}

#define LENGTH_MAX ((size_t)(4 * SHA256_BLOCK + 17))
#define CUT_MAX ((size_t)(2 * SHA256_BLOCK + 2))
#define RANDOM_CASES 20000
#define RANDOM_LENGTH_MAX 4096
#define LARGE_LENGTH ((size_t)65536)
// How far past a 16-byte boundary the copy of a message can start.
#define ALIGN_MAX ((size_t)16)
// A case's mask: one bit for each of the three updates and one for the
// final. A set bit runs that call on the instructions.
#define PATH_FINAL 8U
#define PATHS_ALL 15U

static uint8_t message[LARGE_LENGTH];
static int failures = 0;
static unsigned long compared = 0;

static void report(const char *case_name, const char *what, size_t n, size_t first_cut,
                   size_t second_cut, unsigned paths) {
    failures++;
    (void)fprintf(stderr, "sha2 equivalence: %s: %s (n %zu, cuts at %zu and %zu, paths 0x%x)\n",
                  case_name, what, n, first_cut, second_cut, paths);
}

// One update on the path the bit names.
static void update_on(unsigned on_instructions, sha256 *s, const uint8_t *in, size_t n) {
    if (on_instructions != 0) {
        sha256_update_hw(s, in, n);
    } else {
        sha256_update(s, in, n);
    }
}

// Whether two contexts hold the same state: the eight words, the byte
// count and the buffered partial block. A context may pass between the two
// paths (sha256.h), so each must leave what the other reads.
static int same_state(const sha256 *a, const sha256 *b) {
    return memcmp(a->h, b->h, sizeof a->h) == 0 && a->total_bytes == b->total_bytes &&
           a->fill == b->fill && memcmp(a->block, b->block, a->fill) == 0;
}

// The portable path over message[0..n) in one update, against a copy of
// the same bytes in three updates cut at first_cut and second_cut and a
// final, each on the path its bit of paths names, with the copy offset
// bytes past a 16-byte boundary.
static void compare(const char *case_name, size_t n, size_t first_cut, size_t second_cut,
                    size_t offset, unsigned paths) {
    if (second_cut < first_cut || n < second_cut || n > LARGE_LENGTH) {
        (void)fprintf(stderr, "sha2 equivalence: a case the test cannot hold\n");
        exit(1);
    }
    sha256 portable;
    sha256_init(&portable);
    sha256_update(&portable, message, n);

    // An empty case still takes a byte, since malloc(0) may return NULL.
    size_t size = offset + n;
    uint8_t *buffer = malloc(size > 0 ? size : 1);
    if (buffer == NULL) {
        (void)fprintf(stderr, "sha2 equivalence: out of memory\n");
        exit(1);
    }
    uint8_t *copy = buffer + offset;
    memcpy(copy, message, n);
    sha256 mixed;
    sha256_init(&mixed);
    update_on(paths & 1U, &mixed, copy, first_cut);
    update_on(paths & 2U, &mixed, copy + first_cut, second_cut - first_cut);
    update_on(paths & 4U, &mixed, copy + second_cut, n - second_cut);
    uint8_t whole[SHA256_LEN];
    sha256_of_hw(copy, n, whole);
    free(buffer);
    compared++;

    if (!same_state(&portable, &mixed)) {
        report(case_name, "the contexts differ before the final", n, first_cut, second_cut, paths);
    }
    uint8_t want[SHA256_LEN];
    uint8_t got[SHA256_LEN];
    sha256_final(&portable, want);
    if ((paths & PATH_FINAL) != 0) {
        sha256_final_hw(&mixed, got);
    } else {
        sha256_final(&mixed, got);
    }
    if (memcmp(want, got, sizeof want) != 0) {
        report(case_name, "the digests differ", n, first_cut, second_cut, paths);
    }
    if (memcmp(want, whole, sizeof want) != 0) {
        report(case_name, "sha256_of_hw's digest differs", n, first_cut, second_cut, paths);
    }
}

// Every length, on the instructions alone with no cut, and then cut at
// every offset below CUT_MAX and once more halfway through the rest, with
// the paths and the alignment the cut picks.
static void run_every_length(void) {
    for (size_t n = 0; n <= LENGTH_MAX && failures == 0; n++) {
        rng_fill(message, n);
        compare("every length", n, 0, 0, 0, PATHS_ALL);
        for (size_t cut = 1; cut < CUT_MAX && cut <= n; cut++) {
            compare("every length", n, cut, cut + (n - cut) / 2, cut % ALIGN_MAX,
                    (unsigned)(cut % (PATHS_ALL + 1)));
        }
    }
}

// Messages of all 0x00 and all 0xff, whose schedule words are the smallest
// and the largest, at every length within two bytes of a block boundary:
// the padding takes a block of its own from 56 bytes into a block on.
static void run_extremes(void) {
    static const uint8_t fills[] = {0x00, 0xff};
    for (size_t f = 0; f < sizeof fills; f++) {
        memset(message, fills[f], LENGTH_MAX + SHA256_BLOCK);
        for (size_t n = 0; n <= LENGTH_MAX && failures == 0; n++) {
            size_t into_block = n % SHA256_BLOCK;
            if (into_block <= 2 || into_block >= SHA256_BLOCK - 10) {
                compare("extremes", n, 0, 0, 0, PATHS_ALL);
                compare("extremes", n, n / 3, n / 2, 5, 5U);
            }
        }
    }
}

static void run_random(void) {
    for (unsigned long i = 0; i < RANDOM_CASES && failures == 0; i++) {
        size_t n = (size_t)(rng_next() % (RANDOM_LENGTH_MAX + 1));
        rng_fill(message, n);
        size_t first_cut = (size_t)(rng_next() % (n + 1));
        size_t second_cut = first_cut + (size_t)(rng_next() % (n - first_cut + 1));
        size_t offset = (size_t)(rng_next() % ALIGN_MAX);
        unsigned paths = (unsigned)(rng_next() % (PATHS_ALL + 1));
        compare("random", n, first_cut, second_cut, offset, paths);
    }
}

// A 16 KiB record with its content type byte, and 64 KiB: many whole
// blocks in one call, which the instructions take without a copy.
static void run_large(void) {
    static const size_t lengths[] = {16385, LARGE_LENGTH};
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
        rng_fill(message, lengths[i]);
        compare("large", lengths[i], 0, 0, 0, PATHS_ALL);
        compare("large", lengths[i], 1, lengths[i] - 1, 3, PATHS_ALL);
        compare("large", lengths[i], 63, 4097, 1, 5U);
    }
}

// An update of no bytes takes a NULL pointer, as sha256_update does, and
// the empty message has the digest FIPS 180-4's example gives.
static void run_empty(void) {
    static const uint8_t empty_digest[SHA256_LEN] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
        0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
        0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    uint8_t got[SHA256_LEN];
    sha256 s;
    sha256_init(&s);
    sha256_update_hw(&s, NULL, 0);
    sha256_final_hw(&s, got);
    compared++;
    if (memcmp(got, empty_digest, sizeof got) != 0) {
        report("empty", "the empty message's digest is not FIPS 180-4's", 0, 0, 0, PATHS_ALL);
    }
    sha256_of_hw(NULL, 0, got);
    if (memcmp(got, empty_digest, sizeof got) != 0) {
        report("empty", "sha256_of_hw's empty digest is not FIPS 180-4's", 0, 0, 0, PATHS_ALL);
    }
}

#include "sha2_equiv_copies.h"
#include "sha2_equiv_residue.h"

int main(void) {
    if (!cpu_has_sha256_instructions()) {
        if (hash_instructions_required()) {
            (void)fprintf(stderr, "sha2 equivalence: this CPU lacks the SHA-256 instructions, and "
                                  "CH_REQUIRE_HASH_INSTRUCTIONS is 1\n");
            return 1;
        }
        (void)printf("SKIP sha2 equivalence: this CPU lacks the SHA-256 instructions\n");
        return 0;
    }
    uint64_t seed = rng_seed_from_env();
    run_every_length();
    run_extremes();
    run_random();
    run_large();
    run_empty();
    run_copies();
    run_residue();
    if (failures != 0) {
        (void)fprintf(stderr, "sha2 equivalence: %d failure(s), seed 0x%016llx\n", failures,
                      (unsigned long long)seed);
        return 1;
    }
    (void)printf("sha2 equivalence: %lu cases agree with the portable code (seed 0x%016llx)\n",
                 compared, (unsigned long long)seed);
    return 0;
}
