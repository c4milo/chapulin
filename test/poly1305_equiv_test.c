// A host object's vector Poly1305 against the portable one: the same key
// and message, the same accumulator modulo 2^130 - 5 after every update
// and the same tag. This is what holds the vector paths, because CBMC
// cannot read an intrinsic: proof/poly1305_harness.c proves poly1305.c's
// loop, and this binary holds poly1305_vector.c to that loop's answer,
// and on an x86-64 CPU with AVX2 poly1305_avx2.c's kernel too, over the
// same cases. poly1305.c compiles here without -DCH_CPU_RUNTIME, so
// poly1305_update is the portable loop alone, as a device object runs it,
// and test/poly1305_equiv_vector.c compiles a host object's native copy
// of poly1305.c beside it, which holds the vector path, as
// poly1305_update_native, and on x86-64 the kernel, as
// poly1305_update_avx2_native. test/poly1305_equiv_avx2.c compiles the
// kernel's own source. Whether the CPU has AVX2 is
// test/x86_kernels_cpu.h's question, which only test code asks.
//
// Every case runs the portable path over the whole message in one update,
// and the native copy over the same message in two or three updates cut
// at odd offsets, so a buffered partial block meets a long update and the
// cut lands inside a group. The native copy's message sits in a heap
// buffer that ends where the message ends, so under AddressSanitizer
// (make san-check) a read past it stops the binary.
//
// The inputs, in order, for each path:
//
//   - every length from 0 to the path's fewest bytes and four more groups,
//     each cut at every odd offset below 2 groups;
//   - the keys and messages whose limbs are largest: r clamped from a key
//     of all 0xff bytes, and blocks of all 0xff, which carry into every
//     limb, beside r of 0 and blocks of 0;
//   - the path's blocks entry called alone, from an accumulator that
//     earlier blocks left, for one group to GROUPS_MAX groups, below the
//     threshold too, with the limb bounds poly1305_vector.h states checked
//     on return, and once on a group a search found, whose h1 the first
//     pass of carry_scalar leaves past 2^26;
//   - RANDOM_CASES cases with a random key, length up to RANDOM_LENGTH_MAX,
//     cuts and alignment;
//   - a 16 KiB record with its content type byte, 16,385 bytes, and 64 KiB.
//
// Beside those cases, test/poly1305_equiv_residue.h looks for the powers of
// r a call of each path computed in the stack it leaves behind.
//
// RFC 8439's vectors are not repeated here. bin/unit runs them on the
// portable loop and bin/unit_host, with the multiply bit, on this path,
// so both answer the published standard directly and not only through
// each other.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// poly1305_vector.h and poly1305_avx2.h declare the paths' group sizes and
// thresholds only to the native copy of a host object, which the two
// defines state, the second as widemul_native.h states it. This file
// compiles no library source, so the defines change nothing else.
#define CH_CPU_RUNTIME
#define CH_WIDEMUL_NATIVE_COPY 1
#include "ch_assert.h"
#include "poly1305.h"
#include "poly1305_avx2.h"
#include "poly1305_vector.h"
#include "x86_kernels_cpu.h"

#ifndef CH_POLY1305_VECTOR
#error "bin/poly1305_equiv_test needs the vector Poly1305 in a host object's native copy"
#endif

// test/poly1305_equiv_vector.c: a host object's native copy of poly1305.c,
// under the names widemul_native.h gives it. poly1305.h declares the
// copy's update and final for a host object, and on x86-64 its AVX2
// update, and poly1305_vector.h and poly1305_avx2.h the paths' entries in
// that copy.
void poly1305_init_native(poly1305 *p, const uint8_t key[POLY1305_KEY]);

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "poly1305 equivalence: CH_ASSERT(%s) failed at %s:%d\n", cond, file,
                  line);
    exit(1);
}

// xorshift64, the generator test/chacha20_equiv_test.c uses. The default
// seed is fixed, so an ordinary run replays the same cases and a mismatch
// reproduces bit for bit; CH_POLY1305_EQUIV_SEED sets another, and this
// binary prints the seed it used.
#define POLY1305_EQUIV_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = POLY1305_EQUIV_DEFAULT_SEED;

// Reads CH_POLY1305_EQUIV_SEED, if set, as the seed, and returns the seed
// in use. A value that is not a number, or zero, keeps the default:
// xorshift64 is all zeroes forever from zero.
static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_POLY1305_EQUIV_SEED");
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

// The value of one lowercase hex digit.
static unsigned int hex_digit(char c) {
    if (c >= '0' && c <= '9') {
        return (unsigned int)(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return (unsigned int)(c - 'a') + 10;
    }
    (void)fprintf(stderr, "poly1305 equivalence: a fixed case is not hex\n");
    exit(1);
}

// The n bytes the 2n hex digits at hex spell, into out.
static void unhex(const char *hex, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)(hex_digit(hex[2 * i]) << 4 | hex_digit(hex[2 * i + 1]));
    }
}

// A path this binary holds to the portable loop: its update, the entry
// that update hands whole groups to, the bytes of a group, the fewest
// bytes of whole blocks the update hands the entry, and a key and one
// group in hex whose lane totals leave h1 past 2^26 after the first pass
// of carry_scalar, which about one call in two million does, so the
// random cases below almost never meet it. A search over random keys and
// groups found each.
typedef struct {
    const char *name;
    void (*update)(poly1305 *p, const uint8_t *in, size_t n);
    void (*blocks)(poly1305 *p, const uint8_t *m, size_t n);
    size_t group;
    size_t min;
    const char *wide_h1_key;
    const char *wide_h1_group;
} vector_path;

static const vector_path vector_128 = {
    "the 128-bit path",
    poly1305_update_native,
    poly1305_vector_blocks_native,
    POLY1305_VECTOR_GROUP,
    POLY1305_VECTOR_MIN,
    "da026d5d18ad6338e42d34b3bd32ab72537c70fd5eb14a40df78c4559b76e594",
    "51047e886250af05749c24b0a3b551306f5665dba6dbdeef122a49d8cafad4ed"
    "7f08fd47ec5c361b89c8f3842293b6308e96a9696d6739983e8a278457de0aa1",
};
#ifdef CH_POLY1305_AVX2
static const vector_path vector_avx2 = {
    "the AVX2 kernel",
    poly1305_update_avx2_native,
    poly1305_avx2_blocks_native,
    POLY1305_AVX2_GROUP,
    POLY1305_AVX2_MIN,
    "c5354408f81b11f167125292ecbd16dea9de6e9cc08ed44d79b5834f278f2930",
    "0d3a55ddc6bddbe4b600e356cc4d3c5c2d68b85f4d8a2527fcc09fe88cd12ca1"
    "76d066bc4f547a4695a49c9445d255b8cfefebc5e4de9e45841d8285fb147666"
    "7cb51baeded83b1c477ebbabc0683130d8572b56f317a5b8f728dc4a684a33df"
    "6d1ab3c5a354a59447dfaeb5d471955a7ddacdfd4f6a9c92f76e4c22953f8b25",
};
#endif

static const vector_path *current = &vector_128;

#define GROUP (current->group)
#define LENGTH_MAX (current->min + 4 * GROUP + 32)
#define CUT_MAX (2 * GROUP)
#define GROUPS_MAX 12
// The most bytes of whole blocks a direct call's accumulator starts from.
#define PREFIX_MAX ((size_t)64)
#define RANDOM_CASES 20000
#define RANDOM_LENGTH_MAX 2048
#define LARGE_LENGTH ((size_t)65536)
// How far past a 16-byte boundary the native copy's message can start.
#define ALIGN_MAX ((size_t)16)
#define LIMB_MASK 0x3ffffffU

static uint8_t message[LARGE_LENGTH];
static int failures = 0;
static unsigned long compared = 0;

// The number five 26-bit limbs of at most 32 bits hold, reduced modulo
// 2^130 - 5, as five limbs below 2^26. The test may branch: nothing here
// is a secret.
static void reduced(const uint32_t in[5], uint32_t out[5]) {
    uint64_t h[5];
    for (size_t i = 0; i < 5; i++) {
        h[i] = in[i];
    }
    // Three rounds of carries leave every limb below 2^26 and the number
    // below 2^130: 2^130 is 5 modulo 2^130 - 5.
    for (int round = 0; round < 3; round++) {
        for (size_t i = 0; i < 4; i++) {
            h[i + 1] += h[i] >> 26;
            h[i] &= LIMB_MASK;
        }
        h[0] += (h[4] >> 26) * 5;
        h[4] &= LIMB_MASK;
    }
    // A number from 2^130 - 5 to 2^130 - 1 is at least the modulus once.
    if (h[4] == LIMB_MASK && h[3] == LIMB_MASK && h[2] == LIMB_MASK && h[1] == LIMB_MASK &&
        h[0] >= LIMB_MASK - 4) {
        h[0] -= LIMB_MASK - 4;
        h[1] = h[2] = h[3] = h[4] = 0;
    }
    for (size_t i = 0; i < 5; i++) {
        out[i] = (uint32_t)h[i];
    }
}

static int same_value(const poly1305 *a, const poly1305 *b) {
    uint32_t x[5];
    uint32_t y[5];
    reduced(a->h, x);
    reduced(b->h, y);
    return memcmp(x, y, sizeof x) == 0;
}

static void report(const char *case_name, const char *what, size_t n, size_t first_cut,
                   size_t second_cut) {
    failures++;
    (void)fprintf(stderr, "poly1305 equivalence: %s: %s (n %zu, cuts at %zu and %zu)\n", case_name,
                  what, n, first_cut, second_cut);
}

// The portable path over message[0..n) in one update, against the vector
// build over the same bytes in three updates cut at first_cut and
// second_cut, with its copy offset bytes past a 16-byte boundary.
static void compare(const char *case_name, const uint8_t key[POLY1305_KEY], size_t n,
                    size_t first_cut, size_t second_cut, size_t offset) {
    if (second_cut < first_cut || n < second_cut || n > LARGE_LENGTH) {
        (void)fprintf(stderr, "poly1305 equivalence: a case the test cannot hold\n");
        exit(1);
    }
    poly1305 portable;
    poly1305_init(&portable, key);
    poly1305_update(&portable, message, n);

    // An empty case still takes a byte, since malloc(0) may return NULL.
    size_t size = offset + n;
    uint8_t *buffer = malloc(size > 0 ? size : 1);
    if (buffer == NULL) {
        (void)fprintf(stderr, "poly1305 equivalence: out of memory\n");
        exit(1);
    }
    uint8_t *copy = buffer + offset;
    memcpy(copy, message, n);
    poly1305 vector;
    poly1305_init_native(&vector, key);
    current->update(&vector, copy, first_cut);
    current->update(&vector, copy + first_cut, second_cut - first_cut);
    current->update(&vector, copy + second_cut, n - second_cut);
    free(buffer);
    compared++;

    if (!same_value(&portable, &vector)) {
        report(case_name, "the accumulators differ modulo 2^130 - 5", n, first_cut, second_cut);
    }
    if (portable.fill != vector.fill || memcmp(portable.block, vector.block, portable.fill) != 0) {
        report(case_name, "the buffered partial blocks differ", n, first_cut, second_cut);
    }
    uint8_t want[POLY1305_TAG];
    uint8_t got[POLY1305_TAG];
    poly1305_final(&portable, want);
    poly1305_final_native(&vector, got);
    if (memcmp(want, got, sizeof want) != 0) {
        report(case_name, "the tags differ", n, first_cut, second_cut);
    }
}

// Every length, each cut once at every odd offset below CUT_MAX and once
// more halfway through the rest.
static void run_every_length(void) {
    uint8_t key[POLY1305_KEY];
    for (size_t n = 0; n <= LENGTH_MAX && failures == 0; n++) {
        rng_fill(key, sizeof key);
        rng_fill(message, n);
        compare("every length", key, n, 0, 0, 0);
        for (size_t cut = 1; cut < CUT_MAX && cut <= n; cut += 2) {
            compare("every length", key, n, cut, cut + (n - cut) / 2, cut % ALIGN_MAX);
        }
    }
}

// The largest limbs and the smallest: a key of all 0xff clamps to the
// largest r, and blocks of all 0xff give the largest limbs, which carry
// into every limb of every sum; r of 0 and blocks of 0 meet the other
// end.
static void run_extremes(void) {
    static const uint8_t fills[] = {0x00, 0xff};
    uint8_t key[POLY1305_KEY];
    for (size_t k = 0; k < sizeof fills; k++) {
        for (size_t f = 0; f < sizeof fills; f++) {
            memset(key, fills[k], sizeof key);
            memset(message, fills[f], LENGTH_MAX);
            for (size_t n = 16; n <= LENGTH_MAX && failures == 0; n += 16) {
                compare("extremes", key, n, 0, 0, 0);
                compare("extremes", key, n, n / 3 | 1, n / 3 | 1, 3);
            }
        }
    }
}

// The path's blocks entry called alone on message[prefix..prefix + n),
// after poly1305_update took the prefix bytes, against the portable path
// over all of it. On return the accumulator must hold the portable path's
// value within the bounds poly1305_vector.h states.
static void compare_direct(const char *case_name, const uint8_t key[POLY1305_KEY], size_t prefix,
                           size_t n) {
    poly1305 portable;
    poly1305_init(&portable, key);
    poly1305_update(&portable, message, prefix + n);
    poly1305 vector;
    poly1305_init(&vector, key);
    poly1305_update(&vector, message, prefix);
    current->blocks(&vector, message + prefix, n);
    compared++;
    if (!same_value(&portable, &vector)) {
        report(case_name, "the accumulators differ modulo 2^130 - 5", n, prefix, prefix);
    }
    if (vector.h[0] > LIMB_MASK || vector.h[1] > LIMB_MASK + 1 || vector.h[2] > LIMB_MASK ||
        vector.h[3] > LIMB_MASK || vector.h[4] > LIMB_MASK) {
        report(case_name, "a limb is past the bounds poly1305_vector.h states", n, prefix, prefix);
    }
}

// One group to GROUPS_MAX groups, from the accumulator that zero to four
// random blocks left. One group is below POLY1305_VECTOR_MIN, so only a
// direct call reaches the path with it.
static void run_direct(void) {
    uint8_t key[POLY1305_KEY];
    for (size_t groups = 1; groups <= GROUPS_MAX && failures == 0; groups++) {
        for (size_t prefix = 0; prefix <= PREFIX_MAX; prefix += 16) {
            rng_fill(key, sizeof key);
            rng_fill(message, prefix + GROUP * groups);
            compare_direct("direct", key, prefix, GROUP * groups);
        }
    }
}

// The path's key and group whose lane totals leave h1 past 2^26 after the
// first pass of carry_scalar. The second pass must bring h1 back to at
// most 2^26.
static void run_wide_h1(void) {
    uint8_t key[POLY1305_KEY];
    unhex(current->wide_h1_key, key, sizeof key);
    unhex(current->wide_h1_group, message, GROUP);
    compare_direct("wide h1", key, 0, GROUP);
}

#include "poly1305_equiv_residue.h"

static void run_random(void) {
    uint8_t key[POLY1305_KEY];
    for (unsigned long i = 0; i < RANDOM_CASES && failures == 0; i++) {
        rng_fill(key, sizeof key);
        size_t n = (size_t)(rng_next() % (RANDOM_LENGTH_MAX + 1));
        rng_fill(message, n);
        size_t first_cut = (size_t)(rng_next() % (n + 1));
        size_t second_cut = first_cut + (size_t)(rng_next() % (n - first_cut + 1));
        compare("random", key, n, first_cut, second_cut, (size_t)(rng_next() % ALIGN_MAX));
    }
}

// A 16 KiB record's TLSInnerPlaintext, the plaintext and its content type
// byte, and 64 KiB, each in one update and cut at odd offsets.
static void run_large(void) {
    static const size_t lengths[] = {16385, LARGE_LENGTH};
    uint8_t key[POLY1305_KEY];
    for (size_t l = 0; l < sizeof lengths / sizeof lengths[0] && failures == 0; l++) {
        size_t n = lengths[l];
        rng_fill(key, sizeof key);
        rng_fill(message, n);
        compare("large", key, n, 0, 0, 0);
        compare("large", key, n, 5, n / 2 + 1, 7);
    }
}

// Every case above, against one path. The generator starts again from
// the seed, so each path meets the same keys and messages.
static void run_path(const vector_path *path, uint64_t seed) {
    current = path;
    rng_state = seed;
    unsigned long before_path = compared;
    run_every_length();
    run_extremes();
    run_direct();
    run_wide_h1();
    run_residue();
    run_random();
    run_large();
    printf("poly1305 equivalence: %lu cases agree between the portable loop and %s "
           "(seed 0x%llx)\n",
           compared - before_path, path->name, (unsigned long long)seed);
}

int main(void) {
    uint64_t seed = rng_seed_from_env();
    run_path(&vector_128, seed);
#ifdef CH_POLY1305_AVX2
    if (x86_cpu_has_avx2()) {
        run_path(&vector_avx2, seed);
    } else if (x86_kernels_required()) {
        (void)fprintf(stderr, "poly1305 equivalence: this CPU lacks AVX2, and "
                              "CH_REQUIRE_X86_KERNELS is 1\n");
        return 1;
    } else {
        printf("poly1305 equivalence: SKIP the AVX2 kernel: this CPU lacks AVX2\n");
    }
#endif
    if (failures > 0) {
        printf("poly1305 equivalence: %d mismatches\n", failures);
        return 1;
    }
    return 0;
}
