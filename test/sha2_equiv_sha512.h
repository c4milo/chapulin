// SHA-512 and SHA-384 as a host object runs them, against sha512.c's second
// arm, the reference a device object runs (test/sha512_portable.c): the
// cases test/sha2_equiv_test.c runs for SHA-256, at SHA-512's block of 128
// bytes, for both hashes. A host object has two paths to hold to that arm:
//
//   - sha512.c's first arm over sha512_compress_blocks.c, plain C that every
//     session runs under the library's own names (docs/decisions.md 127),
//     which the cases run on every machine;
//   - sha512_hw.c: on arm64 the SHA-512 instructions, and on x86-64
//     sha512.c's first arm once more over sha512_avx2.c's kernel, the
//     message schedule in AVX2 registers (docs/decisions.md 128). The cases
//     run on a CPU with the instructions or with AVX2.
//
// Every case hashes the message on the reference in one call, and a copy of
// it in three updates and a final. Each of those four calls runs on the
// path the case holds where its bit of the case's mask is set, and on the
// reference where it is clear, so a context passes between the two at each
// call. The case compares the two contexts before the final, then the
// digests, and the digest of the path's call that takes a whole message.
// The copy is in a heap buffer that ends where the message ends.
//
// The inputs: every length from 0 to LENGTH512_MAX cut at every offset
// below CUT512_MAX; messages of all 0x00 and all 0xff at every length a
// block boundary is next to; RANDOM_CASES random lengths, cuts, alignments
// and masks; 16,385 bytes and 64 KiB; an update of no bytes from a NULL
// pointer and the empty message's two digests, which FIPS 180-4 fixes; and,
// for sha512_hw.c, HMAC, HKDF and the key schedule at SHA-384's hash length
// in the copies hkdf_hw.c and keysched_hw.c hold.
// test/sha2_equiv_residue512.h then looks in the stack each kind of call
// leaves, and on x86-64 in the vector registers after the kernel's call.
//
// Included by test/sha2_equiv_test.c only, which declares the generator,
// the message, report and the counts this file uses.
#ifndef CH_SHA2_EQUIV_SHA512_H
#define CH_SHA2_EQUIV_SHA512_H

#include "sha512.h"
#include "sha512_compress_blocks.h"
#include "sha512_portable.h"

#define LENGTH512_MAX ((size_t)(4 * SHA512_BLOCK + 17))
#define CUT512_MAX ((size_t)(2 * SHA512_BLOCK + 2))

// One path's five calls that hash, and what a failure calls the path.
typedef struct {
    const char *name;
    void (*update)(sha512 *s, const uint8_t *in, size_t n);
    void (*final512)(sha512 *s, uint8_t out[SHA512_LEN]);
    void (*final384)(sha512 *s, uint8_t out[SHA384_LEN]);
    void (*of512)(const uint8_t *in, size_t n, uint8_t out[SHA512_LEN]);
    void (*of384)(const uint8_t *in, size_t n, uint8_t out[SHA384_LEN]);
} path512;

// The reference: sha512.c's second arm over sha512_compress.c.
static const path512 PATH512_REFERENCE = {"sha512.c's second arm", sha512_update_portable,
                                          sha512_final_portable,   sha384_final_portable,
                                          sha512_of_portable,      sha384_of_portable};

// The library's own names, which in this binary are sha512.c's first arm
// over sha512_compress_blocks.c.
static const path512 PATH512_FIRST_ARM = {"sha512.c's first arm", sha512_update, sha512_final,
                                          sha384_final,           sha512_of,     sha384_of};

// sha512_hw.c's five calls: the SHA-512 instructions on arm64, and
// sha512_avx2.c's kernel on x86-64.
static const path512 PATH512_INSTRUCTIONS = {"sha512_hw.c",   sha512_update_hw, sha512_final_hw,
                                             sha384_final_hw, sha512_of_hw,     sha384_of_hw};

// The two hashes a case runs: SHA-384 where is384 is set, and SHA-512.
// Either path's contexts start from the library's two calls, as a
// session's do.
static void init512(int is384, sha512 *s) {
    if (is384) {
        sha384_init(s);
    } else {
        sha512_init(s);
    }
}

static size_t digest_len512(int is384) {
    return is384 ? SHA384_LEN : SHA512_LEN;
}

// The path a call of a case runs on: held where the call's bit is set, and
// the reference where it is clear.
static const path512 *path512_of(const path512 *held, unsigned bit) {
    return bit != 0 ? held : &PATH512_REFERENCE;
}

static void final512_on(const path512 *path, int is384, sha512 *s, uint8_t *out) {
    if (is384) {
        path->final384(s, out);
    } else {
        path->final512(s, out);
    }
}

static void whole_message512_on(const path512 *path, int is384, const uint8_t *in, size_t n,
                                uint8_t *out) {
    if (is384) {
        path->of384(in, n, out);
    } else {
        path->of512(in, n, out);
    }
}

// Whether two contexts hold the same state: the eight words, the byte
// count and the buffered partial block.
static int same_state512(const sha512 *a, const sha512 *b) {
    return memcmp(a->h, b->h, sizeof a->h) == 0 && a->total_bytes == b->total_bytes &&
           a->fill == b->fill && memcmp(a->block, b->block, a->fill) == 0;
}

// One comparison's failure, with the path it held.
static void report512(const path512 *held, const char *case_name, const char *what, size_t n,
                      size_t first_cut, size_t second_cut, unsigned paths) {
    (void)fprintf(stderr, "sha2 equivalence: %s against the reference:\n", held->name);
    report(case_name, what, n, first_cut, second_cut, paths);
}

// compare for one of the two hashes and one path: the reference over
// message[0..n) in one update, against a copy in three updates cut at
// first_cut and second_cut and a final, each on held where its bit of paths
// is set.
static void compare512(const path512 *held, const char *case_name, int is384, size_t n,
                       size_t first_cut, size_t second_cut, size_t offset, unsigned paths) {
    if (second_cut < first_cut || n < second_cut || n > LARGE_LENGTH) {
        (void)fprintf(stderr, "sha2 equivalence: a case the test cannot hold\n");
        exit(1);
    }
    sha512 reference;
    init512(is384, &reference);
    sha512_update_portable(&reference, message, n);

    size_t size = offset + n;
    uint8_t *buffer = malloc(size > 0 ? size : 1);
    if (buffer == NULL) {
        (void)fprintf(stderr, "sha2 equivalence: out of memory\n");
        exit(1);
    }
    uint8_t *copy = buffer + offset;
    memcpy(copy, message, n);
    sha512 mixed;
    init512(is384, &mixed);
    path512_of(held, paths & 1U)->update(&mixed, copy, first_cut);
    path512_of(held, paths & 2U)->update(&mixed, copy + first_cut, second_cut - first_cut);
    path512_of(held, paths & 4U)->update(&mixed, copy + second_cut, n - second_cut);
    uint8_t whole[SHA512_LEN];
    whole_message512_on(held, is384, copy, n, whole);
    free(buffer);
    compared++;

    if (!same_state512(&reference, &mixed)) {
        report512(held, case_name, "the SHA-512 contexts differ before the final", n, first_cut,
                  second_cut, paths);
    }
    uint8_t want[SHA512_LEN];
    uint8_t got[SHA512_LEN];
    final512_on(&PATH512_REFERENCE, is384, &reference, want);
    final512_on(path512_of(held, paths & PATH_FINAL), is384, &mixed, got);
    if (memcmp(want, got, digest_len512(is384)) != 0) {
        report512(held, case_name,
                  is384 ? "the SHA-384 digests differ" : "the SHA-512 digests differ", n, first_cut,
                  second_cut, paths);
    }
    if (memcmp(want, whole, digest_len512(is384)) != 0) {
        report512(held, case_name,
                  is384 ? "the whole message's SHA-384 digest differs"
                        : "the whole message's SHA-512 digest differs",
                  n, first_cut, second_cut, paths);
    }
}

static void run_every_length512(const path512 *held) {
    for (size_t n = 0; n <= LENGTH512_MAX && failures == 0; n++) {
        rng_fill(message, n);
        compare512(held, "every length", 0, n, 0, 0, 0, PATHS_ALL);
        compare512(held, "every length", 1, n, 0, 0, 0, PATHS_ALL);
        for (size_t cut = 1; cut < CUT512_MAX && cut <= n; cut++) {
            compare512(held, "every length", (int)(cut & 1U), n, cut, cut + (n - cut) / 2,
                       cut % ALIGN_MAX, (unsigned)(cut % (PATHS_ALL + 1)));
        }
    }
}

// The padding takes a block of its own from 112 bytes into a block on.
static void run_extremes512(const path512 *held) {
    static const uint8_t fills[] = {0x00, 0xff};
    for (size_t f = 0; f < sizeof fills; f++) {
        memset(message, fills[f], LENGTH512_MAX + SHA512_BLOCK);
        for (size_t n = 0; n <= LENGTH512_MAX && failures == 0; n++) {
            size_t into_block = n % SHA512_BLOCK;
            if (into_block <= 2 || into_block >= SHA512_BLOCK - 18) {
                compare512(held, "extremes", 0, n, 0, 0, 0, PATHS_ALL);
                compare512(held, "extremes", 1, n, n / 3, n / 2, 5, 5U);
            }
        }
    }
}

static void run_random512(const path512 *held) {
    for (unsigned long i = 0; i < RANDOM_CASES && failures == 0; i++) {
        size_t n = (size_t)(rng_next() % (RANDOM_LENGTH_MAX + 1));
        rng_fill(message, n);
        size_t first_cut = (size_t)(rng_next() % (n + 1));
        size_t second_cut = first_cut + (size_t)(rng_next() % (n - first_cut + 1));
        size_t offset = (size_t)(rng_next() % ALIGN_MAX);
        unsigned paths = (unsigned)(rng_next() % (PATHS_ALL + 1));
        compare512(held, "random", (int)(i & 1U), n, first_cut, second_cut, offset, paths);
    }
}

static void run_large512(const path512 *held) {
    static const size_t lengths[] = {16385, LARGE_LENGTH};
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
        rng_fill(message, lengths[i]);
        compare512(held, "large", 0, lengths[i], 0, 0, 0, PATHS_ALL);
        compare512(held, "large", 1, lengths[i], 1, lengths[i] - 1, 3, PATHS_ALL);
        compare512(held, "large", 1, lengths[i], 127, 4097, 1, 5U);
    }
}

// An update of no bytes takes a NULL pointer, and the empty message has
// the two digests FIPS 180-4's examples give.
static void run_empty512(const path512 *held) {
    static const uint8_t empty384[SHA384_LEN] = {
        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e,
        0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
        0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf,
        0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b};
    static const uint8_t empty512[SHA512_LEN] = {
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6,
        0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4,
        0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2,
        0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd,
        0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e};
    uint8_t got[SHA512_LEN];
    sha512 s;
    sha384_init(&s);
    held->update(&s, NULL, 0);
    held->final384(&s, got);
    compared++;
    if (memcmp(got, empty384, SHA384_LEN) != 0) {
        report512(held, "empty", "the empty message's SHA-384 digest is not FIPS 180-4's", 0, 0, 0,
                  PATHS_ALL);
    }
    held->of512(NULL, 0, got);
    compared++;
    if (memcmp(got, empty512, SHA512_LEN) != 0) {
        report512(held, "empty", "the empty message's SHA-512 digest is not FIPS 180-4's", 0, 0, 0,
                  PATHS_ALL);
    }
}

// Every case that hashes, for one path.
static void run_cases512(const path512 *held) {
    run_every_length512(held);
    run_extremes512(held);
    run_random512(held);
    run_large512(held);
    run_empty512(held);
}

#include "sha2_equiv_residue512.h"

// sha512.c's first arm, on every machine: the cases, and then what each
// kind of call leaves on the stack.
static void run_sha512_first_arm(void) {
    run_cases512(&PATH512_FIRST_ARM);
    run_residue512_first_arm();
}

#include "sha2_equiv_copies384.h"

#ifdef __x86_64__
// sha512_hw.c over sha512_avx2.c's kernel, on a CPU with AVX2. On one
// without it the cases skip, or fail where the environment requires the
// x86-64 kernels (test/x86_kernels_cpu.h).
static void run_sha512_instructions(void) {
    if (!x86_cpu_has_avx2()) {
        if (x86_kernels_required()) {
            failures++;
            (void)fprintf(stderr, "sha2 equivalence: this CPU lacks AVX2, and "
                                  "CH_REQUIRE_X86_KERNELS is 1\n");
            return;
        }
        (void)printf("SKIP sha2 equivalence, SHA-512 on AVX2: this CPU lacks AVX2\n");
        return;
    }
    run_cases512(&PATH512_INSTRUCTIONS);
    run_copies384();
    run_residue512_avx2();
}
#else
// sha512_hw.c, on a CPU with the instructions. On one without them the
// cases skip, or fail where the environment requires the instructions
// (test/hash_instructions_cpu.h).
static void run_sha512_instructions(void) {
    if (!cpu_has_sha512_instructions()) {
        if (hash_instructions_required()) {
            failures++;
            (void)fprintf(stderr, "sha2 equivalence: this CPU lacks the SHA-512 instructions, and "
                                  "CH_REQUIRE_HASH_INSTRUCTIONS is 1\n");
            return;
        }
        (void)printf("SKIP sha2 equivalence, SHA-512: this CPU lacks the SHA-512 instructions\n");
        return;
    }
    run_cases512(&PATH512_INSTRUCTIONS);
    run_copies384();
    run_residue512_instructions();
}
#endif

#endif
