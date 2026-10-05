// SHA-512 and SHA-384 on arm64's SHA-512 instructions against sha512.c:
// the cases test/sha2_equiv_test.c runs for SHA-256, at SHA-512's block of
// 128 bytes, for both hashes. sha512_hw.c has a body on arm64 alone, and so
// has this file: an x86-64 host object holds SHA-512 on sha512.c alone
// (cpu_cfg.h), so there is no second path to hold to it.
//
// Every case hashes the message on the portable path in one call, and a
// copy of it in three updates and a final, each on the path one bit of the
// case's mask names. It compares the two contexts before the final, then
// the digests, and the digest of the call that takes a whole message. The
// copy sits in a heap buffer that ends where the message ends.
//
// The inputs: every length from 0 to LENGTH512_MAX cut at every offset
// below CUT512_MAX; messages of all 0x00 and all 0xff at every length a
// block boundary is next to; RANDOM_CASES random lengths, cuts, alignments
// and masks; 16,385 bytes and 64 KiB; an update of no bytes from a NULL
// pointer and the empty message's two digests, which FIPS 180-4 fixes; and
// HMAC, HKDF and the key schedule at SHA-384's hash length in the copies
// hkdf_hw.c and keysched_hw.c hold. test/sha2_equiv_residue512.h then
// looks in the stack each kind of call leaves.
//
// Included by test/sha2_equiv_test.c only, on arm64, which declares the
// generator, the message, report and the counts this file uses.
#ifndef CH_SHA2_EQUIV_SHA512_H
#define CH_SHA2_EQUIV_SHA512_H

#include "sha512.h"

#define LENGTH512_MAX ((size_t)(4 * SHA512_BLOCK + 17))
#define CUT512_MAX ((size_t)(2 * SHA512_BLOCK + 2))

// The two hashes a case runs: SHA-384 where is384 is set, and SHA-512.
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

// One call on the path the bit names.
static void update512_on(unsigned on_instructions, sha512 *s, const uint8_t *in, size_t n) {
    if (on_instructions != 0) {
        sha512_update_hw(s, in, n);
    } else {
        sha512_update(s, in, n);
    }
}

static void final512_on(unsigned on_instructions, int is384, sha512 *s, uint8_t *out) {
    if (is384 && on_instructions != 0) {
        sha384_final_hw(s, out);
    } else if (is384) {
        sha384_final(s, out);
    } else if (on_instructions != 0) {
        sha512_final_hw(s, out);
    } else {
        sha512_final(s, out);
    }
}

static void whole_message512_hw(int is384, const uint8_t *in, size_t n, uint8_t *out) {
    if (is384) {
        sha384_of_hw(in, n, out);
    } else {
        sha512_of_hw(in, n, out);
    }
}

// Whether two contexts hold the same state: the eight words, the byte
// count and the buffered partial block.
static int same_state512(const sha512 *a, const sha512 *b) {
    return memcmp(a->h, b->h, sizeof a->h) == 0 && a->total_bytes == b->total_bytes &&
           a->fill == b->fill && memcmp(a->block, b->block, a->fill) == 0;
}

// compare for one of the two hashes: the portable path over message[0..n)
// in one update, against a copy in three updates cut at first_cut and
// second_cut and a final, each on the path its bit of paths names.
static void compare512(const char *case_name, int is384, size_t n, size_t first_cut,
                       size_t second_cut, size_t offset, unsigned paths) {
    if (second_cut < first_cut || n < second_cut || n > LARGE_LENGTH) {
        (void)fprintf(stderr, "sha2 equivalence: a case the test cannot hold\n");
        exit(1);
    }
    sha512 portable;
    init512(is384, &portable);
    sha512_update(&portable, message, n);

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
    update512_on(paths & 1U, &mixed, copy, first_cut);
    update512_on(paths & 2U, &mixed, copy + first_cut, second_cut - first_cut);
    update512_on(paths & 4U, &mixed, copy + second_cut, n - second_cut);
    uint8_t whole[SHA512_LEN];
    whole_message512_hw(is384, copy, n, whole);
    free(buffer);
    compared++;

    if (!same_state512(&portable, &mixed)) {
        report(case_name, "the SHA-512 contexts differ before the final", n, first_cut, second_cut,
               paths);
    }
    uint8_t want[SHA512_LEN];
    uint8_t got[SHA512_LEN];
    final512_on(0, is384, &portable, want);
    final512_on(paths & PATH_FINAL, is384, &mixed, got);
    if (memcmp(want, got, digest_len512(is384)) != 0) {
        report(case_name, is384 ? "the SHA-384 digests differ" : "the SHA-512 digests differ", n,
               first_cut, second_cut, paths);
    }
    if (memcmp(want, whole, digest_len512(is384)) != 0) {
        report(case_name, is384 ? "sha384_of_hw's digest differs" : "sha512_of_hw's digest differs",
               n, first_cut, second_cut, paths);
    }
}

static void run_every_length512(void) {
    for (size_t n = 0; n <= LENGTH512_MAX && failures == 0; n++) {
        rng_fill(message, n);
        compare512("every length", 0, n, 0, 0, 0, PATHS_ALL);
        compare512("every length", 1, n, 0, 0, 0, PATHS_ALL);
        for (size_t cut = 1; cut < CUT512_MAX && cut <= n; cut++) {
            compare512("every length", (int)(cut & 1U), n, cut, cut + (n - cut) / 2,
                       cut % ALIGN_MAX, (unsigned)(cut % (PATHS_ALL + 1)));
        }
    }
}

// The padding takes a block of its own from 112 bytes into a block on.
static void run_extremes512(void) {
    static const uint8_t fills[] = {0x00, 0xff};
    for (size_t f = 0; f < sizeof fills; f++) {
        memset(message, fills[f], LENGTH512_MAX + SHA512_BLOCK);
        for (size_t n = 0; n <= LENGTH512_MAX && failures == 0; n++) {
            size_t into_block = n % SHA512_BLOCK;
            if (into_block <= 2 || into_block >= SHA512_BLOCK - 18) {
                compare512("extremes", 0, n, 0, 0, 0, PATHS_ALL);
                compare512("extremes", 1, n, n / 3, n / 2, 5, 5U);
            }
        }
    }
}

static void run_random512(void) {
    for (unsigned long i = 0; i < RANDOM_CASES && failures == 0; i++) {
        size_t n = (size_t)(rng_next() % (RANDOM_LENGTH_MAX + 1));
        rng_fill(message, n);
        size_t first_cut = (size_t)(rng_next() % (n + 1));
        size_t second_cut = first_cut + (size_t)(rng_next() % (n - first_cut + 1));
        size_t offset = (size_t)(rng_next() % ALIGN_MAX);
        unsigned paths = (unsigned)(rng_next() % (PATHS_ALL + 1));
        compare512("random", (int)(i & 1U), n, first_cut, second_cut, offset, paths);
    }
}

static void run_large512(void) {
    static const size_t lengths[] = {16385, LARGE_LENGTH};
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
        rng_fill(message, lengths[i]);
        compare512("large", 0, lengths[i], 0, 0, 0, PATHS_ALL);
        compare512("large", 1, lengths[i], 1, lengths[i] - 1, 3, PATHS_ALL);
        compare512("large", 1, lengths[i], 127, 4097, 1, 5U);
    }
}

// An update of no bytes takes a NULL pointer, and the empty message has
// the two digests FIPS 180-4's examples give.
static void run_empty512(void) {
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
    sha512_update_hw(&s, NULL, 0);
    sha384_final_hw(&s, got);
    compared++;
    if (memcmp(got, empty384, SHA384_LEN) != 0) {
        report("empty", "the empty message's SHA-384 digest is not FIPS 180-4's", 0, 0, 0,
               PATHS_ALL);
    }
    sha512_of_hw(NULL, 0, got);
    compared++;
    if (memcmp(got, empty512, SHA512_LEN) != 0) {
        report("empty", "the empty message's SHA-512 digest is not FIPS 180-4's", 0, 0, 0,
               PATHS_ALL);
    }
}

#include "sha2_equiv_copies384.h"
#include "sha2_equiv_residue512.h"

// Every SHA-512 and SHA-384 case, on a CPU with the instructions. On one
// without them the cases skip, or fail where the environment requires the
// instructions (test/hash_instructions_cpu.h).
static void run_sha512(void) {
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
    run_every_length512();
    run_extremes512();
    run_random512();
    run_large512();
    run_empty512();
    run_copies384();
    run_residue512();
}

#endif
