// SHA-512 and SHA-384 (FIPS 180-4) on arm64's SHA-512 instructions, through <arm_neon.h>'s
// vsha512hq_u64, vsha512h2q_u64, vsha512su0q_u64 and vsha512su1q_u64: the compression function
// over whole blocks, and the five calls sha512.h declares around it. An arm64 host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h) compiles this file beside sha512.c and sha512_compress_blocks.c,
// and sha512.h's entries call it for a session whose caller set CH_CPU_CONSTANT_TIME_SHA512
// (docs/decisions.md 93). No x86-64 CPU this tree targets has SHA-512 instructions, so on
// x86-64 the file holds nothing, and cpu_cfg.h refuses the bit there.
//
// The object compiles this file with no instruction flag, so the rest of the object runs on any
// arm64 CPU. The pragma below puts the target attribute that turns the instructions on onto
// each function in this file and on no function outside it, as sha256_hw.c does. Nothing here
// probes a CPU: the caller does, and states what it found in ch_cfg.cpu.
//
// SHA-384 is the hash of TLS_AES_256_GCM_SHA384's key schedule, so this file reads HMAC keys
// and traffic secrets, and its timing matters. It reads no table with a secret index and
// branches on lengths alone, which is what it can state for itself. Whether the instructions
// take the same time whatever their operands are is the CPU's, in the mode the thread runs in,
// and CH_CPU_CONSTANT_TIME_SHA512 is the caller's statement that they do (cpu_cfg.h).
//
// CBMC cannot read an intrinsic, so no proof compiles this file. bin/sha2_equiv_test holds it
// to sha512.c's second arm over sha512_compress.c, the reference a device object runs, over
// every length and split it tries, FIPS 180-4's vectors run on it in bin/sha512_test_host, RFC
// 4231's and RFC 5869's in bin/hkdf384_test_host, and the Wycheproof HMAC and HKDF suites in
// the Wycheproof host binary (docs/verification.md, "The hash instructions").
#include "sha512.h"

#if defined(CH_CPU_RUNTIME) && defined(__aarch64__)

#include <arm_neon.h>
#include <string.h>

#include "ct.h"
#include "sha512_round_constants.h"

// Two 64-bit words of the state or of the message schedule.
typedef uint64x2_t words;

// Every function from here to the pop at the end of this file carries the target attribute that
// turns the instructions on. Its name is "sha3": the Arm C Language Extensions put FEAT_SHA512's
// four instructions and FEAT_SHA3's four, EOR3, RAX1, XAR and BCAX, under that one feature. The
// SHA-512 bit states nothing about FEAT_SHA3's, and with the attribute on a compiler writes them
// for plain C: clang 23 wrote EOR3 for an exclusive OR of three vectors, and for a loop over
// three arrays that it turned into vectors. So this file computes no exclusive OR, and
// test/hash-builds.sh and test/aes-runtime-disasm.sh require that its object holds none of the
// four.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("sha3"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("+sha3")
#endif

// Everything compress_blocks computes from the state and the message, in one object so that
// one wipe when it ends clears all of it: under HMAC the first block is the key, and the state
// after it stands for the key.
typedef struct {
    words ab; // the working variables a to h, two to a vector
    words cd;
    words ef;
    words gh;
    words ab_start; // all four as the block began
    words cd_start;
    words ef_start;
    words gh_start;
    words w0; // sixteen words of the message schedule, the oldest two first
    words w1;
    words w2;
    words w3;
    words w4;
    words w5;
    words w6;
    words w7;
    words with_constants; // two schedule words, each plus its round constant
    words sum;            // those two, in the other order, plus g and h
    words half;           // what SHA512H leaves: the two sums the new e and f and the new a
                          // and b are both made from
} block_state;

// A field of a block_state, read from memory at the point of use, as sha256_hw.c's kept reads
// one. The state a block began with is added back when the block ends, eighty rounds later.
// Read this way, the four vectors stay in the block_state for those rounds, where the wipe
// clears them, and in no register or stack slot of the compiler's own.
static inline words kept(const words *field) {
    const volatile words *in_state = field;
    return *in_state;
}

// Two message words as the hash reads them, most significant byte first (FIPS 180-4 §5.2.2).
static inline words load_block_words(const uint8_t *p) {
    return vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p)));
}

// Rounds 2 * pair and 2 * pair + 1 (FIPS 180-4 §6.4.2 step 3) on the two words in current. The
// four pointers name the state's vectors by what each holds before the two rounds. After them
// the vector at gh holds the new a and b and the one at cd the new e and f, and the other two
// are untouched: the old a and b are the new c and d, and the old e and f the new g and h. So
// the next pair takes the same four vectors with each name moved on by one place, and four
// pairs bring every name back to where it began.
static inline void round_pair(block_state *c, const words *ab, words *cd, const words *ef,
                              words *gh, words current, size_t pair) {
    c->with_constants = vaddq_u64(current, vld1q_u64(&sha512_round_constants[2 * pair]));
    c->sum = vaddq_u64(vextq_u64(c->with_constants, c->with_constants, 1), *gh);
    c->half = vsha512hq_u64(c->sum, vextq_u64(*ef, *gh, 1), vextq_u64(*cd, *ef, 1));
    *gh = vsha512h2q_u64(c->half, *cd, *ab);
    *cd = vaddq_u64(*cd, c->half);
}

// Sixteen rounds from round 2 * first, on the eight vectors of the schedule in order: eight
// pairs, which move the state's names all the way round twice.
static inline void sixteen_rounds(block_state *c, size_t first) {
    round_pair(c, &c->ab, &c->cd, &c->ef, &c->gh, c->w0, first);
    round_pair(c, &c->gh, &c->ab, &c->cd, &c->ef, c->w1, first + 1);
    round_pair(c, &c->ef, &c->gh, &c->ab, &c->cd, c->w2, first + 2);
    round_pair(c, &c->cd, &c->ef, &c->gh, &c->ab, c->w3, first + 3);
    round_pair(c, &c->ab, &c->cd, &c->ef, &c->gh, c->w4, first + 4);
    round_pair(c, &c->gh, &c->ab, &c->cd, &c->ef, c->w5, first + 5);
    round_pair(c, &c->ef, &c->gh, &c->ab, &c->cd, c->w6, first + 6);
    round_pair(c, &c->cd, &c->ef, &c->gh, &c->ab, c->w7, first + 7);
}

// The two schedule words sixteen after current's (FIPS 180-4 §6.4.2 step 1): from current, the
// two after it, the two seven before the new ones, which lie across two vectors, and the two
// before the new ones.
static inline words schedule(words current, words next, words seven_back_low, words seven_back_high,
                             words two_back) {
    return vsha512su1q_u64(vsha512su0q_u64(current, next), two_back,
                           vextq_u64(seven_back_low, seven_back_high, 1));
}

// The schedule's next sixteen words over its last sixteen, two at a time. Each step reads the
// vectors the steps before it wrote.
static inline void next_sixteen_words(block_state *c) {
    c->w0 = schedule(c->w0, c->w1, c->w4, c->w5, c->w7);
    c->w1 = schedule(c->w1, c->w2, c->w5, c->w6, c->w0);
    c->w2 = schedule(c->w2, c->w3, c->w6, c->w7, c->w1);
    c->w3 = schedule(c->w3, c->w4, c->w7, c->w0, c->w2);
    c->w4 = schedule(c->w4, c->w5, c->w0, c->w1, c->w3);
    c->w5 = schedule(c->w5, c->w6, c->w1, c->w2, c->w4);
    c->w6 = schedule(c->w6, c->w7, c->w2, c->w3, c->w5);
    c->w7 = schedule(c->w7, c->w0, c->w3, c->w4, c->w6);
}

// FIPS 180-4 §6.4.2 over blocks whole blocks at p: h in, h out, with every value it computes
// on the way in c.
static inline void run_blocks(block_state *c, uint64_t h[8], const uint8_t *p, size_t blocks) {
    c->ab = vld1q_u64(h);
    c->cd = vld1q_u64(h + 2);
    c->ef = vld1q_u64(h + 4);
    c->gh = vld1q_u64(h + 6);
    for (; blocks > 0; blocks--) {
        c->ab_start = c->ab;
        c->cd_start = c->cd;
        c->ef_start = c->ef;
        c->gh_start = c->gh;
        c->w0 = load_block_words(p);
        c->w1 = load_block_words(p + 16);
        c->w2 = load_block_words(p + 32);
        c->w3 = load_block_words(p + 48);
        c->w4 = load_block_words(p + 64);
        c->w5 = load_block_words(p + 80);
        c->w6 = load_block_words(p + 96);
        c->w7 = load_block_words(p + 112);
        // Eighty rounds, sixteen at a time. The block's own sixteen words serve the first
        // sixteen, and the schedule gives the next sixteen before each of the other four. Each
        // of the two calls stands once in this file, so gcc at -O2 compiles both into this
        // loop: called from two places, sixteen_rounds stayed a function of its own there and
        // passed the state through memory at every call (docs/decisions.md 93).
        for (size_t first = 0; first < 40; first += 8) {
            if (first > 0) {
                next_sixteen_words(c);
            }
            sixteen_rounds(c, first);
        }
        c->ab = vaddq_u64(c->ab, kept(&c->ab_start));
        c->cd = vaddq_u64(c->cd, kept(&c->cd_start));
        c->ef = vaddq_u64(c->ef, kept(&c->ef_start));
        c->gh = vaddq_u64(c->gh, kept(&c->gh_start));
        p += SHA512_BLOCK;
    }
    vst1q_u64(h, c->ab);
    vst1q_u64(h + 2, c->cd);
    vst1q_u64(h + 4, c->ef);
    vst1q_u64(h + 6, c->gh);
}

// The compression function over blocks whole blocks at p, and the wipe of what it computed.
static void compress_blocks(uint64_t h[8], const uint8_t *p, size_t blocks) {
    block_state c;
    run_blocks(&c, h, p, blocks);
    ct_wipe(&c, sizeof c);
}

void sha512_update_hw(sha512 *s, const uint8_t *in, size_t n) {
    // No byte to take: in may be NULL, which no step below may offset or copy from.
    if (n == 0) {
        return;
    }
    s->total_bytes += n;
    if (s->fill > 0) {
        size_t take = SHA512_BLOCK - s->fill;
        if (take > n) {
            take = n;
        }
        memcpy(s->block + s->fill, in, take);
        s->fill += take;
        in += take;
        n -= take;
        if (s->fill < SHA512_BLOCK) {
            return;
        }
        compress_blocks(s->h, s->block, 1);
        s->fill = 0;
    }
    size_t whole = n / SHA512_BLOCK;
    if (whole > 0) {
        compress_blocks(s->h, in, whole);
        in += whole * SHA512_BLOCK;
        n -= whole * SHA512_BLOCK;
    }
    memcpy(s->block, in, n);
    s->fill = n;
}

// FIPS 180-4 §5.1.2: the 1 bit, zeros to 112 mod 128, then the message bit length as a 128-bit
// big-endian integer, written into the pending block as sha512.c's finalize writes it.
static void finalize(sha512 *s) {
    uint64_t high = s->total_bytes >> 61;
    uint64_t low = s->total_bytes << 3;
    s->block[s->fill++] = 0x80;
    if (s->fill > SHA512_BLOCK - 16) {
        memset(s->block + s->fill, 0, SHA512_BLOCK - s->fill);
        compress_blocks(s->h, s->block, 1);
        s->fill = 0;
    }
    memset(s->block + s->fill, 0, SHA512_BLOCK - 16 - s->fill);
    for (size_t i = 0; i < 8; i++) {
        s->block[SHA512_BLOCK - 16 + i] = (uint8_t)(high >> (56 - 8 * i));
        s->block[SHA512_BLOCK - 8 + i] = (uint8_t)(low >> (56 - 8 * i));
    }
    compress_blocks(s->h, s->block, 1);
    s->fill = 0;
}

// The first count words of h, each most significant byte first, into out.
static void store_digest(const uint64_t *h, size_t count, uint8_t *out) {
    for (size_t i = 0; i < count; i++) {
        for (size_t j = 0; j < 8; j++) {
            out[8 * i + j] = (uint8_t)(h[i] >> (56 - 8 * j));
        }
    }
}

void sha512_final_hw(sha512 *s, uint8_t out[SHA512_LEN]) {
    finalize(s);
    store_digest(s->h, 8, out);
}

void sha384_final_hw(sha512 *s, uint8_t out[SHA384_LEN]) {
    finalize(s);
    store_digest(s->h, 6, out);
}

void sha512_of_hw(const uint8_t *in, size_t n, uint8_t out[SHA512_LEN]) {
    sha512 s;
    sha512_init(&s);
    sha512_update_hw(&s, in, n);
    sha512_final_hw(&s, out);
    ct_wipe(&s, sizeof s);
}

void sha384_of_hw(const uint8_t *in, size_t n, uint8_t out[SHA384_LEN]) {
    sha512 s;
    sha384_init(&s);
    sha512_update_hw(&s, in, n);
    sha384_final_hw(&s, out);
    ct_wipe(&s, sizeof s);
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_CPU_RUNTIME && __aarch64__
