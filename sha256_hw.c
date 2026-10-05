// SHA-256 (FIPS 180-4) on the CPU's SHA-256 instructions, through the compiler's own intrinsic
// headers: the compression function over whole blocks, and the three calls sha256.h declares
// around it. A host object (-DCH_CPU_RUNTIME, cpu_cfg.h) compiles this file beside sha256.c, and
// sha256.h's entries call it for a session whose caller set CH_CPU_CONSTANT_TIME_SHA256
// (docs/decisions.md 93).
//
// Two instruction sets, and the architecture picks between them: FEAT_SHA256 on arm64, through
// <arm_neon.h>'s vsha256hq_u32, vsha256h2q_u32, vsha256su0q_u32 and vsha256su1q_u32, and the SHA
// extensions on x86-64, through <immintrin.h>'s _mm_sha256rnds2_epu32, _mm_sha256msg1_epu32 and
// _mm_sha256msg2_epu32, with SSSE3's byte shuffle and SSE4.1's blend beside them. cpu_cfg.h
// refuses a host object for any other target.
//
// The object compiles this file with no instruction flag, so the rest of the object runs on any
// CPU of its architecture. The pragma below puts the target attribute that turns the
// instructions on onto each function in this file and on no function outside it, as aes_hw.c
// does for the AES instructions. Nothing here probes a CPU: the caller does, and states what it
// found in ch_cfg.cpu.
//
// A hash reads HMAC keys and traffic secrets, so this file's timing matters. It reads no table
// with a secret index and branches on lengths alone, which is what it can state for itself.
// Whether the instructions take the same time whatever their operands are is the CPU's, in the
// mode the thread runs in, and CH_CPU_CONSTANT_TIME_SHA256 is the caller's statement that they
// do (cpu_cfg.h).
//
// CBMC cannot read an intrinsic, so the proofs stay on sha256.c. bin/sha2_equiv_test holds this
// file to that code over every length and split it tries, FIPS 180-4's vectors run on it in
// bin/unit_host, and the Wycheproof HMAC and HKDF suites in the Wycheproof host binary
// (docs/verification.md, "The hash instructions").
#include "sha256.h"

#ifdef CH_CPU_RUNTIME

#include <string.h>

#include "ct.h"

// Which instruction set the arms below take: arm64's where SHA256_HW_ARM is defined, and
// x86-64's where it is not. cpu_cfg.h has refused every target but these two.
#ifdef __aarch64__
#define SHA256_HW_ARM
#endif

#ifdef SHA256_HW_ARM
#include <arm_neon.h>
// Four 32-bit words of the state or of the message schedule.
typedef uint32x4_t words;
#else
#include <immintrin.h>
typedef __m128i words;
#endif

// FIPS 180-4 §4.2.2: the sixty-four constant words, sha256.c's K.
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Every function from here to the pop at the end of this file carries the target attribute that
// turns the instructions on: "+sha2" is arm64's SHA-256 extension, and "sha", "ssse3" and
// "sse4.1" are the three x86-64 sets the bit names. GCC's target pragma applies the attribute
// to each function defined after it, and clang's attribute pragma to each function it covers,
// so the includes above and every other file of the object stay without it.
#ifdef __clang__
#ifdef SHA256_HW_ARM
#pragma clang attribute push(__attribute__((target("+sha2"))), apply_to = function)
#else
#pragma clang attribute push(__attribute__((target("sha,ssse3,sse4.1"))), apply_to = function)
#endif
#else
#pragma GCC push_options
#ifdef SHA256_HW_ARM
#pragma GCC target("+sha2")
#else
#pragma GCC target("sha,ssse3,sse4.1")
#endif
#endif

// A field of a block_state, read from memory at the point of use. The state a block began with
// is added back when the block ends, sixty-four rounds later. Held in a register that long, it
// went into a stack slot of the compiler's own on x86-64, which has 16 vector registers: gcc 13
// kept one of the two halves there, where the wipe of the block_state does not clear it. Read
// this way, both halves stay in the block_state.
static inline words kept(const words *field) {
    const volatile words *in_state = field;
    return *in_state;
}

#ifdef SHA256_HW_ARM

// Everything compress_blocks computes from the state and the message, in one object so that
// one wipe when it ends clears all of it: under HMAC the first block is the key, and the state
// after it stands for the key.
typedef struct {
    words abcd;       // the working variables a, b, c and d
    words efgh;       // and e, f, g and h
    words abcd_start; // both as the block began
    words efgh_start;
    words w0; // sixteen words of the message schedule, the oldest four first
    words w1;
    words w2;
    words w3;
    words with_constants; // four schedule words, each plus its round constant
    words before;         // the half of the state a group's first instruction overwrites
} block_state;

// Four message words as the hash reads them, most significant byte first (FIPS 180-4 §5.2.1).
static inline words load_block_words(const uint8_t *p) {
    return vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)));
}

// Rounds 4 * group to 4 * group + 3 (FIPS 180-4 §6.2.2 step 3) on the four words in current.
// SHA256H computes the new a, b, c and d and SHA256H2 the new e, f, g and h, each from both
// halves as they were, so one half is copied before the first of the two overwrites it. This
// one runs SHA256H first and copies a, b, c and d.
static inline void rounds_abcd_first(block_state *c, words current, size_t group) {
    c->with_constants = vaddq_u32(current, vld1q_u32(&K[4 * group]));
    c->before = c->abcd;
    c->abcd = vsha256hq_u32(c->abcd, c->efgh, c->with_constants);
    c->efgh = vsha256h2q_u32(c->efgh, c->before, c->with_constants);
}

// The same four rounds with SHA256H2 first and e, f, g and h copied. run_blocks takes the two
// in turn. Both compilers measured put the copy in front of the instruction that runs first,
// so one order alone puts a register copy on the same half's path in every group. Taken in
// turn, each half's path holds the copy in every other group (docs/decisions.md 93).
static inline void rounds_efgh_first(block_state *c, words current, size_t group) {
    c->with_constants = vaddq_u32(current, vld1q_u32(&K[4 * group]));
    c->before = c->efgh;
    c->efgh = vsha256h2q_u32(c->efgh, c->abcd, c->with_constants);
    c->abcd = vsha256hq_u32(c->abcd, c->before, c->with_constants);
}

// The four schedule words sixteen after current's (FIPS 180-4 §6.2.2 step 1), from current and
// the three groups after it.
static inline words schedule(words current, words next, words third, words fourth) {
    return vsha256su1q_u32(vsha256su0q_u32(current, next), third, fourth);
}

// FIPS 180-4 §6.2.2 over blocks whole blocks at p: h in, h out, with every value it computes
// on the way in c.
static inline void run_blocks(block_state *c, uint32_t h[8], const uint8_t *p, size_t blocks) {
    c->abcd = vld1q_u32(h);
    c->efgh = vld1q_u32(h + 4);
    for (; blocks > 0; blocks--) {
        c->abcd_start = c->abcd;
        c->efgh_start = c->efgh;
        c->w0 = load_block_words(p);
        c->w1 = load_block_words(p + 16);
        c->w2 = load_block_words(p + 32);
        c->w3 = load_block_words(p + 48);
        for (size_t group = 0; group < 12; group += 4) {
            rounds_abcd_first(c, c->w0, group);
            c->w0 = schedule(c->w0, c->w1, c->w2, c->w3);
            rounds_efgh_first(c, c->w1, group + 1);
            c->w1 = schedule(c->w1, c->w2, c->w3, c->w0);
            rounds_abcd_first(c, c->w2, group + 2);
            c->w2 = schedule(c->w2, c->w3, c->w0, c->w1);
            rounds_efgh_first(c, c->w3, group + 3);
            c->w3 = schedule(c->w3, c->w0, c->w1, c->w2);
        }
        rounds_abcd_first(c, c->w0, 12);
        rounds_efgh_first(c, c->w1, 13);
        rounds_abcd_first(c, c->w2, 14);
        rounds_efgh_first(c, c->w3, 15);
        c->abcd = vaddq_u32(c->abcd, kept(&c->abcd_start));
        c->efgh = vaddq_u32(c->efgh, kept(&c->efgh_start));
        p += SHA256_BLOCK;
    }
    vst1q_u32(h, c->abcd);
    vst1q_u32(h + 4, c->efgh);
}

#else // x86-64

// compress_blocks's working values, in one object for the reason the arm64 arm gives. The
// instructions take the state as two vectors in an order of their own: a, b, e and f from the
// most significant word down, and c, d, g and h.
typedef struct {
    words abef;
    words cdgh;
    words abef_start; // both as the block began
    words cdgh_start;
    words w0; // sixteen words of the message schedule, the oldest four first
    words w1;
    words w2;
    words w3;
    words with_constants; // four schedule words, each plus its round constant
    words sum;            // a schedule step's sum, before SHA256MSG2 ends it
    words first;          // the two vectors the state passes through between h's order and
    words second;         // the instructions'
} block_state;

// Four words moved between memory and a register through memcpy, so no load or store assumes an
// alignment. Both compilers turn each into the unaligned move.
static inline words load_words(const void *p) {
    words v;
    memcpy(&v, p, sizeof v);
    return v;
}

static inline void store_words(void *p, words v) {
    memcpy(p, &v, sizeof v);
}

// Four message words as the hash reads them, most significant byte first (FIPS 180-4 §5.2.1):
// PSHUFB reverses the four bytes of each word.
static inline words load_block_words(const uint8_t *p) {
    const words byte_swap = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
    return _mm_shuffle_epi8(load_words(p), byte_swap);
}

// Rounds 4 * group to 4 * group + 3 (FIPS 180-4 §6.2.2 step 3) on the four words in current.
// SHA256RNDS2 runs two rounds. From c, d, g and h in its first operand, a, b, e and f in its
// second and two words plus their constants, it writes the new a, b, e and f over the first,
// and the second, which it leaves as it was, then holds the new c, d, g and h. So after the
// first instruction each field holds the other's half, and the second instruction, on the upper
// two words, puts each back.
static inline void rounds(block_state *c, words current, size_t group) {
    c->with_constants = _mm_add_epi32(current, load_words(&K[4 * group]));
    c->cdgh = _mm_sha256rnds2_epu32(c->cdgh, c->abef, c->with_constants);
    c->abef = _mm_sha256rnds2_epu32(c->abef, c->cdgh, _mm_shuffle_epi32(c->with_constants, 0x0e));
}

// The four schedule words sixteen after current's (FIPS 180-4 §6.2.2 step 1), from current and
// the three groups after it: SHA256MSG1 adds sigma0 of the next four words, the add brings the
// words seven back, and SHA256MSG2 adds sigma1 of the two before each.
static inline words schedule(block_state *c, words current, words next, words third, words fourth) {
    c->sum = _mm_add_epi32(_mm_sha256msg1_epu32(current, next), _mm_alignr_epi8(fourth, third, 4));
    return _mm_sha256msg2_epu32(c->sum, fourth);
}

// FIPS 180-4 §6.2.2 over blocks whole blocks at p: h in, h out, with every value it computes
// on the way in c.
static inline void run_blocks(block_state *c, uint32_t h[8], const uint8_t *p, size_t blocks) {
    // h holds a to d and e to h, least significant word first. The instructions take them as
    // abef and cdgh.
    c->first = _mm_shuffle_epi32(load_words(h), 0xb1);      // c, d, a, b
    c->second = _mm_shuffle_epi32(load_words(h + 4), 0x1b); // e, f, g, h
    c->abef = _mm_alignr_epi8(c->first, c->second, 8);
    c->cdgh = _mm_blend_epi16(c->second, c->first, 0xf0);
    for (; blocks > 0; blocks--) {
        c->abef_start = c->abef;
        c->cdgh_start = c->cdgh;
        c->w0 = load_block_words(p);
        c->w1 = load_block_words(p + 16);
        c->w2 = load_block_words(p + 32);
        c->w3 = load_block_words(p + 48);
        for (size_t group = 0; group < 12; group += 4) {
            rounds(c, c->w0, group);
            c->w0 = schedule(c, c->w0, c->w1, c->w2, c->w3);
            rounds(c, c->w1, group + 1);
            c->w1 = schedule(c, c->w1, c->w2, c->w3, c->w0);
            rounds(c, c->w2, group + 2);
            c->w2 = schedule(c, c->w2, c->w3, c->w0, c->w1);
            rounds(c, c->w3, group + 3);
            c->w3 = schedule(c, c->w3, c->w0, c->w1, c->w2);
        }
        rounds(c, c->w0, 12);
        rounds(c, c->w1, 13);
        rounds(c, c->w2, 14);
        rounds(c, c->w3, 15);
        c->abef = _mm_add_epi32(c->abef, kept(&c->abef_start));
        c->cdgh = _mm_add_epi32(c->cdgh, kept(&c->cdgh_start));
        p += SHA256_BLOCK;
    }
    c->first = _mm_shuffle_epi32(c->abef, 0x1b);  // f, e, b, a
    c->second = _mm_shuffle_epi32(c->cdgh, 0xb1); // d, c, h, g
    store_words(h, _mm_blend_epi16(c->first, c->second, 0xf0));
    store_words(h + 4, _mm_alignr_epi8(c->second, c->first, 8));
}

#endif

// The compression function over blocks whole blocks at p, on either instruction set, and the
// wipe of what it computed. The line is outside the two arms, so one test on either
// architecture holds it for both.
static void compress_blocks(uint32_t h[8], const uint8_t *p, size_t blocks) {
    block_state c;
    run_blocks(&c, h, p, blocks);
    ct_wipe(&c, sizeof c);
}

void sha256_update_hw(sha256 *s, const uint8_t *in, size_t n) {
    // No byte to take: in may be NULL, which no step below may offset or copy from.
    if (n == 0) {
        return;
    }
    s->total_bytes += n;
    if (s->fill > 0) {
        size_t take = SHA256_BLOCK - s->fill;
        if (take > n) {
            take = n;
        }
        memcpy(s->block + s->fill, in, take);
        s->fill += take;
        in += take;
        n -= take;
        if (s->fill < SHA256_BLOCK) {
            return;
        }
        compress_blocks(s->h, s->block, 1);
        s->fill = 0;
    }
    size_t whole = n / SHA256_BLOCK;
    if (whole > 0) {
        compress_blocks(s->h, in, whole);
        in += whole * SHA256_BLOCK;
        n -= whole * SHA256_BLOCK;
    }
    memcpy(s->block, in, n);
    s->fill = n;
}

// FIPS 180-4 §5.1.1: the 1 bit, zeros to 56 mod 64, then the message bit length as a 64-bit
// big-endian integer, written into the pending block, as sha512.c's finalize pads.
void sha256_final_hw(sha256 *s, uint8_t out[SHA256_LEN]) {
    uint64_t bits = s->total_bytes * 8;
    s->block[s->fill++] = 0x80;
    if (s->fill > SHA256_BLOCK - 8) {
        memset(s->block + s->fill, 0, SHA256_BLOCK - s->fill);
        compress_blocks(s->h, s->block, 1);
        s->fill = 0;
    }
    memset(s->block + s->fill, 0, SHA256_BLOCK - 8 - s->fill);
    for (size_t i = 0; i < 8; i++) {
        s->block[SHA256_BLOCK - 8 + i] = (uint8_t)(bits >> (56 - 8 * i));
    }
    compress_blocks(s->h, s->block, 1);
    s->fill = 0;
    for (size_t i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(s->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(s->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)s->h[i];
    }
}

void sha256_of_hw(const uint8_t *in, size_t n, uint8_t out[SHA256_LEN]) {
    sha256 s;
    sha256_init(&s);
    sha256_update_hw(&s, in, n);
    sha256_final_hw(&s, out);
    ct_wipe(&s, sizeof s);
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_CPU_RUNTIME
