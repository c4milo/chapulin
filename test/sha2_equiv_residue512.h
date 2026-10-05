// What sha512_hw.c's calls leave on the stack: test/sha2_equiv_residue.h's
// check for SHA-512 and SHA-384, whose words are 64 bits and whose block is
// 128 bytes. Each residue512_call_ function makes the calls of one shape,
// so that every call sha512_hw.c makes to its compression function runs
// once, and run_residue512_shape looks in the stack the calls left for two
// 64-bit words in a row that are each one of the call's secret words. Those
// are every value FIPS 180-4 §6.4.2 computes for a block of the padded
// message, and the partial sums the instructions leave on the way to them:
//
//   the 80 words of the block's message schedule (step 1), whose first 16
//   are the block's bytes most significant byte first;
//   those 16 as the block's bytes hold them, which is how a copy of the
//   input lies in memory;
//   for each schedule word past the first 16, W[t-16] + sigma0(W[t-15]),
//   which SHA512SU0 returns;
//   for each round, the schedule word plus its constant, that sum plus h,
//   and T1, which SHA512H returns;
//   the eight working variables after each of the 80 rounds (step 3);
//   the eight words of the state after the block (step 4).
//
// A word of the first 16 that holds a byte of padding is public and is not
// in the set, and neither is its sum with a constant, a word of either
// initial value, or a word that is zero. Two 64-bit words in a row are as
// many bits as the four 32-bit words the SHA-256 check asks for.
//
// Included by test/sha2_equiv_sha512.h only, on arm64. It uses
// residue_copy, residue_snapshot and RESIDUE_BYTES of
// test/sha2_equiv_residue.h.
#ifndef CH_SHA2_EQUIV_RESIDUE512_H
#define CH_SHA2_EQUIV_RESIDUE512_H

#define RESIDUE512_BLOCKS_MAX 4
// The most words one block adds: 16 message words in two forms, two values
// for each of the 64 schedule words after them, three sums and eight
// working variables for each of 80 rounds, and the state.
#define RESIDUE512_BLOCK_WORDS (2 * 16 + 2 * 64 + 80 * (3 + 8) + 8)

static uint8_t residue512_data[RESIDUE512_BLOCKS_MAX * SHA512_BLOCK];
static uint8_t residue512_digest[SHA512_LEN];
static sha512 residue512_state;
static uint64_t residue512_words[RESIDUE512_BLOCKS_MAX * RESIDUE512_BLOCK_WORDS];
static size_t residue512_word_count;

// FIPS 180-4 §4.2.3, §5.3.4 and §5.3.5, written out here apart from the
// library's tables, so that a wrong word there is not read here too.
static const uint64_t residue512_constants[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
static const uint64_t residue512_initial[2][8] = {
    {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
     0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179},
    {0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
     0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4}
};

// Two whole blocks, which the update hashes where the caller holds them.
#define RESIDUE512_WHOLE_LEN ((size_t)(2 * SHA512_BLOCK))
static __attribute__((noinline)) void residue512_call_whole_blocks(void) {
    sha384_init(&residue512_state);
    sha512_update_hw(&residue512_state, residue512_data, RESIDUE512_WHOLE_LEN);
}

// The same two blocks in two updates: the second fills the block the first
// left in the context, and the update hashes it there.
static __attribute__((noinline)) void residue512_call_buffered_block(void) {
    sha384_init(&residue512_state);
    sha512_update_hw(&residue512_state, residue512_data, 40);
    sha512_update_hw(&residue512_state, residue512_data + 40, RESIDUE512_WHOLE_LEN - 40);
}

// A SHA-384 final whose padding fits the pending block: one block of
// padding.
#define RESIDUE512_FINAL_ONE_LEN ((size_t)(SHA512_BLOCK + 20))
static __attribute__((noinline)) void residue512_call_final_one_block(void) {
    sha384_init(&residue512_state);
    sha512_update_hw(&residue512_state, residue512_data, RESIDUE512_FINAL_ONE_LEN);
    sha384_final_hw(&residue512_state, residue512_digest);
}

// A SHA-512 final whose length does not fit the pending block: two blocks.
#define RESIDUE512_FINAL_TWO_LEN ((size_t)(SHA512_BLOCK + 120))
static __attribute__((noinline)) void residue512_call_final_two_blocks(void) {
    sha512_init(&residue512_state);
    sha512_update_hw(&residue512_state, residue512_data, RESIDUE512_FINAL_TWO_LEN);
    sha512_final_hw(&residue512_state, residue512_digest);
}

// sha384_of_hw and sha512_of_hw, whose context is on their own frame.
#define RESIDUE512_OF_LEN ((size_t)(2 * SHA512_BLOCK + 22))
static __attribute__((noinline)) void residue512_call_whole_message384(void) {
    sha384_of_hw(residue512_data, RESIDUE512_OF_LEN, residue512_digest);
}

static __attribute__((noinline)) void residue512_call_whole_message512(void) {
    sha512_of_hw(residue512_data, RESIDUE512_OF_LEN, residue512_digest);
}

static uint64_t residue512_rotate_right(uint64_t x, unsigned r) {
    return (x >> r) | (x << (64 - r));
}

// Adds one word to residue512_words. A zero is left out, because memory no
// call wrote holds zeros too, and so is a word of either initial value,
// which is public.
static void residue512_add(uint64_t word) {
    if (word == 0) {
        return;
    }
    for (size_t i = 0; i < 8; i++) {
        if (word == residue512_initial[0][i] || word == residue512_initial[1][i]) {
            return;
        }
    }
    residue512_words[residue512_word_count++] = word;
}

// The 80 words of the message schedule of the block at p (FIPS 180-4
// §6.4.2 step 1), into w. It adds to residue512_words each word past the
// first 16 and the sum before it. message_words is how many of the first
// 16 hold eight bytes of the message: it adds each of those, and the same
// eight bytes as memory holds them.
static void residue512_schedule(const uint8_t *p, size_t message_words, uint64_t w[80]) {
    for (size_t i = 0; i < 16; i++) {
        uint64_t word = 0;
        for (size_t j = 0; j < 8; j++) {
            word = (word << 8) | p[8 * i + j];
        }
        w[i] = word;
        if (i < message_words) {
            uint64_t as_stored = 0;
            memcpy(&as_stored, p + 8 * i, sizeof as_stored);
            residue512_add(w[i]);
            residue512_add(as_stored);
        }
    }
    for (size_t i = 16; i < 80; i++) {
        uint64_t s0 = residue512_rotate_right(w[i - 15], 1) ^
                      residue512_rotate_right(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = residue512_rotate_right(w[i - 2], 19) ^
                      residue512_rotate_right(w[i - 2], 61) ^ (w[i - 2] >> 6);
        residue512_add(w[i - 16] + s0);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        residue512_add(w[i]);
    }
}

// The 80 rounds of one block (FIPS 180-4 §6.4.2 steps 2 to 4) from the
// state in h, which it leaves holding the state after the block. For each
// round it adds to residue512_words the schedule word plus its constant,
// but for a word of padding among the first 16, that sum plus h, T1, and
// the eight working variables after the round; then it adds the state.
static void residue512_rounds(uint64_t h[8], const uint64_t w[80], size_t message_words) {
    uint64_t v[8];
    memcpy(v, h, sizeof v);
    for (size_t t = 0; t < 80; t++) {
        uint64_t with_constant = w[t] + residue512_constants[t];
        if (t >= 16 || t < message_words) {
            residue512_add(with_constant);
        }
        uint64_t s1 = residue512_rotate_right(v[4], 14) ^ residue512_rotate_right(v[4], 18) ^
                      residue512_rotate_right(v[4], 41);
        uint64_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        uint64_t t1 = v[7] + with_constant + s1 + ch;
        uint64_t s0 = residue512_rotate_right(v[0], 28) ^ residue512_rotate_right(v[0], 34) ^
                      residue512_rotate_right(v[0], 39);
        uint64_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        residue512_add(v[7] + with_constant);
        residue512_add(t1);
        memmove(&v[1], &v[0], 7 * sizeof v[0]);
        v[4] += t1;
        v[0] = t1 + s0 + maj;
        for (size_t i = 0; i < 8; i++) {
            residue512_add(v[i]);
        }
    }
    for (size_t i = 0; i < 8; i++) {
        h[i] += v[i];
        residue512_add(h[i]);
    }
}

// The n bytes at residue512_data as FIPS 180-4 §5.1.2 pads them when
// padded is set, into blocks, and the count of blocks. Without padded, n
// is a whole number of blocks and they are the blocks.
static size_t residue512_blocks(size_t n, int padded, uint8_t blocks[sizeof residue512_data]) {
    memset(blocks, 0, sizeof residue512_data);
    memcpy(blocks, residue512_data, n);
    if (!padded) {
        return n / SHA512_BLOCK;
    }
    blocks[n] = 0x80;
    size_t count = (n + 1 + 16 + SHA512_BLOCK - 1) / SHA512_BLOCK;
    uint64_t bits = (uint64_t)n * 8;
    for (size_t i = 0; i < 8; i++) {
        blocks[count * SHA512_BLOCK - 8 + i] = (uint8_t)(bits >> (56 - 8 * i));
    }
    return count;
}

// The secret words of a call over the n bytes at residue512_data, into
// residue512_words, and whether the state this file computed for them is
// the one sha512.c computes. is384 names the initial value the call began
// from.
static int residue512_secret_words(int is384, size_t n, int padded) {
    static uint8_t blocks[sizeof residue512_data];
    size_t count = residue512_blocks(n, padded, blocks);
    size_t whole_words = n / 8;
    uint64_t h[8];
    memcpy(h, residue512_initial[is384 ? 1 : 0], sizeof h);
    sha512 s;
    init512(is384, &s);
    residue512_word_count = 0;
    for (size_t block = 0; block < count; block++) {
        const uint8_t *p = &blocks[block * SHA512_BLOCK];
        size_t message_words = 0;
        if (whole_words > 16 * block) {
            message_words = whole_words - 16 * block;
        }
        uint64_t w[80];
        residue512_schedule(p, message_words, w);
        residue512_rounds(h, w, message_words);
        sha512_update(&s, p, SHA512_BLOCK);
    }
    return memcmp(h, s.h, sizeof h) == 0;
}

static int residue512_is_secret(uint64_t word) {
    for (size_t i = 0; i < residue512_word_count; i++) {
        if (residue512_words[i] == word) {
            return 1;
        }
    }
    return 0;
}

// Whether the copy holds two secret words in a row at the byte offset at.
static int residue512_holds_at(size_t at) {
    for (size_t i = 0; i < 2; i++) {
        uint64_t word = 0;
        memcpy(&word, &residue_copy[at + 8 * i], sizeof word);
        if (!residue512_is_secret(word)) {
            return 0;
        }
    }
    return 1;
}

// One shape: its calls over n random bytes, then the search of the stack
// they left.
static void run_residue512_shape(const char *shape, void (*call)(void), int is384, size_t n,
                                 int padded) {
    rng_fill(residue512_data, sizeof residue512_data);
    call();
    residue_snapshot();
    compared++;
    if (!residue512_secret_words(is384, n, padded)) {
        report("residue", "this file's SHA-512 and sha512.c's disagree", n, 0, 0, 0);
        return;
    }
    for (size_t at = 0; at + 16 <= RESIDUE_BYTES; at++) {
        if (residue512_holds_at(at)) {
            failures++;
            (void)fprintf(stderr,
                          "sha2 equivalence: residue: after %s, the stack below the call holds "
                          "two words in a row that the call computed from its input, %zu bytes "
                          "into the copy\n",
                          shape, at);
            return;
        }
    }
}

// The six shapes, in a binary whose stack the search can read, as
// run_residue runs SHA-256's (test/stack_residue.c).
static void run_residue512(void) {
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        (void)printf("SKIP sha2 equivalence, the SHA-512 stack check: %s\n", unsearched);
        return;
    }
    run_residue512_shape("a SHA-384 update over whole blocks", residue512_call_whole_blocks, 1,
                         RESIDUE512_WHOLE_LEN, 0);
    run_residue512_shape("a SHA-384 update that fills a buffered block",
                         residue512_call_buffered_block, 1, RESIDUE512_WHOLE_LEN, 0);
    run_residue512_shape("a SHA-384 final with one block of padding",
                         residue512_call_final_one_block, 1, RESIDUE512_FINAL_ONE_LEN, 1);
    run_residue512_shape("a SHA-512 final with two blocks of padding",
                         residue512_call_final_two_blocks, 0, RESIDUE512_FINAL_TWO_LEN, 1);
    run_residue512_shape("sha384_of_hw", residue512_call_whole_message384, 1, RESIDUE512_OF_LEN, 1);
    run_residue512_shape("sha512_of_hw", residue512_call_whole_message512, 0, RESIDUE512_OF_LEN, 1);
}

#endif
