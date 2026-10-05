// What sha256_hw.c's calls leave on the stack. A call computes a message
// schedule and a state from its input, which under HMAC is the key, keeps
// them in one struct on compress_blocks's frame, and wipes that struct once
// when it returns; sha256_of_hw also wipes the context it hashes in
// (sha256_hw.c). A frame is dead after its call returns, but its bytes stay
// in memory below this binary's own frames until another call writes over
// them.
//
// Each residue_call_ function below makes the calls of one shape, so that
// every call sha256_hw.c makes to its compression function runs once: over
// whole blocks of the caller's bytes, over a block the context buffered,
// and over one and two blocks of padding. All but the last hash into a
// context that is static, so the context's own copy of the state is not on
// the stack, and the last calls sha256_of_hw, whose context is on its
// frame. residue_snapshot then copies the stack below its caller as deep as
// RESIDUE_BYTES, where the dead frames lay, and run_residue_shape looks in
// the copy for four 32-bit words in a row that are each one of the call's
// secret words. Those are every value FIPS 180-4 §6.2.2 computes for a
// block of the padded message, and the partial sums the instructions leave
// on the way to them:
//
//   the 64 words of the block's message schedule (step 1), whose first 16
//   are the block's bytes most significant byte first;
//   those 16 as the block's bytes hold them, least significant byte first
//   on these targets, which is how a copy of the input lies in memory;
//   for each schedule word past the first 16, the two sums before it:
//   W[t-16] + sigma0(W[t-15]), which SHA256SU0 and SHA256MSG1 return, and
//   that plus W[t-7], which the x86-64 arm holds before SHA256MSG2;
//   each schedule word plus its round constant, which the round
//   instructions take;
//   the eight working variables after each of the 64 rounds (step 3);
//   the eight words of the state after the block (step 4).
//
// A word of the first 16 that holds a byte of padding is public and is
// not in the set, and neither is its sum with a constant, a word of the
// initial value, which the working variables of a message's first rounds
// still hold, or a word that is zero. It takes the four at any byte offset
// and in any order: the x86-64 instructions keep the state in an order of
// their own, and a compiler's spill slot holds a vector as the register
// held it. The words are computed only after the copy, by this file's own
// code, so this file's frames cannot hold them first, and the state this
// file computes must be the one sha256.c computes.
//
// The search holds a claim about optimized code alone. An unoptimized
// build keeps every temporary in a stack slot, and AddressSanitizer lays
// frames out its own way, so a binary built either way skips the search
// and says so (test/stack_residue.c).
//
// Included by test/sha2_equiv_test.c only, which declares the generator,
// report and the counts this file uses.
#ifndef CH_SHA2_EQUIV_RESIDUE_H
#define CH_SHA2_EQUIV_RESIDUE_H

#define RESIDUE_BLOCKS_MAX 4
#define RESIDUE_BYTES 4096
// The most words one block adds: 16 message words in two forms, three
// values for each of the 48 schedule words after them, 64 sums with a
// constant, eight working variables after each of 64 rounds, and the
// state.
#define RESIDUE_BLOCK_WORDS (2 * 16 + 3 * 48 + 64 + 64 * 8 + 8)

static uint8_t residue_copy[RESIDUE_BYTES];
static uint8_t residue_data[RESIDUE_BLOCKS_MAX * SHA256_BLOCK];
static uint8_t residue_digest[SHA256_LEN];
static sha256 residue_state;
static uint32_t residue_words[RESIDUE_BLOCKS_MAX * RESIDUE_BLOCK_WORDS];
static size_t residue_word_count;

// FIPS 180-4 §4.2.2 and §5.3.3, written out here apart from the library's
// tables, so that a wrong word there is not read here too.
static const uint32_t residue_constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
static const uint32_t residue_initial[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

// Two whole blocks, which the update hashes where the caller holds them.
#define RESIDUE_WHOLE_LEN ((size_t)(2 * SHA256_BLOCK))
static __attribute__((noinline)) void residue_call_whole_blocks(void) {
    sha256_init(&residue_state);
    sha256_update_hw(&residue_state, residue_data, RESIDUE_WHOLE_LEN);
}

// The same two blocks in two updates: the second fills the block the first
// left in the context, and the update hashes it there.
static __attribute__((noinline)) void residue_call_buffered_block(void) {
    sha256_init(&residue_state);
    sha256_update_hw(&residue_state, residue_data, 40);
    sha256_update_hw(&residue_state, residue_data + 40, RESIDUE_WHOLE_LEN - 40);
}

// A final whose padding fits the pending block: one block of padding.
#define RESIDUE_FINAL_ONE_LEN ((size_t)(SHA256_BLOCK + 20))
static __attribute__((noinline)) void residue_call_final_one_block(void) {
    sha256_init(&residue_state);
    sha256_update_hw(&residue_state, residue_data, RESIDUE_FINAL_ONE_LEN);
    sha256_final_hw(&residue_state, residue_digest);
}

// A final whose length does not fit the pending block: two blocks.
#define RESIDUE_FINAL_TWO_LEN ((size_t)(SHA256_BLOCK + 60))
static __attribute__((noinline)) void residue_call_final_two_blocks(void) {
    sha256_init(&residue_state);
    sha256_update_hw(&residue_state, residue_data, RESIDUE_FINAL_TWO_LEN);
    sha256_final_hw(&residue_state, residue_digest);
}

// sha256_of_hw, whose context is on its own frame.
#define RESIDUE_OF_LEN ((size_t)(2 * SHA256_BLOCK + 22))
static __attribute__((noinline)) void residue_call_whole_message(void) {
    sha256_of_hw(residue_data, RESIDUE_OF_LEN, residue_digest);
}

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
const char *stack_residue_unsearched(void);

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

static uint32_t residue_rotate_right(uint32_t x, unsigned r) {
    return (x >> r) | (x << (32 - r));
}

// Adds one word to residue_words. A zero is left out, because memory no
// call wrote holds zeros too, and so is a word of the initial value, which
// is public.
static void residue_add(uint32_t word) {
    if (word == 0) {
        return;
    }
    for (size_t i = 0; i < 8; i++) {
        if (word == residue_initial[i]) {
            return;
        }
    }
    residue_words[residue_word_count++] = word;
}

// The 64 words of the message schedule of the block at p (FIPS 180-4
// §6.2.2 step 1), into w. It adds to residue_words each word past the
// first 16 and the two sums before it. message_words is how many of the
// first 16 hold four bytes of the message: it adds each of those, and the
// same four bytes as memory holds them.
static void residue_schedule(const uint8_t *p, size_t message_words, uint32_t w[64]) {
    for (size_t i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) |
               ((uint32_t)p[4 * i + 2] << 8) | (uint32_t)p[4 * i + 3];
        if (i < message_words) {
            uint32_t as_stored = 0;
            memcpy(&as_stored, p + 4 * i, sizeof as_stored);
            residue_add(w[i]);
            residue_add(as_stored);
        }
    }
    for (size_t i = 16; i < 64; i++) {
        uint32_t s0 = residue_rotate_right(w[i - 15], 7) ^ residue_rotate_right(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = residue_rotate_right(w[i - 2], 17) ^ residue_rotate_right(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        residue_add(w[i - 16] + s0);
        residue_add(w[i - 16] + s0 + w[i - 7]);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        residue_add(w[i]);
    }
}

// The 64 rounds of one block (FIPS 180-4 §6.2.2 steps 2 to 4) from the
// state in h, which it leaves holding the state after the block. It adds
// to residue_words each schedule word plus its constant, but for a word of
// padding among the first 16, then the eight working variables after each
// round, and the state.
static void residue_rounds(uint32_t h[8], const uint32_t w[64], size_t message_words) {
    uint32_t v[8];
    memcpy(v, h, sizeof v);
    for (size_t t = 0; t < 64; t++) {
        uint32_t with_constant = w[t] + residue_constants[t];
        if (t >= 16 || t < message_words) {
            residue_add(with_constant);
        }
        uint32_t s1 = residue_rotate_right(v[4], 6) ^ residue_rotate_right(v[4], 11) ^
                      residue_rotate_right(v[4], 25);
        uint32_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        uint32_t t1 = v[7] + s1 + ch + with_constant;
        uint32_t s0 = residue_rotate_right(v[0], 2) ^ residue_rotate_right(v[0], 13) ^
                      residue_rotate_right(v[0], 22);
        uint32_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        memmove(&v[1], &v[0], 7 * sizeof v[0]);
        v[4] += t1;
        v[0] = t1 + s0 + maj;
        for (size_t i = 0; i < 8; i++) {
            residue_add(v[i]);
        }
    }
    for (size_t i = 0; i < 8; i++) {
        h[i] += v[i];
        residue_add(h[i]);
    }
}

// The n bytes at residue_data as FIPS 180-4 §5.1.1 pads them when padded
// is set, into blocks, and the count of blocks. Without padded, n is a
// whole number of blocks and they are the blocks.
static size_t residue_blocks(size_t n, int padded, uint8_t blocks[sizeof residue_data]) {
    memset(blocks, 0, sizeof residue_data);
    memcpy(blocks, residue_data, n);
    if (!padded) {
        return n / SHA256_BLOCK;
    }
    blocks[n] = 0x80;
    size_t count = (n + 1 + 8 + SHA256_BLOCK - 1) / SHA256_BLOCK;
    uint64_t bits = (uint64_t)n * 8;
    for (size_t i = 0; i < 8; i++) {
        blocks[count * SHA256_BLOCK - 8 + i] = (uint8_t)(bits >> (56 - 8 * i));
    }
    return count;
}

// The secret words of a call over the n bytes at residue_data, into
// residue_words, and whether the state this file computed for them is the
// one sha256.c computes.
static int residue_secret_words(size_t n, int padded) {
    static uint8_t blocks[sizeof residue_data];
    size_t count = residue_blocks(n, padded, blocks);
    size_t whole_words = n / 4;
    uint32_t h[8];
    memcpy(h, residue_initial, sizeof h);
    sha256 s;
    sha256_init(&s);
    residue_word_count = 0;
    for (size_t block = 0; block < count; block++) {
        const uint8_t *p = &blocks[block * SHA256_BLOCK];
        size_t message_words = 0;
        if (whole_words > 16 * block) {
            message_words = whole_words - 16 * block;
        }
        uint32_t w[64];
        residue_schedule(p, message_words, w);
        residue_rounds(h, w, message_words);
        sha256_update(&s, p, SHA256_BLOCK);
    }
    return memcmp(h, s.h, sizeof h) == 0;
}

static int residue_is_secret(uint32_t word) {
    for (size_t i = 0; i < residue_word_count; i++) {
        if (residue_words[i] == word) {
            return 1;
        }
    }
    return 0;
}

// Whether the copy holds four secret words in a row at the byte offset at.
static int residue_holds_at(size_t at) {
    for (size_t i = 0; i < 4; i++) {
        uint32_t word = 0;
        memcpy(&word, &residue_copy[at + 4 * i], sizeof word);
        if (!residue_is_secret(word)) {
            return 0;
        }
    }
    return 1;
}

// One shape: its calls over n random bytes, then the search of the stack
// they left.
static void run_residue_shape(const char *shape, void (*call)(void), size_t n, int padded) {
    rng_fill(residue_data, sizeof residue_data);
    call();
    residue_snapshot();
    compared++;
    if (!residue_secret_words(n, padded)) {
        report("residue", "this file's SHA-256 and sha256.c's disagree", n, 0, 0, 0);
        return;
    }
    for (size_t at = 0; at + 16 <= RESIDUE_BYTES; at++) {
        if (residue_holds_at(at)) {
            failures++;
            (void)fprintf(stderr,
                          "sha2 equivalence: residue: after %s, the stack below the call holds "
                          "four words in a row that the call computed from its input, %zu bytes "
                          "into the copy\n",
                          shape, at);
            return;
        }
    }
}

// The five shapes, in a binary whose stack the search can read: an
// optimized build without AddressSanitizer. Any other says why it skips
// the search (test/stack_residue.c). make check and the qemu lane build
// such a binary, and the sanitizer lane does not.
static void run_residue(void) {
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        (void)printf("SKIP sha2 equivalence, the stack check: %s\n", unsearched);
        return;
    }
    run_residue_shape("an update over whole blocks", residue_call_whole_blocks, RESIDUE_WHOLE_LEN,
                      0);
    run_residue_shape("an update that fills a buffered block", residue_call_buffered_block,
                      RESIDUE_WHOLE_LEN, 0);
    run_residue_shape("a final with one block of padding", residue_call_final_one_block,
                      RESIDUE_FINAL_ONE_LEN, 1);
    run_residue_shape("a final with two blocks of padding", residue_call_final_two_blocks,
                      RESIDUE_FINAL_TWO_LEN, 1);
    run_residue_shape("sha256_of_hw", residue_call_whole_message, RESIDUE_OF_LEN, 1);
}

#endif
