// What the SHA-3 calls leave on the stack. A call's state comes from its input, which under
// ML-KEM and ML-DSA-87 is a secret seed, and Keccak-f[1600] is a permutation: one whole state
// gives back the state before it. A frame is dead after its call returns, but its bytes stay in
// memory below this binary's own frames until another call writes over them.
//
// Two binaries include this file, and each holds one set of calls to the rule:
//
//   test/sha3_hw_equiv_test.c holds sha3_hw.c's calls. sha3_hw.c keeps the 25 lanes in
//   registers through the rounds of permute_blocks and writes them to the caller's state alone,
//   and sha3_256_hw and sha3_512_hw wipe the state they hash in.
//   test/sha3_equiv_test.c holds sha3.c's calls, in every object. An x86-64 host object runs
//   sha3_inverted_lanes.h's form. Its function of 24 rounds keeps its values in registers and in
//   the two states it names, and the scratch state is wiped (docs/decisions.md 216 and 218).
//   Every other object runs keccak_f1600_plain, whose compilers keep lanes in stack slots, and
//   there each entry wipes SHA3_BELOW_LEN bytes of the stack below it (docs/decisions.md 219).
//
// Before the include, each binary defines three names:
//
//   SHA3_RESIDUE_ENTRY(name), the expression that names its entry for sha3.h's call `name`;
//   SHA3_RESIDUE_SUFFIX, the text that ends the name of an entry in a message;
//   SHA3_RESIDUE_TEST, the text that starts each message.
//
// test/sha3_equiv_test.c defines SHA3_RESIDUE_BODIES as well in an object that wipes below the
// entries. Then run_residue_depth (test/sha3_residue_depth.h) first calls each entry's body by
// its own name, with no wipe after it. It requires the lowest byte the bodies wrote within
// SHA3_BELOW_LEN of their caller, so the wipe covers their frames. It also requires the search to
// find a word there, so a search that could find nothing fails.
//
// Each also declares the generator rng_bytes, the round constants round_constants and the counts
// compared and failures.
//
// Each residue_call_ function below makes the calls of one kind, so that every way the entries
// run the permutation runs once: over whole blocks of the caller's bytes at each of the three
// rates, on a block the state held part of, after the padding, and between two blocks of output.
// Four more kinds hold the two lengths at which a call starts to run the permutation, and so
// where sha3.c's entries start to wipe: an absorb one byte short of the block and one that fills
// it to the last byte, and a squeeze to the last byte of the block and one a byte past it.
// The streams work in a context that is static, so the context's own copy of the state is not on
// the stack; the two digests hash in a state on their own frame. residue_snapshot then copies
// the stack below its caller as deep as RESIDUE_BYTES, where the dead frames lay, and
// run_residue_shape looks in the copy for one 64-bit word that is a lane the call computed.
// Those are, for every permutation the call ran:
//
//   the state the permutation starts from;
//   each eight bytes of the message as a lane, which is how a copy of the input lies in a
//   register;
//   and for each of the 24 rounds, by FIPS 202 §3.2: the parity of each column, and the
//   exclusive OR of the column's first three lanes, which the first of the two EOR3 instructions
//   returns; the five values theta adds to a column; every lane after theta, after rho and after
//   chi; and lane 0 after iota.
//
// sha3_inverted_lanes.h's form keeps six lanes inverted between rounds, each bit flipped, and so
// four of the column parities and two of theta's values as well. So the search looks for each of
// those words and for its complement.
//
// proof/sha3_reference.h computes them, the standard's steps as loops, which share no line with
// sha3_hw.c or with sha3.c's rounds.
//
// A public word is left out, because memory may hold it for another reason: a zero, which a
// fresh state and unwritten memory hold, the last bit of the padding alone in its lane, and the
// complement of each. Every kind's message ends seven bytes into a lane, so the lane that takes
// the first byte of the padding holds seven bytes of the message as well.
//
// One word is enough to fail. A register holds a lane in its low half, so a register a compiler
// stored is one lane beside eight bytes that are no lane, and 64 bits a call computed do not turn
// up by chance.
//
// The search reads the stack one compiler left on one call. It cannot see a register, and
// test/stack_residue.c names the builds whose stack it does not search.
#ifndef CH_SHA3_RESIDUE_H
#define CH_SHA3_RESIDUE_H

#define RESIDUE_BYTES 4096
#define RESIDUE_PERMUTATIONS_MAX 4
// The most words one permutation adds: the 25 lanes it starts from, at most 21 lanes of message,
// and for each round five parities, five partial parities, five values of d, 25 lanes after each
// of three steps and lane 0 after iota. residue_add adds each word and its complement.
#define RESIDUE_PERMUTATION_WORDS (25 + 21 + 24 * (5 + 5 + 5 + 3 * 25 + 1))
#define RESIDUE_WORDS_MAX ((size_t)2 * RESIDUE_PERMUTATIONS_MAX * RESIDUE_PERMUTATION_WORDS)
#define RESIDUE_DATA_LEN ((size_t)2 * SHAKE128_RATE)
// Two whole blocks at each rate a call over whole blocks absorbs.
#define RESIDUE_TWO_BLOCKS256_LEN ((size_t)2 * SHAKE256_RATE)
#define RESIDUE_TWO_BLOCKS128_LEN ((size_t)2 * SHAKE128_RATE)

static uint8_t residue_data[RESIDUE_DATA_LEN];
static uint8_t residue_out[2 * SHAKE256_RATE];
static shake residue_context;
static uint64_t residue_words[RESIDUE_WORDS_MAX];
static size_t residue_word_count;
static int residue_words_full;
static uint8_t residue_copy[RESIDUE_BYTES];

// Whole blocks of the caller's bytes: the state stays in registers from the first block to the
// second, and each block's lanes go into it from the message.
static __attribute__((noinline)) void residue_call_whole_blocks256(void) {
    SHA3_RESIDUE_ENTRY(shake256_init)(&residue_context);
    SHA3_RESIDUE_ENTRY(shake_absorb)(&residue_context, residue_data, RESIDUE_TWO_BLOCKS256_LEN);
}

static __attribute__((noinline)) void residue_call_whole_blocks128(void) {
    SHA3_RESIDUE_ENTRY(shake128_init)(&residue_context);
    SHA3_RESIDUE_ENTRY(shake_absorb)(&residue_context, residue_data, RESIDUE_TWO_BLOCKS128_LEN);
}

// A block the state held part of: the second call fills it, and the permutation runs with no
// lane from the message.
#define RESIDUE_BUFFERED_LEN ((size_t)200)
static __attribute__((noinline)) void residue_call_buffered_block(void) {
    SHA3_RESIDUE_ENTRY(shake256_init)(&residue_context);
    SHA3_RESIDUE_ENTRY(shake_absorb)(&residue_context, residue_data, 100);
    SHA3_RESIDUE_ENTRY(shake_absorb)(&residue_context, residue_data + 100,
                                     RESIDUE_BUFFERED_LEN - 100);
}

// The permutation after the padding, and the one between two blocks of output.
#define RESIDUE_SQUEEZE_IN_LEN ((size_t)55)
#define RESIDUE_SQUEEZE_OUT_LEN ((size_t)200)
static __attribute__((noinline)) void residue_call_squeeze(void) {
    SHA3_RESIDUE_ENTRY(shake256_init)(&residue_context);
    SHA3_RESIDUE_ENTRY(shake_absorb)(&residue_context, residue_data, RESIDUE_SQUEEZE_IN_LEN);
    SHA3_RESIDUE_ENTRY(shake_squeeze)(&residue_context, residue_out, RESIDUE_SQUEEZE_OUT_LEN);
}

// An absorb one byte short of the block, the longest that runs no permutation. Its words are
// the message's lanes.
static __attribute__((noinline)) void residue_call_short_block(void) {
    SHA3_RESIDUE_ENTRY(shake256_init)(&residue_context);
    SHA3_RESIDUE_ENTRY(shake_absorb)(&residue_context, residue_data, SHAKE256_RATE - 1);
}

// An absorb that fills the block the state held part of to its last byte, the shortest that
// runs the permutation.
#define RESIDUE_FIRST_PART_LEN ((size_t)100)
static __attribute__((noinline)) void residue_call_exact_block(void) {
    SHA3_RESIDUE_ENTRY(shake256_init)(&residue_context);
    SHA3_RESIDUE_ENTRY(shake_absorb)(&residue_context, residue_data, RESIDUE_FIRST_PART_LEN);
    SHA3_RESIDUE_ENTRY(shake_absorb)(&residue_context, residue_data + RESIDUE_FIRST_PART_LEN,
                                     SHAKE256_RATE - RESIDUE_FIRST_PART_LEN);
}

// The padding's permutation, and then a squeeze to the last byte of that block, the longest that
// runs no permutation.
#define RESIDUE_READ_FIRST_LEN ((size_t)10)
static __attribute__((noinline)) void residue_call_read_block(void) {
    SHA3_RESIDUE_ENTRY(shake256_init)(&residue_context);
    SHA3_RESIDUE_ENTRY(shake_absorb)(&residue_context, residue_data, RESIDUE_SQUEEZE_IN_LEN);
    SHA3_RESIDUE_ENTRY(shake_squeeze)(&residue_context, residue_out, RESIDUE_READ_FIRST_LEN);
    SHA3_RESIDUE_ENTRY(shake_squeeze)(&residue_context, residue_out,
                                      SHAKE256_RATE - RESIDUE_READ_FIRST_LEN);
}

// A squeeze of the whole block the padding's permutation left, and then one of a byte past it,
// the shortest that runs the permutation.
static __attribute__((noinline)) void residue_call_past_block(void) {
    SHA3_RESIDUE_ENTRY(shake256_init)(&residue_context);
    SHA3_RESIDUE_ENTRY(shake_absorb)(&residue_context, residue_data, RESIDUE_SQUEEZE_IN_LEN);
    SHA3_RESIDUE_ENTRY(shake_squeeze)(&residue_context, residue_out, SHAKE256_RATE);
    SHA3_RESIDUE_ENTRY(shake_squeeze)(&residue_context, residue_out, 1);
}

// The two digests, whose state is on their own frame.
#define RESIDUE_SHA3_256_LEN ((size_t)(2 * SHA3_256_RATE + 23))
static __attribute__((noinline)) void residue_call_sha3_256(void) {
    SHA3_RESIDUE_ENTRY(sha3_256)(residue_data, RESIDUE_SHA3_256_LEN, residue_out);
}

#define RESIDUE_SHA3_512_LEN ((size_t)(2 * SHA3_512_RATE + 23))
static __attribute__((noinline)) void residue_call_sha3_512(void) {
    SHA3_RESIDUE_ENTRY(sha3_512)(residue_data, RESIDUE_SHA3_512_LEN, residue_out);
}

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
const char *stack_residue_unsearched(void);

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

// Whether a word is public: a zero, the last bit of the padding alone in its lane, or the
// complement of one of the two.
static int residue_is_public(uint64_t word) {
    return word == 0 || word == UINT64_C(0x8000000000000000) || word == UINT64_MAX ||
           word == UINT64_C(0x7fffffffffffffff);
}

// Adds one word and its complement to residue_words, unless the word is public.
static void residue_add(uint64_t word) {
    if (residue_is_public(word)) {
        return;
    }
    if (residue_word_count + 2 > RESIDUE_WORDS_MAX) {
        residue_words_full = 1;
        return;
    }
    residue_words[residue_word_count++] = word;
    residue_words[residue_word_count++] = ~word;
}

// One round on a, FIPS 202's Rnd, adding each value it computes on the way.
static void residue_round(uint64_t a[25], uint64_t round_constant) {
    uint64_t after_theta[25];
    uint64_t after_rho[25];
    uint64_t after_pi[25];
    for (int x = 0; x < 5; x++) {
        uint64_t first_three = a[x] ^ a[x + 5] ^ a[x + 10];
        residue_add(first_three);
        residue_add(first_three ^ a[x + 15] ^ a[x + 20]);
    }
    reference_theta(after_theta, a);
    for (int x = 0; x < 5; x++) {
        // theta adds one value, D[x], to each lane of column x.
        residue_add(after_theta[x] ^ a[x]);
    }
    reference_rho(after_rho, after_theta);
    reference_pi(after_pi, after_rho);
    reference_chi(a, after_pi);
    for (int i = 0; i < 25; i++) {
        residue_add(after_theta[i]);
        residue_add(after_rho[i]);
        residue_add(a[i]);
    }
    a[0] ^= round_constant;
    residue_add(a[0]);
}

// The sponge of FIPS 202 §4 a byte at a time, as proof/sha3_reference.h writes it, with the words
// of each permutation added as it runs.
typedef struct {
    uint64_t lane[25];
    size_t rate;
    size_t pos;
} residue_sponge;

static void residue_permute(residue_sponge *s) {
    for (int i = 0; i < 25; i++) {
        residue_add(s->lane[i]);
    }
    for (unsigned round = 0; round < 24; round++) {
        residue_round(s->lane, round_constants[round]);
    }
    s->pos = 0;
}

static void residue_absorb(residue_sponge *s, const uint8_t *in, size_t n) {
    for (size_t at = 0; at + 8 <= n; at += 8) {
        uint64_t lane = 0;
        for (size_t k = 0; k < 8; k++) {
            lane |= (uint64_t)in[at + k] << (8 * k);
        }
        residue_add(lane);
    }
    for (size_t i = 0; i < n; i++) {
        s->lane[s->pos / 8] ^= (uint64_t)in[i] << (8 * (s->pos % 8));
        s->pos++;
        if (s->pos == s->rate) {
            residue_permute(s);
        }
    }
}

static void residue_pad(residue_sponge *s, uint8_t domain) {
    s->lane[s->pos / 8] ^= (uint64_t)domain << (8 * (s->pos % 8));
    s->lane[(s->rate - 1) / 8] ^= (uint64_t)0x80 << (8 * ((s->rate - 1) % 8));
    residue_permute(s);
}

// n bytes of output: the block the padding's permutation left, and a permutation before each
// block after it.
static void residue_squeeze(residue_sponge *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (s->pos == s->rate) {
            residue_permute(s);
        }
        s->pos++;
    }
}

// The words of one kind of call: n_in bytes of residue_data absorbed at the rate, then, where
// domain is not zero, the padding with that suffix and n_out bytes of output.
static void residue_secret_words(size_t rate, size_t n_in, uint8_t domain, size_t n_out) {
    residue_sponge s;
    memset(&s, 0, sizeof s);
    s.rate = rate;
    residue_word_count = 0;
    residue_words_full = 0;
    residue_absorb(&s, residue_data, n_in);
    if (domain != 0) {
        residue_pad(&s, domain);
        residue_squeeze(&s, n_out);
    }
}

static int residue_is_secret(uint64_t word) {
    for (size_t i = 0; i < residue_word_count; i++) {
        if (residue_words[i] == word) {
            return 1;
        }
    }
    return 0;
}

// One kind: its calls over random bytes, then the search of the stack they left.
static void run_residue_shape(const char *shape, void (*call)(void), size_t rate, size_t n_in,
                              uint8_t domain, size_t n_out) {
    rng_bytes(residue_data, sizeof residue_data);
    call();
    residue_snapshot();
    compared++;
    residue_secret_words(rate, n_in, domain, n_out);
    if (residue_words_full) {
        failures++;
        (void)fprintf(stderr,
                      SHA3_RESIDUE_TEST ": residue: %s computes more words than "
                                        "RESIDUE_WORDS_MAX holds\n",
                      shape);
        return;
    }
    for (size_t at = 0; at + 8 <= RESIDUE_BYTES; at++) {
        uint64_t word = 0;
        memcpy(&word, &residue_copy[at], sizeof word);
        if (word != 0 && residue_is_secret(word)) {
            failures++;
            (void)fprintf(stderr,
                          SHA3_RESIDUE_TEST ": residue: after %s, the stack below the call holds "
                                            "a lane the call computed from its input, %zu bytes "
                                            "into the copy\n",
                          shape, at);
            return;
        }
    }
}

#ifdef SHA3_RESIDUE_BODIES
#include "sha3_residue_depth.h"
#endif

// The ten kinds, in a binary whose stack the search can read (test/stack_residue.c).
static void run_residue(void) {
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        (void)printf("SKIP " SHA3_RESIDUE_TEST ", the stack check: %s\n", unsearched);
        return;
    }
#ifdef SHA3_RESIDUE_BODIES
    run_residue_depth();
#endif
    run_residue_shape("a SHAKE256 absorb over whole blocks", residue_call_whole_blocks256,
                      SHAKE256_RATE, RESIDUE_TWO_BLOCKS256_LEN, 0, 0);
    run_residue_shape("a SHAKE128 absorb over whole blocks", residue_call_whole_blocks128,
                      SHAKE128_RATE, RESIDUE_TWO_BLOCKS128_LEN, 0, 0);
    run_residue_shape("a SHAKE256 absorb that fills a block the state held part of",
                      residue_call_buffered_block, SHAKE256_RATE, RESIDUE_BUFFERED_LEN, 0, 0);
    run_residue_shape("a SHAKE256 squeeze of two blocks", residue_call_squeeze, SHAKE256_RATE,
                      RESIDUE_SQUEEZE_IN_LEN, 0x1f, RESIDUE_SQUEEZE_OUT_LEN);
    run_residue_shape("a SHAKE256 absorb one byte short of a block", residue_call_short_block,
                      SHAKE256_RATE, SHAKE256_RATE - 1, 0, 0);
    run_residue_shape("a SHAKE256 absorb that fills its block to the last byte",
                      residue_call_exact_block, SHAKE256_RATE, SHAKE256_RATE, 0, 0);
    run_residue_shape("a SHAKE256 squeeze to the last byte of its block", residue_call_read_block,
                      SHAKE256_RATE, RESIDUE_SQUEEZE_IN_LEN, 0x1f, SHAKE256_RATE);
    run_residue_shape("a SHAKE256 squeeze a byte past its block", residue_call_past_block,
                      SHAKE256_RATE, RESIDUE_SQUEEZE_IN_LEN, 0x1f, SHAKE256_RATE + 1);
    run_residue_shape("sha3_256" SHA3_RESIDUE_SUFFIX, residue_call_sha3_256, SHA3_256_RATE,
                      RESIDUE_SHA3_256_LEN, 0x06, SHA3_256_LEN);
    run_residue_shape("sha3_512" SHA3_RESIDUE_SUFFIX, residue_call_sha3_512, SHA3_512_RATE,
                      RESIDUE_SHA3_512_LEN, 0x06, SHA3_512_LEN);
}

#endif
