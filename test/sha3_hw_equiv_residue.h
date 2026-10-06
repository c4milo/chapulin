// What sha3_hw.c's calls leave on the stack. A call's state comes from its
// input, which under ML-KEM is a secret seed, and Keccak-f[1600] is a
// permutation: one whole state gives back the state before it. sha3_hw.c
// keeps the 25 lanes in registers through the rounds of permute_blocks and
// writes them to the caller's state alone, and sha3_256_hw and sha3_512_hw
// wipe the state they hash in. A frame is dead after its call returns, but
// its bytes stay in memory below this binary's own frames until another
// call writes over them.
//
// Each residue_call_ function below makes the calls of one kind, so that
// every way sha3_hw.c runs its permutation runs once: over whole blocks of
// the caller's bytes at each of the three rates, on a block the state held
// part of, after the padding, and between two blocks of output. The streams
// work in a context that is static, so the context's own copy of the state
// is not on the stack; the two digests hash in a state on their own frame.
// residue_snapshot then copies the stack below its caller as deep as
// RESIDUE_BYTES, where the dead frames lay, and run_residue_shape looks in
// the copy for one 64-bit word that is a lane the call computed. Those are,
// for every permutation the call ran:
//
//   the state the permutation starts from;
//   each eight bytes of the message as a lane, which is how a copy of the
//   input lies in a register;
//   and for each of the 24 rounds, by FIPS 202 §3.2: the parity of each
//   column, and the exclusive OR of the column's first three lanes, which
//   the first of the two EOR3 instructions returns; the five values theta
//   adds to a column; every lane after theta, after rho and after chi; and
//   lane 0 after iota.
//
// proof/sha3_reference.h computes them, the standard's steps as loops,
// which share no line with sha3_hw.c or with sha3.c's round.
//
// A public word is left out, because memory may hold it for another
// reason: a zero, which a fresh state and unwritten memory hold, and the
// last bit of the padding alone in its lane. Every kind's message ends
// seven bytes into a lane, so the lane that takes the first byte of the
// padding holds seven bytes of the message as well.
//
// One word is enough to fail. A register holds a lane in its low half, so a
// register a compiler stored is one lane beside eight bytes that are no
// lane, and 64 bits a call computed do not turn up by chance.
//
// The search reads the stack one compiler left on one call. It cannot see
// a register, and test/stack_residue.c names the builds whose stack it does
// not search.
//
// Included by test/sha3_hw_equiv_test.c only, which declares the generator,
// the round constants and the counts this file uses.
#ifndef CH_SHA3_HW_EQUIV_RESIDUE_H
#define CH_SHA3_HW_EQUIV_RESIDUE_H

#define RESIDUE_BYTES 4096
#define RESIDUE_PERMUTATIONS_MAX 4
// The most words one permutation adds: the 25 lanes it starts from, at most
// 21 lanes of message, and for each round five parities, five partial
// parities, five values of d, 25 lanes after each of three steps and lane 0
// after iota.
#define RESIDUE_PERMUTATION_WORDS (25 + 21 + 24 * (5 + 5 + 5 + 3 * 25 + 1))
#define RESIDUE_WORDS_MAX ((size_t)RESIDUE_PERMUTATIONS_MAX * RESIDUE_PERMUTATION_WORDS)
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

// Whole blocks of the caller's bytes: the state stays in registers from the
// first block to the second, and each block's lanes go into it from the
// message.
static __attribute__((noinline)) void residue_call_whole_blocks256(void) {
    shake256_init_hw(&residue_context);
    shake_absorb_hw(&residue_context, residue_data, RESIDUE_TWO_BLOCKS256_LEN);
}

static __attribute__((noinline)) void residue_call_whole_blocks128(void) {
    shake128_init_hw(&residue_context);
    shake_absorb_hw(&residue_context, residue_data, RESIDUE_TWO_BLOCKS128_LEN);
}

// A block the state held part of: the second call fills it, and the
// permutation runs with no lane from the message.
#define RESIDUE_BUFFERED_LEN ((size_t)200)
static __attribute__((noinline)) void residue_call_buffered_block(void) {
    shake256_init_hw(&residue_context);
    shake_absorb_hw(&residue_context, residue_data, 100);
    shake_absorb_hw(&residue_context, residue_data + 100, RESIDUE_BUFFERED_LEN - 100);
}

// The permutation after the padding, and the one between two blocks of
// output.
#define RESIDUE_SQUEEZE_IN_LEN ((size_t)55)
#define RESIDUE_SQUEEZE_OUT_LEN ((size_t)200)
static __attribute__((noinline)) void residue_call_squeeze(void) {
    shake256_init_hw(&residue_context);
    shake_absorb_hw(&residue_context, residue_data, RESIDUE_SQUEEZE_IN_LEN);
    shake_squeeze_hw(&residue_context, residue_out, RESIDUE_SQUEEZE_OUT_LEN);
}

// The two digests, whose state is on their own frame.
#define RESIDUE_SHA3_256_LEN ((size_t)(2 * SHA3_256_RATE + 23))
static __attribute__((noinline)) void residue_call_sha3_256(void) {
    sha3_256_hw(residue_data, RESIDUE_SHA3_256_LEN, residue_out);
}

#define RESIDUE_SHA3_512_LEN ((size_t)(2 * SHA3_512_RATE + 23))
static __attribute__((noinline)) void residue_call_sha3_512(void) {
    sha3_512_hw(residue_data, RESIDUE_SHA3_512_LEN, residue_out);
}

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
const char *stack_residue_unsearched(void);

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

// Adds one word to residue_words, unless it is public: a zero, or the last
// bit of the padding alone in its lane.
static void residue_add(uint64_t word) {
    if (word == 0 || word == UINT64_C(0x8000000000000000)) {
        return;
    }
    if (residue_word_count == RESIDUE_WORDS_MAX) {
        residue_words_full = 1;
        return;
    }
    residue_words[residue_word_count++] = word;
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

// The sponge of FIPS 202 §4 a byte at a time, as proof/sha3_reference.h
// writes it, with the words of each permutation added as it runs.
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

// n bytes of output: the block the padding's permutation left, and a
// permutation before each block after it.
static void residue_squeeze(residue_sponge *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (s->pos == s->rate) {
            residue_permute(s);
        }
        s->pos++;
    }
}

// The words of one kind of call: n_in bytes of residue_data absorbed at the
// rate, then, where domain is not zero, the padding with that suffix and
// n_out bytes of output.
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

// One kind: its calls over random bytes, then the search of the stack they
// left.
static void run_residue_shape(const char *shape, void (*call)(void), size_t rate, size_t n_in,
                              uint8_t domain, size_t n_out) {
    rng_bytes(residue_data, sizeof residue_data);
    call();
    residue_snapshot();
    compared++;
    residue_secret_words(rate, n_in, domain, n_out);
    if (residue_words_full) {
        failures++;
        (void)fprintf(stderr, "sha3 instructions equivalence: residue: %s computes more words "
                              "than RESIDUE_WORDS_MAX holds\n", shape);
        return;
    }
    for (size_t at = 0; at + 8 <= RESIDUE_BYTES; at++) {
        uint64_t word = 0;
        memcpy(&word, &residue_copy[at], sizeof word);
        if (word != 0 && residue_is_secret(word)) {
            failures++;
            (void)fprintf(stderr,
                          "sha3 instructions equivalence: residue: after %s, the stack below the "
                          "call holds a lane the call computed from its input, %zu bytes into "
                          "the copy\n",
                          shape, at);
            return;
        }
    }
}

// The six kinds, in a binary whose stack the search can read
// (test/stack_residue.c).
static void run_residue(void) {
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        (void)printf("SKIP sha3 instructions equivalence, the stack check: %s\n", unsearched);
        return;
    }
    run_residue_shape("a SHAKE256 absorb over whole blocks", residue_call_whole_blocks256,
                      SHAKE256_RATE, RESIDUE_TWO_BLOCKS256_LEN, 0, 0);
    run_residue_shape("a SHAKE128 absorb over whole blocks", residue_call_whole_blocks128,
                      SHAKE128_RATE, RESIDUE_TWO_BLOCKS128_LEN, 0, 0);
    run_residue_shape("a SHAKE256 absorb that fills a block the state held part of",
                      residue_call_buffered_block, SHAKE256_RATE, RESIDUE_BUFFERED_LEN, 0, 0);
    run_residue_shape("a SHAKE256 squeeze of two blocks", residue_call_squeeze, SHAKE256_RATE,
                      RESIDUE_SQUEEZE_IN_LEN, 0x1f, RESIDUE_SQUEEZE_OUT_LEN);
    run_residue_shape("sha3_256_hw", residue_call_sha3_256, SHA3_256_RATE, RESIDUE_SHA3_256_LEN,
                      0x06, SHA3_256_LEN);
    run_residue_shape("sha3_512_hw", residue_call_sha3_512, SHA3_512_RATE, RESIDUE_SHA3_512_LEN,
                      0x06, SHA3_512_LEN);
}

#endif
