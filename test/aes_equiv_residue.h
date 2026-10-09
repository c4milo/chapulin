// What aes_hw.c's key expansions leave on the stack. Under
// -DCH_SUITE_AES_GCM a key is a traffic key, and FIPS 197 §5.2's step runs
// backwards as well as forwards: any one round key of AES-128, or any two
// in a row of AES-256, gives back the key. The x86-64 expansion keeps its
// values in vector registers and writes the round keys to the caller's
// schedule alone. The arm64 one keeps two words in memory and wipes them
// before it returns. A frame is dead after its call returns, but its bytes
// stay in memory below this binary's own frames until another call writes
// over them.
//
// Each run takes a key from the seeded generator, and residue_snapshot
// clears the stack below its caller as deep as RESIDUE_BYTES. The run
// makes one call to an expansion on the instructions, and
// residue_snapshot copies the same bytes. Every byte in the copy that is
// not zero was written by the call. run_residue_key then looks in the
// copy, at every byte offset, for any 32-bit word the expansion computed.
// Those are, in the host's byte order:
//
//   each word of every round key, the key's own words among them;
//   for each step of §5.2 that takes a temporary, every Nk-th word and
//   AES-256's fourth word after it: the SubWord of the word before, and
//   where the step takes RotWord, that SubWord rotated and the temporary
//   with the round constant on its first byte;
//   for each round key Nk words before another, the words aes_hw.c's
//   prefix_xor adds up: each two words in a row after its first shift,
//   and its first three and all four words after the second.
//
// The words come from the schedule quic_aes_soft.c's table writes, which
// runs only after the copy, so its own frame cannot hold them first. A
// step's temporary is its new word exclusive-ored with the word Nk before
// it, and the SubWord follows from the temporary by removing the round
// constant and the rotation.
//
// Two of rot_word_each's values are left out: its shifts by 8 and by 24
// bits, which hold three bytes and one byte of a word beside zeros, and
// so would match bytes no call wrote. A zero word is left out too,
// because the cleared stack holds zeros.
//
// One word is enough to fail. 32 bits the call computed do not turn up by
// chance in the bytes one call writes.
//
// The search reads the stack one compiler left on one call. It cannot see
// a register, and test/stack_residue.c names the builds whose stack it
// does not search.
//
// Included by test/aes_equiv_test.c only, which declares both
// implementations, the generator and the failure count this file uses.
#ifndef CH_AES_EQUIV_RESIDUE_H
#define CH_AES_EQUIV_RESIDUE_H

#define RESIDUE_BYTES 4096
#define RESIDUE_RUNS 16
// AES-256's words, the more of the two sizes: 60 round-key words, three
// words for each of the seven steps that take RotWord and one for each of
// the six that do not, and five sums for each of the 13 round keys
// prefix_xor reads.
#define RESIDUE_WORDS_MAX 256
#define RESIDUE_WORDS_PER_ROUND_KEY 4

// FIPS 197 Table 5's round constants, the first byte of Rcon[1] to
// Rcon[10]. AES-256 reads the first seven.
static const uint8_t residue_round_constants[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
                                                    0x20, 0x40, 0x80, 0x1b, 0x36};

static uint8_t residue_copy[RESIDUE_BYTES];
static uint8_t residue_key[AES_256_KEY];
static uint8_t residue_schedule[ROUND_KEY_BYTES_256];
static uint8_t residue_reference[ROUND_KEY_BYTES_256];
static uint32_t residue_words[RESIDUE_WORDS_MAX];
static size_t residue_word_count;
static unsigned long residue_runs;

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
void stack_residue_fill(volatile uint8_t *below, size_t n, uint8_t value);
const char *stack_residue_unsearched(void);

// The copy starts below residue_snapshot's return address and stack
// canary, a few dozen bytes under its caller's frame. A call made straight
// from that caller could keep its values in those bytes: an x86-64 leaf
// function may store up to 128 bytes below its stack pointer without
// moving it, and gcc 13 makes a one-line wrapper's call a jump, so the
// expansion's stack pointer sits one return address under the caller's.
// So each expansion runs one frame deeper, under RESIDUE_DEPTH bytes the
// wrapper keeps until the call returns, and its stores land in the copy.
#define RESIDUE_DEPTH 64

static __attribute__((noinline)) void residue_call_128(void) {
    volatile uint8_t depth[RESIDUE_DEPTH];
    stack_residue_fill(depth, RESIDUE_DEPTH, 0);
    aes_expand_round_keys_hw(residue_key, residue_schedule);
    (void)depth[0];
}

static __attribute__((noinline)) void residue_call_256(void) {
    volatile uint8_t depth[RESIDUE_DEPTH];
    stack_residue_fill(depth, RESIDUE_DEPTH, 0);
    aes_expand_round_keys_256_hw(residue_key, residue_schedule);
    (void)depth[0];
}

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

static void residue_add(uint32_t word) {
    if (word != 0 && residue_word_count < RESIDUE_WORDS_MAX) {
        residue_words[residue_word_count++] = word;
    }
}

// Word i of the schedule, as its four bytes lie in memory.
static uint32_t residue_schedule_word(size_t i) {
    uint32_t word;
    memcpy(&word, &residue_reference[i * 4], sizeof word);
    return word;
}

// The words of a schedule of word_count words for a key of nk words,
// which residue_reference holds. A host object is little-endian
// (cpu_cfg.h), so a word's first byte is its low 8 bits, where the round
// constant goes, and RotWord is a rotation right by 8 bits.
static void residue_secret_words(size_t nk, size_t word_count) {
    residue_word_count = 0;
    for (size_t i = 0; i < word_count; i++) {
        residue_add(residue_schedule_word(i));
    }
    for (size_t i = nk; i < word_count; i++) {
        uint32_t temporary = residue_schedule_word(i) ^ residue_schedule_word(i - nk);
        if (i % nk == 0) {
            uint32_t rotated = temporary ^ residue_round_constants[i / nk - 1];
            residue_add((rotated << 8) | (rotated >> 24));
            residue_add(rotated);
            residue_add(temporary);
        } else if (nk == 8 && i % nk == 4) {
            residue_add(temporary);
        }
    }
    size_t round_keys = word_count / RESIDUE_WORDS_PER_ROUND_KEY;
    for (size_t r = 0; r + nk / RESIDUE_WORDS_PER_ROUND_KEY < round_keys; r++) {
        uint32_t a[RESIDUE_WORDS_PER_ROUND_KEY];
        for (size_t k = 0; k < RESIDUE_WORDS_PER_ROUND_KEY; k++) {
            a[k] = residue_schedule_word(r * RESIDUE_WORDS_PER_ROUND_KEY + k);
        }
        residue_add(a[0] ^ a[1]);
        residue_add(a[1] ^ a[2]);
        residue_add(a[2] ^ a[3]);
        residue_add(a[0] ^ a[1] ^ a[2]);
        residue_add(a[0] ^ a[1] ^ a[2] ^ a[3]);
    }
}

// One run: a fresh key, the call between two snapshots, and the search.
static void run_residue_key(const char *size, void (*call)(void), size_t key_len,
                            void (*reference)(const uint8_t *, uint8_t *), size_t schedule_len) {
    rng_fill(residue_key, key_len);
    residue_snapshot();
    call();
    residue_snapshot();
    reference(residue_key, residue_reference);
    residue_secret_words(key_len / 4, schedule_len / 4);
    if (residue_word_count == RESIDUE_WORDS_MAX) {
        failures++;
        (void)fprintf(stderr,
                      "FAIL residue: the %s expansion computes more words than "
                      "RESIDUE_WORDS_MAX holds\n",
                      size);
        return;
    }
    for (size_t at = 0; at + 4 <= RESIDUE_BYTES; at++) {
        uint32_t word;
        memcpy(&word, &residue_copy[at], sizeof word);
        for (size_t i = 0; word != 0 && i < residue_word_count; i++) {
            if (word == residue_words[i]) {
                failures++;
                (void)fprintf(stderr,
                              "FAIL residue: after the %s expansion on the instructions, the "
                              "stack below the call holds a word the expansion computed, %zu "
                              "bytes into the copy\n",
                              size, at);
                return;
            }
        }
    }
    residue_runs++;
}

static void run_residue(void) {
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        (void)printf("SKIP aes equivalence, the stack check: %s\n", unsearched);
        return;
    }
    for (size_t i = 0; i < RESIDUE_RUNS && failures == 0; i++) {
        run_residue_key("AES-128", residue_call_128, AES_128_KEY, aes_expand_round_keys_soft,
                        ROUND_KEY_BYTES);
        run_residue_key("AES-256", residue_call_256, AES_256_KEY, aes_expand_round_keys_256_soft,
                        ROUND_KEY_BYTES_256);
    }
}

#endif
