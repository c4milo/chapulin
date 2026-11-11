// The depth check of test/sha3_residue.h, for an object whose sha3.c wipes the stack below each
// entry that ran the permutation (docs/decisions.md 219). test/sha3_equiv_test.c defines
// SHA3_RESIDUE_BODIES in such an object, and test/sha3_residue.h then includes this file. It
// calls each entry's body by its own name, with no wipe after it, and requires the lowest byte
// the body wrote within SHA3_BELOW_LEN of its caller, so the wipe covers the body's frames. It
// also requires the search to find a word after the bodies, so a search that could find nothing
// fails.
//
// Included by test/sha3_residue.h only, after the kinds of call, the snapshot and the words of a
// kind.
#ifndef CH_SHA3_RESIDUE_DEPTH_H
#define CH_SHA3_RESIDUE_DEPTH_H

// The bodies of the entries, which sha3.c's entries call before the wipe below them, called here
// by their own names with no wipe after them: absorb under shake_absorb, pad_finish and squeeze
// under shake_squeeze, and keccak under sha3_256 and sha3_512. Each kind's calls match the
// entries' calls of the same kind above.
static __attribute__((noinline)) void residue_body_whole_blocks256(void) {
    SHA3_RESIDUE_ENTRY(shake256_init)(&residue_context);
    absorb(residue_context.lane, residue_context.rate, &residue_context.pos, residue_data,
           RESIDUE_TWO_BLOCKS256_LEN);
}

static __attribute__((noinline)) void residue_body_whole_blocks128(void) {
    SHA3_RESIDUE_ENTRY(shake128_init)(&residue_context);
    absorb(residue_context.lane, residue_context.rate, &residue_context.pos, residue_data,
           RESIDUE_TWO_BLOCKS128_LEN);
}

static __attribute__((noinline)) void residue_body_buffered_block(void) {
    SHA3_RESIDUE_ENTRY(shake256_init)(&residue_context);
    absorb(residue_context.lane, residue_context.rate, &residue_context.pos, residue_data, 100);
    absorb(residue_context.lane, residue_context.rate, &residue_context.pos, residue_data + 100,
           RESIDUE_BUFFERED_LEN - 100);
}

static __attribute__((noinline)) void residue_body_squeeze(void) {
    SHA3_RESIDUE_ENTRY(shake256_init)(&residue_context);
    absorb(residue_context.lane, residue_context.rate, &residue_context.pos, residue_data,
           RESIDUE_SQUEEZE_IN_LEN);
    pad_finish(residue_context.lane, residue_context.rate, &residue_context.pos, SHAKE_DOMAIN);
    squeeze(residue_context.lane, residue_context.rate, &residue_context.pos, residue_out,
            RESIDUE_SQUEEZE_OUT_LEN);
}

static __attribute__((noinline)) void residue_body_sha3_256(void) {
    keccak(SHA3_256_RATE, SHA3_DOMAIN, residue_data, RESIDUE_SHA3_256_LEN, residue_out,
           SHA3_256_LEN);
}

static __attribute__((noinline)) void residue_body_sha3_512(void) {
    keccak(SHA3_512_RATE, SHA3_DOMAIN, residue_data, RESIDUE_SHA3_512_LEN, residue_out,
           SHA3_512_LEN);
}

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_fill(volatile uint8_t *below, size_t n, uint8_t value);

#define RESIDUE_PAINT 0xa5
// residue_paint paints this many bytes below the copy as well, so the copy's lowest bytes are
// painted wherever a compiler puts each function's array in its frame.
#define RESIDUE_PAINT_MARGIN 512

static uint8_t residue_no_call[RESIDUE_BYTES];

static __attribute__((noinline)) void residue_paint(void) {
    volatile uint8_t below[RESIDUE_BYTES + RESIDUE_PAINT_MARGIN];
    stack_residue_fill(below, sizeof below, RESIDUE_PAINT);
}

// How far below the top of the copy the lowest byte lies that the call since residue_paint
// wrote: a byte that no longer holds the paint, and that holds it where no call ran. 0 when the
// call wrote nothing.
static size_t residue_depth(void) {
    for (size_t i = 0; i < RESIDUE_BYTES; i++) {
        if (residue_copy[i] != RESIDUE_PAINT && residue_no_call[i] == RESIDUE_PAINT) {
            return RESIDUE_BYTES - i;
        }
    }
    return 0;
}

// How many words of the set the copy holds, at any byte offset.
static size_t residue_found(void) {
    size_t found = 0;
    for (size_t at = 0; at + 8 <= RESIDUE_BYTES; at++) {
        uint64_t word = 0;
        memcpy(&word, &residue_copy[at], sizeof word);
        if (word != 0 && residue_is_secret(word)) {
            found++;
        }
    }
    return found;
}

// One kind's bodies between the paint and the copy: the depth they write to, which must lie
// within SHA3_BELOW_LEN, and the count of words they leave, which run_residue_depth adds up. The
// calls run once before the paint, so a first call's work in the dynamic linker counts for no
// depth.
static size_t run_residue_body(const char *shape, void (*call)(void), size_t rate, size_t n_in,
                               uint8_t domain, size_t n_out) {
    rng_bytes(residue_data, sizeof residue_data);
    call();
    residue_paint();
    call();
    residue_snapshot();
    compared++;
    size_t depth = residue_depth();
    residue_secret_words(rate, n_in, domain, n_out);
    size_t found = residue_found();
    (void)printf(SHA3_RESIDUE_TEST ": the body under %s writes %zu bytes below its caller and "
                                   "leaves %zu words it computed there\n",
                 shape, depth, found);
    if (depth == 0 || depth > SHA3_BELOW_LEN) {
        failures++;
        (void)fprintf(stderr,
                      SHA3_RESIDUE_TEST ": residue: the body under %s writes %zu bytes below its "
                                        "caller, and sha3.c wipes %d\n",
                      shape, depth, SHA3_BELOW_LEN);
    }
    return found;
}

// The six kinds' bodies, and a search that finds at least one word after them.
static void run_residue_depth(void) {
    residue_paint();
    residue_snapshot();
    memcpy(residue_no_call, residue_copy, sizeof residue_no_call);
    size_t found = 0;
    found += run_residue_body("a SHAKE256 absorb over whole blocks", residue_body_whole_blocks256,
                              SHAKE256_RATE, RESIDUE_TWO_BLOCKS256_LEN, 0, 0);
    found += run_residue_body("a SHAKE128 absorb over whole blocks", residue_body_whole_blocks128,
                              SHAKE128_RATE, RESIDUE_TWO_BLOCKS128_LEN, 0, 0);
    found +=
        run_residue_body("a SHAKE256 absorb that fills a block the state held part of",
                         residue_body_buffered_block, SHAKE256_RATE, RESIDUE_BUFFERED_LEN, 0, 0);
    found += run_residue_body("a SHAKE256 squeeze of two blocks", residue_body_squeeze,
                              SHAKE256_RATE, RESIDUE_SQUEEZE_IN_LEN, 0x1f, RESIDUE_SQUEEZE_OUT_LEN);
    found += run_residue_body("sha3_256", residue_body_sha3_256, SHA3_256_RATE,
                              RESIDUE_SHA3_256_LEN, 0x06, SHA3_256_LEN);
    found += run_residue_body("sha3_512", residue_body_sha3_512, SHA3_512_RATE,
                              RESIDUE_SHA3_512_LEN, 0x06, SHA3_512_LEN);
    if (found == 0) {
        failures++;
        (void)fprintf(stderr, SHA3_RESIDUE_TEST ": residue: the search finds no word after the "
                                                "bodies with no wipe, so it would find none "
                                                "after the entries with one\n");
    }
}

#endif
