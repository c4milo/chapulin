// What sha512.c's first arm leaves on the stack: the plain C every session
// of a host object hashes SHA-512 and SHA-384 with (docs/decisions.md 127).
// sha512_compress_blocks leaves the sixteen words of its message schedule
// in its frame, and whichever working variables its compiler wrote to stack
// slots of its own, so sha512.c wipes SHA512_COMPRESS_BLOCKS_BELOW_LEN bytes
// of the stack below each call of it, and its two calls that take a whole
// message wipe the context they hash in. Three checks, each on a copy
// residue512_snapshot takes of the RESIDUE512_BYTES of stack below its
// caller, after residue512_paint has written RESIDUE512_PAINT over them:
//
//   run_residue512_depth calls sha512_compress_blocks by its own name, with
//   no wipe after it. It requires the lowest byte the call wrote within
//   SHA512_COMPRESS_BLOCKS_BELOW_LEN of its caller, so the wipe covers the
//   frame, and it requires the search to find a word of the schedule there,
//   so a search that could find nothing fails.
//
//   run_residue512_first_arm makes the six kinds of call
//   test/sha2_equiv_residue512.h lists under the library's own names, and
//   requires no word of the set in the copy, at any byte offset, and the
//   copy's lowest bytes still painted, so the copy holds every byte the
//   calls wrote.
//
//   report_residue512_reference makes one of those calls on sha512.c's
//   second arm, the reference, and prints how many words it finds. That
//   arm and sha512_compress.c wipe nothing (docs/invariants.md INV-17),
//   and the line is the measure of it on this compiler. It fails nothing.
//
// One word is enough to fail the first arm: a compiler that keeps a value
// in a slot of its own need not keep two side by side, and a word of 64
// random bits matches no other eight bytes by chance.
//
// RESIDUE512_BYTES stays under 4096 for test/p256_equiv_residue.h's reason:
// a frame of 4096 bytes or more makes the compiler call a stack probe, and
// Darwin's stores scratch registers on the stack, which after a hash can
// hold a word of the state. That word would be this file's doing.
//
// A compiler may still write into the copied bytes on its own account: gcc
// for arm64 stores a zero 1,024 bytes above the bottom of each frame
// longer than that, residue512_snapshot's among them. So the first check
// takes one copy with no call between the paint and the copy, and a byte
// that copy shows unpainted counts for no call's depth.
//
// The searches hold a claim about optimized code alone, as
// test/sha2_equiv_residue.h's do (test/stack_residue.c).
//
// Included by test/sha2_equiv_residue512.h only.
#ifndef CH_SHA2_EQUIV_RESIDUE512_FIRST_ARM_H
#define CH_SHA2_EQUIV_RESIDUE512_FIRST_ARM_H

#define RESIDUE512_BYTES 3072
#define RESIDUE512_PAINT 0xa5
// How many of the copy's lowest bytes must still hold the paint after a
// call, so that the copy is known to hold everything the call wrote.
#define RESIDUE512_UNWRITTEN_MIN 64

static uint8_t residue512_copy[RESIDUE512_BYTES];
// What the copy holds when no call runs between the paint and the copy.
static uint8_t residue512_no_call[RESIDUE512_BYTES];

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_fill(volatile uint8_t *below, size_t n, uint8_t value);

static __attribute__((noinline)) void residue512_snapshot(void) {
    volatile uint8_t below[RESIDUE512_BYTES];
    stack_residue_take(below, RESIDUE512_BYTES, residue512_copy);
}

// Writes RESIDUE512_PAINT over the stack residue512_snapshot copies, and
// over RESIDUE512_PAINT_MARGIN bytes below that, so the copy's lowest bytes
// are painted wherever a compiler puts each function's array in its frame.
#define RESIDUE512_PAINT_MARGIN 512
static __attribute__((noinline)) void residue512_paint(void) {
    volatile uint8_t below[RESIDUE512_BYTES + RESIDUE512_PAINT_MARGIN];
    stack_residue_fill(below, sizeof below, RESIDUE512_PAINT);
}

// The copy with no call between the paint and the copy, into
// residue512_no_call: the bytes this file's own two functions leave
// unpainted.
static void residue512_take_no_call(void) {
    residue512_paint();
    residue512_snapshot();
    memcpy(residue512_no_call, residue512_copy, sizeof residue512_no_call);
}

// How far below the top of the copy the lowest byte lies that the calls
// since residue512_paint wrote: one that no longer holds the paint, and
// that holds it where no call ran. 0 when they wrote nothing.
static size_t residue512_depth(void) {
    for (size_t i = 0; i < RESIDUE512_BYTES; i++) {
        if (residue512_copy[i] != RESIDUE512_PAINT && residue512_no_call[i] == RESIDUE512_PAINT) {
            return RESIDUE512_BYTES - i;
        }
    }
    return 0;
}

// How many secret words the copy holds, at any byte offset, and where the
// first one lies, through *first_at.
static size_t residue512_found(size_t *first_at) {
    size_t found = 0;
    for (size_t at = 0; at + 8 <= RESIDUE512_BYTES; at++) {
        if (residue512_word_at(residue512_copy, at)) {
            if (found == 0) {
                *first_at = at;
            }
            found++;
        }
    }
    return found;
}

// One shape's calls on path between the paint and the copy, and then the
// set of its secret words. Returns 0 where this file's SHA-512 and the
// reference's disagree, which fails the run.
static int residue512_painted_call(const residue512_shape *shape, const path512 *path) {
    rng_fill(residue512_data, sizeof residue512_data);
    residue512_path = path;
    residue512_every_value = 1;
    residue512_paint();
    shape->call();
    residue512_snapshot();
    compared++;
    if (!residue512_secret_words(shape->is384, shape->n, shape->padded)) {
        report("residue", "this file's SHA-512 and sha512.c's disagree", shape->n, 0, 0, 0);
        return 0;
    }
    return 1;
}

// Two whole blocks through sha512_compress_blocks itself, from SHA-512's
// initial value, with no wipe after the call.
static __attribute__((noinline)) void residue512_call_compress_blocks(void) {
    sha512_init(&residue512_state);
    sha512_compress_blocks(residue512_state.h, residue512_data, 2);
}

static void run_residue512_depth(void) {
    static const residue512_shape shape = {"sha512_compress_blocks over two blocks",
                                           residue512_call_compress_blocks, RESIDUE512_WHOLE_LEN, 0,
                                           0};
    if (!residue512_painted_call(&shape, &PATH512_FIRST_ARM)) {
        return;
    }
    size_t depth = residue512_depth();
    size_t first_at = 0;
    size_t found = residue512_found(&first_at);
    (void)printf("sha2 equivalence: sha512_compress_blocks writes %zu bytes below its caller and "
                 "leaves %zu words it computed there\n",
                 depth, found);
    if (depth == 0 || depth > SHA512_COMPRESS_BLOCKS_BELOW_LEN) {
        failures++;
        (void)fprintf(stderr,
                      "sha2 equivalence: residue: sha512_compress_blocks writes %zu bytes below "
                      "its caller, and sha512.c wipes %d\n",
                      depth, SHA512_COMPRESS_BLOCKS_BELOW_LEN);
    }
    if (found == 0) {
        failures++;
        (void)fprintf(stderr, "sha2 equivalence: residue: the search finds no word of the message "
                              "schedule after a call of sha512_compress_blocks with no wipe, so "
                              "it would find none after a call with one\n");
    }
}

static void run_residue512_first_arm_shape(const residue512_shape *shape) {
    if (!residue512_painted_call(shape, &PATH512_FIRST_ARM)) {
        return;
    }
    size_t depth = residue512_depth();
    if (depth > RESIDUE512_BYTES - RESIDUE512_UNWRITTEN_MIN) {
        failures++;
        (void)fprintf(stderr,
                      "sha2 equivalence: residue: %s on sha512.c's first arm writes %zu bytes "
                      "below its caller, and the copy holds %d\n",
                      shape->name, depth, RESIDUE512_BYTES);
        return;
    }
    size_t first_at = 0;
    size_t found = residue512_found(&first_at);
    if (found != 0) {
        failures++;
        (void)fprintf(stderr,
                      "sha2 equivalence: residue: after %s on sha512.c's first arm, the stack "
                      "below the call holds %zu words that the call computed from its input, the "
                      "first %zu bytes below the top of the copy\n",
                      shape->name, found, RESIDUE512_BYTES - first_at);
    }
}

// What the reference leaves after SHA-384 of a whole message, printed and
// not judged.
static void report_residue512_reference(void) {
    const residue512_shape *shape = &residue512_shapes[RESIDUE512_SHAPES - 2];
    if (!residue512_painted_call(shape, &PATH512_REFERENCE)) {
        return;
    }
    size_t first_at = 0;
    (void)printf("sha2 equivalence: sha512.c's second arm, which wipes nothing, leaves %zu words "
                 "it computed from a %zu-byte message on the stack after sha384_of\n",
                 residue512_found(&first_at), shape->n);
}

// The three checks, in a binary whose stack the search can read: an
// optimized build without AddressSanitizer (test/stack_residue.c).
static void run_residue512_first_arm(void) {
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        (void)printf("SKIP sha2 equivalence, the stack check of sha512.c's first arm: %s\n",
                     unsearched);
        return;
    }
    residue512_take_no_call();
    run_residue512_depth();
    for (size_t i = 0; i < RESIDUE512_SHAPES; i++) {
        run_residue512_first_arm_shape(&residue512_shapes[i]);
    }
    report_residue512_reference();
}

#endif
