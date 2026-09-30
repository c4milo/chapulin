// CHACHA=vector against CHACHA=portable: the same key, nonce, counter and
// input, the same output, byte for byte. This is what holds the vector
// path, because CBMC cannot read an intrinsic: proof/chacha20_harness.c
// proves chacha20.c's loop, and this binary holds chacha20_vector.c to
// that loop's answer. chacha20.c compiles here without -DCH_CHACHA_VECTOR,
// so chacha20_xor is the portable loop, and test/chacha20_equiv_vector.c
// compiles chacha20_vector_xor under it, both in one binary.
//
// Every comparison checks two things over the bytes a case uses: the
// output holds the portable path's bytes, and no byte outside the output
// changed. It does so in each aliasing shape chacha20.h allows: a
// separate output, the output on the input, and the output below the
// input, as rec_open decrypts over its header, each at every alignment
// past a 16-byte boundary.
//
// The inputs, in order:
//
//   - every length from 0 to LENGTH_MAX, which crosses the path's pass
//     of eight blocks four times on NEON and its pass of four blocks
//     eight times on SSE2, so the pass loop, the last partial pass, every
//     length of that pass, and on NEON a last pass that ends in either
//     of its two groups all run;
//   - the counter's last values, 2^32 - 17 to 2^32 - 1, and 0, at every
//     length to 20 blocks, so the 32-bit counter wraps inside a group, at
//     the edge between a pass's two groups, at a pass's edge, inside the
//     pass after it, and in the last partial pass;
//   - RANDOM_CASES cases with a random key, nonce, counter, length up to
//     RANDOM_LENGTH_MAX, alignment and aliasing shape;
//   - a 16 KiB record with its content type byte, 16,385 bytes, and 64 KiB.
//
// RFC 8439's vectors are not repeated here. bin/unit runs them on the
// portable loop and bin/unit_chacha_vector on this path, so both answer
// the published standard directly and not only through each other.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// chacha20_vector.h declares the vector path only under the define. This
// file compiles no library source, so the define changes nothing else.
#define CH_CHACHA_VECTOR
#include "chacha20.h"
#include "chacha20_vector.h"

// xorshift64, the generator test/aes_equiv_test.c uses. The default seed
// is fixed, so an ordinary run replays the same cases and a mismatch
// reproduces bit for bit; CH_CHACHA20_EQUIV_SEED sets another, and this
// binary prints the seed it used.
#define CHACHA20_EQUIV_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = CHACHA20_EQUIV_DEFAULT_SEED;

// Reads CH_CHACHA20_EQUIV_SEED, if set, as the seed, and returns the seed
// in use. A value that is not a number, or zero, keeps the default:
// xorshift64 is all zeroes forever from zero.
static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_CHACHA20_EQUIV_SEED");
    if (text != NULL) {
        char *end = NULL;
        unsigned long long value = strtoull(text, &end, 0);
        if (end != text && *end == 0 && value != 0) {
            rng_state = (uint64_t)value;
        }
    }
    return rng_state;
}

static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static void rng_fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(rng_next() >> 56);
    }
}

// The vector path computes one pass of eight blocks at a time on NEON,
// two groups of four side by side, and of four blocks on SSE2. The
// lengths below count in the larger pass, so each build crosses its own
// pass's edge at least four times.
#define PASS_BYTES_MAX ((size_t)8 * CHACHA20_BLOCK)
#define LENGTH_MAX (4 * PASS_BYTES_MAX)
#define WRAP_BACK_MAX 17
#define WRAP_LENGTH_MAX ((size_t)20 * CHACHA20_BLOCK)
#define RANDOM_CASES 20000
#define RANDOM_LENGTH_MAX (4 * PASS_BYTES_MAX)
#define LARGE_LENGTH ((size_t)65536)
// Bytes the vector path's buffer keeps on each side of what a case uses,
// filled with GUARD_BYTE, to see a write outside the n output bytes.
#define GUARD 32
#define GUARD_BYTE 0xa5
// The widest shift below the input the cases use, and how far past a
// 16-byte boundary a buffer can start.
#define SHIFT_MAX ((size_t)300)
#define ALIGN_MAX ((size_t)16)

// The aliasing shapes chacha20.h allows.
typedef enum { SEPARATE, IN_PLACE, BELOW } shape;

static const char *const shape_names[] = {"separate output", "in place", "output below input"};

typedef struct {
    uint8_t key[CHACHA20_KEY];
    uint8_t nonce[CHACHA20_NONCE];
    uint32_t counter;
    size_t n;
    shape aliasing;
    size_t shift;        // BELOW: how far below the input the output starts
    size_t offset;       // how far past a 16-byte boundary the output starts
    size_t input_offset; // SEPARATE: how far past one the input starts
} equiv_case;

// The input bytes, at input_offset, and the portable path's answer.
static _Alignas(16) uint8_t input_buffer[ALIGN_MAX + LARGE_LENGTH];
static uint8_t want[LARGE_LENGTH];
// The vector path's buffer, and a copy of it made before the call: a
// guard, the offset, the output, room for the input when it sits past the
// output, and a guard.
#define WORK_BYTES (GUARD + ALIGN_MAX + SHIFT_MAX + LARGE_LENGTH + GUARD)
static _Alignas(16) uint8_t work[WORK_BYTES];
static uint8_t before[WORK_BYTES];

static int failures = 0;
static unsigned long compared = 0;

static void report(const char *case_name, const equiv_case *c, const char *what, size_t at) {
    failures++;
    (void)fprintf(stderr,
                  "chacha20 equivalence: %s: %s %zu (n %zu, counter 0x%08lx, %s, shift %zu, "
                  "offset %zu, input offset %zu)\n",
                  case_name, what, at, c->n, (unsigned long)c->counter, shape_names[c->aliasing],
                  c->shift, c->offset, c->input_offset);
}

// The vector path once more, on heap buffers of exactly the bytes the
// case's shape uses, so that under AddressSanitizer (make san-check) a
// read or a write one byte outside them stops the binary. Returns the
// first byte of the output that differs from want, or n when none does.
// A case of no bytes has no buffer to hold, and compare has run it.
static size_t exact_run(const equiv_case *c, const uint8_t *source) {
    shape aliasing = c->aliasing;
    size_t n = c->n;
    size_t shift = aliasing == BELOW ? c->shift : 0;
    if (n == 0) {
        return 0;
    }
    if (n > LARGE_LENGTH || shift > SHIFT_MAX) {
        (void)fprintf(stderr, "chacha20 equivalence: a case larger than the test allows\n");
        exit(1);
    }
    // The input sits at buffer + shift. The output is buffer itself, or in
    // the SEPARATE shape a buffer of its own.
    uint8_t *buffer = malloc(shift + n);
    uint8_t *separate = malloc(n);
    if (buffer == NULL || separate == NULL) {
        (void)fprintf(stderr, "chacha20 equivalence: out of memory\n");
        exit(1);
    }
    uint8_t *out = aliasing == SEPARATE ? separate : buffer;
    memcpy(buffer + shift, source, n);
    chacha20_vector_xor(c->key, c->nonce, c->counter, buffer + shift, out, n);
    size_t first = n;
    for (size_t i = 0; i < n && first == n; i++) {
        if (out[i] != want[i]) {
            first = i;
        }
    }
    free(buffer);
    free(separate);
    return first;
}

// Runs both paths on one case and compares every byte of the window the
// case uses: the output must hold the portable path's bytes, and every
// other byte, the guards and an input the output sits below, must be what
// it was before the call. Then exact_run repeats the case.
static void compare(const char *case_name, const equiv_case *c) {
    const uint8_t *source = input_buffer + c->input_offset;
    chacha20_xor(c->key, c->nonce, c->counter, source, want, c->n);
    size_t start = GUARD + c->offset;
    size_t window = start + c->shift + c->n + GUARD;
    memset(work, GUARD_BYTE, window);
    uint8_t *out = work + start;
    const uint8_t *in = source;
    if (c->aliasing == IN_PLACE) {
        memcpy(out, source, c->n);
        in = out;
    } else if (c->aliasing == BELOW) {
        memcpy(out + c->shift, source, c->n);
        in = out + c->shift;
    }
    memcpy(before, work, window);
    chacha20_vector_xor(c->key, c->nonce, c->counter, in, out, c->n);
    compared++;
    for (size_t i = 0; i < window; i++) {
        int inside = i >= start && i - start < c->n;
        uint8_t expected = inside ? want[i - start] : before[i];
        if (work[i] != expected) {
            if (inside) {
                report(case_name, c, "the output differs from the portable path's at byte",
                       i - start);
            } else {
                report(case_name, c, "a byte outside the output changed, window byte", i);
            }
            return;
        }
    }
    size_t first = exact_run(c, source);
    if (first != c->n) {
        report(case_name, c, "on exact buffers, the output differs at byte", first);
    }
}

// A case with a random key, nonce, counter, shape and alignments, over n
// random input bytes.
static void random_case(equiv_case *c, size_t n) {
    rng_fill(c->key, sizeof c->key);
    rng_fill(c->nonce, sizeof c->nonce);
    c->counter = (uint32_t)rng_next();
    c->n = n;
    c->aliasing = (shape)(rng_next() % 3);
    c->shift = c->aliasing == BELOW ? 1 + (size_t)(rng_next() % SHIFT_MAX) : 0;
    c->offset = (size_t)(rng_next() % ALIGN_MAX);
    c->input_offset = (size_t)(rng_next() % ALIGN_MAX);
    rng_fill(input_buffer + c->input_offset, n);
}

// One case in a given shape, with the output 5 bytes below the input in
// the BELOW shape, as rec_open writes it.
static void shaped_case(equiv_case *c, size_t n, shape s) {
    random_case(c, n);
    c->aliasing = s;
    c->shift = s == BELOW ? 5 : 0;
}

// Every length in every shape, each buffer at a new alignment.
static void run_every_length(void) {
    equiv_case c;
    for (size_t n = 0; n <= LENGTH_MAX && failures == 0; n++) {
        for (int s = SEPARATE; s <= BELOW; s++) {
            shaped_case(&c, n, (shape)s);
            compare("every length", &c);
        }
    }
}

// The counter's last values and its wrap to 0, at every length to twenty
// blocks, so a wrap falls inside each group of the first pass, at the edge
// between them, at the pass's edge, inside the next pass, and in the last
// partial pass.
static void run_counter_wrap(void) {
    equiv_case c;
    for (uint32_t back = 0; back <= WRAP_BACK_MAX && failures == 0; back++) {
        for (size_t n = 0; n <= WRAP_LENGTH_MAX && failures == 0; n++) {
            random_case(&c, n);
            c.counter = 0U - back; // 0, then 2^32 - 1 down to 2^32 - 17
            compare("counter wrap", &c);
        }
    }
}

static void run_random(void) {
    equiv_case c;
    for (unsigned long i = 0; i < RANDOM_CASES && failures == 0; i++) {
        random_case(&c, (size_t)(rng_next() % (RANDOM_LENGTH_MAX + 1)));
        compare("random", &c);
    }
}

// A 16 KiB record's TLSInnerPlaintext, the plaintext and its content type
// byte, and 64 KiB, in each shape.
static void run_large(void) {
    static const size_t lengths[] = {16385, LARGE_LENGTH};
    equiv_case c;
    for (size_t l = 0; l < sizeof lengths / sizeof lengths[0]; l++) {
        for (int s = SEPARATE; s <= BELOW && failures == 0; s++) {
            shaped_case(&c, lengths[l], (shape)s);
            compare("large", &c);
        }
    }
}

int main(void) {
    uint64_t seed = rng_seed_from_env();
    run_every_length();
    run_counter_wrap();
    run_random();
    run_large();
    printf("chacha20 equivalence: %lu cases agree between CHACHA=portable and CHACHA=vector "
           "(seed 0x%llx)\n",
           compared, (unsigned long long)seed);
    if (failures > 0) {
        printf("chacha20 equivalence: %d mismatches\n", failures);
        return 1;
    }
    return 0;
}
