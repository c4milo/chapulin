// What the current path's blocks entry leaves on the stack:
// poly1305_vector_blocks_native, poly1305_avx2_blocks_native or
// poly1305_ifma_blocks_native. The call computes r^2, r^3 and r^4, the
// AVX2 kernel r^5 to r^8 as well and the IFMA kernel r^5 to r^16, keeps
// them and the multipliers built from them in one struct on its frame, and
// wipes that struct once when it returns. The frame is dead after the
// return, but its bytes stay in memory below this binary's own frames
// until another call writes over them.
//
// residue_call makes one call over RESIDUE_GROUPS groups, residue_snapshot
// copies the stack below its caller as deep as RESIDUE_BYTES, where the
// dead frame lay, and run_residue looks in the copy for r^2 to r^16 in
// each layout the call holds a power in:
//
//   five uint32_t words side by side, as the struct holds each power;
//   one word in every 8 bytes, as a NEON multiplier holds a lane's power;
//   one word in every 16 bytes, as an SSE2 multiplier holds it;
//   one word in every 32 bytes, as an AVX2 multiplier holds it;
//   one word in every 64 bytes, as a 512-bit vector would hold it;
//
// and, for a path whose powers are digits, as poly1305_ifma.c's are:
//
//   three uint64_t digits side by side, as the struct holds r's;
//   one digit in every 64 bytes, as an IFMA multiplier holds a lane's
//   power, its three digits in three 512-bit vectors;
//   one digit in every 24 or 32 bytes, as a struct of three digits and an
//   array of such would.
//
// Five words match a power when each is below 2^27 and together they hold
// its value modulo 2^130 - 5, and three digits when each is below 2^45 and
// together they hold it, so a power in another carry form matches too.
// The powers are computed only after the copy, so this file's own frames
// cannot hold them first.
//
// Included by test/poly1305_equiv_test.c only, which declares the
// generator, reduced, report, the failure count and the current path this
// file uses.
#ifndef CH_POLY1305_EQUIV_RESIDUE_H
#define CH_POLY1305_EQUIV_RESIDUE_H

#define RESIDUE_GROUPS 4
// Deep enough for the IFMA kernel's frame, which holds its struct of
// powers, 1,984 bytes, beside its own spills.
#define RESIDUE_BYTES 8192
// The most bytes RESIDUE_GROUPS groups of any path hold: the IFMA
// kernel's groups are the longest, sixteen blocks.
#define RESIDUE_DATA_MAX (RESIDUE_GROUPS * 256)
// r^2 to r^16.
#define RESIDUE_POWERS 15

static uint8_t residue_copy[RESIDUE_BYTES];
static uint8_t residue_key[POLY1305_KEY];
static uint8_t residue_data[RESIDUE_DATA_MAX];

static __attribute__((noinline)) void residue_call(void) {
    poly1305 p;
    poly1305_init(&p, residue_key);
    current->blocks(&p, residue_data, RESIDUE_GROUPS * current->group);
}

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

// out = a * b modulo 2^130 - 5, reduced, for words of at most 2^26.
static void residue_multiply(const uint32_t a[5], const uint32_t b[5], uint32_t out[5]) {
    uint64_t d[5] = {0, 0, 0, 0, 0};
    for (size_t i = 0; i < 5; i++) {
        for (size_t j = 0; j < 5; j++) {
            uint64_t product = (uint64_t)a[i] * b[j];
            // A product past word 4 is past 2^130, which is 5 modulo
            // 2^130 - 5.
            if (i + j < 5) {
                d[i + j] += product;
            } else {
                d[i + j - 5] += 5 * product;
            }
        }
    }
    for (size_t i = 0; i < 4; i++) {
        d[i + 1] += d[i] >> 26;
        d[i] &= WORD_MASK;
    }
    d[0] += (d[4] >> 26) * 5;
    d[4] &= WORD_MASK;
    d[1] += d[0] >> 26;
    d[0] &= WORD_MASK;
    uint32_t words[5];
    for (size_t i = 0; i < 5; i++) {
        words[i] = (uint32_t)d[i];
    }
    reduced(words, out);
}

// Whether the copy holds the power as three digits stride bytes apart, at
// any byte offset: digit0 + digit1 2^44 + digit2 2^88, each digit below 2^45,
// carried into five 26-bit words and reduced.
static int residue_holds_digits(const uint32_t power[5], size_t stride) {
    for (size_t at = 0; at + 2 * stride + 8 <= RESIDUE_BYTES; at++) {
        uint64_t digit[3];
        int below_2_45 = 1;
        for (size_t i = 0; i < 3; i++) {
            memcpy(&digit[i], &residue_copy[at + i * stride], sizeof digit[i]);
            below_2_45 &= digit[i] < (UINT64_C(1) << 45);
        }
        if (!below_2_45) {
            continue;
        }
        uint64_t d[5];
        d[0] = digit[0] & WORD_MASK;
        d[1] = (digit[0] >> 26) + ((digit[1] & 0xff) << 18);
        d[2] = digit[1] >> 8;
        d[3] = (digit[2] & 0xffff) << 10;
        d[4] = digit[2] >> 16;
        for (size_t i = 0; i < 4; i++) {
            d[i + 1] += d[i] >> 26;
            d[i] &= WORD_MASK;
        }
        uint32_t words[5];
        for (size_t i = 0; i < 5; i++) {
            words[i] = (uint32_t)d[i];
        }
        uint32_t value[5];
        reduced(words, value);
        if (memcmp(value, power, sizeof value) == 0) {
            return 1;
        }
    }
    return 0;
}

// Whether the copy holds the power as five words stride bytes apart, at
// any byte offset.
static int residue_holds(const uint32_t power[5], size_t stride) {
    for (size_t at = 0; at + 4 * stride + 4 <= RESIDUE_BYTES; at++) {
        uint32_t words[5];
        int below_2_27 = 1;
        for (size_t i = 0; i < 5; i++) {
            memcpy(&words[i], &residue_copy[at + i * stride], sizeof words[i]);
            below_2_27 &= words[i] < (UINT32_C(1) << 27);
        }
        uint32_t value[5];
        reduced(words, value);
        if (below_2_27 && memcmp(value, power, sizeof value) == 0) {
            return 1;
        }
    }
    return 0;
}

static void run_residue(void) {
    if (RESIDUE_GROUPS * current->group > sizeof residue_data) {
        (void)fprintf(stderr, "poly1305 equivalence: a residue call the test cannot hold\n");
        exit(1);
    }
    rng_fill(residue_key, sizeof residue_key);
    rng_fill(residue_data, sizeof residue_data);
    residue_call();
    residue_snapshot();
    poly1305 p;
    poly1305_init(&p, residue_key);
    // power[k] is r^(k + 2).
    uint32_t power[RESIDUE_POWERS][5];
    residue_multiply(p.r, p.r, power[0]);
    for (size_t k = 1; k < RESIDUE_POWERS; k++) {
        residue_multiply(power[k - 1], p.r, power[k]);
    }
    static const size_t strides[5] = {4, 8, 16, 32, 64};
    static const size_t digit_strides[4] = {8, 24, 32, 64};
    for (size_t k = 0; k < RESIDUE_POWERS; k++) {
        for (size_t s = 0; current->digits && s < 4; s++) {
            if (residue_holds_digits(power[k], digit_strides[s])) {
                char what[96];
                (void)snprintf(what, sizeof what,
                               "the stack below the call still holds r^%zu, one digit every %zu "
                               "bytes",
                               k + 2, digit_strides[s]);
                report("residue", what, RESIDUE_GROUPS * current->group, 0, 0);
                return;
            }
        }
        for (size_t s = 0; s < 5; s++) {
            if (residue_holds(power[k], strides[s])) {
                char what[96];
                (void)snprintf(
                    what, sizeof what,
                    "the stack below the call still holds r^%zu, one word every %zu bytes", k + 2,
                    strides[s]);
                report("residue", what, RESIDUE_GROUPS * current->group, 0, 0);
                return;
            }
        }
    }
}

#endif
