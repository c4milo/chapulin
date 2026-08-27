// The constant-time software multiply, against the compiler's own `*`.
//
// softmul.c only compiles where there is no hardware multiplier, so this
// forces it on with CH_SOFT_MUL and includes the translation unit: the
// host has a multiplier, which is what makes `*` an independent oracle
// here rather than a call back into the code under test.
#include <stdint.h>
#include <stdio.h>

#define CH_SOFT_MUL 1
#include "softmul.c"

static int failures;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            (void)printf("softmul_test: FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);              \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

// xorshift64, so the run is the same everywhere without a generator.
static uint64_t rng_state = UINT64_C(0x2545f4914f6cdd1d);

static uint64_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

int main(void) {
    // The values a shift-and-add gets wrong: zero, one, the top bit, the
    // all-ones operand that carries through every iteration.
    static const uint32_t edge[] = {0,          1,          2,      3,      0x7fffffff,
                                    0x80000000, 0xffffffff, 0xffff, 0x10000};
    for (size_t i = 0; i < sizeof edge / sizeof *edge; i++) {
        for (size_t j = 0; j < sizeof edge / sizeof *edge; j++) {
            CHECK(__mulsi3(edge[i], edge[j]) == (uint32_t)(edge[i] * edge[j]));
            CHECK(__muldi3(edge[i], edge[j]) == (uint64_t)edge[i] * edge[j]);
        }
    }
    // The 64-bit edges separately: a 32-bit list cannot reach them.
    static const uint64_t edge64[] = {0, 1, UINT64_C(0x8000000000000000), UINT64_MAX,
                                      UINT64_C(0x100000000)};
    for (size_t i = 0; i < sizeof edge64 / sizeof *edge64; i++) {
        for (size_t j = 0; j < sizeof edge64 / sizeof *edge64; j++) {
            CHECK(__muldi3(edge64[i], edge64[j]) == (uint64_t)(edge64[i] * edge64[j]));
        }
    }
    long n = 0;
    for (int k = 0; k < 200000; k++) {
        uint32_t a = (uint32_t)rng_next();
        uint32_t b = (uint32_t)rng_next();
        CHECK(__mulsi3(a, b) == (uint32_t)(a * b));
        uint64_t x = rng_next();
        uint64_t y = rng_next();
        CHECK(__muldi3(x, y) == (uint64_t)(x * y));
        n += 2;
    }
    if (failures != 0) {
        (void)printf("softmul_test: %d failures\n", failures);
        return 1;
    }
    (void)printf("softmul_test: %ld products against the compiler's own, all equal\n", n);
    (void)printf("softmul_test: all checks passed\n");
    return 0;
}
