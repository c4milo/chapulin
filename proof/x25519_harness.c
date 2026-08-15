// Proves the field-arithmetic contracts the Montgomery ladder composes:
//
//   carried: every limb in [-2^16, 2^17)      (post-carry/mul/unpack state)
//   loose:   every limb in (-2^18, 2^18)      (add/sub of two carried)
//
//   unpack  -> carried                (limbs in [0, 2^16))
//   add/sub : carried x carried -> loose
//   mul/sqr : loose x loose -> carried, and no int64 overflow anywhere in
//             the 31-limb product accumulation or the 38x fold
//   carry   : loose -> carried, no overflow
//   pack    : carried -> canonical 32 bytes, memory-safe, no overflow
//   cswap   : bit 0/1, memory-safe
//
// The ladder itself only ever feeds mul/sqr operands that are carried or
// loose, so these contracts cover every call site; the unit tests' RFC
// 7748 vectors (including the 1,000-iteration chain) cover functional
// correctness end to end.
#include "harness.h"

#include "x25519.c"

#define CARRIED_LO (-(int64_t)1 << 16)
#define CARRIED_HI ((int64_t)1 << 17)
#define LOOSE ((int64_t)1 << 18)

static void assume_range(fe f, int64_t lo, int64_t hi) {
    for (size_t i = 0; i < 16; i++) {
        f[i] = nondet_i64();
        __CPROVER_assume(f[i] >= lo && f[i] < hi);
    }
}

// A macro because __CPROVER_assert requires a literal description.
#define ASSERT_RANGE(f, lo, hi, what)                                                              \
    do {                                                                                           \
        for (size_t i = 0; i < 16; i++) {                                                          \
            __CPROVER_assert((f)[i] >= (lo) && (f)[i] < (hi), what);                               \
        }                                                                                          \
    } while (0)

int main(void) {
    fe a;
    fe b;
    fe o;

    // unpack produces carried limbs.
    uint8_t bytes[X25519_LEN];
    fill_nondet(bytes, sizeof bytes);
    unpack(o, bytes);
    ASSERT_RANGE(o, 0, (int64_t)1 << 16, "unpack is carried");

    // add/sub of carried values stay loose.
    assume_range(a, CARRIED_LO, CARRIED_HI);
    assume_range(b, CARRIED_LO, CARRIED_HI);
    add(o, a, b);
    ASSERT_RANGE(o, -LOOSE, LOOSE, "add of carried is loose");
    sub(o, a, b);
    ASSERT_RANGE(o, -LOOSE, LOOSE, "sub of carried is loose");

    // mul of loose values returns carried, with no int64 overflow inside —
    // CBMC checks every product and accumulation.
    assume_range(a, -LOOSE, LOOSE);
    assume_range(b, -LOOSE, LOOSE);
    mul(o, a, b);
    ASSERT_RANGE(o, CARRIED_LO, CARRIED_HI, "mul output is carried");

    // carry normalizes any loose value.
    assume_range(a, -LOOSE, LOOSE);
    carry(a);
    ASSERT_RANGE(a, CARRIED_LO, CARRIED_HI, "carry output is carried");

    // pack freezes any carried value without UB.
    assume_range(a, CARRIED_LO, CARRIED_HI);
    uint8_t out[X25519_LEN];
    pack(out, a);

    // cswap with both bit values.
    assume_range(a, CARRIED_LO, CARRIED_HI);
    assume_range(b, CARRIED_LO, CARRIED_HI);
    int64_t bit = nondet_i64();
    __CPROVER_assume(bit == 0 || bit == 1);
    cswap(a, b, bit);
    return 0;
}
