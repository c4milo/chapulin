// Constant-time software multiply, for cores with no hardware multiplier.
//
// A core without a multiply instruction turns every `*` into a call to the
// compiler's runtime library, and those routines are shift-and-add loops that
// branch on the multiplier's bits: they iterate once per bit up to the
// operand's bit length, and add only where a bit is set. Duration and power
// both follow the operand. poly1305 multiplies by half the one-time MAC key,
// x25519 by the private scalar, and mlkem_poly by secret coefficients, so on
// such a core the library's constant-time claim would hold in the source and
// not in what executes (https://github.com/c4milo/chapulin/issues/53).
//
// These definitions carry the names the compiler emits, so they replace
// the runtime library's at link time and no crypto source changes. Both
// run a fixed number of iterations and select with a mask rather than a
// branch, the same discipline x25519's cswap and poly1305's final
// reduction already use. Neither uses `*`, or it would call itself.
//
// The mask is the multiplier's low bit copied into every bit position,
// written as a shift to the top and an arithmetic shift back down. It is
// not written as `0 - bit`: gcc rewrites `a & (0 - bit)` into `a * bit`,
// and at -Os for rv32ic it then emits that 64-bit product as a call to
// __muldi3 from inside __muldi3, which never returns
// (https://github.com/c4milo/chapulin/issues/107). The shift form is not
// a shape gcc turns into a multiply, measured at -O1, -O2, -O3 and -Os,
// and the rv32ic-gcc spec of lint-wide-multiply holds this file at zero
// calls to __muldi3 so the rewrite cannot come back.
//
// Cost is real: 32 or 64 masked adds where a hardware multiplier takes one
// instruction. That is the price of the guarantee on a core that cannot
// multiply, and a core that can never compiles this file.
#include <stdint.h>

#if defined(CH_SOFT_MUL) || (defined(__riscv) && !defined(__riscv_mul))

// The compiler emits these for `*` on a core without the instruction. The
// names are its ABI, not this codebase's naming.
uint32_t __mulsi3(uint32_t a, uint32_t b);
uint64_t __muldi3(uint64_t a, uint64_t b);

uint32_t __mulsi3(uint32_t a, uint32_t b) {
    uint32_t acc = 0;
    // Every bit, every time: the loop count cannot depend on b.
    for (int i = 0; i < 32; i++) {
        uint32_t mask = (uint32_t)((int32_t)(b << 31) >> 31); // 0 or all ones
        acc += a & mask;
        a <<= 1;
        b >>= 1;
    }
    return acc;
}

uint64_t __muldi3(uint64_t a, uint64_t b) {
    uint64_t acc = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t mask = (uint64_t)((int64_t)(b << 63) >> 63); // 0 or all ones
        acc += a & mask;
        a <<= 1;
        b >>= 1;
    }
    return acc;
}

#endif
