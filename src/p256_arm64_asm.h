// p256_arm64_field.c's Montgomery product and square on four 64-bit words in
// arm64 inline assembly: the 512-bit product on MUL, UMULH, ADDS and ADCS,
// then the four rounds of p256_wide_field.c's reduce() and its final
// subtraction of p, in one statement each. p256_arm64_field_inline.h includes
// this file in every build but the model build, which takes
// test/p256_arm64_model.h in its place. Each routine takes elements below p
// and writes the element below p that is a b / 2^256 mod p.
//
// The steps are p256_wide_field.c's. The product is four rows of
// p256_wide_word.h's p256_wide_mul_row: row i adds a[i] times b's four
// words at word i, the low halves of the four products down one carry chain
// and the high halves down a second. The square is p256_wide_sqr_product's
// ten products. Each round k takes u = t[k] and adds u * p, which clears
// t[k], because p's low word is 2^64 - 1 and so -p^-1 mod 2^64 is 1: u << 32
// at t[k+1], u >> 32 at t[k+2], and the two words of u * p3 at t[k+3] and
// t[k+4], with p3 = 2^64 - 2^32 + 1. MUL and UMULH compute u * p3, as MULX
// does in p256_adx_asm.h, where reduce_round subtracts shifted copies of u:
// both give the same two words. The carry out of t[k+4] stays in the C flag,
// and the next round adds it to its own high word of u * p3 with ADC before
// it starts its chain. That high word is at most 2^64 - 2^32, so the carry
// fits beside it. The last step is p256_wide_fe_reduce_once: the four words
// and the last carry less p, kept where that borrows, chosen by CSEL on the
// borrow. ADDS of 1 subtracts p's low word, 2^64 - 1, with the same result
// and the same carry flag as SUBS would.
//
// Why assembly, and why on registers: Apple clang 21 compiles
// p256_wide_field.c's carry chains with moves of the flags to general
// registers and back, MRS and MSR of NZCV. Between its loads and its stores
// its product is 128 instructions and its square 105, where these statements
// are 104 and 84. A statement that read its operands through pointers, as
// p256_adx_asm.h's do, made a shared secret 9% faster on an M1 Pro. These
// take every word in a register and give every word in a register, and read
// and write no memory. Inline in a point formula, the compiler then keeps
// the formula's elements in registers from one product to the next, where a
// store and the load after it took about 5 cycles on each edge of the
// formula's chain (docs/decisions.md 215).
//
// No instruction here branches, and none reads or writes memory. MUL, UMULH,
// ADDS, ADCS, SBCS, CSEL and the shifts are among the instructions whose
// timing FEAT_DIT states. Each statement names every register it writes as
// an output that the compiler picks, so it has no clobber list but the
// flags. Semgrep reads no macro inside an asm statement, so each statement
// spells its text and its operands out. The immediates are in hex, because
// tools/issue-links.py reads a decimal number after # as an issue's.
#ifndef CH_P256_ARM64_ASM_H
#define CH_P256_ARM64_ASM_H

#include <stdint.h>

// p's two words that are neither 0 nor 2^64 - 1, as register operands, so a
// formula that runs several statements loads each once.
#define P256_ARM64_P1 UINT64_C(0x00000000ffffffff)
#define P256_ARM64_P3 UINT64_C(0xffffffff00000001)

// o = a * b / 2^256 mod p. o may be a or b: every word of both is read before
// o is written. The statement writes the last round's carry over b0, which
// row 3 reads last, so the compiler hands it a copy of b0 where the caller
// reads that word after. With b0 an input alone, Apple clang 21 placed the
// other words of a doubling so that it took 289 cycles on an M1 Pro, where it
// takes 268 (docs/decisions.md 215).
static inline __attribute__((always_inline)) void
p256_arm64_mul_mont(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t a0 = a[0];
    uint64_t a1 = a[1];
    uint64_t a2 = a[2];
    uint64_t a3 = a[3];
    uint64_t b0 = b[0];
    uint64_t b1 = b[1];
    uint64_t b2 = b[2];
    uint64_t b3 = b[3];
    uint64_t t0;
    uint64_t t1;
    uint64_t t2;
    uint64_t t3;
    uint64_t w0;
    uint64_t w1;
    uint64_t w2;
    uint64_t w3;
    uint64_t l0;
    uint64_t l1;
    uint64_t l2;
    uint64_t l3;
    __asm__(
        // Row 0: (w0 : t3 : t2 : t1 : t0) = a0 * b.
        "mul %[t0], %[a0], %[b0]\n"
        "umulh %[t1], %[a0], %[b0]\n"
        "mul %[l0], %[a0], %[b1]\n"
        "umulh %[t2], %[a0], %[b1]\n"
        "mul %[l1], %[a0], %[b2]\n"
        "umulh %[t3], %[a0], %[b2]\n"
        "mul %[l2], %[a0], %[b3]\n"
        "umulh %[w0], %[a0], %[b3]\n"
        "adds %[t1], %[t1], %[l0]\n"
        "adcs %[t2], %[t2], %[l1]\n"
        "adcs %[t3], %[t3], %[l2]\n"
        "adc %[w0], %[w0], xzr\n"
        // Row 1: a1 * b at word 1. The carry out of the low halves' chain
        // starts word 5, and the high halves' chain ends there.
        "mul %[l0], %[a1], %[b0]\n"
        "mul %[l1], %[a1], %[b1]\n"
        "mul %[l2], %[a1], %[b2]\n"
        "mul %[l3], %[a1], %[b3]\n"
        "adds %[t1], %[t1], %[l0]\n"
        "adcs %[t2], %[t2], %[l1]\n"
        "adcs %[t3], %[t3], %[l2]\n"
        "adcs %[w0], %[w0], %[l3]\n"
        "cset %[w1], hs\n"
        "umulh %[l0], %[a1], %[b0]\n"
        "umulh %[l1], %[a1], %[b1]\n"
        "umulh %[l2], %[a1], %[b2]\n"
        "umulh %[l3], %[a1], %[b3]\n"
        "adds %[t2], %[t2], %[l0]\n"
        "adcs %[t3], %[t3], %[l1]\n"
        "adcs %[w0], %[w0], %[l2]\n"
        "adc %[w1], %[w1], %[l3]\n"
        // Row 2: a2 * b at word 2.
        "mul %[l0], %[a2], %[b0]\n"
        "mul %[l1], %[a2], %[b1]\n"
        "mul %[l2], %[a2], %[b2]\n"
        "mul %[l3], %[a2], %[b3]\n"
        "adds %[t2], %[t2], %[l0]\n"
        "adcs %[t3], %[t3], %[l1]\n"
        "adcs %[w0], %[w0], %[l2]\n"
        "adcs %[w1], %[w1], %[l3]\n"
        "cset %[w2], hs\n"
        "umulh %[l0], %[a2], %[b0]\n"
        "umulh %[l1], %[a2], %[b1]\n"
        "umulh %[l2], %[a2], %[b2]\n"
        "umulh %[l3], %[a2], %[b3]\n"
        "adds %[t3], %[t3], %[l0]\n"
        "adcs %[w0], %[w0], %[l1]\n"
        "adcs %[w1], %[w1], %[l2]\n"
        "adc %[w2], %[w2], %[l3]\n"
        // Row 3: a3 * b at word 3.
        "mul %[l0], %[a3], %[b0]\n"
        "mul %[l1], %[a3], %[b1]\n"
        "mul %[l2], %[a3], %[b2]\n"
        "mul %[l3], %[a3], %[b3]\n"
        "adds %[t3], %[t3], %[l0]\n"
        "adcs %[w0], %[w0], %[l1]\n"
        "adcs %[w1], %[w1], %[l2]\n"
        "adcs %[w2], %[w2], %[l3]\n"
        "cset %[w3], hs\n"
        "umulh %[l0], %[a3], %[b0]\n"
        "umulh %[l1], %[a3], %[b1]\n"
        "umulh %[l2], %[a3], %[b2]\n"
        "umulh %[l3], %[a3], %[b3]\n"
        "adds %[w0], %[w0], %[l0]\n"
        "adcs %[w1], %[w1], %[l1]\n"
        "adcs %[w2], %[w2], %[l2]\n"
        "adc %[w3], %[w3], %[l3]\n"
        // Round 0, u = t0: u << 32, u >> 32 and u * p3 at words 1 to 4.
        "mul %[l0], %[t0], %[p3]\n"
        "umulh %[l1], %[t0], %[p3]\n"
        "lsr %[l2], %[t0], #0x20\n"
        "adds %[t1], %[t1], %[t0], lsl #0x20\n"
        "adcs %[t2], %[t2], %[l2]\n"
        "adcs %[t3], %[t3], %[l0]\n"
        "adcs %[w0], %[w0], %[l1]\n"
        // Round 1, u = t1, at words 2 to 5. ADC adds the carry of round 0 to
        // the high word of u * p3. MUL, UMULH and LSR write no flag.
        "mul %[l0], %[t1], %[p3]\n"
        "umulh %[l1], %[t1], %[p3]\n"
        "lsr %[l2], %[t1], #0x20\n"
        "adc %[l1], %[l1], xzr\n"
        "adds %[t2], %[t2], %[t1], lsl #0x20\n"
        "adcs %[t3], %[t3], %[l2]\n"
        "adcs %[w0], %[w0], %[l0]\n"
        "adcs %[w1], %[w1], %[l1]\n"
        // Round 2, u = t2, at words 3 to 6.
        "mul %[l0], %[t2], %[p3]\n"
        "umulh %[l1], %[t2], %[p3]\n"
        "lsr %[l2], %[t2], #0x20\n"
        "adc %[l1], %[l1], xzr\n"
        "adds %[t3], %[t3], %[t2], lsl #0x20\n"
        "adcs %[w0], %[w0], %[l2]\n"
        "adcs %[w1], %[w1], %[l0]\n"
        "adcs %[w2], %[w2], %[l1]\n"
        // Round 3, u = t3, at words 4 to 7. Its carry out goes to b0, which
        // no step reads after row 3.
        "mul %[l0], %[t3], %[p3]\n"
        "umulh %[l1], %[t3], %[p3]\n"
        "lsr %[l2], %[t3], #0x20\n"
        "adc %[l1], %[l1], xzr\n"
        "adds %[w0], %[w0], %[t3], lsl #0x20\n"
        "adcs %[w1], %[w1], %[l2]\n"
        "adcs %[w2], %[w2], %[l0]\n"
        "adcs %[w3], %[w3], %[l1]\n"
        "cset %[b0], hs\n"
        // The final subtraction of p, and the choice by its borrow: the
        // last SBCS borrows exactly when b0 is 0 and the four words were
        // below p.
        "adds %[l0], %[w0], #0x1\n"
        "sbcs %[l1], %[w1], %[p1]\n"
        "sbcs %[l2], %[w2], xzr\n"
        "sbcs %[l3], %[w3], %[p3]\n"
        "sbcs xzr, %[b0], xzr\n"
        "csel %[w0], %[w0], %[l0], lo\n"
        "csel %[w1], %[w1], %[l1], lo\n"
        "csel %[w2], %[w2], %[l2], lo\n"
        "csel %[w3], %[w3], %[l3], lo\n"
        : [t0] "=&r"(t0), [t1] "=&r"(t1), [t2] "=&r"(t2), [t3] "=&r"(t3), [w0] "=&r"(w0),
          [w1] "=&r"(w1), [w2] "=&r"(w2), [w3] "=&r"(w3), [l0] "=&r"(l0), [l1] "=&r"(l1),
          [l2] "=&r"(l2), [l3] "=&r"(l3), [b0] "+&r"(b0)
        : [a0] "r"(a0), [a1] "r"(a1), [a2] "r"(a2), [a3] "r"(a3), [b1] "r"(b1), [b2] "r"(b2),
          [b3] "r"(b3), [p1] "r"(P256_ARM64_P1), [p3] "r"(P256_ARM64_P3)
        : "cc");
    o[0] = w0;
    o[1] = w1;
    o[2] = w2;
    o[3] = w3;
}

// o = a * a / 2^256 mod p: the six products of two different words once,
// doubled, then the four squares, then the same reduction. o may be a.
static inline __attribute__((always_inline)) void p256_arm64_sqr_mont(uint64_t o[4],
                                                                      const uint64_t a[4]) {
    uint64_t a0 = a[0];
    uint64_t a1 = a[1];
    uint64_t a2 = a[2];
    uint64_t a3 = a[3];
    uint64_t t0;
    uint64_t t1;
    uint64_t t2;
    uint64_t t3;
    uint64_t w0;
    uint64_t w1;
    uint64_t w2;
    uint64_t w3;
    uint64_t l0;
    uint64_t l1;
    uint64_t l2;
    uint64_t l3;
    __asm__(
        // a0 (a1 + a2 2^64 + a3 2^128), at words 1 to 4.
        "mul %[t1], %[a0], %[a1]\n"
        "umulh %[t2], %[a0], %[a1]\n"
        "mul %[l0], %[a0], %[a2]\n"
        "umulh %[t3], %[a0], %[a2]\n"
        "mul %[l1], %[a0], %[a3]\n"
        "umulh %[w0], %[a0], %[a3]\n"
        "adds %[t2], %[t2], %[l0]\n"
        "adcs %[t3], %[t3], %[l1]\n"
        "adc %[w0], %[w0], xzr\n"
        // a1 (a2 + a3 2^64), at words 3 to 5: the low word of a1 a2 in l0,
        // the next in l1 and the top in w1.
        "mul %[l0], %[a1], %[a2]\n"
        "umulh %[l1], %[a1], %[a2]\n"
        "mul %[l2], %[a1], %[a3]\n"
        "umulh %[w1], %[a1], %[a3]\n"
        "adds %[l1], %[l1], %[l2]\n"
        "adc %[w1], %[w1], xzr\n"
        // The two rows and a2 a3, at words 1 to 6.
        "mul %[l2], %[a2], %[a3]\n"
        "umulh %[w2], %[a2], %[a3]\n"
        "adds %[t3], %[t3], %[l0]\n"
        "adcs %[w0], %[w0], %[l1]\n"
        "adcs %[w1], %[w1], %[l2]\n"
        "adc %[w2], %[w2], xzr\n"
        // Twice that sum, at words 1 to 7. EXTR takes a word's low 63 bits
        // and the bit above them from the word below.
        "lsr %[w3], %[w2], #0x3f\n"
        "extr %[w2], %[w2], %[w1], #0x3f\n"
        "extr %[w1], %[w1], %[w0], #0x3f\n"
        "extr %[w0], %[w0], %[t3], #0x3f\n"
        "extr %[t3], %[t3], %[t2], #0x3f\n"
        "extr %[t2], %[t2], %[t1], #0x3f\n"
        "lsl %[t1], %[t1], #0x1\n"
        // The four squares, a_i^2 at words 2i and 2i + 1.
        "mul %[t0], %[a0], %[a0]\n"
        "umulh %[l0], %[a0], %[a0]\n"
        "mul %[l1], %[a1], %[a1]\n"
        "umulh %[l2], %[a1], %[a1]\n"
        "adds %[t1], %[t1], %[l0]\n"
        "adcs %[t2], %[t2], %[l1]\n"
        "adcs %[t3], %[t3], %[l2]\n"
        "mul %[l0], %[a2], %[a2]\n"
        "umulh %[l1], %[a2], %[a2]\n"
        "adcs %[w0], %[w0], %[l0]\n"
        "adcs %[w1], %[w1], %[l1]\n"
        "mul %[l0], %[a3], %[a3]\n"
        "umulh %[l1], %[a3], %[a3]\n"
        "adcs %[w2], %[w2], %[l0]\n"
        "adc %[w3], %[w3], %[l1]\n"
        // Round 0, u = t0: u << 32, u >> 32 and u * p3 at words 1 to 4.
        "mul %[l0], %[t0], %[p3]\n"
        "umulh %[l1], %[t0], %[p3]\n"
        "lsr %[l2], %[t0], #0x20\n"
        "adds %[t1], %[t1], %[t0], lsl #0x20\n"
        "adcs %[t2], %[t2], %[l2]\n"
        "adcs %[t3], %[t3], %[l0]\n"
        "adcs %[w0], %[w0], %[l1]\n"
        // Round 1, u = t1, at words 2 to 5.
        "mul %[l0], %[t1], %[p3]\n"
        "umulh %[l1], %[t1], %[p3]\n"
        "lsr %[l2], %[t1], #0x20\n"
        "adc %[l1], %[l1], xzr\n"
        "adds %[t2], %[t2], %[t1], lsl #0x20\n"
        "adcs %[t3], %[t3], %[l2]\n"
        "adcs %[w0], %[w0], %[l0]\n"
        "adcs %[w1], %[w1], %[l1]\n"
        // Round 2, u = t2, at words 3 to 6.
        "mul %[l0], %[t2], %[p3]\n"
        "umulh %[l1], %[t2], %[p3]\n"
        "lsr %[l2], %[t2], #0x20\n"
        "adc %[l1], %[l1], xzr\n"
        "adds %[t3], %[t3], %[t2], lsl #0x20\n"
        "adcs %[w0], %[w0], %[l2]\n"
        "adcs %[w1], %[w1], %[l0]\n"
        "adcs %[w2], %[w2], %[l1]\n"
        // Round 3, u = t3, at words 4 to 7. Its carry out goes to t0, which
        // no step reads after round 0.
        "mul %[l0], %[t3], %[p3]\n"
        "umulh %[l1], %[t3], %[p3]\n"
        "lsr %[l2], %[t3], #0x20\n"
        "adc %[l1], %[l1], xzr\n"
        "adds %[w0], %[w0], %[t3], lsl #0x20\n"
        "adcs %[w1], %[w1], %[l2]\n"
        "adcs %[w2], %[w2], %[l0]\n"
        "adcs %[w3], %[w3], %[l1]\n"
        "cset %[t0], hs\n"
        // The final subtraction of p, and the choice by its borrow: the
        // last SBCS borrows exactly when t0 is 0 and the four words were
        // below p.
        "adds %[l0], %[w0], #0x1\n"
        "sbcs %[l1], %[w1], %[p1]\n"
        "sbcs %[l2], %[w2], xzr\n"
        "sbcs %[l3], %[w3], %[p3]\n"
        "sbcs xzr, %[t0], xzr\n"
        "csel %[w0], %[w0], %[l0], lo\n"
        "csel %[w1], %[w1], %[l1], lo\n"
        "csel %[w2], %[w2], %[l2], lo\n"
        "csel %[w3], %[w3], %[l3], lo\n"
        : [t0] "=&r"(t0), [t1] "=&r"(t1), [t2] "=&r"(t2), [t3] "=&r"(t3), [w0] "=&r"(w0),
          [w1] "=&r"(w1), [w2] "=&r"(w2), [w3] "=&r"(w3), [l0] "=&r"(l0), [l1] "=&r"(l1),
          [l2] "=&r"(l2), [l3] "=&r"(l3)
        : [a0] "r"(a0), [a1] "r"(a1), [a2] "r"(a2), [a3] "r"(a3), [p1] "r"(P256_ARM64_P1),
          [p3] "r"(P256_ARM64_P3)
        : "cc");
    o[0] = w0;
    o[1] = w1;
    o[2] = w2;
    o[3] = w3;
}

#endif
