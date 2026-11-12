// p256_adx_field.c's Montgomery product and square on four 64-bit words in
// inline assembly: the 512-bit product on MULX, ADCX and ADOX, then the four
// rounds of p256_wide_field.c's reduce() and its final subtraction of p, in
// one statement each. p256_adx_field.c includes this file alone, in every
// build but the model build, which takes test/p256_adx_model.h in its place.
// Each routine takes elements below p and writes the element below p that
// is a b / 2^256 mod p.
//
// Why assembly: C names neither MULX, a multiply whose second operand is rdx
// and that writes no flag, nor the two carry flags that ADCX and ADOX keep
// apart, so no compiler here builds a product's two carry chains side by
// side. The reduction is in the same statement, so the eight words of the
// product stay in r8 to r15 and never pass through memory: under gcc for
// x86-64 that made a key exchange 5% faster than the product alone in
// assembly beside reduce() in C (docs/decisions.md 171).
//
// Each statement reads a through rsi and b through rdi, which the "+S" and
// "+D" operands bind, because a round writes both registers once the
// product is done. It leaves its result in r8 to r11, which four register
// variables bind as its outputs: GNU C keeps a local register variable in
// its register for the asm statement that names it as an operand.
// p256_adx_store, after the statement, stores them to o. Every other
// register a statement writes is in its clobber list.
//
// Each round k takes u = t[k] and adds u * p, which clears t[k], because
// p's low word is 2^64 - 1 and so -p^-1 mod 2^64 is 1. As in reduce_round,
// u * p is u << 96 less u plus u * p3 << 192, with p3 = 2^64 - 2^32 + 1 in
// rbx: u << 32 at t[k+1], u >> 32 at t[k+2], and MULX's two words of u * p3
// at t[k+3] and t[k+4]. rcx holds the carry the round before left past its
// t[k+4], which belongs at this round's t[k+4], and the high word of u * p3
// is at most 2^64 - 2^32, so the carry fits beside it. The last step is
// p256_wide_fe_reduce_once: (rcx : r15 : r14 : r13 : r12) less p, kept
// where that borrows, chosen by CMOVC on the borrow. No instruction here
// branches, and every address is rsi or rdi plus a constant. Semgrep reads
// no macro inside an asm statement, so each statement spells its text and
// its operands out.
#ifndef CH_P256_ADX_ASM_H
#define CH_P256_ADX_ASM_H

#include <stdint.h>

// o = (w3 : w2 : w1 : w0), the four words a statement leaves in r8 to r11.
// Under gcc, between each two stores is an empty statement that clobbers
// memory, so gcc does not merge the four stores into two from vector
// registers, as x25519_adx_asm.h's adx_store does (docs/decisions.md 205).
// The statements emit no instruction. clang merges no such stores, so under
// clang the stores stand alone, and the C after a product reads the words
// it needs from registers, where after a statement that clobbers memory it
// loaded each word that the store before had written. On an EPYC 7763 a
// doubling under clang took 305 to 313 cycles where it took 317.5. Under gcc
// an empty statement that names one word in place of all memory took it to
// 346 cycles from 330 (docs/decisions.md 224).
static inline __attribute__((always_inline)) void
p256_adx_store(uint64_t o[4], uint64_t w0, uint64_t w1, uint64_t w2, uint64_t w3) {
#ifdef __clang__
    o[0] = w0;
    o[1] = w1;
    o[2] = w2;
    o[3] = w3;
#else
    o[0] = w0;
    __asm__ volatile("" ::: "memory");
    o[1] = w1;
    __asm__ volatile("" ::: "memory");
    o[2] = w2;
    __asm__ volatile("" ::: "memory");
    o[3] = w3;
#endif
}

// o = a * b / 2^256 mod p. o may be a or b: every word of both is read
// before o is written.
static inline __attribute__((always_inline)) void
p256_adx_mul_mont(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]) {
    register uint64_t w0 __asm__("r8");
    register uint64_t w1 __asm__("r9");
    register uint64_t w2 __asm__("r10");
    register uint64_t w3 __asm__("r11");
    const uint64_t *a_words = a;
    const uint64_t *b_words = b;
    __asm__ volatile(
        // Row 0: r8 to r12 = a * b[0].
        "mov (%%rdi), %%rdx\n"
        "mulx (%%rsi), %%r8, %%r9\n"
        "mulx 8(%%rsi), %%rax, %%r10\n add %%rax, %%r9\n"
        "mulx 16(%%rsi), %%rax, %%r11\n adc %%rax, %%r10\n"
        "mulx 24(%%rsi), %%rax, %%r12\n adc %%rax, %%r11\n adc $0, %%r12\n"
        // Rows 1 to 3: a * b[i] added at word i, the low words of the
        // products on the CF chain and the high words on the OF chain.
        "mov 8(%%rdi), %%rdx\n"
        "xor %%ecx, %%ecx\n"
        "mulx (%%rsi), %%rax, %%rcx\n adcx %%rax, %%r9\n adox %%rcx, %%r10\n"
        "mulx 8(%%rsi), %%rax, %%rcx\n adcx %%rax, %%r10\n adox %%rcx, %%r11\n"
        "mulx 16(%%rsi), %%rax, %%rcx\n adcx %%rax, %%r11\n adox %%rcx, %%r12\n"
        "mulx 24(%%rsi), %%rax, %%r13\n adcx %%rax, %%r12\n"
        "mov $0, %%ecx\n adox %%rcx, %%r13\n adcx %%rcx, %%r13\n"
        "mov 16(%%rdi), %%rdx\n"
        "xor %%ecx, %%ecx\n"
        "mulx (%%rsi), %%rax, %%rcx\n adcx %%rax, %%r10\n adox %%rcx, %%r11\n"
        "mulx 8(%%rsi), %%rax, %%rcx\n adcx %%rax, %%r11\n adox %%rcx, %%r12\n"
        "mulx 16(%%rsi), %%rax, %%rcx\n adcx %%rax, %%r12\n adox %%rcx, %%r13\n"
        "mulx 24(%%rsi), %%rax, %%r14\n adcx %%rax, %%r13\n"
        "mov $0, %%ecx\n adox %%rcx, %%r14\n adcx %%rcx, %%r14\n"
        "mov 24(%%rdi), %%rdx\n"
        "xor %%ecx, %%ecx\n"
        "mulx (%%rsi), %%rax, %%rcx\n adcx %%rax, %%r11\n adox %%rcx, %%r12\n"
        "mulx 8(%%rsi), %%rax, %%rcx\n adcx %%rax, %%r12\n adox %%rcx, %%r13\n"
        "mulx 16(%%rsi), %%rax, %%rcx\n adcx %%rax, %%r13\n adox %%rcx, %%r14\n"
        "mulx 24(%%rsi), %%rax, %%r15\n adcx %%rax, %%r14\n"
        "mov $0, %%ecx\n adox %%rcx, %%r15\n adcx %%rcx, %%r15\n"
        // The four rounds of the reduction.
        "mov $0xffffffff00000001, %%rbx\n xor %%ecx, %%ecx\n"
        "mov %%r8, %%rdx\n mulx %%rbx, %%rsi, %%rdi\n"
        "mov %%rdx, %%rax\n shl $32, %%rax\n shr $32, %%rdx\n add %%rcx, %%rdi\n"
        "add %%rax, %%r9\n adc %%rdx, %%r10\n adc %%rsi, %%r11\n adc %%rdi, %%r12\n"
        "mov $0, %%ecx\n adc $0, %%rcx\n"
        "mov %%r9, %%rdx\n mulx %%rbx, %%rsi, %%rdi\n"
        "mov %%rdx, %%rax\n shl $32, %%rax\n shr $32, %%rdx\n add %%rcx, %%rdi\n"
        "add %%rax, %%r10\n adc %%rdx, %%r11\n adc %%rsi, %%r12\n adc %%rdi, %%r13\n"
        "mov $0, %%ecx\n adc $0, %%rcx\n"
        "mov %%r10, %%rdx\n mulx %%rbx, %%rsi, %%rdi\n"
        "mov %%rdx, %%rax\n shl $32, %%rax\n shr $32, %%rdx\n add %%rcx, %%rdi\n"
        "add %%rax, %%r11\n adc %%rdx, %%r12\n adc %%rsi, %%r13\n adc %%rdi, %%r14\n"
        "mov $0, %%ecx\n adc $0, %%rcx\n"
        "mov %%r11, %%rdx\n mulx %%rbx, %%rsi, %%rdi\n"
        "mov %%rdx, %%rax\n shl $32, %%rax\n shr $32, %%rdx\n add %%rcx, %%rdi\n"
        "add %%rax, %%r12\n adc %%rdx, %%r13\n adc %%rsi, %%r14\n adc %%rdi, %%r15\n"
        "mov $0, %%ecx\n adc $0, %%rcx\n"
        // The final subtraction of p: p0 is 2^64 - 1, so its subtraction
        // is the subtraction of -1 as a sign-extended immediate.
        "mov %%r12, %%r8\n mov %%r13, %%r9\n mov %%r14, %%r10\n mov %%r15, %%r11\n"
        "mov $0xffffffff, %%eax\n"
        "sub $-1, %%r8\n sbb %%rax, %%r9\n sbb $0, %%r10\n sbb %%rbx, %%r11\n sbb $0, %%rcx\n"
        "cmovc %%r12, %%r8\n cmovc %%r13, %%r9\n cmovc %%r14, %%r10\n cmovc %%r15, %%r11\n"
        : "=&r"(w0), "=&r"(w1), "=&r"(w2), "=&r"(w3), "+S"(a_words), "+D"(b_words)
        :
        : "memory", "cc", "rax", "rbx", "rcx", "rdx", "r12", "r13", "r14", "r15");
    p256_adx_store(o, w0, w1, w2, w3);
}

// o = a * a / 2^256 mod p: the six products of two different words once,
// doubled, then the four squares, then the same reduction. o may be a.
static inline __attribute__((always_inline)) void p256_adx_sqr_mont(uint64_t o[4],
                                                                    const uint64_t a[4]) {
    register uint64_t w0 __asm__("r8");
    register uint64_t w1 __asm__("r9");
    register uint64_t w2 __asm__("r10");
    register uint64_t w3 __asm__("r11");
    const uint64_t *a_words = a;
    const uint64_t *b_words = a;
    __asm__ volatile(
        // r9 to r14 = the sum of a[i] a[j] 2^(64 (i + j)) for i < j.
        "mov (%%rsi), %%rdx\n"
        "mulx 8(%%rsi), %%r9, %%r10\n"
        "mulx 16(%%rsi), %%rax, %%r11\n add %%rax, %%r10\n"
        "mulx 24(%%rsi), %%rax, %%r12\n adc %%rax, %%r11\n adc $0, %%r12\n"
        "mov 8(%%rsi), %%rdx\n"
        "mulx 16(%%rsi), %%rax, %%rcx\n add %%rax, %%r11\n adc %%rcx, %%r12\n"
        "mulx 24(%%rsi), %%rax, %%r13\n adc $0, %%r13\n"
        "add %%rax, %%r12\n adc $0, %%r13\n"
        "mov 16(%%rsi), %%rdx\n"
        "mulx 24(%%rsi), %%rax, %%r14\n add %%rax, %%r13\n adc $0, %%r14\n"
        // Doubled into r9 to r15, then the squares a[i]^2 at word 2i.
        "xor %%r15d, %%r15d\n"
        "add %%r9, %%r9\n adc %%r10, %%r10\n adc %%r11, %%r11\n adc %%r12, %%r12\n"
        "adc %%r13, %%r13\n adc %%r14, %%r14\n adc $0, %%r15\n"
        "mov (%%rsi), %%rdx\n mulx %%rdx, %%r8, %%rax\n add %%rax, %%r9\n"
        "mov 8(%%rsi), %%rdx\n mulx %%rdx, %%rax, %%rcx\n"
        "adc %%rax, %%r10\n adc %%rcx, %%r11\n"
        "mov 16(%%rsi), %%rdx\n mulx %%rdx, %%rax, %%rcx\n"
        "adc %%rax, %%r12\n adc %%rcx, %%r13\n"
        "mov 24(%%rsi), %%rdx\n mulx %%rdx, %%rax, %%rcx\n"
        "adc %%rax, %%r14\n adc %%rcx, %%r15\n"
        // The four rounds of the reduction.
        "mov $0xffffffff00000001, %%rbx\n xor %%ecx, %%ecx\n"
        "mov %%r8, %%rdx\n mulx %%rbx, %%rsi, %%rdi\n"
        "mov %%rdx, %%rax\n shl $32, %%rax\n shr $32, %%rdx\n add %%rcx, %%rdi\n"
        "add %%rax, %%r9\n adc %%rdx, %%r10\n adc %%rsi, %%r11\n adc %%rdi, %%r12\n"
        "mov $0, %%ecx\n adc $0, %%rcx\n"
        "mov %%r9, %%rdx\n mulx %%rbx, %%rsi, %%rdi\n"
        "mov %%rdx, %%rax\n shl $32, %%rax\n shr $32, %%rdx\n add %%rcx, %%rdi\n"
        "add %%rax, %%r10\n adc %%rdx, %%r11\n adc %%rsi, %%r12\n adc %%rdi, %%r13\n"
        "mov $0, %%ecx\n adc $0, %%rcx\n"
        "mov %%r10, %%rdx\n mulx %%rbx, %%rsi, %%rdi\n"
        "mov %%rdx, %%rax\n shl $32, %%rax\n shr $32, %%rdx\n add %%rcx, %%rdi\n"
        "add %%rax, %%r11\n adc %%rdx, %%r12\n adc %%rsi, %%r13\n adc %%rdi, %%r14\n"
        "mov $0, %%ecx\n adc $0, %%rcx\n"
        "mov %%r11, %%rdx\n mulx %%rbx, %%rsi, %%rdi\n"
        "mov %%rdx, %%rax\n shl $32, %%rax\n shr $32, %%rdx\n add %%rcx, %%rdi\n"
        "add %%rax, %%r12\n adc %%rdx, %%r13\n adc %%rsi, %%r14\n adc %%rdi, %%r15\n"
        "mov $0, %%ecx\n adc $0, %%rcx\n"
        // The final subtraction of p.
        "mov %%r12, %%r8\n mov %%r13, %%r9\n mov %%r14, %%r10\n mov %%r15, %%r11\n"
        "mov $0xffffffff, %%eax\n"
        "sub $-1, %%r8\n sbb %%rax, %%r9\n sbb $0, %%r10\n sbb %%rbx, %%r11\n sbb $0, %%rcx\n"
        "cmovc %%r12, %%r8\n cmovc %%r13, %%r9\n cmovc %%r14, %%r10\n cmovc %%r15, %%r11\n"
        : "=&r"(w0), "=&r"(w1), "=&r"(w2), "=&r"(w3), "+S"(a_words), "+D"(b_words)
        :
        : "memory", "cc", "rax", "rbx", "rcx", "rdx", "r12", "r13", "r14", "r15");
    p256_adx_store(o, w0, w1, w2, w3);
}

#endif
