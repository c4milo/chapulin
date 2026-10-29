// x25519_adx.c's five operations on four 64-bit words in inline assembly:
// the product, the square, the sum, the difference and the product by
// 121666. x25519_adx.c includes this file alone, after its fe typedef, in
// every build but the model build, which takes test/x25519_adx_model.h in
// its place. Each operation writes four words under 2^256 congruent mod p to
// its result: 2^256 = 38 mod p, so what passes 2^256 comes back in at word 0
// times 38.
//
// Why assembly: C names neither MULX, a multiply whose second operand is rdx
// and that writes no flag, nor the two carry flags that ADCX and ADOX keep
// apart, so no compiler here builds a product's two carry chains side by
// side (docs/decisions.md 165).
//
// Each statement reads its operands through the pointers it is given and
// leaves its result in r8 to r11, which four register variables bind as its
// outputs: GNU C keeps a local register variable in its register for the asm
// statement that names it as an operand. The C after the statement stores
// them to o. Every other register a statement writes is in its clobber list.
#ifndef CH_X25519_ADX_ASM_H
#define CH_X25519_ADX_ASM_H

#include <stdint.h>

// Each product's last step is the same reduction: r8 to r11 plus 38 times
// r12 to r15, then the carry out of that sum times 38 once more, then 38
// again if that carried. The value left in r8 to r11 is under 2^256 and
// congruent mod p to the eight words. Semgrep reads no macro inside an asm
// statement, so each statement spells its text and its operands out.

// o = a * b. o may be a or b: every word of both is read before o is written.
static void adx_mul(fe o, const fe a, const fe b) {
    register uint64_t w0 __asm__("r8");
    register uint64_t w1 __asm__("r9");
    register uint64_t w2 __asm__("r10");
    register uint64_t w3 __asm__("r11");
    __asm__ volatile(
        // Row 0: r8 to r12 = a * b[0].
        "mov (%[b]), %%rdx\n"
        "mulx (%[a]), %%r8, %%r9\n"
        "mulx 8(%[a]), %%rax, %%r10\n add %%rax, %%r9\n"
        "mulx 16(%[a]), %%rax, %%r11\n adc %%rax, %%r10\n"
        "mulx 24(%[a]), %%rax, %%r12\n adc %%rax, %%r11\n adc $0, %%r12\n"
        // Row 1: r9 to r13 += a * b[1]. ADCX adds the low halves on the
        // carry flag and ADOX the high halves on the overflow flag.
        "mov 8(%[b]), %%rdx\n"
        "xor %%ecx, %%ecx\n"
        "mulx (%[a]), %%rax, %%rcx\n adcx %%rax, %%r9\n adox %%rcx, %%r10\n"
        "mulx 8(%[a]), %%rax, %%rcx\n adcx %%rax, %%r10\n adox %%rcx, %%r11\n"
        "mulx 16(%[a]), %%rax, %%rcx\n adcx %%rax, %%r11\n adox %%rcx, %%r12\n"
        "mulx 24(%[a]), %%rax, %%r13\n adcx %%rax, %%r12\n"
        "mov $0, %%ecx\n adox %%rcx, %%r13\n adcx %%rcx, %%r13\n"
        // Row 2: r10 to r14 += a * b[2]. ADCX adds the low halves on the
        // carry flag and ADOX the high halves on the overflow flag.
        "mov 16(%[b]), %%rdx\n"
        "xor %%ecx, %%ecx\n"
        "mulx (%[a]), %%rax, %%rcx\n adcx %%rax, %%r10\n adox %%rcx, %%r11\n"
        "mulx 8(%[a]), %%rax, %%rcx\n adcx %%rax, %%r11\n adox %%rcx, %%r12\n"
        "mulx 16(%[a]), %%rax, %%rcx\n adcx %%rax, %%r12\n adox %%rcx, %%r13\n"
        "mulx 24(%[a]), %%rax, %%r14\n adcx %%rax, %%r13\n"
        "mov $0, %%ecx\n adox %%rcx, %%r14\n adcx %%rcx, %%r14\n"
        // Row 3: r11 to r15 += a * b[3]. ADCX adds the low halves on the
        // carry flag and ADOX the high halves on the overflow flag.
        "mov 24(%[b]), %%rdx\n"
        "xor %%ecx, %%ecx\n"
        "mulx (%[a]), %%rax, %%rcx\n adcx %%rax, %%r11\n adox %%rcx, %%r12\n"
        "mulx 8(%[a]), %%rax, %%rcx\n adcx %%rax, %%r12\n adox %%rcx, %%r13\n"
        "mulx 16(%[a]), %%rax, %%rcx\n adcx %%rax, %%r13\n adox %%rcx, %%r14\n"
        "mulx 24(%[a]), %%rax, %%r15\n adcx %%rax, %%r14\n"
        "mov $0, %%ecx\n adox %%rcx, %%r15\n adcx %%rcx, %%r15\n"
        // r8 to r11 += 38 * r12 to r15, as stated at the top of this file.
        "xor %%ecx, %%ecx\n mov $38, %%edx\n"
        "mulx %%r12, %%rax, %%r12\n adcx %%rax, %%r8\n adox %%r12, %%r9\n"
        "mulx %%r13, %%rax, %%r13\n adcx %%rax, %%r9\n adox %%r13, %%r10\n"
        "mulx %%r14, %%rax, %%r14\n adcx %%rax, %%r10\n adox %%r14, %%r11\n"
        "mulx %%r15, %%rax, %%r15\n adcx %%rax, %%r11\n"
        "mov $0, %%ecx\n adox %%rcx, %%r15\n adcx %%rcx, %%r15\n"
        "imul $38, %%r15, %%r15\n"
        "add %%r15, %%r8\n adc $0, %%r9\n adc $0, %%r10\n adc $0, %%r11\n"
        "sbb %%rax, %%rax\n and $38, %%eax\n add %%rax, %%r8\n"
        : "=&r"(w0), "=&r"(w1), "=&r"(w2), "=&r"(w3)
        : [a] "r"(a), [b] "r"(b)
        : "memory", "cc", "rax", "rcx", "rdx", "r12", "r13", "r14", "r15");
    o[0] = w0;
    o[1] = w1;
    o[2] = w2;
    o[3] = w3;
}

// o = a * a: the six products of two different words once, doubled, then
// the four squares, then adx_mul's reduction. o may be a.
static void adx_sqr(fe o, const fe a) {
    register uint64_t w0 __asm__("r8");
    register uint64_t w1 __asm__("r9");
    register uint64_t w2 __asm__("r10");
    register uint64_t w3 __asm__("r11");
    __asm__ volatile(
        // r9 to r14 = the six products of two different words, then twice
        // that in r9 to r15.
        "mov (%[a]), %%rdx\n"
        "mulx 8(%[a]), %%r9, %%r10\n"
        "mulx 16(%[a]), %%rax, %%r11\n add %%rax, %%r10\n"
        "mulx 24(%[a]), %%rax, %%r12\n adc %%rax, %%r11\n adc $0, %%r12\n"
        "mov 8(%[a]), %%rdx\n"
        "mulx 16(%[a]), %%rax, %%rcx\n add %%rax, %%r11\n adc %%rcx, %%r12\n"
        "mulx 24(%[a]), %%rax, %%r13\n adc $0, %%r13\n"
        "add %%rax, %%r12\n adc $0, %%r13\n"
        "mov 16(%[a]), %%rdx\n"
        "mulx 24(%[a]), %%rax, %%r14\n add %%rax, %%r13\n adc $0, %%r14\n"
        "xor %%r15d, %%r15d\n"
        "add %%r9, %%r9\n adc %%r10, %%r10\n adc %%r11, %%r11\n adc %%r12, %%r12\n"
        "adc %%r13, %%r13\n adc %%r14, %%r14\n adc $0, %%r15\n"
        // Add the four squares, word 0's in r8 and r9.
        "mov (%[a]), %%rdx\n mulx %%rdx, %%r8, %%rax\n add %%rax, %%r9\n"
        "mov 8(%[a]), %%rdx\n mulx %%rdx, %%rax, %%rcx\n"
        "adc %%rax, %%r10\n adc %%rcx, %%r11\n"
        "mov 16(%[a]), %%rdx\n mulx %%rdx, %%rax, %%rcx\n"
        "adc %%rax, %%r12\n adc %%rcx, %%r13\n"
        "mov 24(%[a]), %%rdx\n mulx %%rdx, %%rax, %%rcx\n"
        "adc %%rax, %%r14\n adc %%rcx, %%r15\n"
        // r8 to r11 += 38 * r12 to r15.
        "xor %%ecx, %%ecx\n mov $38, %%edx\n"
        "mulx %%r12, %%rax, %%r12\n adcx %%rax, %%r8\n adox %%r12, %%r9\n"
        "mulx %%r13, %%rax, %%r13\n adcx %%rax, %%r9\n adox %%r13, %%r10\n"
        "mulx %%r14, %%rax, %%r14\n adcx %%rax, %%r10\n adox %%r14, %%r11\n"
        "mulx %%r15, %%rax, %%r15\n adcx %%rax, %%r11\n"
        "mov $0, %%ecx\n adox %%rcx, %%r15\n adcx %%rcx, %%r15\n"
        "imul $38, %%r15, %%r15\n"
        "add %%r15, %%r8\n adc $0, %%r9\n adc $0, %%r10\n adc $0, %%r11\n"
        "sbb %%rax, %%rax\n and $38, %%eax\n add %%rax, %%r8\n"
        : "=&r"(w0), "=&r"(w1), "=&r"(w2), "=&r"(w3)
        : [a] "r"(a)
        : "memory", "cc", "rax", "rcx", "rdx", "r12", "r13", "r14", "r15");
    o[0] = w0;
    o[1] = w1;
    o[2] = w2;
    o[3] = w3;
}

// o = a + b. A carry out of 2^256 adds 38, and a carry out of that adds 38
// once more.
static void adx_add(fe o, const fe a, const fe b) {
    register uint64_t w0 __asm__("r8");
    register uint64_t w1 __asm__("r9");
    register uint64_t w2 __asm__("r10");
    register uint64_t w3 __asm__("r11");
    __asm__ volatile("mov (%[a]), %%r8\n add (%[b]), %%r8\n"
                     "mov 8(%[a]), %%r9\n adc 8(%[b]), %%r9\n"
                     "mov 16(%[a]), %%r10\n adc 16(%[b]), %%r10\n"
                     "mov 24(%[a]), %%r11\n adc 24(%[b]), %%r11\n"
                     "sbb %%rax, %%rax\n and $38, %%eax\n"
                     "add %%rax, %%r8\n adc $0, %%r9\n adc $0, %%r10\n adc $0, %%r11\n"
                     "sbb %%rax, %%rax\n and $38, %%eax\n add %%rax, %%r8\n"
                     : "=&r"(w0), "=&r"(w1), "=&r"(w2), "=&r"(w3)
                     : [a] "r"(a), [b] "r"(b)
                     : "memory", "cc", "rax");
    o[0] = w0;
    o[1] = w1;
    o[2] = w2;
    o[3] = w3;
}

// o = a - b. A borrow out of 2^256 subtracts 38, and a borrow out of that
// subtracts 38 once more.
static void adx_sub(fe o, const fe a, const fe b) {
    register uint64_t w0 __asm__("r8");
    register uint64_t w1 __asm__("r9");
    register uint64_t w2 __asm__("r10");
    register uint64_t w3 __asm__("r11");
    __asm__ volatile("mov (%[a]), %%r8\n sub (%[b]), %%r8\n"
                     "mov 8(%[a]), %%r9\n sbb 8(%[b]), %%r9\n"
                     "mov 16(%[a]), %%r10\n sbb 16(%[b]), %%r10\n"
                     "mov 24(%[a]), %%r11\n sbb 24(%[b]), %%r11\n"
                     "sbb %%rax, %%rax\n and $38, %%eax\n"
                     "sub %%rax, %%r8\n sbb $0, %%r9\n sbb $0, %%r10\n sbb $0, %%r11\n"
                     "sbb %%rax, %%rax\n and $38, %%eax\n sub %%rax, %%r8\n"
                     : "=&r"(w0), "=&r"(w1), "=&r"(w2), "=&r"(w3)
                     : [a] "r"(a), [b] "r"(b)
                     : "memory", "cc", "rax");
    o[0] = w0;
    o[1] = w1;
    o[2] = w2;
    o[3] = w3;
}

// o = a * 121666, RFC 7748's a24 plus one: the ladder adds BB rather than AA
// to it, as OpenSSL's x25519_scalar_mulx does.
static void adx_mul_a24(fe o, const fe a) {
    register uint64_t w0 __asm__("r8");
    register uint64_t w1 __asm__("r9");
    register uint64_t w2 __asm__("r10");
    register uint64_t w3 __asm__("r11");
    __asm__ volatile("mov $121666, %%edx\n"
                     "mulx (%[a]), %%r8, %%rcx\n"
                     "mulx 8(%[a]), %%r9, %%rax\n add %%rcx, %%r9\n"
                     "mulx 16(%[a]), %%r10, %%rcx\n adc %%rax, %%r10\n"
                     "mulx 24(%[a]), %%r11, %%rax\n adc %%rcx, %%r11\n adc $0, %%rax\n"
                     "imul $38, %%rax, %%rax\n"
                     "add %%rax, %%r8\n adc $0, %%r9\n adc $0, %%r10\n adc $0, %%r11\n"
                     "sbb %%rax, %%rax\n and $38, %%eax\n add %%rax, %%r8\n"
                     : "=&r"(w0), "=&r"(w1), "=&r"(w2), "=&r"(w3)
                     : [a] "r"(a)
                     : "memory", "cc", "rax", "rcx", "rdx");
    o[0] = w0;
    o[1] = w1;
    o[2] = w2;
    o[3] = w3;
}

#endif
