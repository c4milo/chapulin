// rsa_mont64_adx.c's five operations on 64-bit words in inline assembly:
// three rows of products, the square's doubling and the final subtraction.
// rsa_mont64_adx.c includes this file alone, in every build but the model
// build, which takes test/rsa_mont64_adx_model.h in its place. Each
// operation writes the words its model writes, which are the exact sums
// its comment states.
//
// Why assembly: C names neither MULX, a multiply whose second operand is rdx
// and that writes no flag, nor the two carry flags that ADCX and ADOX keep
// apart, so no compiler here adds a row's low halves and high halves on two
// carry chains side by side (docs/decisions.md 165 and 183).
//
// A row adds y * v to the words at t, one word of v at a time: ADCX adds the
// low half of y * v[j] to t[j] on the carry flag, and ADOX adds the high half
// of y * v[j - 1] on the overflow flag. A row of n words runs n % 4 words one
// at a time, then n / 4 blocks of four, and every count is the public word
// count of the modulus. LEA moves the pointers and the count, and JRCXZ tests
// the count, because neither writes a flag, so both chains run from the first
// word of a row to its last. No branch and no address here depends on a word
// of t, y or v.
//
// Semgrep reads no macro inside an asm statement, so each statement spells
// its text and its operands out.
#ifndef CH_RSA_MONT64_ADX_ASM_H
#define CH_RSA_MONT64_ADX_ASM_H

#include <stddef.h>
#include <stdint.h>

// The zero ADOX adds into the last word of a row whose top word no row wrote.
static const uint64_t adx_zero_word = 0;

// t[0..n] = y * v[0..n-1]: every word written, none read. One chain: t[j] is
// the low half of y * v[j] plus the high half of y * v[j - 1] plus the carry.
// n is 1 or more.
static void adx_row_first(uint64_t *t, uint64_t y, const uint64_t *v, size_t n) {
    // The assembly advances dst and writes the words of t through it.
    uint64_t *dst = t;
    uint64_t lo;
    uint64_t hi;
    uint64_t prev;
    __asm__ volatile("xorl %k[prev], %k[prev]\n"
                     "1:\n\t"
                     "mulx 0(%[v]), %[lo], %[hi]\n\t"
                     "adcx %[prev], %[lo]\n\t"
                     "movq %[lo], 0(%[t])\n\t"
                     "movq %[hi], %[prev]\n\t"
                     "leaq 8(%[v]), %[v]\n\t"
                     "leaq 8(%[t]), %[t]\n\t"
                     "leaq -1(%[n]), %[n]\n\t"
                     "jrcxz 2f\n\t"
                     "jmp 1b\n"
                     "2:\n\t"
                     "movl $0, %k[lo]\n\t"
                     "adcx %[prev], %[lo]\n\t"
                     "movq %[lo], 0(%[t])\n\t"
                     : [t] "+&r"(dst), [v] "+&r"(v), [n] "+&c"(n), [lo] "=&r"(lo), [hi] "=&r"(hi),
                       [prev] "=&r"(prev)
                     : "d"(y)
                     : "cc", "memory");
}

// t[0..n-1] += y * v[0..n-1], and t[n] = the top word of that sum, for a
// t[n] no row wrote: the product rows, whose sum always fits n + 1 words.
// n is 1 or more.
static void adx_row_store_top(uint64_t *t, uint64_t y, const uint64_t *v, size_t n) {
    // The assembly advances dst and writes the words of t through it.
    uint64_t *dst = t;
    uint64_t lo;
    uint64_t hi;
    uint64_t r;
    uint64_t prev;
    size_t rem = n % 4;
    size_t blocks = n / 4;
    __asm__ volatile("xorl %k[prev], %k[prev]\n\t"
                     "jrcxz 3f\n"
                     "4:\n\t"
                     "mulx 0(%[v]), %[lo], %[hi]\n\t"
                     "movq 0(%[t]), %[r]\n\t"
                     "adcx %[lo], %[r]\n\t"
                     "adox %[prev], %[r]\n\t"
                     "movq %[r], 0(%[t])\n\t"
                     "movq %[hi], %[prev]\n\t"
                     "leaq 8(%[v]), %[v]\n\t"
                     "leaq 8(%[t]), %[t]\n\t"
                     "leaq -1(%[n]), %[n]\n\t"
                     "jrcxz 3f\n\t"
                     "jmp 4b\n"
                     "3:\n\t"
                     "movq %[blocks], %[n]\n\t"
                     "jrcxz 2f\n"
                     "1:\n\t"
                     "mulx 0(%[v]), %[lo], %[hi]\n\t"
                     "movq 0(%[t]), %[r]\n\t"
                     "adcx %[lo], %[r]\n\t"
                     "adox %[prev], %[r]\n\t"
                     "movq %[r], 0(%[t])\n\t"
                     "mulx 8(%[v]), %[lo], %[prev]\n\t"
                     "movq 8(%[t]), %[r]\n\t"
                     "adcx %[lo], %[r]\n\t"
                     "adox %[hi], %[r]\n\t"
                     "movq %[r], 8(%[t])\n\t"
                     "mulx 16(%[v]), %[lo], %[hi]\n\t"
                     "movq 16(%[t]), %[r]\n\t"
                     "adcx %[lo], %[r]\n\t"
                     "adox %[prev], %[r]\n\t"
                     "movq %[r], 16(%[t])\n\t"
                     "mulx 24(%[v]), %[lo], %[prev]\n\t"
                     "movq 24(%[t]), %[r]\n\t"
                     "adcx %[lo], %[r]\n\t"
                     "adox %[hi], %[r]\n\t"
                     "movq %[r], 24(%[t])\n\t"
                     "leaq 32(%[v]), %[v]\n\t"
                     "leaq 32(%[t]), %[t]\n\t"
                     "leaq -1(%[n]), %[n]\n\t"
                     "jrcxz 2f\n\t"
                     "jmp 1b\n"
                     "2:\n\t"
                     "movl $0, %k[r]\n\t"
                     "adcx %[prev], %[r]\n\t"
                     "adox %[zero], %[r]\n\t"
                     "movq %[r], 0(%[t])\n\t"
                     : [t] "+&r"(dst), [v] "+&r"(v), [n] "+&c"(rem), [lo] "=&r"(lo), [hi] "=&r"(hi),
                       [r] "=&r"(r), [prev] "=&r"(prev)
                     : "d"(y), [blocks] "r"(blocks), [zero] "m"(adx_zero_word)
                     : "cc", "memory");
}

// t[0..n] += y * v[0..n-1] + cin * 2^(64n): a reduction row, whose sum can
// carry out of t[n]. Returns that carry, 0 or 1. n is 1 or more and cin is
// 0 or 1.
static uint64_t adx_row_carry(uint64_t *t, uint64_t y, const uint64_t *v, size_t n, uint64_t cin) {
    // The assembly advances dst and writes the words of t through it.
    uint64_t *dst = t;
    uint64_t lo;
    uint64_t hi;
    uint64_t r;
    uint64_t prev;
    uint64_t cf;
    uint64_t of;
    size_t rem = n % 4;
    size_t blocks = n / 4;
    __asm__ volatile("xorl %k[prev], %k[prev]\n\t"
                     "jrcxz 3f\n"
                     "4:\n\t"
                     "mulx 0(%[v]), %[lo], %[hi]\n\t"
                     "movq 0(%[t]), %[r]\n\t"
                     "adcx %[lo], %[r]\n\t"
                     "adox %[prev], %[r]\n\t"
                     "movq %[r], 0(%[t])\n\t"
                     "movq %[hi], %[prev]\n\t"
                     "leaq 8(%[v]), %[v]\n\t"
                     "leaq 8(%[t]), %[t]\n\t"
                     "leaq -1(%[n]), %[n]\n\t"
                     "jrcxz 3f\n\t"
                     "jmp 4b\n"
                     "3:\n\t"
                     "movq %[blocks], %[n]\n\t"
                     "jrcxz 2f\n"
                     "1:\n\t"
                     "mulx 0(%[v]), %[lo], %[hi]\n\t"
                     "movq 0(%[t]), %[r]\n\t"
                     "adcx %[lo], %[r]\n\t"
                     "adox %[prev], %[r]\n\t"
                     "movq %[r], 0(%[t])\n\t"
                     "mulx 8(%[v]), %[lo], %[prev]\n\t"
                     "movq 8(%[t]), %[r]\n\t"
                     "adcx %[lo], %[r]\n\t"
                     "adox %[hi], %[r]\n\t"
                     "movq %[r], 8(%[t])\n\t"
                     "mulx 16(%[v]), %[lo], %[hi]\n\t"
                     "movq 16(%[t]), %[r]\n\t"
                     "adcx %[lo], %[r]\n\t"
                     "adox %[prev], %[r]\n\t"
                     "movq %[r], 16(%[t])\n\t"
                     "mulx 24(%[v]), %[lo], %[prev]\n\t"
                     "movq 24(%[t]), %[r]\n\t"
                     "adcx %[lo], %[r]\n\t"
                     "adox %[hi], %[r]\n\t"
                     "movq %[r], 24(%[t])\n\t"
                     "leaq 32(%[v]), %[v]\n\t"
                     "leaq 32(%[t]), %[t]\n\t"
                     "leaq -1(%[n]), %[n]\n\t"
                     "jrcxz 2f\n\t"
                     "jmp 1b\n"
                     "2:\n\t"
                     "movq 0(%[t]), %[r]\n\t"
                     "adcx %[prev], %[r]\n\t"
                     "adox %[cin], %[r]\n\t"
                     "movq %[r], 0(%[t])\n\t"
                     "movl $0, %k[cf]\n\t"
                     "movl $0, %k[of]\n\t"
                     "setc %b[cf]\n\t"
                     "seto %b[of]\n\t"
                     : [t] "+&r"(dst), [v] "+&r"(v), [n] "+&c"(rem), [lo] "=&r"(lo), [hi] "=&r"(hi),
                       [r] "=&r"(r), [prev] "=&r"(prev), [cf] "=&r"(cf), [of] "=&r"(of)
                     : "d"(y), [blocks] "r"(blocks), [cin] "r"(cin)
                     : "cc", "memory");
    return cf + of;
}

// t[0..2k-1] = 2 * t + the sum of a[i]^2 * 2^(128 i): the square from its
// cross products. ADCX doubles each word in order, ADOX adds the diagonal.
// k is 1 or more, and the result fits the 2k words.
static void adx_double_add_diagonal(uint64_t *t, const uint64_t *a, size_t k) {
    // The assembly advances dst and writes the words of t through it.
    uint64_t *dst = t;
    uint64_t lo;
    uint64_t hi;
    uint64_t r;
    uint64_t x;
    __asm__ volatile("xorl %k[r], %k[r]\n"
                     "1:\n\t"
                     "movq 0(%[a]), %%rdx\n\t"
                     "mulx %%rdx, %[lo], %[hi]\n\t"
                     "movq 0(%[t]), %[r]\n\t"
                     "adcx %[r], %[r]\n\t"
                     "adox %[lo], %[r]\n\t"
                     "movq %[r], 0(%[t])\n\t"
                     "movq 8(%[t]), %[x]\n\t"
                     "adcx %[x], %[x]\n\t"
                     "adox %[hi], %[x]\n\t"
                     "movq %[x], 8(%[t])\n\t"
                     "leaq 8(%[a]), %[a]\n\t"
                     "leaq 16(%[t]), %[t]\n\t"
                     "leaq -1(%[n]), %[n]\n\t"
                     "jrcxz 2f\n\t"
                     "jmp 1b\n"
                     "2:\n\t"
                     : [t] "+&r"(dst), [a] "+&r"(a), [n] "+&c"(k), [lo] "=&r"(lo), [hi] "=&r"(hi),
                       [r] "=&r"(r), [x] "=&r"(x)
                     :
                     : "rdx", "cc", "memory");
}

// o = top:t - m when top:t is m or more, and top:t otherwise, for the k + 1
// word value top:t below 2m. SBB writes t - m into o, the borrow out of top
// says whether top:t was below m, and CMOVC then keeps t's word in each
// word of o. CMOVC loads both words whatever the flag. o overlaps neither t
// nor m, and k is 1 or more.
static void adx_final_sub(uint64_t *o, const uint64_t *t, uint64_t top, const uint64_t *m,
                          size_t k) {
    uint64_t r;
    const uint64_t *t_first = t;
    uint64_t *o_first = o;
    size_t n = k;
    __asm__ volatile(
        "clc\n"
        "1:\n\t"
        "movq 0(%[t]), %[r]\n\t"
        "sbbq 0(%[m]), %[r]\n\t"
        "movq %[r], 0(%[o])\n\t"
        "leaq 8(%[t]), %[t]\n\t"
        "leaq 8(%[m]), %[m]\n\t"
        "leaq 8(%[o]), %[o]\n\t"
        "leaq -1(%[n]), %[n]\n\t"
        "jrcxz 2f\n\t"
        "jmp 1b\n"
        "2:\n\t"
        "sbbq $0, %[top]\n\t"
        "movq %[k], %[n]\n\t"
        "movq %[t_first], %[t]\n\t"
        "movq %[o_first], %[o]\n"
        "3:\n\t"
        "movq 0(%[o]), %[r]\n\t"
        "cmovcq 0(%[t]), %[r]\n\t"
        "movq %[r], 0(%[o])\n\t"
        "leaq 8(%[t]), %[t]\n\t"
        "leaq 8(%[o]), %[o]\n\t"
        "leaq -1(%[n]), %[n]\n\t"
        "jrcxz 4f\n\t"
        "jmp 3b\n"
        "4:\n\t"
        : [t] "+&r"(t), [m] "+&r"(m), [o] "+&r"(o), [n] "+&c"(n), [top] "+&r"(top), [r] "=&r"(r)
        : [k] "r"(k), [t_first] "r"(t_first), [o_first] "r"(o_first)
        : "cc", "memory");
}

#endif
