// avx512_wipe.c's one call on the instructions: after avx512_wipe_registers
// returns, every vector register, zmm0 to zmm31, and the mask registers k1
// to k7 must hold zero. A kernel calls it before it returns, so that no
// secret it ran through those registers stays in them.
//
// One block of assembly sets every bit of the 32 vector registers and of
// k1 to k7, calls the function and stores the registers to memory, so no
// instruction the compiler picks runs between the three. The same block
// with the call left out runs first, and its stores must hold every bit
// set: that shows the block fills each register it reads back, so a zero
// after the call is the call's. The block keeps its pointers in registers
// the call may not change, and moves the stack pointer below the red zone
// before the call, because the return address the call pushes would land
// there.
//
// It needs an x86-64 CPU with AVX-512F. A CPU without it skips, unless
// CH_REQUIRE_AVX512_IFMA is 1 (test/x86_kernels_cpu.h): the nightly's
// rsa-ifma-sde job sets it and runs this binary under Intel SDE
// (test/platforms.mk, rsa-ifma-sde-check). On any other architecture the
// function has no body, and the binary prints SKIP.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// avx512_wipe.h declares the call only in a host object, and the binary
// compiles this file and avx512_wipe.c under -DCH_CPU_RUNTIME, as a host
// object compiles the call.
#include "avx512_wipe.h"
#include "x86_kernels_cpu.h"

#ifdef __x86_64__

#define VECTOR_REGISTERS 32
#define VECTOR_WORDS 8
#define MASK_REGISTERS 7
// zmm0 to zmm31, eight 64-bit words each, then k1 to k7, one word each.
#define STORED_WORDS (VECTOR_REGISTERS * VECTOR_WORDS + MASK_REGISTERS)

static uint64_t stored[STORED_WORDS];

// Every bit of the 32 vector registers and of k1 to k7 set, wipe called
// where it is not NULL, and the registers stored to stored: zmm0 to zmm31
// at 64 bytes each, then the 16 bits of each mask register in a word of
// its own. VPTERNLOGD with the truth table 0xff writes 1 whatever its inputs
// hold, and KXNORW of k0 with itself sets every bit. The block names as
// changed every vector register, k1 to k7, and the registers the System V
// ABI lets a call change, so the compiler keeps the two addresses the
// block reads in others.
__attribute__((target("avx512f"), noinline)) static void set_call_store(void (*wipe)(void)) {
    __asm__ volatile("vpternlogd $0xff, %%zmm0, %%zmm0, %%zmm0\n\t"
                     "vpternlogd $0xff, %%zmm1, %%zmm1, %%zmm1\n\t"
                     "vpternlogd $0xff, %%zmm2, %%zmm2, %%zmm2\n\t"
                     "vpternlogd $0xff, %%zmm3, %%zmm3, %%zmm3\n\t"
                     "vpternlogd $0xff, %%zmm4, %%zmm4, %%zmm4\n\t"
                     "vpternlogd $0xff, %%zmm5, %%zmm5, %%zmm5\n\t"
                     "vpternlogd $0xff, %%zmm6, %%zmm6, %%zmm6\n\t"
                     "vpternlogd $0xff, %%zmm7, %%zmm7, %%zmm7\n\t"
                     "vpternlogd $0xff, %%zmm8, %%zmm8, %%zmm8\n\t"
                     "vpternlogd $0xff, %%zmm9, %%zmm9, %%zmm9\n\t"
                     "vpternlogd $0xff, %%zmm10, %%zmm10, %%zmm10\n\t"
                     "vpternlogd $0xff, %%zmm11, %%zmm11, %%zmm11\n\t"
                     "vpternlogd $0xff, %%zmm12, %%zmm12, %%zmm12\n\t"
                     "vpternlogd $0xff, %%zmm13, %%zmm13, %%zmm13\n\t"
                     "vpternlogd $0xff, %%zmm14, %%zmm14, %%zmm14\n\t"
                     "vpternlogd $0xff, %%zmm15, %%zmm15, %%zmm15\n\t"
                     "vpternlogd $0xff, %%zmm16, %%zmm16, %%zmm16\n\t"
                     "vpternlogd $0xff, %%zmm17, %%zmm17, %%zmm17\n\t"
                     "vpternlogd $0xff, %%zmm18, %%zmm18, %%zmm18\n\t"
                     "vpternlogd $0xff, %%zmm19, %%zmm19, %%zmm19\n\t"
                     "vpternlogd $0xff, %%zmm20, %%zmm20, %%zmm20\n\t"
                     "vpternlogd $0xff, %%zmm21, %%zmm21, %%zmm21\n\t"
                     "vpternlogd $0xff, %%zmm22, %%zmm22, %%zmm22\n\t"
                     "vpternlogd $0xff, %%zmm23, %%zmm23, %%zmm23\n\t"
                     "vpternlogd $0xff, %%zmm24, %%zmm24, %%zmm24\n\t"
                     "vpternlogd $0xff, %%zmm25, %%zmm25, %%zmm25\n\t"
                     "vpternlogd $0xff, %%zmm26, %%zmm26, %%zmm26\n\t"
                     "vpternlogd $0xff, %%zmm27, %%zmm27, %%zmm27\n\t"
                     "vpternlogd $0xff, %%zmm28, %%zmm28, %%zmm28\n\t"
                     "vpternlogd $0xff, %%zmm29, %%zmm29, %%zmm29\n\t"
                     "vpternlogd $0xff, %%zmm30, %%zmm30, %%zmm30\n\t"
                     "vpternlogd $0xff, %%zmm31, %%zmm31, %%zmm31\n\t"
                     "kxnorw %%k0, %%k0, %%k1\n\t"
                     "kxnorw %%k0, %%k0, %%k2\n\t"
                     "kxnorw %%k0, %%k0, %%k3\n\t"
                     "kxnorw %%k0, %%k0, %%k4\n\t"
                     "kxnorw %%k0, %%k0, %%k5\n\t"
                     "kxnorw %%k0, %%k0, %%k6\n\t"
                     "kxnorw %%k0, %%k0, %%k7\n\t"
                     "testq %[wipe], %[wipe]\n\t"
                     "jz 1f\n\t"
                     "subq $128, %%rsp\n\t"
                     "call *%[wipe]\n\t"
                     "addq $128, %%rsp\n\t"
                     "1:\n\t"
                     "vmovdqu64 %%zmm0, 0(%[out])\n\t"
                     "vmovdqu64 %%zmm1, 64(%[out])\n\t"
                     "vmovdqu64 %%zmm2, 128(%[out])\n\t"
                     "vmovdqu64 %%zmm3, 192(%[out])\n\t"
                     "vmovdqu64 %%zmm4, 256(%[out])\n\t"
                     "vmovdqu64 %%zmm5, 320(%[out])\n\t"
                     "vmovdqu64 %%zmm6, 384(%[out])\n\t"
                     "vmovdqu64 %%zmm7, 448(%[out])\n\t"
                     "vmovdqu64 %%zmm8, 512(%[out])\n\t"
                     "vmovdqu64 %%zmm9, 576(%[out])\n\t"
                     "vmovdqu64 %%zmm10, 640(%[out])\n\t"
                     "vmovdqu64 %%zmm11, 704(%[out])\n\t"
                     "vmovdqu64 %%zmm12, 768(%[out])\n\t"
                     "vmovdqu64 %%zmm13, 832(%[out])\n\t"
                     "vmovdqu64 %%zmm14, 896(%[out])\n\t"
                     "vmovdqu64 %%zmm15, 960(%[out])\n\t"
                     "vmovdqu64 %%zmm16, 1024(%[out])\n\t"
                     "vmovdqu64 %%zmm17, 1088(%[out])\n\t"
                     "vmovdqu64 %%zmm18, 1152(%[out])\n\t"
                     "vmovdqu64 %%zmm19, 1216(%[out])\n\t"
                     "vmovdqu64 %%zmm20, 1280(%[out])\n\t"
                     "vmovdqu64 %%zmm21, 1344(%[out])\n\t"
                     "vmovdqu64 %%zmm22, 1408(%[out])\n\t"
                     "vmovdqu64 %%zmm23, 1472(%[out])\n\t"
                     "vmovdqu64 %%zmm24, 1536(%[out])\n\t"
                     "vmovdqu64 %%zmm25, 1600(%[out])\n\t"
                     "vmovdqu64 %%zmm26, 1664(%[out])\n\t"
                     "vmovdqu64 %%zmm27, 1728(%[out])\n\t"
                     "vmovdqu64 %%zmm28, 1792(%[out])\n\t"
                     "vmovdqu64 %%zmm29, 1856(%[out])\n\t"
                     "vmovdqu64 %%zmm30, 1920(%[out])\n\t"
                     "vmovdqu64 %%zmm31, 1984(%[out])\n\t"
                     "kmovw %%k1, %%eax\n\t"
                     "movq %%rax, 2048(%[out])\n\t"
                     "kmovw %%k2, %%eax\n\t"
                     "movq %%rax, 2056(%[out])\n\t"
                     "kmovw %%k3, %%eax\n\t"
                     "movq %%rax, 2064(%[out])\n\t"
                     "kmovw %%k4, %%eax\n\t"
                     "movq %%rax, 2072(%[out])\n\t"
                     "kmovw %%k5, %%eax\n\t"
                     "movq %%rax, 2080(%[out])\n\t"
                     "kmovw %%k6, %%eax\n\t"
                     "movq %%rax, 2088(%[out])\n\t"
                     "kmovw %%k7, %%eax\n\t"
                     "movq %%rax, 2096(%[out])\n\t"
                     :
                     : [out] "r"(stored), [wipe] "r"(wipe)
                     : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8",
                       "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "xmm16",
                       "xmm17", "xmm18", "xmm19", "xmm20", "xmm21", "xmm22", "xmm23", "xmm24",
                       "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31", "k1", "k2",
                       "k3", "k4", "k5", "k6", "k7", "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9",
                       "r10", "r11", "cc", "memory");
}

// The bits a stored mask register holds: the 16 KXNORW sets.
#define MASK_BITS UINT64_C(0xffff)

// The first stored word that is not want, or STORED_WORDS where none
// differs. A mask register's word is want's low 16 bits.
static size_t first_other(uint64_t want) {
    for (size_t i = 0; i < STORED_WORDS; i++) {
        uint64_t expected = i < VECTOR_REGISTERS * VECTOR_WORDS ? want : want & MASK_BITS;
        if (stored[i] != expected) {
            return i;
        }
    }
    return STORED_WORDS;
}

// The register that stored word i, for a failure's message.
static void name_register(size_t i, char *name, size_t size) {
    if (i < VECTOR_REGISTERS * VECTOR_WORDS) {
        (void)snprintf(name, size, "zmm%zu word %zu", i / VECTOR_WORDS, i % VECTOR_WORDS);
    } else {
        (void)snprintf(name, size, "k%zu", i - VECTOR_REGISTERS * VECTOR_WORDS + 1);
    }
}

int main(void) {
    if (!x86_cpu_has_avx512f()) {
        if (x86_ifma_required()) {
            (void)fprintf(stderr, "avx512_wipe: this CPU lacks AVX-512F, and "
                                  "CH_REQUIRE_AVX512_IFMA is 1\n");
            return 1;
        }
        printf("avx512_wipe: SKIP: this CPU lacks AVX-512F\n");
        return 0;
    }
    char name[32];
    set_call_store(NULL);
    size_t at = first_other(UINT64_MAX);
    if (at != STORED_WORDS) {
        name_register(at, name, sizeof name);
        (void)fprintf(stderr, "avx512_wipe: the block left %s unset, so it tests nothing\n", name);
        return 1;
    }
    set_call_store(avx512_wipe_registers);
    at = first_other(0);
    if (at != STORED_WORDS) {
        name_register(at, name, sizeof name);
        (void)fprintf(stderr, "avx512_wipe: %s holds 0x%016llx after avx512_wipe_registers\n", name,
                      (unsigned long long)stored[at]);
        return 1;
    }
    printf("avx512_wipe: zmm0 to zmm31 and k1 to k7 hold zero after avx512_wipe_registers\n");
    return 0;
}

#else

int main(void) {
    printf("avx512_wipe: SKIP: the target is not x86-64\n");
    return 0;
}

#endif
