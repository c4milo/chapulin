// What an x86-64 kernel leaves in ymm0 to ymm15 when it returns. Three
// kernels hold secret values in those registers and write zero to all
// sixteen before they return, with VZEROALL: sha512_avx2.c's
// (docs/decisions.md 128), chacha20_avx2.c's and poly1305_avx2.c's
// (docs/decisions.md 129). No digest, keystream or tag shows whether they
// did, so a test reads the registers back.
//
// avx2_set_call_store sets every bit of the sixteen registers, calls the
// kernel and stores the registers, in one block of assembly, so no
// instruction the compiler picks runs between the three. A test runs the
// same block with no call first, whose stores must hold every bit set, so
// a zero after the call is the call's.
//
// Included on x86-64 alone, by test/sha2_equiv_residue512_avx2.h,
// test/chacha20_equiv_test.c and test/poly1305_equiv_test.c.
#ifndef CH_TEST_AVX2_REGISTERS_H
#define CH_TEST_AVX2_REGISTERS_H

#include <stddef.h>
#include <stdint.h>

#define AVX2_REGISTERS 16
#define AVX2_REGISTER_WORDS 4

// The kernel as the block of assembly calls it. A test casts the kernel's
// own pointer to this type, which no C call goes through: the block puts
// the arguments where the System V ABI passes the first six integer and
// pointer arguments, rdi, rsi, rdx, rcx, r8 and r9, and calls the address.
typedef void (*avx2_function)(void);

typedef struct {
    avx2_function call; // NULL: the block calls nothing
    uintptr_t argument[6];
} avx2_call;

// ymm0 to ymm15 as the block of assembly stored them, four 64-bit words
// each.
static uint64_t avx2_registers[AVX2_REGISTERS][AVX2_REGISTER_WORDS];

// Every bit of ymm0 to ymm15 set, c->call called on c->argument where it is
// not NULL, and the sixteen registers stored to avx2_registers. VPCMPEQD of
// a register with itself sets every bit. Before the call the block lowers
// the stack pointer past the 128 bytes below it that this function may
// use, to a multiple of 32 bytes, and then by shift more, and after the
// call it restores it. It reads the six arguments, the kernel's address
// and shift from block, 8 bytes each in that order, and loads the
// arguments into rdi, rsi, rdx, rcx, r8 and r9 itself. It names as changed
// the sixteen registers and every general register the System V ABI lets
// a call change, so the compiler keeps block, the stores' address and the
// saved stack pointer in registers a call saves.
__attribute__((target("avx2"), noinline)) static void avx2_set_call_store(const avx2_call *c,
                                                                          size_t shift) {
    uintptr_t block[8];
    for (size_t i = 0; i < 6; i++) {
        block[i] = c->argument[i];
    }
    block[6] = (uintptr_t)c->call;
    block[7] = shift;
    uintptr_t stack_pointer;
    __asm__ volatile("vpcmpeqd %%ymm0, %%ymm0, %%ymm0\n\t"
                     "vpcmpeqd %%ymm1, %%ymm1, %%ymm1\n\t"
                     "vpcmpeqd %%ymm2, %%ymm2, %%ymm2\n\t"
                     "vpcmpeqd %%ymm3, %%ymm3, %%ymm3\n\t"
                     "vpcmpeqd %%ymm4, %%ymm4, %%ymm4\n\t"
                     "vpcmpeqd %%ymm5, %%ymm5, %%ymm5\n\t"
                     "vpcmpeqd %%ymm6, %%ymm6, %%ymm6\n\t"
                     "vpcmpeqd %%ymm7, %%ymm7, %%ymm7\n\t"
                     "vpcmpeqd %%ymm8, %%ymm8, %%ymm8\n\t"
                     "vpcmpeqd %%ymm9, %%ymm9, %%ymm9\n\t"
                     "vpcmpeqd %%ymm10, %%ymm10, %%ymm10\n\t"
                     "vpcmpeqd %%ymm11, %%ymm11, %%ymm11\n\t"
                     "vpcmpeqd %%ymm12, %%ymm12, %%ymm12\n\t"
                     "vpcmpeqd %%ymm13, %%ymm13, %%ymm13\n\t"
                     "vpcmpeqd %%ymm14, %%ymm14, %%ymm14\n\t"
                     "vpcmpeqd %%ymm15, %%ymm15, %%ymm15\n\t"
                     "cmpq $0, 48(%[block])\n\t"
                     "je 1f\n\t"
                     "movq %%rsp, %[stack_pointer]\n\t"
                     "subq $128, %%rsp\n\t"
                     "andq $-32, %%rsp\n\t"
                     "subq 56(%[block]), %%rsp\n\t"
                     "movq 0(%[block]), %%rdi\n\t"
                     "movq 8(%[block]), %%rsi\n\t"
                     "movq 16(%[block]), %%rdx\n\t"
                     "movq 24(%[block]), %%rcx\n\t"
                     "movq 32(%[block]), %%r8\n\t"
                     "movq 40(%[block]), %%r9\n\t"
                     "call *48(%[block])\n\t"
                     "movq %[stack_pointer], %%rsp\n\t"
                     "1:\n\t"
                     "vmovdqu %%ymm0, 0(%[out])\n\t"
                     "vmovdqu %%ymm1, 32(%[out])\n\t"
                     "vmovdqu %%ymm2, 64(%[out])\n\t"
                     "vmovdqu %%ymm3, 96(%[out])\n\t"
                     "vmovdqu %%ymm4, 128(%[out])\n\t"
                     "vmovdqu %%ymm5, 160(%[out])\n\t"
                     "vmovdqu %%ymm6, 192(%[out])\n\t"
                     "vmovdqu %%ymm7, 224(%[out])\n\t"
                     "vmovdqu %%ymm8, 256(%[out])\n\t"
                     "vmovdqu %%ymm9, 288(%[out])\n\t"
                     "vmovdqu %%ymm10, 320(%[out])\n\t"
                     "vmovdqu %%ymm11, 352(%[out])\n\t"
                     "vmovdqu %%ymm12, 384(%[out])\n\t"
                     "vmovdqu %%ymm13, 416(%[out])\n\t"
                     "vmovdqu %%ymm14, 448(%[out])\n\t"
                     "vmovdqu %%ymm15, 480(%[out])\n\t"
                     : [stack_pointer] "=&r"(stack_pointer)
                     : [block] "r"(block), [out] "r"(avx2_registers)
                     : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8",
                       "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "rax", "rcx",
                       "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "cc", "memory");
    // The block wrote stack_pointer, and nothing reads it after the block.
    (void)stack_pointer;
}

// Whether every stored word of the sixteen registers is value. Where one
// is not, *at takes its place: the register times AVX2_REGISTER_WORDS plus
// the word.
static int avx2_registers_hold(uint64_t value, size_t *at) {
    for (size_t i = 0; i < AVX2_REGISTERS; i++) {
        for (size_t j = 0; j < AVX2_REGISTER_WORDS; j++) {
            if (avx2_registers[i][j] != value) {
                *at = i * AVX2_REGISTER_WORDS + j;
                return 0;
            }
        }
    }
    return 1;
}

// The stored word at, as avx2_registers_hold names it.
static uint64_t avx2_register_word(size_t at) {
    return avx2_registers[at / AVX2_REGISTER_WORDS][at % AVX2_REGISTER_WORDS];
}

#endif
