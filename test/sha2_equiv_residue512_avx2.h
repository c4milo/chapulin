// What sha512_hw.c's calls leave on the stack and in the vector registers
// on x86-64, where the file is sha512.c's first arm compiled once more over
// sha512_avx2.c's kernel (docs/decisions.md 128). The kernel leaves the
// last sixteen schedule words plus their constants in its frame, and
// whichever registers its compiler wrote to stack slots of its own, so the
// copy wipes SHA512_AVX2_BELOW_LEN bytes of the stack below each call of
// it, and the kernel writes zero to ymm0 to ymm15 before it returns. Four
// checks, on test/sha2_equiv_residue512_first_arm.h's copy of the stack:
//
//   run_residue512_avx2_registers sets every bit of ymm0 to ymm15, calls
//   sha512_avx2_compress_blocks and stores the sixteen registers, in
//   test/avx2_registers.h's one block of assembly, so no instruction the
//   compiler picks runs between the three. Every stored word must be
//   zero. The same block with the call left out runs first, and its
//   stores must hold every bit set, so a zero after the call is the
//   call's.
//
//   run_residue512_avx2_depth calls the kernel by its own name, with no
//   wipe after it. It requires the lowest byte the call wrote, and 16 bytes
//   more, within SHA512_AVX2_BELOW_LEN of its caller: the function aligns
//   its frame to 32 bytes, so a caller 16 bytes lower in the stack may
//   find it 16 bytes deeper. It requires the search to find a word there,
//   so a search that could find nothing fails.
//
//   run_residue512_avx2_sums calls the kernel through the block of
//   assembly, with the stack pointer at a multiple of 32 bytes and then 16
//   bytes past one, and finds in the copy the sixteen sums the last block
//   left, four to a 256-bit store. Each four must lie at a multiple of 32
//   bytes, so no store of them lies across a cache line or a page boundary
//   wherever the caller's stack is (docs/invariants.md INV-49).
//
//   run_residue512_wiped_shape makes the six kinds of call
//   test/sha2_equiv_residue512.h lists under the _hw names, and requires no
//   word of the set in the copy, at any byte offset.
//
// The three searches hold a claim about optimized code alone
// (test/stack_residue.c). The registers are read in every build but the
// sanitizer lane's. There AddressSanitizer adds code of its own to the
// kernel's return, after VZEROALL, and gcc 13.3's writes the marker of a
// returned frame, 0xf5 in every byte, through ymm0. So that binary reads
// the sanitizer's marker, which says nothing of the object a caller links.
//
// Included by test/sha2_equiv_residue512.h only, on x86-64.
#ifndef CH_SHA2_EQUIV_RESIDUE512_AVX2_H
#define CH_SHA2_EQUIV_RESIDUE512_AVX2_H

#include "avx2_registers.h"
#include "sha512_avx2.h"

// sha512_avx2_compress_blocks on state, p and blocks through
// test/avx2_registers.h's block of assembly, called with the stack
// pointer shift bytes below a multiple of 32, or the block with no call
// where call is NULL.
static void residue512_set_call_store(void (*call)(uint64_t *, const uint8_t *, size_t),
                                      uint64_t *state, const uint8_t *p, size_t blocks,
                                      size_t shift) {
    const avx2_call c = {
        (avx2_function)call, {(uintptr_t)state, (uintptr_t)p, blocks, 0, 0, 0}
    };
    avx2_set_call_store(&c, shift);
}

static void run_residue512_avx2_registers(void) {
    size_t at = 0;
    rng_fill(residue512_data, sizeof residue512_data);
    sha512_init(&residue512_state);
    residue512_set_call_store(NULL, residue512_state.h, residue512_data, 2, 0);
    compared++;
    if (!avx2_registers_hold(UINT64_MAX, &at)) {
        failures++;
        (void)fprintf(stderr,
                      "sha2 equivalence: registers: the block of assembly left ymm%zu word %zu "
                      "unset, so it tests nothing\n",
                      at / AVX2_REGISTER_WORDS, at % AVX2_REGISTER_WORDS);
        return;
    }
#ifdef TEST_ADDRESS_SANITIZER
    (void)printf("SKIP sha2 equivalence, the registers after sha512_avx2.c's kernel: this binary "
                 "runs under AddressSanitizer, whose code at the kernel's return writes a vector "
                 "register after VZEROALL\n");
    return;
#endif
    residue512_set_call_store(sha512_avx2_compress_blocks, residue512_state.h, residue512_data, 2,
                              0);
    compared++;
    if (!avx2_registers_hold(0, &at)) {
        failures++;
        (void)fprintf(stderr,
                      "sha2 equivalence: registers: ymm%zu word %zu holds 0x%016llx after "
                      "sha512_avx2_compress_blocks\n",
                      at / AVX2_REGISTER_WORDS, at % AVX2_REGISTER_WORDS,
                      (unsigned long long)avx2_register_word(at));
    }
}

// Two whole blocks through sha512_avx2_compress_blocks itself, from
// SHA-512's initial value, with no wipe after the call.
static __attribute__((noinline)) void residue512_call_avx2_kernel(void) {
    sha512_init(&residue512_state);
    sha512_avx2_compress_blocks(residue512_state.h, residue512_data, 2);
}

// How much deeper a caller at another stack address may find the kernel's
// frame: the function aligns it to 32 bytes, and a stack pointer is a
// multiple of 16.
#define AVX2_FRAME_ALIGN_SLACK 16

static void run_residue512_avx2_depth(void) {
    static const residue512_shape shape = {"sha512_avx2_compress_blocks over two blocks",
                                           residue512_call_avx2_kernel, RESIDUE512_WHOLE_LEN, 0, 0};
    if (!residue512_painted_call(&shape, &PATH512_INSTRUCTIONS)) {
        return;
    }
    size_t depth = residue512_depth();
    size_t first_at = 0;
    size_t found = residue512_found(&first_at);
    (void)printf("sha2 equivalence: sha512_avx2_compress_blocks writes %zu bytes below its caller "
                 "and leaves %zu words it computed there\n",
                 depth, found);
    if (depth == 0 || depth + AVX2_FRAME_ALIGN_SLACK > SHA512_AVX2_BELOW_LEN) {
        failures++;
        (void)fprintf(stderr,
                      "sha2 equivalence: residue: sha512_avx2_compress_blocks writes %zu bytes "
                      "below its caller, and %d more for a caller at another stack address, and "
                      "sha512_hw.c wipes %d\n",
                      depth, AVX2_FRAME_ALIGN_SLACK, SHA512_AVX2_BELOW_LEN);
    }
    if (found == 0) {
        failures++;
        (void)fprintf(stderr, "sha2 equivalence: residue: the search finds no word of the message "
                              "schedule after a call of sha512_avx2_compress_blocks with no wipe, "
                              "so it would find none after a call with one\n");
    }
}

// The sixteen sums the kernel's frame holds after the block at p: schedule
// words 64 to 79 (FIPS 180-4 §6.4.2 step 1), each plus its round constant.
static void residue512_last_sums(const uint8_t *p, uint64_t sums[16]) {
    uint64_t w[80];
    for (size_t i = 0; i < 16; i++) {
        uint64_t word = 0;
        for (size_t j = 0; j < 8; j++) {
            word = (word << 8) | p[8 * i + j];
        }
        w[i] = word;
    }
    for (size_t i = 16; i < 80; i++) {
        uint64_t s0 = residue512_rotate_right(w[i - 15], 1) ^
                      residue512_rotate_right(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = residue512_rotate_right(w[i - 2], 19) ^
                      residue512_rotate_right(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    for (size_t i = 0; i < 16; i++) {
        sums[i] = w[64 + i] + residue512_constants[64 + i];
    }
}

// Where in the stack the copy holds the 32 bytes at four, or 0 where it
// does not hold them.
static uintptr_t residue512_address_of(const uint64_t four[4]) {
    for (size_t at = 0; at + 32 <= RESIDUE512_BYTES; at++) {
        if (memcmp(&residue512_copy[at], four, 32) == 0) {
            return residue512_copy_address + at;
        }
    }
    return 0;
}

// The kernel over two blocks, called with the stack pointer shift bytes
// below a multiple of 32, and then where its last sums lie.
static void run_residue512_avx2_sums(size_t shift) {
    uint64_t sums[16];
    rng_fill(residue512_data, sizeof residue512_data);
    sha512_init(&residue512_state);
    residue512_paint();
    residue512_set_call_store(sha512_avx2_compress_blocks, residue512_state.h, residue512_data, 2,
                              shift);
    residue512_snapshot();
    compared++;
    residue512_last_sums(residue512_data + SHA512_BLOCK, sums);
    for (size_t j = 0; j < 4; j++) {
        uintptr_t address = residue512_address_of(&sums[4 * j]);
        if (address == 0) {
            failures++;
            (void)fprintf(stderr,
                          "sha2 equivalence: residue: the copy of the stack does not hold sums "
                          "%zu to %zu of sha512_avx2_compress_blocks, so the check of where they "
                          "lie tests nothing\n",
                          4 * j, 4 * j + 3);
            return;
        }
        if (address % 32 != 0) {
            failures++;
            (void)fprintf(stderr,
                          "sha2 equivalence: residue: with the stack pointer %zu bytes below a "
                          "multiple of 32, sums %zu to %zu of sha512_avx2_compress_blocks lie %zu "
                          "bytes past a multiple of 32\n",
                          shift, 4 * j, 4 * j + 3, (size_t)(address % 32));
            return;
        }
    }
}

// The four checks. The registers are read in every build but the
// sanitizer lane's (run_residue512_avx2_registers), and the three that
// read the stack in a binary whose stack the search can read: an
// optimized build without AddressSanitizer (test/stack_residue.c).
static void run_residue512_avx2(void) {
    run_residue512_avx2_registers();
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        (void)printf("SKIP sha2 equivalence, the stack check of sha512_hw.c on AVX2: %s\n",
                     unsearched);
        return;
    }
    residue512_take_no_call();
    run_residue512_avx2_depth();
    run_residue512_avx2_sums(0);
    run_residue512_avx2_sums(16);
    for (size_t i = 0; i < RESIDUE512_SHAPES; i++) {
        run_residue512_wiped_shape(&residue512_shapes[i], &PATH512_INSTRUCTIONS);
    }
}

#endif
