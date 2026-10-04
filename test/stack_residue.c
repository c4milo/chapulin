// Copies n bytes from below to copy and writes zero over each after the
// copy, one byte at a time through a volatile pointer.
// test/ghash_equiv_residue.h, test/poly1305_equiv_residue.h and
// test/p256_equiv_residue.h hand it a local array that their caller never
// wrote, so the bytes are whatever an earlier call left on the stack
// there. It is a source of its own so that the compiler that builds the
// caller cannot see the read, and does not refuse the unwritten array as a
// value used before it is set.
//
// stack_residue_fill writes value over n bytes at below the same way, for
// the caller that wants to know afterwards which of them a call wrote
// (test/p256_equiv_residue.h). It sits here for the same reason: a
// compiler that saw the writes into an array nothing reads would refuse
// the array as set and never used.
#include <stddef.h>
#include <stdint.h>

void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
void stack_residue_fill(volatile uint8_t *below, size_t n, uint8_t value);
const char *stack_residue_unsearched(void);

void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy) {
    for (size_t i = 0; i < n; i++) {
        copy[i] = below[i];
        below[i] = 0;
    }
}

void stack_residue_fill(volatile uint8_t *below, size_t n, uint8_t value) {
    for (size_t i = 0; i < n; i++) {
        below[i] = value;
    }
}

// Why a search of this binary's stack for what a call left would hold no
// claim about the code an object's caller runs, or NULL where it holds
// one. An unoptimized build gives every temporary a stack slot of its own,
// an instruction's operands among them, so no source could keep a value
// out of the stack there. AddressSanitizer lays a frame out its own way,
// and may keep a frame's variables off the stack the search reads. The
// sanitizer lane says it is one with -DTEST_ADDRESS_SANITIZER (Makefile,
// SAN_CFLAGS): gcc and clang name the sanitizer by different means, and
// the lane's own define reads the same under both. One command compiles
// every source of a test binary, so this file's answer is the binary's. A
// test whose search looks for any value a call computed asks, and skips
// the search where the answer is a reason (test/sha2_equiv_residue.h).
const char *stack_residue_unsearched(void) {
#ifndef __OPTIMIZE__
    return "this binary is not optimized, and an unoptimized build keeps every temporary in a "
           "stack slot";
#elif defined(TEST_ADDRESS_SANITIZER)
    return "this binary runs under AddressSanitizer, which lays each frame out its own way";
#else
    return NULL;
#endif
}
