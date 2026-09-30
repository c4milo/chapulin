// Copies n bytes from below to copy and writes zero over each after the
// copy, one byte at a time through a volatile pointer.
// test/ghash_equiv_residue.h hands it a local array that its caller never
// wrote, so the bytes are whatever an earlier call left on the stack
// there. It is a source of its own so that the compiler that builds the
// caller cannot see the read, and does not refuse the unwritten array as
// a value used before it is set.
#include <stddef.h>
#include <stdint.h>

void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);

void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy) {
    for (size_t i = 0; i < n; i++) {
        copy[i] = below[i];
        below[i] = 0;
    }
}
