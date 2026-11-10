// Proves: rsa_mont64_from_bytes and rsa_mont64_to_bytes, which move a word
// at a time (docs/decisions.md 209), write what a loop of one byte at a
// time writes, at every length from 0 to 24 bytes and for every byte, in
// three words. Byte i from the end has weight 2^(8i): it is in word i / 8,
// moved up 8 * (i % 8) bits. The words past the number are zero, and
// rsa_mont64_to_bytes gives the bytes back.
//
// Three words hold a length of no word, of one, two and three whole
// words, and every length between them, whose top word has fewer than
// eight bytes. A longer number repeats the whole-word move.
//
// Each length is a number in a loop, and not one unconstrained value: an
// unconstrained length makes each load of eight bytes a choice among every
// offset, and this harness then took 111 s where it takes 4 s. The bytes
// are unconstrained and are never written.
//
// What it does not prove: the memory accesses at the bound, which
// rsa_mont64_ops proves at every length the build admits.
#define RSA_MONT64_ADDCARRY 0
#include "harness.h"

#include "rsa_mont64.c"

#define BYTES_WORDS 3

int main(void) {
    uint8_t bytes[8 * BYTES_WORDS];
    uint8_t back[8 * BYTES_WORDS];
    uint64_t words[BYTES_WORDS];
    uint64_t want[BYTES_WORDS];
    fill_nondet(bytes, sizeof bytes);
    for (size_t len = 0; len <= 8 * BYTES_WORDS; len++) {
        for (size_t i = 0; i < BYTES_WORDS; i++) {
            want[i] = 0;
        }
        for (size_t i = 0; i < len; i++) {
            want[i >> 3] |= (uint64_t)bytes[len - 1 - i] << (8 * (i & 7));
        }
        rsa_mont64_from_bytes(words, BYTES_WORDS, bytes, len);
        for (size_t i = 0; i < BYTES_WORDS; i++) {
            __CPROVER_assert(words[i] == want[i],
                             "rsa_mont64_from_bytes writes the byte loop's words");
        }
        rsa_mont64_to_bytes(back, len, words);
        for (size_t i = 0; i < len; i++) {
            __CPROVER_assert(back[i] == bytes[i], "rsa_mont64_to_bytes gives the bytes back");
        }
    }
    return 0;
}
