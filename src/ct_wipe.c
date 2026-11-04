// ct_wipe, which ct.h declares. It sits in a file of its own so that the
// proofs can link proof/ct_wipe_stub.c in its place (docs/decisions.md 91
// and 144).
#include "ct.h"

// Every store in this file goes through a volatile lvalue. A store to a
// volatile object is a side effect the compiler must perform as the
// abstract machine does (C11 5.1.2.3p2 and p6). So it cannot delete a
// store, merge two stores into one, or omit a store that no later read
// needs. That holds where it inlines ct_wipe into a caller whose buffer
// ends right after the call, as link-time optimization does. The compiler
// also cannot replace a loop with a call to memset, because memset's
// stores are not volatile. docs/decisions.md 144 lists the compilers and
// targets whose output was read.
//
// The address and the length are public, so the branches read nothing
// secret. When n is 0 no loop runs and no pointer arithmetic happens, so
// a caller with nothing to wipe may pass a null p.

#if defined(__GNUC__) || defined(__clang__)

// ct_wipe writes zero one word at a time where it can, and one byte at a
// time before the first aligned address and after the last whole word.
// The word is 16 bytes where the compiler has unsigned __int128, which
// gcc and clang have on every 64-bit target: arm64 then stores a word
// with one stp of two zero registers. It is 4 bytes on the 32-bit targets
// this tree builds for, the width of a general register.
#ifdef __SIZEOF_INT128__
// C11 has no 128-bit integer, and __extension__ keeps -Wpedantic from
// saying so.
__extension__ typedef unsigned __int128 ct_wipe_word_value;
#else
typedef uint32_t ct_wipe_word_value;
#endif

// The bytes ct_wipe writes belong to objects of every type: an array of
// bytes, a struct, an array of uint32_t. A store through an integer lvalue
// wider than a byte into an object of another type breaks the
// effective-type rule (C11 6.5p7). Under link-time optimization the
// compiler could then move a later store of the caller's own type ahead
// of the wipe. gcc and clang give the may_alias attribute the rule of a
// character type: a store through it may write an object of any type.
typedef ct_wipe_word_value __attribute__((may_alias)) ct_wipe_word;

void ct_wipe(void *p, size_t n) {
    volatile unsigned char *byte = (volatile unsigned char *)p;
    // head counts the bytes before the first address that the size of a
    // word divides. The conversion to uintptr_t gives the address on every
    // target this tree builds for (C11 6.3.2.3p6 leaves the mapping to the
    // implementation).
    size_t head = (size_t)((0U - (uintptr_t)p) % sizeof(ct_wipe_word));
    if (head > n) {
        head = n;
    }
    size_t word_count = (n - head) / sizeof(ct_wipe_word);
    size_t tail = head + word_count * sizeof(ct_wipe_word);
    for (size_t i = 0; i < head; i++) {
        byte[i] = 0;
    }
    // byte + head is a multiple of sizeof(ct_wipe_word), and the size of a
    // type is a multiple of its alignment, so the conversion gives a
    // correctly aligned pointer (C11 6.3.2.3p7).
    for (size_t i = 0; i < word_count; i++) {
        ((volatile ct_wipe_word *)(byte + head))[i] = 0;
    }
    for (size_t i = tail; i < n; i++) {
        byte[i] = 0;
    }
}

#else

// A compiler without the may_alias attribute gets one store per byte,
// through unsigned char, which C11 6.5p7 allows for an object of every
// type.
void ct_wipe(void *p, size_t n) {
    volatile unsigned char *byte = (volatile unsigned char *)p;
    for (size_t i = 0; i < n; i++) {
        byte[i] = 0;
    }
}

#endif
