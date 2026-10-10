// The calls bin/widemul_runtime_test counts into each copy of the files
// built on ct.h's widening multiply in a host object (docs/decisions.md 87
// and 89). The test/widemul_count_*.c units compile the files built on
// the multiply again, the files under their own names, the native
// copies and the wide X25519 field, with each entry widemul.h dispatches to under a second name
// (test/widemul_count_names.h), and test/widemul_runtime_count.c defines
// the names the dispatchers call, each as a count and a call to the
// entry it renamed. So the library's sources run unchanged, and the test
// reads which copy each operation ran.
//
// The second names are this test's alone, as test/aes_runtime_count.h's
// are: the library object compiles the same files under its own names.
#ifndef CH_TEST_WIDEMUL_RUNTIME_COUNT_H
#define CH_TEST_WIDEMUL_RUNTIME_COUNT_H

#include <stdint.h>

#include "cpu_cfg.h"

// Calls into the dispatched entries of the files under their own names,
// which take the 16x16 decomposition.
extern unsigned long widemul_decomposed_calls;
// Calls into the dispatched entries of the native copies, of the wide
// X25519 field, which is X25519's copy on the native multiply, and of the
// 64-bit RSA signer, which is RSA signing's.
extern unsigned long widemul_native_calls;
// Calls into poly1305_vector_native.c's entry, and on x86-64 into
// poly1305_avx2_native.c's and poly1305_ifma_native.c's, which only
// poly1305_native.c's block loop makes.
extern unsigned long widemul_vector_calls;

// One end's calls into the dispatched entries of each copy, which the
// loop binaries count around that end's own calls.
typedef struct {
    unsigned long native;
    unsigned long decomposed;
} widemul_end_calls;

// Adds the calls counted since the counts were last zeroed to *end, and
// zeroes the counts.
static inline void widemul_take_calls(widemul_end_calls *end) {
    end->native += widemul_native_calls;
    end->decomposed += widemul_decomposed_calls;
    widemul_native_calls = 0;
    widemul_decomposed_calls = 0;
}

// Whether an end whose ch_cfg.cpu is cpu ran the copy that value names and
// never the other: the native copies with CH_CPU_CONSTANT_TIME_MULTIPLY,
// and the files under their own names without it.
static inline int widemul_ran_own_copy(const widemul_end_calls *end, uint32_t cpu) {
    if ((cpu & CH_CPU_CONSTANT_TIME_MULTIPLY) != 0) {
        return end->native > 0 && end->decomposed == 0;
    }
    return end->decomposed > 0 && end->native == 0;
}

// The two descriptions a row gives each end: base with the multiply bit,
// and base without it.
static inline uint32_t widemul_row_cpu(uint32_t base, int stated) {
    uint32_t clear = base & ~(uint32_t)CH_CPU_CONSTANT_TIME_MULTIPLY;
    return stated ? (clear | CH_CPU_CONSTANT_TIME_MULTIPLY) : clear;
}

#endif
