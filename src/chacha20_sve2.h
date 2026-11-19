// chacha20_vector.c's ChaCha20 on SVE2 for an arm64 host object: the same nine blocks a pass, with
// each quarter round's four XOR-and-rotate steps on SVE2's XAR, one instruction where NEON takes
// two or three (chacha20_vector.c). chacha20.c's chacha20_xor_cpu runs it for a session whose
// ch_cfg.cpu holds CH_CPU_SVE2, which the caller sets from its own probe of the CPU. On a
// Neoverse N2 it took about 30% less time than the NEON path over 16 KiB (docs/decisions.md 242).
//
// chacha20_sve2.c is chacha20_vector.c compiled once more, under the name chacha20_sve2_xor, with
// SVE2 turned on for its own functions alone. So the object needs no compiler flag, and the rest
// of it runs on any arm64 CPU. The copy is the vector path's own text: only the four steps
// differ, and bin/chacha20_equiv_test compares the copy with chacha20.c's loop on a CPU with SVE2.
//
// It is constant time by the construction chacha20_vector.c keeps. XAR is a XOR and a rotation by
// a constant, on every lane, as the NEON steps it replaces are.
#ifndef CH_CHACHA20_SVE2_H
#define CH_CHACHA20_SVE2_H

#include <stddef.h>
#include <stdint.h>

#include "chacha20.h"

// Whether the object holds the copy: an arm64 host object that clang or gcc 14 and later builds.
// Those compilers ship <arm_neon_sve_bridge.h>, the header whose calls move a NEON vector into an
// SVE vector and back, and gcc 13 does not. In an object gcc 13 built, CH_CPU_SVE2 describes the
// CPU and picks nothing. The test names the compilers, and not the header through
// __has_include, because Semgrep parses no __has_include in an #if (tools/semgrep-parse.py).
#if defined(CH_CPU_RUNTIME) && defined(__aarch64__) &&                                             \
    (defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 14))
#define CH_CHACHA20_SVE2
#endif

#ifdef CH_CHACHA20_SVE2

// chacha20_vector_xor's contract (chacha20_vector.h).
//
// Requires: a CPU with SVE2. chacha20_xor_cpu decides that from the session's CH_CPU_SVE2 bit; on
// a CPU without SVE2 the first XAR faults.
void chacha20_sve2_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                       uint32_t counter, const uint8_t *in, uint8_t *out, size_t n);

#endif // CH_CHACHA20_SVE2

#endif
