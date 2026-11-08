// A host object's two-way Keccak on arm64: Keccak-f[1600] on two states at once in 128-bit NEON
// vectors, lane i of both states in vector i, and the start of the two SHAKE128 streams that
// two entries of ML-KEM's and ML-DSA-87's matrices come from. Every arm64 host object that
// holds either algorithm carries it beside sha3.c, as an x86-64 one carries keccak_avx2.c
// (docs/decisions.md 107, 178 and 198). sha3.c stays the reference: bin/keccak_neon_equiv_test
// holds the two streams to it.
//
// It takes public input alone. Each matrix comes from the seed rho, which the encapsulation key
// or the ML-DSA-87 public key carries in the clear, and from two indices, so no state here
// holds a secret. The 25 lanes of a state and the values a round computes from them fill
// arm64's 32 vector registers, and a compiler may keep some in stack slots of its own, which
// no wipe written in C clears (docs/decisions.md 99). ML-KEM's noise and its hashes, and
// ML-DSA-87's, which read secrets, stay on sha3.c and sha3_hw.c.
//
// The file holds two forms of the permutation:
//
//   - keccak_neon_permute: plain NEON, which every arm64 CPU has, so it runs in every session
//     of an arm64 host object, under any compiler.
//   - keccak_neon_permute_sha3: the same round on FEAT_SHA3's EOR3, RAX1, XAR and BCAX, where
//     clang compiled the object (CH_KECCAK_INSTRUCTIONS, cpu_cfg.h), for a session whose
//     ch_cfg.cpu holds CH_CPU_CONSTANT_TIME_SHA3. The input is public, so the bit is used here
//     only as the statement that the CPU has the instructions.
//
// keccak_neon_runs_sha3 is the one test that picks between them, and keccak_neon_permute_cpu
// below the one branch on it. chapulin probes no CPU: the caller's bit decides.
#ifndef CH_KECCAK_NEON_H
#define CH_KECCAK_NEON_H

#include <stdint.h>

#include "sha3.h"

#if defined(CH_CPU_RUNTIME) && defined(__aarch64__)

#include "cpu_cfg.h"

// Two Keccak-f[1600] states: lane i of state k is lane[i][k], so the two lanes i sit in one
// 16-byte vector.
typedef struct {
    _Alignas(16) uint64_t lane[25][2];
} keccak_x2;

// The two forms of Keccak-f[1600] on both states, after which each holds the next
// SHAKE128_RATE bytes of its stream. The first runs on any arm64 CPU. The second exists only
// where CH_KECCAK_INSTRUCTIONS is defined, and requires a CPU with FEAT_SHA3: on a CPU without
// it the first instruction faults.
void keccak_neon_permute(keccak_x2 *s);
#ifdef CH_KECCAK_INSTRUCTIONS
void keccak_neon_permute_sha3(keccak_x2 *s);
#endif

// Whether a session of this value runs the permutation on the SHA-3 instructions: where clang
// compiled the object and the value holds CH_CPU_CONSTANT_TIME_SHA3, as sha3.h's
// sha3_on_instructions decides for sha3_hw.c.
static inline int keccak_neon_runs_sha3(uint32_t cpu) {
#ifdef CH_KECCAK_INSTRUCTIONS
    return (cpu & CH_CPU_CONSTANT_TIME_SHA3) != 0;
#else
    (void)cpu;
    return 0;
#endif
}

// Keccak-f[1600] on both states, in the form keccak_neon_runs_sha3 picks for cpu, the
// session's ch_cfg.cpu: one branch and no function pointer, as sha3.h's entries do.
static inline void keccak_neon_permute_cpu(keccak_x2 *s, uint32_t cpu) {
#ifdef CH_KECCAK_INSTRUCTIONS
    if (keccak_neon_runs_sha3(cpu)) {
        keccak_neon_permute_sha3(s);
        return;
    }
#else
    (void)cpu;
#endif
    keccak_neon_permute(s);
}

// Writes into state k the one block of a SHAKE128 stream (FIPS 202 §6.2) whose input is the
// 34 bytes seed || x0[k] || x1[k], with its padding: the state before the stream's first
// permutation. The seed and the indices are public.
void keccak_neon_shake128_absorb(keccak_x2 *s, const uint8_t seed[32], const uint8_t x0[2],
                                 const uint8_t x1[2]);

// Starts the two streams: keccak_neon_shake128_absorb, then the first permutation in the form
// cpu picks, so state k holds the first SHAKE128_RATE bytes of its stream
// (keccak_neon_block).
static inline void keccak_neon_shake128_start(keccak_x2 *s, const uint8_t seed[32],
                                              const uint8_t x0[2], const uint8_t x1[2],
                                              uint32_t cpu) {
    keccak_neon_shake128_absorb(s, seed, x0, x1);
    keccak_neon_permute_cpu(s, cpu);
}

// The SHAKE128_RATE bytes state k holds, lanes 0 to 20, each lane's least significant byte
// first (FIPS 202 §3.1.2), as sha3.c squeezes them, for k 0 or 1.
void keccak_neon_block(uint8_t out[SHAKE128_RATE], const keccak_x2 *s, unsigned k);

#endif // CH_CPU_RUNTIME && __aarch64__

#endif
