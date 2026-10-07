// A host object's four-way Keccak on x86-64: Keccak-f[1600] on four states
// at once in 256-bit vectors, lane i of every state in vector i, and the
// start of the four SHAKE128 streams ML-KEM's matrix entries come from.
// Every x86-64 host object carries it beside sha3.c, and mlkem_avx2.c
// samples each row of the matrix on it, for a session whose ch_cfg.cpu
// holds CH_CPU_AVX2 (mlkem.h). sha3.c stays the reference:
// bin/mlkem_avx2_equiv_test holds the four streams to it on a CPU that has
// AVX2.
//
// It takes public input alone. The matrix comes from the seed rho, which
// the encapsulation key carries in the clear, and from two indices, so no
// state here holds a secret. That is the condition this file needs: the
// 25 lanes of a state and the values a round computes from them do not
// fit in AVX2's 16 vector registers, so the compilers keep some in stack
// slots of their own, which no wipe written in C clears (docs/decisions.md
// 99 and 107). ML-KEM's noise and its hashes, which read secrets, stay on
// sha3.c.
//
// Every function in keccak_avx2.c that computes on vectors carries the
// target attribute that turns AVX2 on, as chacha20_avx2.c's do, so the
// object needs no compiler flag and the rest of it runs on any x86-64 CPU.
// chapulin probes no CPU: the caller's bit decides whether this runs.
#ifndef CH_KECCAK_AVX2_H
#define CH_KECCAK_AVX2_H

#include <stdint.h>

#include "sha3.h"

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

// Four Keccak-f[1600] states: lane i of state k is lane[i][k], so the four
// lanes i sit in one 32-byte vector.
typedef struct {
    _Alignas(32) uint64_t lane[25][4];
} keccak_x4;

// Starts four SHAKE128 streams (FIPS 202 §6.2): state k absorbs the 34
// bytes seed || x0[k] || x1[k], which one block holds with its padding, and
// the permutation runs, so state k holds the first SHAKE128_RATE bytes of
// its stream (keccak_avx2_block). The seed and the indices are public.
//
// Requires: a CPU with AVX2. mlkem.h's entries decide that from the
// session's CH_CPU_AVX2 bit; on a CPU without AVX2 the first instruction
// faults.
void keccak_avx2_shake128_start(keccak_x4 *s, const uint8_t seed[32], const uint8_t x0[4],
                                const uint8_t x1[4]);

// Keccak-f[1600] on all four states, after which each holds the next
// SHAKE128_RATE bytes of its stream. Requires a CPU with AVX2, as above.
void keccak_avx2_permute(keccak_x4 *s);

// The SHAKE128_RATE bytes state k holds, lanes 0 to 20, each lane's least
// significant byte first (FIPS 202 §3.1.2), as sha3.c squeezes them. It
// runs no vector instruction, for k from 0 to 3.
void keccak_avx2_block(uint8_t out[SHAKE128_RATE], const keccak_x4 *s, unsigned k);

#endif // CH_CPU_RUNTIME && __x86_64__

#endif
