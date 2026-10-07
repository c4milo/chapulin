// A host object's AVX2 Poly1305 kernel on x86-64: the block loop of RFC
// 8439 §2.5 eight blocks at a time, in four lanes of five 26-bit words in
// 256-bit vectors. It is poly1305_vector.c's SSE2 path with four lanes in
// place of two, and every x86-64 host object carries it beside that path,
// in poly1305.c's native copy alone. poly1305.c's poly1305_update_avx2
// hands it the whole groups of a long update, and widemul.h's
// widemul_poly1305_update_cpu calls that entry for a session whose
// ch_cfg.cpu holds CH_CPU_AVX2 under the answer WIDEMUL_CONSTANT_TIME.
// poly1305.c's loop stays the reference: bin/poly1305_equiv_test compares
// the kernel with it over the same inputs on a CPU that has AVX2.
//
// Each product is VPMULUDQ's 32x32->64 widening multiply in each lane.
// The caller's CH_CPU_CONSTANT_TIME_MULTIPLY covers it, as it covers
// SSE2's PMULUDQ (poly1305_vector.h): the bit states that every widening
// multiply the session runs, scalar or vector, takes a time that does not
// depend on its operands. CH_CPU_AVX2 states no timing: it says the CPU
// has the instructions. Beside the multiplies the kernel runs adds, masks,
// fixed shifts and lane moves on every lane, with no table, no branch on
// the key or the message, and no address computed from either. Only the
// byte count decides how many groups run, and it is public.
//
// Every function in poly1305_avx2.c carries the target attribute that
// turns AVX2 on for that function alone, as chacha20_avx2.c's do, so the
// object needs no compiler flag and the rest of it runs on any x86-64 CPU.
// chapulin probes no CPU: the caller's bits decide whether the kernel runs
// (docs/decisions.md 110).
#ifndef CH_POLY1305_AVX2_H
#define CH_POLY1305_AVX2_H

#include <stddef.h>
#include <stdint.h>

#include "poly1305.h"
#include "poly1305_vector.h"

// The kernel's two conditions, poly1305_vector.h's path and an x86-64
// target, meet here, and poly1305.c and poly1305_avx2.c read this one
// macro.
#if defined(CH_POLY1305_VECTOR) && defined(__x86_64__)
#define CH_POLY1305_AVX2 1
#endif

// Everything below up to its #endif exists only in a build that defines
// CH_POLY1305_AVX2.
#ifdef CH_POLY1305_AVX2

// The bytes of one group, eight blocks. poly1305_update_avx2 hands the
// kernel the whole groups of an update that holds at least
// POLY1305_AVX2_MIN bytes of whole blocks: below that the powers of r cost
// more time than the lanes save, and poly1305_vector.c's path takes the
// update (docs/decisions.md 110).
#define POLY1305_AVX2_GROUP ((size_t)128)
#define POLY1305_AVX2_MIN ((size_t)512)

// poly1305_vector_blocks's contract for groups of eight blocks: absorbs
// the n bytes at m, n / 16 whole blocks, each with its 2^128 bit, into
// p->h, as poly1305.c's loop does. n is a positive multiple of
// POLY1305_AVX2_GROUP. On return p->h holds the value, modulo 2^130 - 5,
// that poly1305.c's loop leaves for the same blocks, with h0, h2, h3 and
// h4 below 2^26 and h1 at most 2^26, inside the bounds that loop keeps.
// It reads p->r and writes nothing but p->h, and it wipes the powers of r
// it computed before it returns.
//
// Requires: a CPU with AVX2. On a CPU without it the first instruction
// faults.
void poly1305_avx2_blocks(poly1305 *p, const uint8_t *m, size_t n);

#endif // CH_POLY1305_AVX2

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
// The name an x86-64 host object defines poly1305_avx2_blocks under
// (poly1305_avx2_native.c, widemul_native.h), which poly1305_native.c's
// poly1305_update_avx2_native alone calls.
void poly1305_avx2_blocks_native(poly1305 *p, const uint8_t *m, size_t n);
#endif

#endif
