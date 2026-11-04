// A host object's AVX-512 IFMA Poly1305 kernel on x86-64: the block loop of
// RFC 8439 §2.5 sixteen blocks at a time, in eight 64-bit lanes of 512-bit
// vectors, each lane holding a number as three digits of 44, 44 and 42 bits,
// the radix of OpenSSL's poly1305_blocks_vpmadd52. Every x86-64 host object
// carries it beside poly1305_avx2.c's kernel, in poly1305.c's native copy
// alone. poly1305.c's poly1305_update_ifma hands it the whole groups of a
// long update, and widemul.h's widemul_poly1305_update_cpu calls that entry
// for a session whose ch_cfg.cpu holds CH_CPU_AVX512_IFMA under the answer
// WIDEMUL_CONSTANT_TIME. poly1305.c's loop stays the reference:
// bin/poly1305_equiv_test compares the kernel with it over the same inputs
// on a CPU that has AVX-512 IFMA.
//
// Each product is AVX-512 IFMA's 52x52->104 multiply in each lane:
// VPMADD52LUQ adds bits 51..0 of the product to a 64-bit lane, and
// VPMADD52HUQ adds bits 103..52. The caller's
// CH_CPU_CONSTANT_TIME_MULTIPLY covers both, as it covers VPMULUDQ: the
// bit states that every widening multiply the session runs, scalar or
// vector, IFMA's 52-bit products among them, takes a time that does not
// depend on its operands. CH_CPU_AVX512_IFMA states no timing: it says the
// CPU has the instructions. Beside the multiplies the kernel runs adds,
// masks, fixed shifts and lane moves on every lane, with no table, no
// branch on the key or the message, and no address computed from either.
// Only the byte count decides how many groups run, and it is public. The
// powers of r and the accumulator pass through 512-bit registers, which no
// C statement can name, so the kernel calls avx512_wipe_registers before it
// returns (avx512_wipe.h, docs/decisions.md 121).
//
// Every function in poly1305_ifma.c carries the target attribute that
// turns AVX-512F and AVX-512 IFMA on for that function alone, as
// poly1305_avx2.c's carry AVX2, so the object needs no compiler flag and
// the rest of it runs on any x86-64 CPU. chapulin probes no CPU: the
// caller's bits decide whether the kernel runs.
#ifndef CH_POLY1305_IFMA_H
#define CH_POLY1305_IFMA_H

#include <stddef.h>
#include <stdint.h>

#include "poly1305.h"
#include "poly1305_vector.h"

// The kernel's two conditions, poly1305_vector.h's path and an x86-64
// target, the AVX2 kernel's too, meet here, and poly1305.c and
// poly1305_ifma.c read this one macro. A test unit that defines
// CH_POLY1305_IFMA_MODEL defines it too, on any host: poly1305_ifma.c then
// compiles over test/poly1305_ifma_model_lanes.h, a model of each
// instruction in portable C. No library build names that define, which
// test/widemul-builds.sh checks.
#if (defined(CH_POLY1305_VECTOR) && defined(__x86_64__)) || defined(CH_POLY1305_IFMA_MODEL)
#define CH_POLY1305_IFMA 1
#endif

// Everything below up to its #endif exists only in a build that defines
// CH_POLY1305_IFMA.
#ifdef CH_POLY1305_IFMA

// The bytes of one group, sixteen blocks. poly1305_update_ifma hands the
// kernel the whole groups of an update that holds at least
// POLY1305_IFMA_MIN bytes of whole blocks: below that the powers of r cost
// more time than the lanes save, and poly1305_vector.c's path takes the
// update.
#define POLY1305_IFMA_GROUP ((size_t)256)
#define POLY1305_IFMA_MIN ((size_t)512)

// poly1305_vector_blocks's contract for groups of sixteen blocks: absorbs
// the n bytes at m, n / 16 whole blocks, each with its 2^128 bit, into
// p->h, as poly1305.c's loop does. n is a positive multiple of
// POLY1305_IFMA_GROUP. On return p->h holds the value, modulo 2^130 - 5,
// that poly1305.c's loop leaves for the same blocks, with h0, h2, h3 and
// h4 below 2^26 and h1 at most 2^26, inside the bounds that loop keeps.
// It reads p->r and writes nothing but p->h, and it wipes the powers of r
// it computed before it returns.
//
// Requires: a CPU with AVX-512F and AVX-512 IFMA whose operating system
// saves the 512-bit and mask registers. On a CPU without them the first
// instruction faults.
void poly1305_ifma_blocks(poly1305 *p, const uint8_t *m, size_t n);

#endif // CH_POLY1305_IFMA

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
// The name an x86-64 host object defines poly1305_ifma_blocks under
// (poly1305_ifma_native.c, widemul_native.h), which poly1305_native.c's
// poly1305_update_ifma_native alone calls.
void poly1305_ifma_blocks_native(poly1305 *p, const uint8_t *m, size_t n);
#endif

#endif
