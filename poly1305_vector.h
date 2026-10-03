// CHACHA=vector with WIDEMUL=native, and the native copy of a host
// object: Poly1305's block loop (RFC 8439 §2.5) four
// blocks at a time, in two lanes of five 26-bit limbs, NEON on
// arm64 and SSE2 on x86-64. poly1305.c chooses between this path and its
// own loop in one place, and stays the reference: it absorbs every block
// this path does not, and it keeps the final reduction and the tag.
// bin/poly1305_equiv_test compares the two over the same inputs.
//
// Each product is a 32x32->64 widening multiply in each lane, NEON's
// UMULL and UMLAL or SSE2's PMULUDQ, so the path runs only where the
// build states that every widening multiply the object runs, scalar or
// vector, takes a time that does not depend on its operands. That is
// CH_NATIVE_WIDEMUL, which WIDEMUL=native puts in a device object (ct.h),
// or in a host object the caller's CH_CPU_CONSTANT_TIME_MULTIPLY bit,
// which runs the native copies alone (widemul.h). CH_CT_WIDEMUL, which
// forces the 16x16 decomposition, turns the path off.
// Under CHACHA=vector without the statement, poly1305.c's loop and its
// decomposition run. Beside the multiplies the path runs adds, masks,
// fixed shifts and lane moves on every lane, with no table, no branch on
// the key or the message, and no address computed from either. Only the
// byte count decides how many groups run, and it is public.
// docs/decisions.md 83 says why.
#ifndef CH_POLY1305_VECTOR_H
#define CH_POLY1305_VECTOR_H

#include <stddef.h>
#include <stdint.h>

#include "ct.h"
#include "poly1305.h"

// ct.h defines CH_WIDEMUL_NATIVE when the build asserts CH_NATIVE_WIDEMUL
// and does not force the decomposition, so the path's two conditions meet
// here, and poly1305.c and poly1305_vector.c read this one macro.
#if defined(CH_CHACHA_VECTOR) && defined(CH_WIDEMUL_NATIVE)
#define CH_POLY1305_VECTOR 1
#endif

// Everything below exists only in a build that defines CH_POLY1305_VECTOR.
#ifdef CH_POLY1305_VECTOR

// chacha20_vector.h's two rules hold for this path too: the compiler
// targets NEON or SSE2, and the target is little-endian, so each 64-bit
// lane a block loads into holds its bytes in the order RFC 8439 §2.5.1
// reads them. The path exists only under CH_CHACHA_VECTOR, and this
// include applies the rules to a file that includes this header alone.
#include "chacha20_vector.h"

// The bytes of one group, four blocks. poly1305_update hands the path the
// whole groups of an update that holds at least POLY1305_VECTOR_MIN bytes
// of whole blocks: below that the powers of r cost more time than the
// lanes save (docs/decisions.md 83).
#define POLY1305_VECTOR_GROUP ((size_t)64)
#define POLY1305_VECTOR_MIN ((size_t)128)

// Absorbs the n bytes at m, n / 16 whole blocks, each with its 2^128 bit,
// into p->h, as poly1305.c's loop does. n is a positive multiple of
// POLY1305_VECTOR_GROUP. On return p->h holds the value, modulo
// 2^130 - 5, that poly1305.c's loop leaves for the same blocks, with h0,
// h2, h3 and h4 below 2^26 and h1 at most 2^26, inside the bounds that
// loop keeps. It reads p->r and writes nothing but p->h, and it wipes the
// powers of r it computed before it returns.
void poly1305_vector_blocks(poly1305 *p, const uint8_t *m, size_t n);

#endif // CH_POLY1305_VECTOR

#if defined(CH_CHACHA_VECTOR) && defined(CH_CPU_RUNTIME)
// The name a host object defines poly1305_vector_blocks under
// (poly1305_vector_native.c, widemul_native.h), which poly1305_native.c's
// block loop alone calls.
void poly1305_vector_blocks_native(poly1305 *p, const uint8_t *m, size_t n);
#endif

#endif
