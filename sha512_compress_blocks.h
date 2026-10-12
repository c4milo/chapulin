// The SHA-512 compression function (FIPS 180-4 §6.4.2) over whole blocks, in plain C: what a
// host object (-DCH_CPU_RUNTIME, cpu_cfg.h) compresses with in sha512_compress.c's place
// (docs/decisions.md 127). sha512.c's five calls that hash call it in a host object, for every
// session and for the calls that take no ch_cfg.cpu, so no bit picks it. A device object holds
// none of it: sha512_compress.c is what a device object runs, and it stays the reference that
// bin/sha2_equiv_test holds this file to.
//
// It is a source of its own so that its frame lies in the stack below its caller's frame, where
// the caller wipes it.
#ifndef CH_SHA512_COMPRESS_BLOCKS_H
#define CH_SHA512_COMPRESS_BLOCKS_H

#include <stddef.h>
#include <stdint.h>

#include "sha512.h"

#ifdef CH_CPU_RUNTIME

// The bytes of stack a caller wipes below its own frame after a call. The call leaves the
// sixteen words of its message schedule in its frame, and beside them whichever working
// variables its compiler wrote to stack slots of its own, which no ct_wipe can name.
// bin/sha2_equiv_test measures how far below its caller the call writes and requires that
// inside this length. For arm64 it measured 184 bytes under Apple clang 21, 224 under gcc 13.3,
// and 192 under clang 18 and clang 23. For x86-64 it measured 200 under gcc 13.3, and 264 under
// clang 18 and clang 23. lint-stack holds the function's frame under
// STACK_BUDGET_SHA512_COMPRESS_BLOCKS, which is below this length.
//
// The length is for an optimized object. At -O1, -Os, -O2 and -O3 gcc 13.3 and clang 18 report
// a frame of 144 to 224 bytes for the function on the two architectures. At -O0 they report
// 4,112 to 7,632 bytes, most of which the wipe then leaves, and bin/sha2_equiv_test makes no
// search of the stack in an unoptimized binary (INV-17).
#define SHA512_COMPRESS_BLOCKS_BELOW_LEN 512

// Absorbs blocks whole blocks at p into the eight-word state: the contract of that many calls
// of sha512_compress in turn (sha512_compress.h). Reads exactly blocks * SHA512_BLOCK bytes at
// p and writes exactly the eight words of state. With blocks == 0 it reads nothing at p and
// writes nothing.
//
// Constant time: its operations are 64-bit adds, rotates, shifts and bitwise logic, it reads no
// table at an index a word decides, and it branches on the block count and on a loop count
// that is a constant.
//
// It wipes nothing. A caller that hashes a secret wipes SHA512_COMPRESS_BLOCKS_BELOW_LEN bytes
// of stack below its own frame after the call, as sha512.c does. No wipe written in C clears a
// register: the ones the ABI lets a call change hold what the last instructions left in them.
void sha512_compress_blocks(uint64_t state[8], const uint8_t *p, size_t blocks);

#endif // CH_CPU_RUNTIME

#endif
