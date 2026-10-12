// The SHA-512 compression function (FIPS 180-4 §6.4.2) over whole blocks, with the message
// schedule in AVX2 registers: what an x86-64 host object (-DCH_CPU_RUNTIME, cpu_cfg.h)
// compresses with for a session whose ch_cfg.cpu holds CH_CPU_AVX2 (docs/decisions.md 128).
// sha512_hw.c compiles sha512.c's five calls that hash once more over it, and sha512.h's entries
// call that copy for such a session. Any other session, and every call that takes no
// ch_cfg.cpu, compresses on sha512_compress_blocks.c. On any other target this header declares
// nothing, and sha512_avx2.c holds nothing.
//
// It is a source of its own so that its frame lies in the stack below its caller's frame, where
// the caller wipes it.
#ifndef CH_SHA512_AVX2_H
#define CH_SHA512_AVX2_H

#include <stddef.h>
#include <stdint.h>

#include "sha512.h"

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

// The bytes of stack a caller wipes below its own frame after a call. The call leaves the last
// sixteen schedule words of the last block, each plus its round constant, in its frame, and
// beside them whichever registers its compiler wrote to stack slots of its own, which no
// ct_wipe can name. bin/sha2_equiv_test measures how far below its caller the call writes and
// requires that, and 16 bytes more, inside this length: the function aligns its frame to 32
// bytes, so the depth differs by 16 between callers. It measured 208 and 224 bytes under gcc
// 13.3, 256 and 272 under clang 23, and 256 under clang 18. lint-stack holds the function's
// frame under STACK_BUDGET_SHA512_AVX2, which is below this length.
#define SHA512_AVX2_BELOW_LEN 512

// Absorbs blocks whole blocks at p into the eight-word state: the contract of
// sha512_compress_blocks (sha512_compress_blocks.h). Reads exactly blocks * SHA512_BLOCK bytes
// at p and writes exactly the eight words of state. With blocks == 0 it reads nothing at p and
// writes nothing.
//
// Constant time: its operations are adds, rotates, shifts, bitwise logic and byte shuffles by
// constant masks, on 64-bit words and on 256-bit registers, it reads no table at an index a
// word decides, and it branches on the block count alone.
//
// Before it returns it writes zero to ymm0 to ymm15, which held schedule words. It wipes no
// stack. A caller that hashes a secret wipes SHA512_AVX2_BELOW_LEN bytes of stack below its own
// frame after the call, as sha512.c's copy in sha512_hw.c does.
//
// Requires: a CPU with AVX2 whose operating system saves the 256-bit registers, which the
// session's caller states with CH_CPU_AVX2. On a CPU without it the first instruction faults.
void sha512_avx2_compress_blocks(uint64_t state[8], const uint8_t *p, size_t blocks);

#endif // CH_CPU_RUNTIME && __x86_64__

#endif
