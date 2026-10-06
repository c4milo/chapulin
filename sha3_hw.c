// SHA-3 and SHAKE (FIPS 202) with Keccak-f[1600] on arm64's SHA-3 instructions, through
// <arm_neon.h>'s veor3q_u64, vrax1q_u64, vxarq_u64 and vbcaxq_u64. An arm64 host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h) compiles this file beside sha3.c, and sha3.h's and mlkem.h's
// entries call it for a session whose caller set CH_CPU_CONSTANT_TIME_SHA3 (docs/decisions.md
// 99). No x86-64 CPU has these instructions, so on x86-64 the file holds nothing, and
// cpu_cfg.h refuses the bit there.
//
// Only clang compiles the instructions (CH_KECCAK_INSTRUCTIONS, cpu_cfg.h). A round keeps 32
// values in arm64's 32 vector registers: the 25 lanes and seven more. A compiler that needs a
// 33rd writes a lane to a stack slot of its choosing, and no wipe written in C clears one.
// Apple clang 21, clang 18 and clang 23 keep all 32 in registers. gcc 13 does not, in this form
// or with four lanes held in a struct the function wipes, so under any other compiler this
// file holds nothing and every session runs sha3.c.
//
// The file is two things. The sponge is sha3.c's text, compiled once more under the names
// keccak_hw.h gives: absorbing, padding and squeezing are the code CBMC proves. The permutation
// is this file's own, the two functions sha3.c leaves to a copy: keccak_f1600, and
// absorb_whole_blocks, which keeps the state in registers from a message's first whole block to
// its last.
//
// The object compiles this file with no instruction flag, so the rest of the object runs on any
// arm64 CPU. The pragma below puts the target attribute that turns the instructions on onto
// each function in this file, the copied text's too, and on no function outside it. Under it
// a compiler may write EOR3 for plain C as well (sha512_hw.c), and here that is the bit's own
// instruction. Nothing here probes a CPU: the caller does, and states what it found in
// ch_cfg.cpu.
//
// ML-KEM hashes its secrets with this file, so its timing matters. It reads no table with a
// secret index and branches on lengths and on the rate alone, which is what it can state for
// itself. Whether the four instructions take the same time whatever their operands are is the
// CPU's, in the mode the thread runs in, and CH_CPU_CONSTANT_TIME_SHA3 is the caller's
// statement that they do (cpu_cfg.h).
//
// CBMC cannot read an intrinsic, so the proofs stay on sha3.c. bin/sha3_hw_equiv_test holds
// this file to that code over every length and split it tries, compares it with FIPS 202 as
// proof/sha3_reference.h writes it, and searches the stack each kind of call leaves.
// bin/mlkem_hw_equiv_test holds ML-KEM's two copies to mlkem.c and mlkem_poly.c
// (docs/verification.md).
#include "sha3.h"

#ifdef CH_KECCAK_INSTRUCTIONS

#include <arm_neon.h>

#pragma clang attribute push(__attribute__((target("sha3"))), apply_to = function)

// sha3.h is read above, so the renames find its declarations of the _hw names in place.
#include "keccak_hw.h"

#define CH_SHA3_HW_COPY

static void keccak_f1600(uint64_t a[25]);
static void absorb_whole_blocks(uint64_t lane[25], size_t rate, const uint8_t **in, size_t *n);

#include "sha3.c"

// A lane in the low half of a vector register. The four instructions work on both halves, and
// the high half here is zero going in and never read.
static inline uint64x2_t register_from_lane(uint64_t lane) {
    return vcombine_u64(vcreate_u64(lane), vdup_n_u64(0));
}

// The same from eight bytes of a message. A host object is little-endian (cpu_cfg.h), so the
// eight bytes in memory are the lane as FIPS 202 §3.1.2 orders them.
static inline uint64x2_t register_from_bytes(const uint8_t *bytes) {
    return vcombine_u64(vreinterpret_u64_u8(vld1_u8(bytes)), vdup_n_u64(0));
}

// Runs `blocks` permutations on the state. Before each one it XORs the next `lanes` lanes of
// the input into the state's first lanes: 9 for a block of SHA3-512, 17 for one of SHA3-256 or
// SHAKE256, 21 for one of SHAKE128, or 0, which reads no input and is the permutation alone.
//
// The state is in 25 registers from the first block to the last, and one round is sha3.c's
// keccak_round with each step on its instruction:
//
//   theta: EOR3 is an exclusive OR of three, so two of them make a column's parity, and RAX1
//     is x ^ rotate_left(y, 1), which is d[x] = c[x - 1] ^ rotate_left(c[x + 1], 1).
//   rho and pi: XAR is an exclusive OR and then a rotation to the right, so XAR by 64 - r is
//     theta's XOR of d into a lane and rho's rotation of it to the left by r, at once. The
//     sources and the offsets are sha3.c's 25 lines, in its order.
//   chi: BCAX(x, y, z) is x ^ (y & ~z).
//   iota: an exclusive OR with the round constant, read from sha3.c's table.
//
// The whole of it is one function with no helper around the rounds, and the five values of d
// are computed in the order that reads each parity for the last time as early as it can.
// Both are for the compiler: a helper it kept out of line would store the state every round,
// and in the standard's order the round needs a 33rd register, which puts a lane on the stack
// (docs/performance.md, the pitfalls).
static void permute_blocks(uint64_t state[25], const uint8_t *in, size_t lanes, size_t blocks) {
    uint64x2_t a0 = register_from_lane(state[0]);
    uint64x2_t a1 = register_from_lane(state[1]);
    uint64x2_t a2 = register_from_lane(state[2]);
    uint64x2_t a3 = register_from_lane(state[3]);
    uint64x2_t a4 = register_from_lane(state[4]);
    uint64x2_t a5 = register_from_lane(state[5]);
    uint64x2_t a6 = register_from_lane(state[6]);
    uint64x2_t a7 = register_from_lane(state[7]);
    uint64x2_t a8 = register_from_lane(state[8]);
    uint64x2_t a9 = register_from_lane(state[9]);
    uint64x2_t a10 = register_from_lane(state[10]);
    uint64x2_t a11 = register_from_lane(state[11]);
    uint64x2_t a12 = register_from_lane(state[12]);
    uint64x2_t a13 = register_from_lane(state[13]);
    uint64x2_t a14 = register_from_lane(state[14]);
    uint64x2_t a15 = register_from_lane(state[15]);
    uint64x2_t a16 = register_from_lane(state[16]);
    uint64x2_t a17 = register_from_lane(state[17]);
    uint64x2_t a18 = register_from_lane(state[18]);
    uint64x2_t a19 = register_from_lane(state[19]);
    uint64x2_t a20 = register_from_lane(state[20]);
    uint64x2_t a21 = register_from_lane(state[21]);
    uint64x2_t a22 = register_from_lane(state[22]);
    uint64x2_t a23 = register_from_lane(state[23]);
    uint64x2_t a24 = register_from_lane(state[24]);

    for (size_t block = 0; block < blocks; block++) {
        if (lanes >= 9) {
            a0 = veorq_u64(a0, register_from_bytes(in));
            a1 = veorq_u64(a1, register_from_bytes(in + 8));
            a2 = veorq_u64(a2, register_from_bytes(in + 16));
            a3 = veorq_u64(a3, register_from_bytes(in + 24));
            a4 = veorq_u64(a4, register_from_bytes(in + 32));
            a5 = veorq_u64(a5, register_from_bytes(in + 40));
            a6 = veorq_u64(a6, register_from_bytes(in + 48));
            a7 = veorq_u64(a7, register_from_bytes(in + 56));
            a8 = veorq_u64(a8, register_from_bytes(in + 64));
        }
        if (lanes >= 17) {
            a9 = veorq_u64(a9, register_from_bytes(in + 72));
            a10 = veorq_u64(a10, register_from_bytes(in + 80));
            a11 = veorq_u64(a11, register_from_bytes(in + 88));
            a12 = veorq_u64(a12, register_from_bytes(in + 96));
            a13 = veorq_u64(a13, register_from_bytes(in + 104));
            a14 = veorq_u64(a14, register_from_bytes(in + 112));
            a15 = veorq_u64(a15, register_from_bytes(in + 120));
            a16 = veorq_u64(a16, register_from_bytes(in + 128));
        }
        if (lanes >= 21) {
            a17 = veorq_u64(a17, register_from_bytes(in + 136));
            a18 = veorq_u64(a18, register_from_bytes(in + 144));
            a19 = veorq_u64(a19, register_from_bytes(in + 152));
            a20 = veorq_u64(a20, register_from_bytes(in + 160));
        }
        if (lanes != 0) {
            in += 8 * lanes;
        }

        for (int round = 0; round < 24; round++) {
            uint64x2_t c0 = veor3q_u64(veor3q_u64(a0, a5, a10), a15, a20);
            uint64x2_t c2 = veor3q_u64(veor3q_u64(a2, a7, a12), a17, a22);
            uint64x2_t d1 = vrax1q_u64(c0, c2);
            uint64x2_t c1 = veor3q_u64(veor3q_u64(a1, a6, a11), a16, a21);
            uint64x2_t b1 = vxarq_u64(a6, d1, 64 - 44);
            uint64x2_t b8 = vxarq_u64(a16, d1, 64 - 45);
            uint64x2_t b10 = vxarq_u64(a1, d1, 64 - 1);
            uint64x2_t b17 = vxarq_u64(a11, d1, 64 - 10);
            uint64x2_t b24 = vxarq_u64(a21, d1, 64 - 2);
            uint64x2_t c3 = veor3q_u64(veor3q_u64(a3, a8, a13), a18, a23);
            uint64x2_t d4 = vrax1q_u64(c3, c0);
            uint64x2_t c4 = veor3q_u64(veor3q_u64(a4, a9, a14), a19, a24);
            uint64x2_t b4 = vxarq_u64(a24, d4, 64 - 14);
            uint64x2_t b6 = vxarq_u64(a9, d4, 64 - 20);
            uint64x2_t b13 = vxarq_u64(a19, d4, 64 - 8);
            uint64x2_t b15 = vxarq_u64(a4, d4, 64 - 27);
            uint64x2_t b22 = vxarq_u64(a14, d4, 64 - 39);
            uint64x2_t d3 = vrax1q_u64(c2, c4);
            uint64x2_t b3 = vxarq_u64(a18, d3, 64 - 21);
            uint64x2_t b5 = vxarq_u64(a3, d3, 64 - 28);
            uint64x2_t b12 = vxarq_u64(a13, d3, 64 - 25);
            uint64x2_t b19 = vxarq_u64(a23, d3, 64 - 56);
            uint64x2_t b21 = vxarq_u64(a8, d3, 64 - 55);
            uint64x2_t d0 = vrax1q_u64(c4, c1);
            uint64x2_t b0 = veorq_u64(a0, d0);
            uint64x2_t b7 = vxarq_u64(a10, d0, 64 - 3);
            uint64x2_t b14 = vxarq_u64(a20, d0, 64 - 18);
            uint64x2_t b16 = vxarq_u64(a5, d0, 64 - 36);
            uint64x2_t b23 = vxarq_u64(a15, d0, 64 - 41);
            uint64x2_t d2 = vrax1q_u64(c1, c3);
            uint64x2_t b2 = vxarq_u64(a12, d2, 64 - 43);
            uint64x2_t b9 = vxarq_u64(a22, d2, 64 - 61);
            uint64x2_t b11 = vxarq_u64(a7, d2, 64 - 6);
            uint64x2_t b18 = vxarq_u64(a17, d2, 64 - 15);
            uint64x2_t b20 = vxarq_u64(a2, d2, 64 - 62);

            a0 = vbcaxq_u64(b0, b2, b1);
            a1 = vbcaxq_u64(b1, b3, b2);
            a2 = vbcaxq_u64(b2, b4, b3);
            a3 = vbcaxq_u64(b3, b0, b4);
            a4 = vbcaxq_u64(b4, b1, b0);
            a5 = vbcaxq_u64(b5, b7, b6);
            a6 = vbcaxq_u64(b6, b8, b7);
            a7 = vbcaxq_u64(b7, b9, b8);
            a8 = vbcaxq_u64(b8, b5, b9);
            a9 = vbcaxq_u64(b9, b6, b5);
            a10 = vbcaxq_u64(b10, b12, b11);
            a11 = vbcaxq_u64(b11, b13, b12);
            a12 = vbcaxq_u64(b12, b14, b13);
            a13 = vbcaxq_u64(b13, b10, b14);
            a14 = vbcaxq_u64(b14, b11, b10);
            a15 = vbcaxq_u64(b15, b17, b16);
            a16 = vbcaxq_u64(b16, b18, b17);
            a17 = vbcaxq_u64(b17, b19, b18);
            a18 = vbcaxq_u64(b18, b15, b19);
            a19 = vbcaxq_u64(b19, b16, b15);
            a20 = vbcaxq_u64(b20, b22, b21);
            a21 = vbcaxq_u64(b21, b23, b22);
            a22 = vbcaxq_u64(b22, b24, b23);
            a23 = vbcaxq_u64(b23, b20, b24);
            a24 = vbcaxq_u64(b24, b21, b20);

            a0 = veorq_u64(a0, vld1q_dup_u64(&RC[round]));
        }
    }

    state[0] = vgetq_lane_u64(a0, 0);
    state[1] = vgetq_lane_u64(a1, 0);
    state[2] = vgetq_lane_u64(a2, 0);
    state[3] = vgetq_lane_u64(a3, 0);
    state[4] = vgetq_lane_u64(a4, 0);
    state[5] = vgetq_lane_u64(a5, 0);
    state[6] = vgetq_lane_u64(a6, 0);
    state[7] = vgetq_lane_u64(a7, 0);
    state[8] = vgetq_lane_u64(a8, 0);
    state[9] = vgetq_lane_u64(a9, 0);
    state[10] = vgetq_lane_u64(a10, 0);
    state[11] = vgetq_lane_u64(a11, 0);
    state[12] = vgetq_lane_u64(a12, 0);
    state[13] = vgetq_lane_u64(a13, 0);
    state[14] = vgetq_lane_u64(a14, 0);
    state[15] = vgetq_lane_u64(a15, 0);
    state[16] = vgetq_lane_u64(a16, 0);
    state[17] = vgetq_lane_u64(a17, 0);
    state[18] = vgetq_lane_u64(a18, 0);
    state[19] = vgetq_lane_u64(a19, 0);
    state[20] = vgetq_lane_u64(a20, 0);
    state[21] = vgetq_lane_u64(a21, 0);
    state[22] = vgetq_lane_u64(a22, 0);
    state[23] = vgetq_lane_u64(a23, 0);
    state[24] = vgetq_lane_u64(a24, 0);
}

// Every call of permute_blocks goes through this pointer. A compiler that sees the call may
// inline the function, or compile a second copy for the arguments one caller passes, and it
// picks the registers of each copy anew: clang 21 and 23 compiled such a copy of an earlier
// form of this file, and the copy wrote five or six lanes to the stack. The pointer is a
// volatile object, so the compiler loads it at every call and cannot tell which function the
// load returns (C11 5.1.2.3p6, as ct_wipe.c's pointer). So permute_blocks is compiled once,
// and the code every call runs is the code whose stack bin/sha3_hw_equiv_test searches.
static void (*const volatile permute_one_copy)(uint64_t state[25], const uint8_t *in, size_t lanes,
                                               size_t blocks) = permute_blocks;

// Keccak-f[1600] on the state: one permutation and no input.
static void keccak_f1600(uint64_t a[25]) {
    permute_one_copy(a, NULL, 0, 1);
}

// sha3.c's absorb_whole_blocks, with the state in registers across the blocks. It counts the
// whole blocks by subtraction, so the file holds no division.
static void absorb_whole_blocks(uint64_t lane[25], size_t rate, const uint8_t **in, size_t *n) {
    size_t blocks = 0;
    for (size_t left = *n; left >= rate; left -= rate) {
        blocks++;
    }
    if (blocks == 0) {
        return;
    }
    permute_one_copy(lane, *in, rate / 8, blocks);
    *in += blocks * rate;
    *n -= blocks * rate;
}

#pragma clang attribute pop

#endif // CH_KECCAK_INSTRUCTIONS
