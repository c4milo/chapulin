// AES=hw: GHASH on the carry-less multiply instruction. ghash_hw.h
// states the two contracts; this file implements them and nothing else.
// The arithmetic is ghash_vector.h's, which states what the instruction
// computes, the bit order, the subkey times x^-1, Karatsuba's three
// products, the reduction and the timing: this file loads the subkey and
// the accumulator, computes the powers of H a call needs, runs the passes
// and wipes what it computed.
//
// The loop over data multiplies up to GHASH_PASS_BLOCKS blocks by powers
// of H before it reduces once. Each call computes the powers it needs
// from H first, keeps them in a ghash_state beside H, and wipes them with
// it when the call ends, the way gcm.c computes H for each call and wipes
// it.
//
// AES=runtime compiles this file with no instruction flag, as it compiles
// aes_hw.c: the architecture picks the instruction, and the pragma below
// puts the target attribute that turns it on onto each function in this
// file, as ghash_vector.h's does onto each of its own, and on no function
// outside them. gcm.c calls this file only for a schedule the AES
// instructions run (aes_schedule.h), so a session whose caller's probe
// found no instructions runs no carry-less multiply.
//
// CBMC cannot read an intrinsic, so the proofs stay on gcm.c's
// portable multiply and test/ghash_equiv_test.c holds this file to it:
// it runs both multiplies, both loops over data and both whole AEADs
// over the same inputs and compares byte for byte.
#include "ghash_hw.h"

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#if defined(CH_AES_HW) || defined(CH_AES_RUNTIME)

#include <stddef.h>
#include <string.h>

#include "ct.h"
#include "ghash_vector.h"

// Under AES=runtime, every function from here to the pop at the end of
// this file carries the target attribute that turns the instruction on:
// "+aes", the Arm AES extension, which the Arm C Language Extensions give
// the 64-bit PMULL, or "pclmul", x86-64's PCLMULQDQ. aes_hw.c states how
// each compiler's pragma applies it.
#ifdef CH_AES_RUNTIME
#ifdef __clang__
#ifdef GHASH_VECTOR_ARM
#pragma clang attribute push(__attribute__((target("+aes"))), apply_to = function)
#else
#pragma clang attribute push(__attribute__((target("pclmul"))), apply_to = function)
#endif
#else
#pragma GCC push_options
#ifdef GHASH_VECTOR_ARM
#pragma GCC target("+aes")
#else
#pragma GCC target("pclmul")
#endif
#endif
#endif

void gcm_multiply_by_subkey_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]) {
    ghash_state s;
    s.subkey = ghash_load_block(subkey);
    s.acc = ghash_load_block(acc);
    ghash_compute_powers(&s, 1);
    ghash_start_sums(&s, &s.sums, s.acc, 0);
    s.acc = ghash_reduce(&s.sums);
    ghash_store_block(acc, s.acc);
    // s holds the hash subkey itself, H * x^-1 and the unreduced product,
    // so the frame would hand a later caller the subkey. gcm.c's multiply
    // wipes its running multiple for the same reason. This entry computes
    // one power, so the wipe stops after it.
    ct_wipe(&s, offsetof(ghash_state, powers) + sizeof s.powers[0]);
}

void gcm_hash_data_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *data,
                      size_t n) {
    // No data to hash, so no power of H to compute or wipe.
    if (n == 0) {
        return;
    }
    ghash_state s;
    s.subkey = ghash_load_block(subkey);
    s.acc = ghash_load_block(acc);
    size_t whole = n / AES_BLOCK;
    // One power for each block of the longest pass, and H alone when the
    // data is one partial block.
    size_t powers = whole < GHASH_PASS_BLOCKS ? whole : GHASH_PASS_BLOCKS;
    if (powers == 0) {
        powers = 1;
    }
    ghash_compute_powers(&s, powers);
    size_t done = 0;
    while (whole - done >= GHASH_PASS_BLOCKS) {
        ghash_hash_pass(&s, &data[done * AES_BLOCK]);
        done += GHASH_PASS_BLOCKS;
    }
    if (done < whole) {
        ghash_hash_blocks(&s, &data[done * AES_BLOCK], whole - done);
    }
    size_t rest = n - whole * AES_BLOCK;
    if (rest > 0) {
        // Zero first, then the bytes there are, which leaves SP 800-38D
        // §6.4's pad on the last block. gcm.c's hash_data pads the same
        // way.
        uint8_t block[AES_BLOCK];
        memset(block, 0, AES_BLOCK);
        memcpy(block, &data[whole * AES_BLOCK], rest);
        ghash_hash_blocks(&s, block, 1);
    }
    ghash_store_block(acc, s.acc);
    // Once per call rather than once per pass: s is the one object the
    // loop writes that holds the subkey and its powers, and a wipe inside
    // the loop would run per pass for no further gain. It covers every
    // power this call computed. block holds bytes of the data the caller
    // passed, which is associated data or ciphertext.
    ct_wipe(&s, offsetof(ghash_state, powers) + powers * sizeof s.powers[0]);
}

#ifdef CH_AES_RUNTIME
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif

#endif // CH_AES_HW || CH_AES_RUNTIME
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
