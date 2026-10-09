#!/usr/bin/env python3
"""Check that a full harness or an audit covers every shipped source's text.

.clang-tidy disables bugprone-signed-bitwise, and that disable rests on the
claim INV-47 in docs/invariants.md states. Every shipped source is compiled by
a CBMC harness launched with the `full` check set, which proves the calls it
drives free of signed overflow and bad shifts at its bound, or it is a copy of
such a source or of an audited one, or someone read it and recorded what holds
its signed arithmetic. Nothing enforced the claim, so it could rot four ways --
a new source arrives with no harness, the Makefile adds a source to an object
on a line this script does not read, a launch line drops from the `full` check
set to a narrower one, or one of the hand-audited files gains a signed operand.

This fails when a shipped source is neither compiled by a harness running the
`full` set, nor listed in AUDITED below, nor a copy COPIES names of a source
that passes, nor still a stub carrying the CH_QUIC_STUB or CH_SRV_STUB marker.
Growing AUDITED is deliberate: it means someone read the file and wrote down
what they found. The stub exemption is not another way to grow: it holds only
while a file has no implementation at all, and it ends on the commit that
deletes that file's last marker. A COPIES entry holds only while its file is
nothing but the text of the source it copies.

The shipped sources are the ones make packages, which the Makefile's
print-lib-srcs prints for each build in tools/shipped_sources.py's BUILDS,
and the sources their text includes. tools/impact_map.py reads the same set.
A root .c file outside that set fails as well, because a list of builds can
leave out the one that packages a new source.

Run through `make lint-proof-cover`.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

from shipped_sources import INCLUDED_SOURCE, shipped_sources

ROOT = Path(__file__).resolve().parent.parent

# Sources with no `full` harness, read by hand instead. Each entry carries what
# the reader established. Re-audit an entry when its file changes shape, and
# delete it once the file gains a harness.
AUDITED = {
    "build.c": (
        "the build record, one const ch_build_info and no function. Every "
        "initializer is a constant expression build.h writes: an integer "
        "constant, a sizeof cast to uint32_t, or CH_BUILD_AXES, an or of "
        "unsigned constants. No operand in the file is signed and nothing "
        "runs at run time, so there is no path for a harness to drive and "
        "no arithmetic for bugprone-signed-bitwise to judge. lib-check links "
        "test/build_test.c against every object it checks and reads each "
        "field back. Delete this entry if the file ever gains a function."
    ),
    "tls.c": (
        "the public calls tls.h declares beside the send path: ch_connect and "
        "the client configuration rules, ch_read, ch_close, ch_export and the "
        "two alert calls. Two bitwise operators in the file, the `& 1` at "
        ":133 and :135 that reads the low bit of a pinned RSA modulus's last "
        "byte: the uint8_t widens to int and holds 0 to 255, so the operand "
        "is never negative and bugprone-signed-bitwise has nothing to say "
        "about it. No shift. No harness runs this file. "
        "proof/writable_len_harness.c included it until ch_write and "
        "ch_writable_len moved to tls_write.c, and drove those two calls "
        "alone; it includes tls_write.c now. bin/unit and the loop tests "
        "test every call left here. Delete this entry when tls.c gets a "
        "harness of its own."
    ),
    "chacha20_vector.c": (
        "a host object's ChaCha20, written in NEON or SSE2 intrinsics, which "
        "CBMC cannot read, so no harness compiles the file. Every bitwise "
        "operator takes unsigned operands: the lane operations run on "
        "uint32x4_t or __m128i values through the intrinsics, load32 shifts "
        "uint32_t values, and the last group's XOR takes two uint8_t bytes, "
        "which widen to int and hold 0 to 255. The SSE2 arm's two (int) "
        "casts hand a uint32_t word to _mm_set1_epi32, a conversion gcc and "
        "clang define as keeping its 32 bits, and no arithmetic runs on the "
        "int. bin/chacha20_equiv_test holds the file to chacha20.c's proven "
        "loop, and bin/unit_host and the host Wycheproof test run the "
        "published vectors on it. Delete this entry if a harness can ever "
        "compile the file."
    ),
    "chacha20_avx2.c": (
        "a host object's AVX2 ChaCha20 kernel on x86-64, written in AVX2 intrinsics, "
        "which CBMC cannot read, so no harness compiles the file. Every "
        "bitwise operator takes unsigned operands: the lane operations run on "
        "__m256i values through the intrinsics, load32 shifts uint32_t "
        "values, and the last row's XOR takes two uint8_t bytes, which widen "
        "to int and hold 0 to 255. The (int) casts hand a uint32_t word to "
        "_mm256_set1_epi32, a conversion gcc and clang define as keeping its "
        "32 bits, and no arithmetic runs on the int. bin/chacha20_equiv_test "
        "holds the kernel to chacha20.c's proven loop on a CPU with AVX2, and "
        "bin/unit_host and the host Wycheproof test run the published vectors "
        "on it there, under a ch_cfg.cpu value with CH_CPU_AVX2. Delete this "
        "entry if a harness can ever compile the file."
    ),
    "chacha20_avx512.c": (
        "a host object's AVX-512 ChaCha20 kernel on x86-64, written in AVX-512F "
        "intrinsics, which CBMC cannot read, so no harness compiles the file. "
        "Every bitwise operator takes unsigned operands: the lane operations "
        "run on __m512i values through the intrinsics, load32 shifts uint32_t "
        "values, and the last block's XOR takes two uint8_t bytes, which widen "
        "to int and hold 0 to 255. The (int) casts hand a uint32_t word to "
        "_mm512_set1_epi32 and _mm_setr_epi32, a conversion gcc and clang "
        "define as keeping its 32 bits, and no arithmetic runs on the int. The "
        "VPSHUFD and VSHUFI32X4 orders are int constants below 256. The rest is "
        "size_t arithmetic on the byte count n and on block indices below 16. "
        "bin/chacha20_equiv_test holds the kernel to chacha20.c's proven loop on "
        "a CPU with AVX-512F, and bin/unit_host and the host Wycheproof test run "
        "the published vectors on it there, under a ch_cfg.cpu value with "
        "CH_CPU_AVX512_IFMA; the nightly's rsa-ifma-sde job runs the first "
        "under Intel SDE. Delete this entry if a harness can ever compile the "
        "file."
    ),
    "avx512_wipe.c": (
        "the wipe of the AVX-512 registers in an x86-64 host object: one "
        "function, avx512_wipe_registers, whose body is one block of inline "
        "assembly: 32 VPXORD, one for each of xmm0 to xmm31, whose EVEX form "
        "clears the whole 512-bit register, and 7 KXORW, one for each of k1 "
        "to k7. CBMC reads no instruction in an assembly string, so no "
        "harness compiles the file, and there would be nothing else to drive: "
        "the C holds no operator, no variable, no argument and no memory "
        "access, and the block reads and writes no memory and branches "
        "nowhere. Its clobber list names those 39 registers, so the compiler "
        "keeps no live value in one across the call. It compiles to nothing "
        "outside an x86-64 host object. On a CPU with AVX-512F, "
        "bin/avx512_wipe_test sets every bit of each of those registers, "
        "calls the function, and requires each of them to read back as zero; "
        "the nightly's rsa-ifma-sde job runs it under Intel SDE. Delete this "
        "entry if the file ever holds C that a harness could drive."
    ),
    "poly1305_vector.c": (
        "the vector Poly1305 of a host object's native copy, written in NEON or SSE2 intrinsics, "
        "which CBMC cannot read, so no harness compiles the file. Every "
        "bitwise operator takes unsigned operands: the lane operations run on "
        "uint32x2_t, uint64x2_t or __m128i values through the intrinsics, "
        "WORD_MASK is 0x3ffffffU and HIGH_BIT a uint32_t, and carry_scalar "
        "and multiply_scalar, which poly1305_scalar.h holds, and "
        "multiplier_set shift, mask and multiply uint32_t and uint64_t "
        "values, where the constant 5 converts to unsigned. The "
        "SSE2 arm's (int) casts hand _mm_set_epi32 a word, 5 times a word, "
        "WORD_MASK or HIGH_BIT, each below 2^31, and no arithmetic runs on "
        "the int. bin/poly1305_equiv_test holds the file to poly1305.c's "
        "proven loop, and bin/unit_host and the host Wycheproof test run the "
        "published vectors on it, under a ch_cfg.cpu value with the multiply "
        "bit. Delete this entry if a harness can ever compile the file."
    ),
    "poly1305_avx2.c": (
        "the AVX2 Poly1305 of an x86-64 host object's native copy, written in "
        "AVX2 intrinsics, which CBMC cannot read, so no harness compiles the "
        "file. Every bitwise operator takes unsigned operands: the lane "
        "operations run on __m256i values through the intrinsics, WORD_MASK "
        "is 0x3ffffffU and HIGH_BIT a uint32_t, and poly1305_scalar.h's "
        "carry_scalar and multiply_scalar and the file's word_lanes shift, "
        "mask and multiply uint32_t and uint64_t values, where the constants "
        "1 and 5 convert to unsigned. The (int) casts hand _mm256_set_epi32 "
        "a word or 5 times a word, each below 2^31, and _mm256_set1_epi64x "
        "takes WORD_MASK and HIGH_BIT, which a long long holds; no arithmetic "
        "runs on the int. The rest is size_t: the byte count n, a positive "
        "multiple of 128 by the CH_ASSERT at the entry, which the group loop "
        "lowers by 128 while it is above 128, and word indices below 5. "
        "bin/poly1305_equiv_test holds the file to poly1305.c's proven loop "
        "on a CPU with AVX2, and the host Wycheproof test runs the published "
        "vectors whose messages hold 512 bytes of whole blocks on it there, "
        "under a ch_cfg.cpu value with the multiply bit and CH_CPU_AVX2. "
        "Delete this entry if a harness can ever compile the file."
    ),
    "mlkem_vector.c": (
        "a host object's ML-KEM NTT, inverse NTT and base multiplication on "
        "eight 16-bit lanes, written in NEON or SSE2 intrinsics through "
        "mlkem_lanes.h, which CBMC cannot read, so no harness compiles the "
        "file. Every session of a host object runs it, and no ch_cfg.cpu bit "
        "picks it. Neither file holds a bitwise operator. The signed "
        "arithmetic is in the lanes, on NEON vectors of 16-bit and 32-bit "
        "lanes or on __m128i values: each add, subtract and low multiply wraps "
        "modulo 2^16 as the instruction defines it, which C's rule for signed "
        "overflow does not govern, and that wrap is what mlkem_poly.c's "
        "(int16_t) casts compute. NEON's SQDMULH saturates only when both its "
        "operands are -32768. Each call passes it a constant or a twiddle "
        "factor, none of them -32768, beside one lane of data, and a product "
        "of two coefficients goes to lanes_fqmul_wide, which forms it in 32 "
        "bits. The lane constants, -3327, 1441, 20159, 1024, 512 and MLKEM_Q, "
        "lie inside int16's range, and the shift counts, 10 and 11, and the "
        "shuffle immediates are int constants below 256. The C arithmetic is "
        "the negations that write those constants and the zeta table, and "
        "size_t loop counters, offsets and table indices: the largest index is "
        "127, the last eight-lane access starts at coefficient 248 and ends at "
        "255, and the subtractions 124 - 4*block, 62 - 2*block, 31 - block, "
        "15 - 2*block, 14 - 2*block and 7 - block leave 64, 32, 16, 9, 8 and "
        "4 at the largest block each loop reaches. bin/mlkem_vector_equiv_test "
        "holds the file to mlkem_poly.c's proven loops over inputs drawn from "
        "all of int16, test/aes-runtime-qemu.sh mlkem-vector runs that test on "
        "the arm the machine's own compiler does not read, and "
        "bin/mlkem_test_host and the host Wycheproof test run the published "
        "ML-KEM vectors on it. Delete this entry if a harness can ever compile "
        "the file."
    ),
    "keccak_avx2.c": (
        "a host object's four-way Keccak on x86-64, written in AVX2 "
        "intrinsics, which CBMC cannot read, so no harness compiles the file. "
        "Every bitwise operator takes unsigned operands: the round runs on "
        "__m256i values through the intrinsics, lane_from_bytes and the start "
        "shift uint64_t values left by constants up to 56 and OR them, and "
        "keccak_avx2_block shifts a uint64_t lane right by the same constants "
        "and narrows each byte to uint8_t. lanes_rotate_left hands the shift "
        "intrinsics r and 64 - r for an r from 1 to 63. The (long long) cast "
        "hands a round constant to _mm256_set1_epi64x, a conversion gcc and "
        "clang define as keeping its 64 bits, and no arithmetic runs on it. "
        "The rest is size_t loop counters bounded by constants: 25 lanes, 24 "
        "rounds, four states, 21 lanes a block, so the largest offset is 160 "
        "into a 168-byte block and 24 into the 32-byte seed. "
        "bin/mlkem_avx2_equiv_test holds the four streams to sha3.c's "
        "SHAKE128 for ten blocks on a CPU with AVX2. Delete this entry if a "
        "harness can ever compile the file."
    ),
    "mlkem_avx2.c": (
        "mlkem.c compiled once more for an x86-64 host object, beside the row "
        "sampler that calls keccak_avx2.c's AVX2 entries, so the file has a "
        "body on x86-64 alone and no harness compiles it. The mlkem harness "
        "proves mlkem.c's text but for mlk_matvec_row, which this file "
        "supplies. Its own code holds no bitwise operator: the candidates' "
        "bits are read in mlk_sample_groups, which the mlkem_poly harness "
        "proves inside mlk_sample_ntt. Its arithmetic is size_t: read grows by "
        "56 to at most 560 and stops the loop at 512 before the subtraction "
        "512 - read can run, so groups stays from 8 to 56, each entry's count "
        "is mlk_sample_groups's return, at most 256, and the indices are "
        "below 3 or 4. bin/mlkem_avx2_equiv_test holds the copy's keys, "
        "ciphertexts and secrets to mlkem.c's, and test/mlkem-builds.sh "
        "requires its rows to call the four-way Keccak. Delete this entry if a "
        "harness can ever compile the file."
    ),
    "sha256_hw.c": (
        "a host object's SHA-256 on the CPU's SHA-256 instructions, written in "
        "the FEAT_SHA256 and SHA-extension intrinsics, which CBMC cannot read, "
        "so no harness compiles the file. Every bitwise operator takes "
        "unsigned operands: the rounds and the schedule run on uint32x4_t or "
        "__m128i values through the intrinsics, sha256_final_hw shifts a "
        "uint64_t bit count and the uint32_t words of the state, and each "
        "result narrows to uint8_t. The x86-64 arm's byte-order constant is "
        "two long long literals _mm_set_epi64x takes, each positive, and the "
        "shuffle and blend immediates are int constants below 256; no "
        "arithmetic runs on a signed value. The framing adds and subtracts "
        "size_t byte counts that the context's fill, below 64, bounds. "
        "bin/sha2_equiv_test holds the file to sha256.c's proven code, and "
        "bin/unit_host and the host Wycheproof test run the published vectors "
        "on it, under a ch_cfg.cpu value with the SHA-256 bit. Delete this "
        "entry if a harness can ever compile the file."
    ),
    "sha512_hw.c": (
        "an arm64 host object's SHA-512 and SHA-384 on FEAT_SHA512's "
        "instructions, written in intrinsics CBMC cannot read, so no harness "
        "compiles the file, and with no body on any other target. Every "
        "bitwise operator takes unsigned operands: the rounds and the schedule "
        "run on uint64x2_t values through the intrinsics, finalize shifts the "
        "uint64_t byte count and store_digest the uint64_t words of the state, "
        "and each result narrows to uint8_t. The framing adds and subtracts "
        "size_t byte counts that the context's fill, below 128, bounds, and "
        "the round loop's size_t counters stop at 40. "
        "bin/sha2_equiv_test holds the file to sha512.c's and "
        "sha512_compress.c's proven code on arm64, and bin/sha512_test_host, "
        "bin/hkdf384_test_host and the host Wycheproof test run the published "
        "vectors on it, under a ch_cfg.cpu value with the SHA-512 bit. Delete "
        "this entry if a harness can ever compile the file."
    ),
    "sha3_hw.c": (
        "an arm64 host object's Keccak-f[1600] on FEAT_SHA3's instructions, "
        "which only clang compiles, so the file has no body on x86-64 or under "
        "gcc. The sponge is sha3.c's text compiled once more under "
        "keccak_hw.h's names, and the sha3, sha3_stream and sha3_round "
        "harnesses prove that text. The rest, the permutation and "
        "absorb_whole_blocks, runs on intrinsics CBMC cannot read and holds no "
        "bitwise operator on a scalar: every round runs on uint64x2_t values "
        "through veor3q_u64, vrax1q_u64, vxarq_u64 and vbcaxq_u64, whose "
        "rotation counts are int constant expressions such as 64 - 44, each "
        "from 2 to 63. The round counter is an int that stops at 24 and "
        "indexes sha3.c's constant table, and absorb_whole_blocks counts whole "
        "blocks by subtraction in size_t, so the product it subtracts is at "
        "most the length it was given. bin/sha3_hw_equiv_test holds the file "
        "to sha3.c's proven code and to FIPS 202 as proof/sha3_reference.h "
        "writes it, under a ch_cfg.cpu value with the SHA-3 bit. Delete this "
        "entry if a harness can ever compile the file."
    ),
    "aes_hw.c": (
        "a host object's AES-128 and AES-256 on the AES instructions, written "
        "in the Arm and x86-64 AES intrinsics, which CBMC cannot read, so no "
        "harness compiles the file. The rounds run on uint8x16_t or __m128i "
        "values through the intrinsics. The scalar bitwise operators are "
        "xtime's and the key expansion's. xtime shifts b, a uint8_t that "
        "widens to int and holds 0 to 255, right by the constant 7, subtracts "
        "that bit from 0U to make a mask, and exclusive-ors (unsigned)b << 1 "
        "with 0x1bU under the mask; the expansion exclusive-ors two uint8_t "
        "bytes. The x86-64 arm's (int) cast hands a uint32_t word to "
        "_mm_set1_epi32, a conversion gcc and clang define as keeping its 32 "
        "bits, and no arithmetic runs on the int. The indices are size_t "
        "counters that each entry's constant key size and round count bound. "
        "bin/aes_equiv_test holds the file to quic_aes_soft.c, which the aes "
        "and aes256 harnesses prove, and bin/quic_test_hw and the host "
        "Wycheproof test run the published vectors on it, under a ch_cfg.cpu value "
        "with the AES bit. Delete this entry if a harness can ever compile the "
        "file."
    ),
    "ghash_hw.c": (
        "a host object's GHASH on the carry-less multiply, PMULL or PCLMULQDQ, "
        "through ghash_vector.h's intrinsics, which CBMC cannot read, so no "
        "harness compiles the file. Neither file holds a bitwise operator on a "
        "scalar: every exclusive-or, shift and mask runs on uint64x2_t or "
        "__m128i values through the intrinsics, with int constants below 256 "
        "for the shift counts and lane selectors, and the shift that spreads "
        "bit 127 into a mask is vshrq_n_s64 or _mm_srai_epi32, an arithmetic "
        "shift the instruction defines for every lane value. ghash_vector_of's "
        "two (long long) casts hand _mm_set_epi64x a uint64_t word, a "
        "conversion gcc and clang define as keeping its 64 bits. The block "
        "counts, the offsets and the wipe's length are size_t values that n, "
        "GHASH_PASS_BLOCKS and sizeof the state bound. bin/ghash_equiv_test "
        "holds the file to gcm.c's portable multiply, which the ghash harness "
        "proves, under a ch_cfg.cpu value with the AES bit. Delete this entry "
        "if a harness can ever compile the file."
    ),
    "gcm_hw.c": (
        "a host object's AES-GCM over whole blocks: counter mode and the "
        "seal's and the open's one-pass loops, on the AES and carry-less "
        "multiply intrinsics, which CBMC cannot read, so no harness compiles "
        "the file. The rounds and the hashing run on vector values through the "
        "intrinsics and ghash_vector.h's functions, which hold no bitwise "
        "operator on a scalar. The scalar ones move the count into and out of "
        "the counter's last four bytes: big_endian_word, counter_count and "
        "set_counter_count shift uint32_t values by the constants 8, 16 and "
        "24, and the uint8_t counter_count ors in last widens to int and holds "
        "0 to 255. The x86-64 arm's (int) cast hands a uint32_t word to "
        "_mm_cvtsi32_si128, a conversion gcc and clang define as keeping its "
        "32 bits. The counts add as uint32_t, which wraps modulo 2^32 as GCM's "
        "inc32 does, and the offsets are size_t products of an index below the "
        "caller's count. bin/aes_equiv_test holds the counter mode to "
        "quic_aes_soft.c, and bin/ghash_equiv_test holds the seal and the open "
        "to gcm.c's one-block counter loop and portable GHASH, which the "
        "gcm_safety and ghash harnesses prove, under a ch_cfg.cpu value with "
        "the AES bit. Delete this entry if a harness can ever compile the "
        "file."
    ),
    "gcm_vaes.c": (
        "an x86-64 host object's AES-GCM kernels, gcm_hw.c's three loops two "
        "blocks to a 256-bit register on the VAES, VPCLMULQDQ and AVX2 "
        "intrinsics, which CBMC cannot read, so no harness compiles the file, "
        "and with no body on any other target. The rounds, the byte shuffles "
        "and the hashing run on __m256i and __m128i values through the "
        "intrinsics and ghash_vector.h's functions, with int constants below "
        "256 for the shuffle orders and immediates. The scalar bitwise "
        "operators are counter_count's and set_counter_count's, which shift "
        "uint32_t values by the constants 8, 16 and 24, and the uint8_t "
        "counter_count ors in last widens to int and holds 0 to 255. "
        "fill_counters' (int) casts hand _mm256_setr_epi32 a uint32_t count, a "
        "conversion gcc and clang define as keeping its 32 bits, and no "
        "arithmetic runs on the int. The counts add as uint32_t, which wraps "
        "modulo 2^32 as GCM's inc32 does, and the offsets are size_t products "
        "of an index below the caller's count. On a CPU with VAES and "
        "VPCLMULQDQ, bin/aes_equiv_test holds the counter mode to "
        "quic_aes_soft.c, bin/ghash_equiv_test holds the seal and the open to "
        "gcm.c's proven one-block loop and portable GHASH, and "
        "bin/x86_kernels_test counts which calls run the kernels, under a "
        "ch_cfg.cpu value with the AES and VAES bits. Delete this entry if a "
        "harness can ever compile the file."
    ),
    "srv_out.c": (
        "the server's handshake output, one arm per transport. One bitwise "
        "operator in the file: the shift `(uint8_t)(n >> 8)` in "
        "srv_out_plain, which splits a record length into two header bytes "
        "by shifting a size_t right. Its left operand is unsigned, so the "
        "shift is defined and bugprone-signed-bitwise has nothing to say "
        "about it. These lines moved out of srv_flight.c, whose entry "
        "carried this same shift before the split. The refused-send paths "
        "compare int results and assign an alert constant, with no "
        "arithmetic. No harness runs this file: "
        "proof/srv_flight_harness.c covers the handlers that call it and "
        "returns no verdict, which proof/run.sh records. Delete this entry "
        "when srv_out.c gets a harness of its own."
    ),
    "srv_flight.c": (
        "the fifteen flight handlers. Every bitwise operator takes unsigned "
        "operands: `ch->suites`, `ch->groups` and `ch->shares` are uint8_t "
        "bitmasks (srv_parser.h:220-222) tested against uint8_t constants. "
        "The file now holds no shift at all: the one it had went to "
        "srv_out.c with the record writer. No operand is signed. "
        "proof/srv_flight_harness.c covers this file and returns no verdict "
        "with all fifteen handlers in one formula -- no answer in 55 minutes "
        "at --unwind 40, none at 20 or 18 -- which proof/run.sh records along "
        "with the layered split it needs. Delete this entry when that split "
        "gives it a launch line."
    ),
    "srv_quic.c": (
        "the QUIC server driver: the step table, the input loop and the three "
        "entry points. One bitwise operator in the file, the |= in announce. "
        "Both its operands are uint8_t values, which widen to int and hold 0 "
        "to 255: q->levels_ready, and CH_QUIC_LEVEL_BIT(level, direction), "
        "which shifts 1U by level * 2 + direction. That count is an int, and "
        "each call computes it from constants, CH_LEVEL_HANDSHAKE or "
        "CH_LEVEL_APPLICATION and CH_KEY_READ or CH_KEY_WRITE, so it is 2 to "
        "5. The rest compares and assigns step numbers, levels and return "
        "codes, and adds size_t offsets that n bounds. No harness runs this "
        "file: bin/srv_quic_test, bin/srv_quic_both_test and "
        "bin/quic_loop_test run its steps, and docs/verification.md lists it "
        "with no harness. Delete this entry when srv_quic.c gets a harness of "
        "its own."
    ),
    "srv_tcp_nonblocking.c": (
        "the ROLE=server tcp-nonblocking driver: the step table, the record "
        "loop and the two entry points. Two bitwise operators in the file, "
        "both in the expression with which ch_srv_record_in reads a record's "
        "length, ((size_t)rec[3] << 8) | rec[4]: a size_t shifted left by the "
        "constant 8, and a uint8_t, which widens to int and holds 0 to 255. "
        "The rest is size_t arithmetic: the room for the record_size_limit, "
        "buf_len less REC_HDR and AEAD_TAG under srv_config_ok's CH_MIN_RXBUF "
        "floor, and the record loop's lengths under the 0x4000 + 256 cap and "
        "n. proof/srv_tcp_nonblocking_harness.c covers this file and has no "
        "launch line, because its formula has never been seen to converge, "
        "which proof/run.sh records with the split it needs. "
        "bin/srv_tcp_nonblocking_test and bin/tcp_nonblocking_loop_test run it "
        "until then. Delete this entry when that split gives it a launch line."
    ),
    "tcp_nonblocking.c": (
        "the client's tcp-nonblocking driver and the two calls either role "
        "exports. Two bitwise operators in the file, both in the expression "
        "with which ch_record_in reads a record's length, ((size_t)rec[3] << "
        "8) | rec[4]: a size_t shifted left by the constant 8, and a uint8_t, "
        "which widens to int and holds 0 to 255. The rest is size_t "
        "arithmetic: the room for the record_size_limit under tlsi_config_ok's "
        "CH_MIN_RXBUF floor, the record loop's lengths under the 0x4000 + 256 "
        "cap and n, and ch_record_out's offsets under tx_len. No harness runs "
        "this file: bin/tcp_nonblocking_loop_test runs every call in it, and "
        "docs/verification.md lists it with no harness. Delete this entry when "
        "tcp_nonblocking.c gets a harness of its own."
    ),
    "tcp_nonblocking_step.c": (
        "the client's tcp-nonblocking step table. One bitwise operator in the "
        "file: tcp_nonblocking_stage_plain writes a record length's high byte "
        "as (uint8_t)(n >> 8), a size_t shifted right by the constant 8. The "
        "rest assigns step numbers and return codes and adds REC_HDR to a "
        "size_t length. No harness runs this file: "
        "bin/tcp_nonblocking_loop_test runs every step, and "
        "docs/verification.md lists it with no harness. Delete this entry when "
        "tcp_nonblocking_step.c gets a harness of its own."
    ),
}


# Sources that are another source's text compiled once more, each under a
# header of renames, and nothing else: `<file>_native.c` on the native multiply
# (widemul_native.h) and `<file>_hw.c` on a hash's instructions (hash_hw.h,
# keccak_hw.h). No harness compiles a copy, and none needs to. The harnesses of
# the source it copies prove the same text under other names, or its AUDITED
# entry reads that text, and an equivalence test holds the copy's output to
# the source's. So a copy passes when the source it copies does. Each entry
# names that source and says where the copy's text differs from what those
# harnesses compile. main() reads each copy's file on every run and fails the
# entry once the file holds anything but comments, preprocessor conditionals
# and includes, or includes a .c other than the one named here.
COPIES = {
    "poly1305_native.c": (
        "poly1305.c",
        "poly1305.c on the native multiply, under widemul_native.h's names. "
        "The poly1305 harness compiles that text on the native multiply too, "
        "because proof/run.sh passes it CH_NATIVE_WIDEMUL, except "
        "whole_blocks' arms for the vector paths and, on x86-64, "
        "poly1305_update_avx2, which only this copy compiles: size_t "
        "arithmetic on a byte count and a call of update with a constant, "
        "with no bitwise operator, which bin/poly1305_equiv_test runs."
    ),
    "mlkem_poly_native.c": (
        "mlkem_poly.c",
        "mlkem_poly.c on the native multiply, under widemul_native.h's names: "
        "the text the mlkem_poly harnesses compile, because proof/run.sh "
        "passes them CH_NATIVE_WIDEMUL."
    ),
    "poly1305_vector_native.c": (
        "poly1305_vector.c",
        "poly1305_vector.c's intrinsics under widemul_native.h's names: the "
        "text its AUDITED entry reads."
    ),
    "poly1305_avx2_native.c": (
        "poly1305_avx2.c",
        "poly1305_avx2.c's intrinsics under widemul_native.h's names: the "
        "text its AUDITED entry reads."
    ),
    "hkdf_hw.c": (
        "hkdf.c",
        "hkdf.c under hash_hw.h's names, which send its hash calls to "
        "sha256_hw.c and, on arm64, to sha512_hw.c. The hkdf and hkdf384 "
        "harnesses prove that text over the hashes' contracts, and "
        "bin/sha2_equiv_test holds the copy's output to hkdf.c's."
    ),
    "keysched_hw.c": (
        "keysched.c",
        "keysched.c under hash_hw.h's names, over hkdf_hw.c. The keysched and "
        "keysched384 harnesses prove that text but for the exporter's two "
        "calls, which no launch line proves for keysched.c either "
        "(docs/verification.md, keysched_exporter), and bin/sha2_equiv_test "
        "holds the copy's output to keysched.c's."
    ),
    "mlkem_hw.c": (
        "mlkem.c",
        "mlkem.c under keccak_hw.h's names, which send its SHA-3 and SHAKE "
        "calls to sha3_hw.c, with a body where sha3_hw.c has one. The mlkem "
        "harness proves that text but for the host arms of mlk_ntt, mlk_invntt "
        "and mlk_multiply_ntts, each one call into mlkem_vector.c, which its "
        "AUDITED entry reads and test/mlkem-builds.sh requires, and "
        "bin/mlkem_hw_equiv_test holds the copy's keys, ciphertexts and "
        "secrets to mlkem.c's."
    ),
    "mlkem_poly_hw.c": (
        "mlkem_poly.c",
        "mlkem_poly.c under keccak_hw.h's names, on ct.h's decomposition, as "
        "mlkem_poly.c compiles in every device object. The mlkem_poly "
        "harnesses prove that text on the native multiply, as they prove "
        "mlkem_poly.c, and proof/run.sh's launch() states what carries that "
        "verdict to the decomposition. bin/mlkem_hw_equiv_test holds the "
        "copy's output to mlkem_poly.c's."
    ),
}


# The two forms a stub body's marker takes, and the same pattern the
# Makefile's SRV_STUB_SRCS greps for; QUIC_STUB_SRCS read the other one
# until the TRANSPORT=quic-nonblocking mode was implemented. A file that still
# carries one holds no implementation to prove, so STUBBED below exempts
# it and the exemption ends on the commit that deletes the last marker in
# that file. The two build axes stub independently, which is why there
# are two names and not one. AUDITED would not retire that way: an entry
# there is checked only for presence, so it would outlive its reason.
STUB_MARKER = re.compile(r"(?m)^[ \t]*// CH_(QUIC|SRV)_STUB: ")


def root_sources():
    """The .c files git tracks at the root, where every library source sits:
    the tests, proofs, examples and tools sit in directories of their own."""
    r = subprocess.run(["git", "ls-files", "-z", "--", "*.c"], cwd=ROOT, capture_output=True)
    names = {os.fsdecode(p) for p in r.stdout.split(b"\0") if p and b"/" not in p}
    if r.returncode != 0 or not names:
        sys.exit("lint-proof-cover: git lists no .c file at the root, so the check that "
                 "every root source is shipped would check nothing")
    return names


def stubbed_sources(sources):
    """The shipped sources whose text still carries the stub marker.

    A stub returns the refusal its header documents and writes nothing,
    so it holds no arithmetic to prove absence of overflow over. The
    commit that implements the file deletes its last marker, and this
    set shrinks by itself on that commit, which is the retirement
    docs/quic.md and docs/server.md state for the markers."""
    return {s for s in sources
            if STUB_MARKER.search((ROOT / s).read_text())}


def harness_compiles(name):
    """Sources a harness pulls in: its own #include of a .c, plus its deps."""
    h = ROOT / "proof" / f"{name}_harness.c"
    if not h.exists():
        return set()
    return set(re.findall(r'#include\s+"([^"]+\.c)"', h.read_text()))


def full_covered():
    run = (ROOT / "proof" / "run.sh").read_text()
    covered = set()
    for m in re.finditer(r"^launch\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S*(.*)$", run, re.M):
        _tier, checks, name, rest = m.groups()
        if checks != "full":
            continue
        covered |= harness_compiles(name)
        covered |= {t for t in re.split(r"\s+", rest) if t.endswith(".c")}
    return covered


# What a copy's file may hold once its comments are gone: includes, and the
# conditionals that guard them, one directive to a line. A #define is not
# among them, because it could change which arms of the copied text compile.
COPY_DIRECTIVE = re.compile(r"#[ \t]*(include|if|ifdef|ifndef|else|endif)\b")
COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def copy_problem(copy, original):
    """Why copy is no longer original's text compiled once more, or None."""
    text = COMMENT.sub("", (ROOT / copy).read_text())
    for line in text.splitlines():
        if line.strip() and not COPY_DIRECTIVE.match(line.strip()):
            return f"holds a line of its own, `{line.strip()}`"
    included = INCLUDED_SOURCE.findall(text)
    if included != [original]:
        return f"includes {', '.join(included) or 'no .c file'} where COPIES names {original}"
    return None


def source_problem(src, covered, stubs):
    """Why src breaks the claim .clang-tidy's entry rests on, or None."""
    script = Path(__file__).name
    if src in covered:
        for table, names in (("AUDITED", AUDITED), ("COPIES", COPIES)):
            if src in names:
                return (f"{src} now has a full harness, so its {table} entry in {script} is "
                        f"stale. Delete it.")
        return None
    if src in stubs:
        return None
    if src in COPIES:
        original = COPIES[src][0]
        why = copy_problem(src, original)
        if why:
            return (f"{src} is in COPIES as {original}'s text compiled once more, but it "
                    f"{why}. Give it a harness, or read it and record what you found in "
                    f"AUDITED in {script}.")
        if original not in covered and original not in AUDITED:
            return (f"{src} is {original}'s text, and {original} has neither a full harness "
                    f"nor an AUDITED entry, so nothing covers the copy either.")
        return None
    if src not in AUDITED:
        return (f"{src} is shipped, no harness runs it under the `full` check set, and it is "
                f"not in AUDITED. Either give it a harness, or read it and record what you "
                f"found in {script}. .clang-tidy's bugprone-signed-bitwise entry rests on one "
                f"of those two being true for every shipped source.")
    return None


def main():
    sources = shipped_sources("lint-proof-cover")
    covered = full_covered()
    stubs = stubbed_sources(sources)
    problems = []

    unpackaged = root_sources() - sources
    for name in sorted(unpackaged):
        problems.append(
            f"{name} is a root source, and no build in BUILDS packages it or a source that "
            f"includes it. Name a build that packages it in tools/shipped_sources.py's BUILDS, "
            f"or move a file no object packages out of the root."
        )

    for src in sorted(sources):
        problem = source_problem(src, covered, stubs)
        if problem:
            problems.append(problem)

    for name in sorted(set(AUDITED) & set(COPIES)):
        problems.append(f"{name} is in both AUDITED and COPIES. Keep one entry.")
    # A root source outside the shipped set is the build list's gap, which
    # the first loop names, so its entry is not reported as stale as well.
    for table, names in (("AUDITED", AUDITED), ("COPIES", COPIES)):
        for name in sorted(set(names) - sources - unpackaged):
            problems.append(f"{table} lists {name}, which is not a shipped source. Delete it.")

    if problems:
        for p in problems:
            print(f"lint-proof-cover: {p}")
        return 1

    line = (f"lint-proof-cover: {len(sources - set(AUDITED) - set(COPIES) - stubs)} shipped "
            f"sources compiled by a harness with the signed-overflow class on, "
            f"{len(COPIES)} copies of such a source or an audited one, "
            f"{len(AUDITED)} audited by hand")
    if stubs:
        line += (f", {len(stubs)} still stubs that carry a stub marker "
                 f"and hold no code to prove")
    print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
