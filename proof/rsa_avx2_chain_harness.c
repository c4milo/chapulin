// Proves: each step of rsa_avx2_public reads and writes inside its arrays
// at CHAIN_WORDS words, over any base bytes, any modulus words, any m0inv
// and any digit_r2 words. main below makes the calls rsa_avx2_public
// makes, in its order and on arrays of the sizes it passes, and makes each
// once: modulus_from_words; words_to_digits on digit_r2; multiply_by_base,
// which marshals the base, converts it into digits and multiplies; one
// square; and write_result, which converts the digits back to words,
// subtracts m once and marshals the bytes out. rsa_avx2_public runs the
// same calls on the same arrays, with sixteen squares where this runs one
// and multiply_by_base a second time before write_result.
//
// The lines run the smallest and the largest word count of each copy of
// the product:
//   rsa_avx2_chain_32          32 words, 19 groups of 28-bit digits
//                              (RSA-2048), the smallest count
//   rsa_avx2_chain             48 words, 28 groups (RSA-3072), the largest
//                              a default build admits
//   rsa_avx2_chain_49_webpki   49 words, 30 groups of 27-bit digits, the
//                              smallest the 27-bit copies take, under
//                              CH_TRUST_WEBPKI
//   rsa_avx2_chain_webpki      64 words, 38 groups (RSA-4096), the most
//                              rsa_avx2_public takes
// At a count between them the product runs the same statements. Each index
// of a lane it reads or writes is at least a constant, the same at every
// count, and at most a sum that grows with the group count G, for the
// digit count n is above 4(G - 1) and at most 4G. So the largest count of
// each copy runs its highest indices. That argument is not proved.
// rsa_avx2_sums_harness.c runs every digit count of 2 and 3 groups, and
// rsa_avx2_number_harness.c runs the conversions at every word count.
//
// Why not rsa_avx2_public whole: a line that called it at 32 words, with
// its eighteen products, returned no verdict in 1200 s, all of it symbolic
// execution. One multiplication at 19 groups took 12 s, and four 114 s:
// each product's symbolic execution costs more than the last.
//
// The base, the output and digit_r2 are arrays of exactly the length the
// calls read or write, so a read or a write past one fails. The length is
// 8 * CHAIN_WORDS bytes, the one length rsa_vp1_cpu passes: it takes the
// kernel only for a modulus whose bit length is 64 times its word count,
// which is a modulus of 8k bytes. The output is apart from the base, as
// rsa_vp1_cpu's callers pass them.
//
// Every lane operation is the contract proof/rsa_avx2_stubs.h states under
// RSA_AVX2_STUB_EVERY_LANE_OPERATION, which rsa_avx2_lanes_harness.c
// discharges: a load reads four words, a store writes four, and every
// value is any value. No index or branch in the file reads a lane, so the
// contracts cost the proof nothing it claims.
//
// The lines run without --unsigned-overflow-check: under these contracts a
// lane is any value, so the triangle's sums could wrap where the real
// lanes never do. That no sum wraps is rsa_avx2_sums_harness.c's claim,
// over the model's real operations but the multiplications.
//
// What it does not prove: that the bytes it writes are base^65537 mod m.
// spec/lean/Spec/RsaAvx2.lean's publicOp_eq proves that of its model of
// the C, and bin/rsa_avx2_model_test holds the C against rsa_mont64.c at
// every word count from 32 to 64.
#define RSA_AVX2_STUB_EVERY_LANE_OPERATION 1
#include "rsa_avx2_stubs.h"

#include "rsa_avx2.c"

#ifndef CHAIN_WORDS
#define CHAIN_WORDS RSA_MONT64_WORDS_MAX
#endif

int main(void) {
    rsa_mont64_modulus mod;
    uint64_t digit_r2[CHAIN_WORDS];
    uint8_t base[8 * CHAIN_WORDS];
    uint8_t out[8 * CHAIN_WORDS];
    havoc_modulus(&mod, CHAIN_WORDS);
    havoc_words(digit_r2, CHAIN_WORDS);
    fill_nondet(base, sizeof base);

    rsa_avx2_modulus modulus;
    modulus_from_words(&modulus, &mod);
    _Alignas(32) uint64_t power[NUMBER_LANES];
    words_to_digits(power, digit_r2, CHAIN_WORDS, modulus.digit_count, modulus.bits);
    multiply_by_base(power, base, sizeof base, CHAIN_WORDS, &modulus);
    square(power, power, &modulus);
    write_result(out, sizeof out, power, &modulus, &mod);
    return 0;
}
