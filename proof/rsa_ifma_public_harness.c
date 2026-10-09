// Proves: rsa_ifma_public, whole, reads and writes inside its arrays at
// PUBLIC_WORDS words, over any base bytes, any modulus words, any m0inv
// and any digit_r2 words: the marshalling of the base, the conversions of
// the modulus, the base and digit_r2 into digits, the eighteen products in
// the copy for the word count's register count, the conversion back to
// words, the last subtraction and the marshalling out.
//
// The lines run the smallest and the largest register count of each
// build:
//   rsa_ifma_public_5       32 words,  5 registers (RSA-2048)
//   rsa_ifma_public         48 words,  8 registers (RSA-3072), the
//                           largest a default build admits
//   rsa_ifma_public_webpki  64 words, 10 registers (RSA-4096), under
//                           CH_TRUST_WEBPKI
// rsa_ifma_product_harness.c runs the copies of the product for the
// register counts between them.
//
// The base, the output and digit_r2 are arrays of exactly the length the
// call reads or writes, so a read or a write past one fails. The length is
// 8 * PUBLIC_WORDS bytes, the one length rsa_vp1_cpu passes: it takes this
// call only for a modulus whose bit length is 64 times its word count,
// which is a modulus of 8k bytes. The output is apart from the base, as
// rsa_vp1_cpu's callers pass them.
//
// Every lane operation is the contract proof/rsa_ifma_stubs.h states under
// RSA_IFMA_STUB_EVERY_LANE_OPERATION, which rsa_ifma_lanes_harness.c
// discharges: a load reads eight words, a store writes eight, and every
// value is any value. No index or branch in the file reads a lane, so the
// contracts cost the proof nothing it claims.
//
// The lines run without --unsigned-overflow-check: under these contracts
// a lane is any value, so digit_zero's add of one could wrap where the
// real lanes never do. That no sum wraps is rsa_ifma_sums_harness.c's
// claim, over the model's real operations but the multiplications.
//
// What it does not prove: that the bytes it writes are base^65537 mod m.
// bin/rsa_ifma_model_test holds that against rsa_mont64.c at every word
// count from 32 to 64.
#define RSA_IFMA_STUB_EVERY_LANE_OPERATION 1
#include "rsa_ifma_stubs.h"

#include "rsa_ifma.c"

#ifndef PUBLIC_WORDS
#define PUBLIC_WORDS RSA_MONT64_WORDS_MAX
#endif

int main(void) {
    rsa_mont64_modulus mod;
    uint64_t digit_r2[PUBLIC_WORDS];
    uint8_t base[8 * PUBLIC_WORDS];
    uint8_t out[8 * PUBLIC_WORDS];
    havoc_modulus(&mod, PUBLIC_WORDS);
    havoc_words(digit_r2, PUBLIC_WORDS);
    fill_nondet(base, sizeof base);
    rsa_ifma_public(out, base, sizeof base, &mod, digit_r2);
    return 0;
}
