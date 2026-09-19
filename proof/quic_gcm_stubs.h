// Contract stub for the one function quic_gcm.c calls, so the GCM
// harness proves GCM's own framing rather than re-deriving AES-128
// inside the formula.
//
// Why this exists: the same reason proof/aead_stubs.h exists. gcm_seal
// and gcm_open each run the forward cipher once per block plus twice
// more, and a round-trip property runs the whole pipeline twice over
// symbolic data with equality constraints tying the two halves together.
// That is the shape that made the AEAD harnesses unsolvable
// (https://github.com/c4milo/chapulin/issues/56), and quic_aes.c proves
// on its own in 23 s (proof/run.sh's quic_aes line).
//
// WHAT THIS MODELS, and therefore what the harness still proves:
//
//   aes_encrypt_block  16 output bytes that are a function of the 16
//                      input bytes and nothing else. Both halves are
//                      load-bearing. Being a function is what lets a
//                      genuine seal open, because seal and open build
//                      the same counter blocks and must get the same
//                      keystream from them. Depending on the input is
//                      what keeps a different counter block from
//                      silently giving the same bytes, which would hide
//                      a wrong inc32.
//
// The mixing below is a rotate and an xor, never a multiply, for the
// reason proof/aead_stubs.h states: a multiply chain over symbolic bytes
// is what made those formulas unsolvable, and a stub that reintroduced
// it would trade one unsolvable formula for another.
//
// WHAT THIS NO LONGER PROVES: that quic_aes.c meets that contract. That
// moves to quic_aes_harness, which proves the real cipher and the real
// key schedule over unconstrained inputs, and to the FIPS 197 and RFC
// 9001 Appendix A vectors in test/quic_vectors.c.
#ifndef CH_QUIC_GCM_STUBS_H
#define CH_QUIC_GCM_STUBS_H

#include "quic_aes_key.h"

// One havoc'd 16-byte value, mixed into every answer so that no output
// byte is a constant the harness chose. Filled once, at first use, so
// every call sees the same value.
static uint8_t stub_cipher_salt[AES_BLOCK];
static int stub_cipher_ready;

static void stub_cipher_init(void) {
    if (!stub_cipher_ready) {
        fill_nondet(stub_cipher_salt, sizeof stub_cipher_salt);
        stub_cipher_ready = 1;
    }
}

void aes_encrypt_block(const aes_public_key *k, const uint8_t in[AES_BLOCK],
                       uint8_t out[AES_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "aes_encrypt_block: key readable");
    __CPROVER_assert(__CPROVER_r_ok(in, AES_BLOCK), "aes_encrypt_block: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, AES_BLOCK), "aes_encrypt_block: output writable");
    stub_cipher_init();
    // Built in a local first, so a caller that passes one buffer twice
    // gets an answer that reads every input byte before writing any.
    uint8_t state[AES_BLOCK];
    for (size_t i = 0; i < AES_BLOCK; i++) {
        state[i] = (uint8_t)(in[i] ^ stub_cipher_salt[i]);
    }
    // Two passes, each carrying every byte seen so far into the next, so
    // the answer depends on all 16 input bytes rather than on the byte at
    // the same index.
    uint8_t carry = stub_cipher_salt[0];
    for (size_t i = 0; i < AES_BLOCK; i++) {
        carry = (uint8_t)(((carry << 1) | (carry >> 7)) ^ state[i]);
        state[i] = carry;
    }
    for (size_t i = AES_BLOCK; i > 0; i--) {
        carry = (uint8_t)(((carry << 3) | (carry >> 5)) ^ state[i - 1]);
        state[i - 1] = carry;
    }
    for (size_t i = 0; i < AES_BLOCK; i++) {
        out[i] = state[i];
    }
}

#endif
