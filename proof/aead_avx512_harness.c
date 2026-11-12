// Proves: aead_avx512_seal and aead_avx512_open read inside their input and
// the context, and write inside their output, the context and their own
// frames, for the three ways a message ends: a whole pass, a row pass of 1
// to 256 bytes beside the last whole pass, and a pass of sixteen blocks over
// 257 to 1,023 bytes, at two passes and the rest, with the output on the
// input or apart from it. The rest is a constant of each launch line, so
// symbolic execution knows where each loop over passes and groups ends:
// this file proves a rest of 0, aead_avx512_row_harness.c a rest of 37,
// and aead_avx512_last_harness.c a rest of 300. Their CH_ASSERTs hold for those n, and every other
// check of the full set runs: bounds, pointers, shifts and signed overflow.
// The open's last region runs chacha20_avx512.c's own text, so its accesses
// are proved too. ct_wipe is proof/ct_wipe_stub.c's loop, so the proof also
// shows each wipe writes inside its object.
//
// The two files compile over test/chacha20_avx512_model_lanes.h and
// test/poly1305_ifma_model_lanes.h, the models of each instruction in
// portable C that bin/aead_avx512_equiv_test runs on every machine. The
// harness defines POLY1305_IFMA_STUBS_ANY_PRODUCT, so each IFMA
// multiplication adds any value: no memory access reads a lane, and the
// poly1305_ifma harnesses prove the operands' bound and the sums of a group
// on the contracts in proof/poly1305_ifma_stubs.h. poly1305_update_native,
// which the last blocks after the groups run, is a stub here that reads
// each byte it is given; the poly1305 harnesses prove its own accesses.
#include <stdlib.h>

#ifndef AEAD_AVX512_PROOF_REST
#define AEAD_AVX512_PROOF_REST 0
#endif

#define POLY1305_IFMA_STUBS_ANY_PRODUCT 1
#include "poly1305_ifma_stubs.h"

#include "chacha20_avx512.c"

#include "aead_avx512.c"

// poly1305.c's update, which hash_rest calls under widemul_native.h's name
// for the bytes after the last group: it reads each of them.
void poly1305_update_native(poly1305 *p, const uint8_t *in, size_t n) {
    uint8_t sum = 0;
    for (size_t i = 0; i < n; i++) {
        sum ^= in[i];
    }
    p->h[0] ^= sum;
}

int main(void) {
    size_t n = AEAD_AVX512_MIN + AEAD_AVX512_PROOF_REST;
    int in_place = nondet_size_t() % 2 == 0;
    uint8_t *in = malloc(n);
    __CPROVER_assume(in != NULL);
    uint8_t *out = in;
    if (!in_place) {
        out = malloc(n);
        __CPROVER_assume(out != NULL);
    }
    fill_nondet(in, n);
    uint8_t key[CHACHA20_KEY];
    uint8_t nonce[CHACHA20_NONCE];
    fill_nondet(key, sizeof key);
    fill_nondet(nonce, sizeof nonce);
    poly1305 p;
    for (size_t i = 0; i < 5; i++) {
        p.r[i] = nondet_u32();
        p.h[i] = nondet_u32();
    }
    p.fill = 0;
    if (nondet_size_t() % 2 == 0) {
        aead_avx512_seal(key, nonce, &p, in, n, out);
    } else {
        aead_avx512_open(key, nonce, &p, in, n, out);
    }
    if (!in_place) {
        free(out);
    }
    free(in);
    return 0;
}
