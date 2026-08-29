// Contract stubs for the primitives aead.c calls, so the AEAD harnesses
// prove aead.c's own framing rather than re-deriving ChaCha20 and
// Poly1305 inside every formula.
//
// Why this exists: aead, aead_overlap and aead_forge compiled chacha20.c
// and poly1305.c concretely and returned no verdict in five hours, every
// night. Bisecting showed no single input dimension was to blame --
// pinning the lengths did not help, pinning the key and nonce did not
// help -- while each primitive proves on its own in under a minute
// (chacha20 17 s, poly1305 56 s). What does not fit is the shape: the
// whole pipeline runs twice over symbolic data with equality constraints
// tying seal and open together. See
// https://github.com/c4milo/chapulin/issues/56.
//
// WHAT THESE MODEL, and therefore what the harnesses still prove:
//
//   chacha20_xor  out[i] = in[i] ^ ks[i], for a keystream that is the same
//                 on every call with the same key, nonce and counter. Both
//                 halves are load-bearing. The XOR structure is what makes
//                 a round-trip provable at all, and the sameness is what
//                 lets open undo seal.
//   chacha20_block  the same keystream, one block of it.
//   poly1305_*    a tag that is a function of the bytes absorbed and
//                 nothing else, so the same message tags the same way and
//                 a different one need not.
//
// WHAT THIS NO LONGER PROVES: that the shipped ChaCha20 and Poly1305 meet
// those contracts. That is not left unproven, it moves: chacha20_harness
// and poly1305_harness check both against their RFC 8439 reference at
// concrete bounds, and the unit vectors and the Lean differential cover
// them over far more inputs than a solver reaches. The composition is an
// argument, not a machine-checked step, and this comment is where that
// argument is written down.
//
// The keystream and the tag are symbolic and havoc'd once, never chosen by
// the harness, so nothing below assumes a value either primitive produces.
#ifndef CH_AEAD_STUBS_H
#define CH_AEAD_STUBS_H

#include "chacha20.h"
#include "poly1305.h"

// One ChaCha20 block, the longest single run any AEAD harness asks for:
// chacha20_block wants all 64, and the data calls stay inside the 16-byte
// plaintext bound.
#define STUB_KS_MAX CHACHA20_BLOCK

// One keystream per counter value aead.c uses: 0 for the Poly1305 key
// block, 1 for the data. Havoc'd once at first use, so every call with the
// same counter sees the same bytes -- the determinism the round-trip
// rests on.
static uint8_t stub_ks[2][STUB_KS_MAX];
static int stub_ks_ready;

static void stub_ks_init(void) {
    if (!stub_ks_ready) {
        fill_nondet(stub_ks[0], sizeof stub_ks[0]);
        fill_nondet(stub_ks[1], sizeof stub_ks[1]);
        stub_ks_ready = 1;
    }
}

void chacha20_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                  uint32_t counter, const uint8_t *in, uint8_t *out, size_t n) {
    __CPROVER_assert(__CPROVER_r_ok(key, CHACHA20_KEY), "chacha20_xor: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, CHACHA20_NONCE), "chacha20_xor: nonce readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "chacha20_xor: input readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(out, n), "chacha20_xor: output writable");
    __CPROVER_assert(counter < 2, "chacha20_xor: counter is one aead.c uses");
    __CPROVER_assert(n <= STUB_KS_MAX, "chacha20_xor: within the modelled keystream");
    stub_ks_init();
    // Ascending order, matching the contract chacha20.h states for the
    // overlap the record layer relies on: each address is written only
    // after it was last read.
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)(in[i] ^ stub_ks[counter][i]);
    }
}

void chacha20_block(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    uint32_t counter, uint8_t out[CHACHA20_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(key, CHACHA20_KEY), "chacha20_block: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, CHACHA20_NONCE), "chacha20_block: nonce readable");
    __CPROVER_assert(__CPROVER_w_ok(out, CHACHA20_BLOCK), "chacha20_block: output writable");
    __CPROVER_assert(counter < 2, "chacha20_block: counter is one aead.c uses");
    stub_ks_init();
    for (size_t i = 0; i < CHACHA20_BLOCK; i++) {
        out[i] = stub_ks[counter][i];
    }
}

// The tag depends on the bytes absorbed and nothing else. h carries a
// running value over them; the particular mixing does not matter, only
// that it is a function of the sequence, because that is what makes a
// genuine seal open and a changed one not.
//
// The mixing is a rotate and an xor rather than the obvious multiply-and-
// add. A multiply chain over symbolic bytes is the shape that made these
// harnesses unsolvable in the first place, and reintroducing it in the
// stub would have traded one unsolvable formula for another.
void poly1305_init(poly1305 *p, const uint8_t key[POLY1305_KEY]) {
    __CPROVER_assert(__CPROVER_w_ok(p, sizeof *p), "poly1305_init: state writable");
    __CPROVER_assert(__CPROVER_r_ok(key, POLY1305_KEY), "poly1305_init: key readable");
    for (int i = 0; i < 5; i++) {
        p->h[i] = 0;
    }
    for (int i = 0; i < 4; i++) {
        p->h[0] = ((p->h[0] << 1) | (p->h[0] >> 31)) ^ key[i];
    }
    p->fill = 0;
}

void poly1305_update(poly1305 *p, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_r_ok(p, sizeof *p), "poly1305_update: state readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "poly1305_update: input readable");
    for (size_t i = 0; i < n; i++) {
        p->h[0] = ((p->h[0] << 1) | (p->h[0] >> 31)) ^ in[i];
    }
    p->fill += n;
}

void poly1305_final(poly1305 *p, uint8_t tag[POLY1305_TAG]) {
    __CPROVER_assert(__CPROVER_r_ok(p, sizeof *p), "poly1305_final: state readable");
    __CPROVER_assert(__CPROVER_w_ok(tag, POLY1305_TAG), "poly1305_final: tag writable");
    for (size_t i = 0; i < POLY1305_TAG; i++) {
        tag[i] = (uint8_t)(p->h[0] >> (8 * (i % 4)));
    }
}

#endif
