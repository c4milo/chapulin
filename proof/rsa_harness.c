// Proves: the shipped rsa_pss_verify — the body rsa.c compiles, called
// here directly, no replicated lines — is memory-safe and UB-free over
// any signature, hash, signature length, and modulus value. Concrete
// (real bodies, real ct.c):
//
//   rsa_pss_verify  : the sig_len != n_len reject, the greater_or_equal s >= n
//                     reject (covers s == n, s == n + 1), modulus_bits
//                     feeding emBits/emLen/off, the I2OSP leading-zero
//                     scan, and the decode call — end to end, three
//                     times: at off == 0 (emLen == n_len), at off == 1
//                     behind a leading zero byte (the scan really runs,
//                     the decode sits one byte in), and at off == 1
//                     with zero_bits == 0 (the decode's top_mask shift at
//                     its distance-8 edge, a shape no other case hits)
//   emsa_pss_verify : the whole PSS/MGF1 decode — MGF1 masking into
//                     db[MODULUS_MAX], the maskedDB XOR, the top-bit clear,
//                     the PS/0x01/salt walk, and H' via ct_memeq
//   greater_or_equal, modulus_bits : direct lemma calls over a fully nondet
//                     modulus and signature (see below)
//
// Two stubs replace already-proven layers at their link boundaries:
//
//   rsa_vp1 : asserts the rsa.h contract — n and sig readable and em
//             writable, all n_len bytes — and havocs em. The nondet em
//             is a strict superset of any sig^65537 mod n, so every
//             branch past the stub is proven over more values than the
//             real modexp can produce; nothing proved here rests on a
//             modexp value. The modexp itself never enters symex (~9k
//             symbolic Montgomery multiplies per mont_mul over 96
//             limbs, the RSA counterpart of x25519's mul-vs-SAT split);
//             its carry arithmetic and byte<->limb marshalling are
//             rsa_mul_harness.c. This mirrors p256_harness leaving
//             point_mul/mod_inv undriven.
//   sha256  : asserts the contract the real code relies on, havocs the
//             digest (proven in sha256_harness). MGF1's block loop and
//             byte accounting stay concrete; the decode's memory shape
//             never depends on a digest value.
//
// Bounds. n_len is fixed to MODULUS_MAX (96 limbs): the largest admitted
// modulus is the binding case for every buffer bound and index, and the
// smaller admitted sizes only shrink the loop counts — the same
// representative-bound reasoning handshake_harness uses for its receive
// buffer (a fully symbolic n_len blew past 10 GB). The same reasoning
// pins the top modulus byte per call: emLen and off are functions of
// the top set bit alone, and leaving that bit symbolic drags every
// decode index through a symbolic offset — measured at 7 GB of CNF,
// which crashes kissat — while the decode's memory shape depends only
// on the offset, never on modulus values (em comes nondet from the
// stub, unlinked to n). Each call therefore pins the alignment and
// havocs everything else, and the alignment cases bind: off == 0 puts
// every db/salt index at its maximum, off == 1 adds the one-byte-in
// shape and (via a 0x01 top byte) the zero_bits == 0 top_mask edge, and
// a larger off only pulls indices further in. The emLen length-check
// boundary (66 valid-edge, 65 early-return) and the maximal emLen run
// as direct emsa_pss_verify calls over fresh nondet bytes. What the
// pinned bytes skip — greater_or_equal and modulus_bits over arbitrary moduli
// — direct lemma calls restore at full generality, together with the
// two facts the off arithmetic rests on: past the s >= n reject n > 0
// holds, so modulus_bits cannot return 0 and emBits = bits - 1 cannot
// underflow; and bits <= 8*n_len keeps emLen <= n_len, so off cannot
// wrap. The pinned bytes only fold into constant offsets when symex
// expands the byte arrays element-wise, so the launch line raises
// --max-field-sensitivity-array-size above the 384-byte width; without
// it the decode goes symbolic and the CNF lands back at 7 GB.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include "ct.h"
#include "sha256.h"

// sha256 stubs: assert the contract the real code relies on, havoc the
// digest. MGF1's block loop and byte accounting stay concrete.

#include "rsa.c"

// rsa_vp1 stub: assert the link-boundary contract rsa.h states, havoc
// em. rsa.c has already established sig < n (hence n > 0) at this point.
void rsa_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em) {
    __CPROVER_assert(__CPROVER_r_ok(n, n_len), "vp1: n readable");
    __CPROVER_assert(__CPROVER_r_ok(sig, n_len), "vp1: sig readable");
    __CPROVER_assert(__CPROVER_w_ok(em, n_len), "vp1: em writable");
    fill_nondet(em, n_len);
}

int main(void) {
    // The wire surface: any modulus, signature, and message hash bytes,
    // any claimed signature length.
    size_t n_len = MODULUS_MAX;
    uint8_t n[MODULUS_MAX];
    uint8_t sig[MODULUS_MAX];
    uint8_t hash[HLEN];
    fill_nondet(n, n_len);
    fill_nondet(sig, n_len);
    fill_nondet(hash, HLEN);

    // greater_or_equal and modulus_bits over the fully nondet n and sig, and the
    // two lemmas the off arithmetic in rsa_pss_verify rests on.
    size_t bits = modulus_bits(n, n_len);
    __CPROVER_assert(bits <= 8 * n_len, "modulus_bits bounded by the byte width");
    if (!greater_or_equal(sig, n, n_len)) {
        __CPROVER_assert(bits >= 1, "sig < n implies n > 0: emBits cannot underflow");
    }

    // The shipped function, end to end, at three alignment shapes. A
    // concrete top byte pins off and emBits (see header); sig, hash,
    // sig_len, and the remaining modulus bytes stay nondet, so both
    // sides of the sig_len gate, the s >= n reject, the scan, and the
    // decode all run in every call.
    n[0] = 0x80; // top bit set: emLen == n_len, off == 0, zero_bits == 1
    (void)rsa_pss_verify(n, n_len, hash, sig, nondet_size_t());
    n[0] = 0;
    n[1] = 0x80; // leading zero byte walked: off == 1, zero_bits == 1
    (void)rsa_pss_verify(n, n_len, hash, sig, nondet_size_t());
    n[0] = 0x01; // bottom-bit top byte: off == 1, zero_bits == 0 — the
                 // decode's top_mask shift at its distance-8 edge
    (void)rsa_pss_verify(n, n_len, hash, sig, nondet_size_t());

    // The decode at the length-check boundary (66 valid-edge, 65
    // early-return) and at the maximal emLen, over arbitrary bytes.
    uint8_t em[MODULUS_MAX];
    fill_nondet(em, n_len);
    (void)emsa_pss_verify(hash, em, n_len, 8 * n_len - 1);
    (void)emsa_pss_verify(hash, em, 66, 66 * 8 - 1);
    (void)emsa_pss_verify(hash, em, 65, 65 * 8 - 1);
    return 0;
}
