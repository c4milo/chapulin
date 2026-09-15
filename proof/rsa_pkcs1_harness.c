// Proves: the shipped rsa_pkcs1_verify — the body rsa_pkcs1.c compiles,
// called here directly — is memory-safe and UB-free over any modulus,
// digest, signature, claimed digest length and claimed signature length.
// Concrete (real bodies, real ct.c):
//
//   rsa_pkcs1_verify         : the size gate, the odd-modulus check, the
//                              DigestInfo selection, the greater_or_equal
//                              s >= n reject, the RSAVP1 call and the
//                              whole-buffer ct_memeq — end to end
//   emsa_pkcs1_v1_5_encode   : the fixed bytes, the PS fill, the separator,
//                              DigestInfo and digest copies, at the largest
//                              admitted length through verify and at the
//                              smallest, MODULUS_MIN, by a direct call —
//                              the shape where PS is shortest
//   greater_or_equal         : a direct lemma call over a fully nondet
//                              modulus and signature
//
// One stub replaces an already-proven layer at its link boundary, as
// rsa_harness.c does:
//
//   rsa_vp1 : asserts the rsa.h contract — n and sig readable and em
//             writable, all n_len bytes — and havocs em. The nondet em is
//             a strict superset of any sig^65537 mod n, so the compare
//             past the stub is proven over more values than the real
//             modexp can produce; rsa_mul_harness.c carries the modexp.
//
// Bounds. n_len is fixed to CH_RSA_MODULUS_MAX through verify (384; 512
// in the rsa_pkcs1_webpki variant, which sets CH_TRUST_WEBPKI): the
// largest admitted modulus is the binding case for every buffer index, and the
// smaller admitted sizes only shrink the fills — the reasoning
// rsa_harness.c records for the same pin. Unlike PSS there is no
// alignment to pin: v1.5 fills every em_len byte, so the modulus stays
// fully nondet. The claimed signature length and digest length stay
// nondet in the verify calls, so both sides of every gate run; the two
// admitted digest lengths then run explicitly, because a nondet length
// that happens to land on 32 or 48 is not a proof that each did.
#include "harness.h"

#include "ct.h"
#include "rsa.h"

#include "rsa_pkcs1.c"

// rsa_vp1 stub: assert the link-boundary contract rsa.h states, havoc em.
// rsa_pkcs1.c has already established sig < n (hence n > 0) here.
void rsa_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em) {
    __CPROVER_assert(__CPROVER_r_ok(n, n_len), "vp1: n readable");
    __CPROVER_assert(__CPROVER_r_ok(sig, n_len), "vp1: sig readable");
    __CPROVER_assert(__CPROVER_w_ok(em, n_len), "vp1: em writable");
    fill_nondet(em, n_len);
}

int main(void) {
    size_t n_len = CH_RSA_MODULUS_MAX;
    uint8_t n[CH_RSA_MODULUS_MAX];
    uint8_t sig[CH_RSA_MODULUS_MAX];
    uint8_t digest[SHA384_LEN];
    fill_nondet(n, n_len);
    fill_nondet(sig, n_len);
    fill_nondet(digest, sizeof digest);

    // The lemma over fully nondet operands, apart from the gate.
    (void)greater_or_equal(sig, n, n_len);

    // The shipped function end to end: nondet claimed lengths first, so
    // every gate's reject runs; then each admitted digest length, so the
    // encode and the compare run at both.
    (void)rsa_pkcs1_verify(n, n_len, digest, nondet_size_t(), sig, nondet_size_t());
    (void)rsa_pkcs1_verify(n, n_len, digest, SHA256_LEN, sig, n_len);
    (void)rsa_pkcs1_verify(n, n_len, digest, SHA384_LEN, sig, n_len);

    // The encoder at the smallest admitted length, where PS is shortest,
    // for the longer DigestInfo and digest.
    uint8_t em[CH_RSA_MODULUS_MAX];
    emsa_pkcs1_v1_5_encode(em, MODULUS_MIN, digest_info_sha384, digest, SHA384_LEN);
    return 0;
}
