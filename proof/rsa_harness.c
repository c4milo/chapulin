// Proves: everything a hostile signature reaches in rsa_pss_verify is
// memory-safe and UB-free, CONCRETE (real bodies, real ct.c):
//
//   ge_bytes            : the s >= n reject over any modulus/signature
//   modulus_bits        : the top-bit scan over any modulus, and that its
//                         result feeds emBits/emLen/off with no underflow
//   from_bytes/to_bytes : the byte<->limb marshalling RSAVP1 runs over the
//                         attacker's n and sig, both directions
//   the I2OSP leading-zero scan over the RSAVP1 output em, at the general
//                         (symbolic) offset
//   emsa_pss_verify     : the whole PSS/MGF1 decode — MGF1 masking into
//                         db[MAXLEN], the maskedDB XOR, the top-bit clear,
//                         the PS/0x01/salt walk, and H' via ct_memeq
//
// Bounds. nlen is fixed to MAXLEN (96 limbs): the largest admitted modulus
// is the binding case for every buffer bound and index, and the smaller
// admitted sizes only shrink the loop counts — the same representative-
// bound reasoning handshake_harness uses for its receive buffer. The
// modulus, signature, and hash bytes are all nondet, so ge_bytes,
// modulus_bits, the emLen/off arithmetic, and the leading-zero scan see
// their whole range. The decode runs at emLen == nlen (offset 0), the
// alignment with the maximal db/salt indices; a shorter emLen only pulls
// those indices in, so the max is the case to prove, and boundary emLen
// (66 valid, 65 early-return) is exercised alongside it. em, the value
// RSAVP1 hands the decoder, is nondet throughout, so every decode branch
// runs against arbitrary bytes.
//
// Not unrolled: the RSAVP1 modexp itself. Past from_bytes/to_bytes the
// 16-square-plus-multiply ladder is ~9k symbolic Montgomery multiplies per
// mont_mul over 96 limbs and never leaves symex, the RSA counterpart of
// x25519's mul-vs-SAT split. mont_mul, mont_r2, and rsa_vp1 are therefore
// never called here; their carry arithmetic is rsa_mul_harness.c. em enters
// fully nondet — a strict superset of any sig^65537 mod n — so nothing the
// decode proves rests on a modexp value. This mirrors p256_harness leaving
// point_mul/mod_inv undriven. sha256 is stubbed to its proven contract
// (sha256_harness); the decode's memory shape never depends on a digest.
//
// The prologue is replicated from rsa_pss_verify statement for statement,
// substituting nondet em for the RSAVP1 call. Past the ge_bytes reject
// sig < n holds, hence n > 0 and modulus_bits does not return 0 (no embits
// underflow) — the reason the gate order matters.
#include "harness.h"

#include "ct.h"
#include "sha256.h"

uint32_t nondet_u32(void);

// sha256 stubs: assert the contract the real code relies on, havoc the
// digest. MGF1's block loop and byte accounting stay concrete.
void sha256_init(sha256 *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha: ctx writable");
}

void sha256_update(sha256 *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha: input readable");
}

void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "sha: ctx writable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "sha: out writable");
    fill_nondet(out, SHA256_LEN);
}

#include "rsa.c"
#include "rsa_mont.c"

int main(void) {
    // The wire surface: any modulus, signature, and message hash bytes.
    size_t nlen = MAXLEN;
    size_t k = nlen / 4;
    uint8_t n[MAXLEN];
    uint8_t sig[MAXLEN];
    uint8_t hash[HLEN];
    fill_nondet(n, nlen);
    fill_nondet(sig, nlen);
    fill_nondet(hash, HLEN);

    // Length gate then s >= n reject (covers s == n, s == n + 1). Public
    // bytes, big-endian direct compare.
    size_t siglen = nondet_size_t();
    if (siglen != nlen) {
        return 0;
    }
    if (ge_bytes(sig, n, nlen)) {
        return 0;
    }

    // byte<->limb marshalling RSAVP1 runs over the attacker's bytes: n and
    // sig into limbs, and a limb vector back out. The ladder between them is
    // the undriven modexp; em below stands in for its result.
    uint32_t ml[MAXLIMBS];
    uint32_t bl[MAXLIMBS];
    uint32_t acc[MAXLIMBS];
    uint8_t em_ser[MAXLEN];
    from_bytes(ml, n, k);
    from_bytes(bl, sig, k);
    for (size_t i = 0; i < k; i++) {
        acc[i] = nondet_u32();
    }
    to_bytes(em_ser, acc, k);
    (void)em_ser;

    // em = RSAVP1 output, nondet over its whole nlen-byte width.
    uint8_t em[MAXLEN];
    fill_nondet(em, nlen);

    // emBits = modBits - 1; emLen = ceil(emBits / 8); the I2OSP-dropped
    // leading bytes must be zero. modulus_bits and this scan run at the
    // general offset over hostile n and em.
    size_t embits = modulus_bits(n, nlen) - 1;
    size_t emlen = (embits + 7) / 8;
    size_t off = nlen - emlen;
    for (size_t i = 0; i < off; i++) {
        if (em[i] != 0) {
            return 0;
        }
    }
    __CPROVER_assert(off <= nlen, "I2OSP offset in bounds"); // em + off is valid

    // The decode at the binding alignment (emLen == nlen, maximal indices),
    // and at the length-check boundary (66 valid, 65 early-return).
    (void)emsa_pss_verify(hash, em, nlen, 8 * nlen - 1);
    (void)emsa_pss_verify(hash, em, 66, 66 * 8 - 1);
    (void)emsa_pss_verify(hash, em, 65, 65 * 8 - 1);
    return 0;
}
