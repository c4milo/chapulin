// Ephemeral Diffie-Hellman over P-256 (see p256_ecdh.h for the
// contracts). Three entries live here and nothing else: key generation,
// the peer-point check and the exchange itself. The arithmetic is
// p256_point.c's and p256_scalar.c's, which p256_sign.c calls too, so
// one complete addition formula and one scalar multiplication serve both
// and an auditor reads them once.
//
// Two choices keep the private scalar off the control path, and both sit
// in p256_point.c: the addition is complete, so no branch on equality or
// on infinity exists to remove, and the multiply is a Montgomery ladder,
// so a scalar bit only picks which running point is which.
//
// The branches this file does have read public values, and each one says
// so at the line.
#include "p256_ecdh.h"

#include <stddef.h>

#include "ct.h"
#include "p256_field.h"
#include "p256_point.h"
#include "p256_scalar.h"

// All ones when k holds a scalar in [1, n-1], zero otherwise. Both
// predicates are p256_scalar.c's, over the group order that file already
// carries, so no copy of n sits in this file.
//
// The two terms are not guarded the same way, and a reader should know
// which is load bearing. The range term is: n+1 is out of range and
// (n+1)*G is a finite point, so this term is the only thing that refuses
// it, and test/p256_ecdh_test.c has that case with
// test/violations/inv03-p256-ecdh-scalar-range.violation to prove the
// case fires. The zero term refuses nothing on its own: 0*P is the point
// at infinity for every P, which p256_point_affine already reports, so
// dropping the term changes no answer a caller can see and no test can
// catch it. It stays because this file states the contract and must not
// rest on the arithmetic being right.
static uint32_t scalar_in_range_mask(const p256_scalar *k) {
    return p256_scalar_reduced_mask(k) & ~p256_scalar_zero_mask(k);
}

int p256_ecdh_keygen(const uint8_t draw[P256_SCALAR_LEN], uint8_t priv[P256_SCALAR_LEN],
                     uint8_t pub[P256_POINT_LEN]) {
    p256_scalar k;
    p256_point product;

    p256_scalar_from_bytes(&k, draw);
    // The one branch on the draw. It reads whether the draw is in range,
    // which is the return code, and nothing else about it.
    if (scalar_in_range_mask(&k) == 0) {
        ct_wipe(&k, sizeof k);
        ct_wipe(priv, P256_SCALAR_LEN);
        ct_wipe(pub, P256_POINT_LEN);
        return 0;
    }

    p256_point_base_mul(&product, &k);
    pub[0] = 0x04; // SEC 1 section 2.3.3, uncompressed
    // ok is all ones here: a scalar in [1, n-1] times a generator of a
    // prime-order group is never the point at infinity. Both outputs
    // pass through the mask anyway, so the one contract this file states
    // -- a zero return leaves zero bytes behind -- holds on every path
    // rather than on the arithmetic being right.
    uint32_t ok = p256_point_affine(pub + 1, pub + 1 + P256_FE_LEN, &product);
    for (size_t i = 0; i < P256_SCALAR_LEN; i++) {
        priv[i] = draw[i] & (uint8_t)ok;
    }
    for (size_t i = 0; i < P256_POINT_LEN; i++) {
        pub[i] &= (uint8_t)ok;
    }

    ct_wipe(&k, sizeof k);
    ct_wipe(&product, sizeof product);
    return (int)(ok & 1U);
}

int p256_ecdh_point_valid(const uint8_t point[P256_POINT_LEN]) {
    p256_point peer;
    return (int)(p256_point_from_bytes(&peer, point) & 1U);
}

int p256_ecdh(const uint8_t priv[P256_SCALAR_LEN], const uint8_t point[P256_POINT_LEN],
              uint8_t out[P256_SECRET_LEN]) {
    p256_scalar k;
    p256_point peer;
    p256_point product;

    p256_scalar_from_bytes(&k, priv);
    // Both branches read public values: the peer's point arrived on the
    // wire, and a private key out of range is the caller's own error.
    if (p256_point_from_bytes(&peer, point) == 0 || scalar_in_range_mask(&k) == 0) {
        ct_wipe(&k, sizeof k);
        ct_wipe(out, P256_SECRET_LEN);
        return 0;
    }

    p256_point_mul(&product, &k, &peer);
    uint32_t ok = p256_point_affine_x(out, &product);
    // The product is the point at infinity only when the scalar is a
    // multiple of n, which the range check above refused. The mask takes
    // the bytes anyway: failing closed costs one and per byte.
    for (size_t i = 0; i < P256_SECRET_LEN; i++) {
        out[i] &= (uint8_t)ok;
    }

    ct_wipe(&k, sizeof k);
    ct_wipe(&product, sizeof product);
    return (int)(ok & 1U);
}
