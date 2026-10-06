// ECDSA P-256 verification over the wide files, which a host object holds
// (p256_wide_verify.h): FIPS 186-4 6.4.2's check of one signature, with
// the scalars on p256_wide_scalar.c, the key's decoding on
// p256_wide_point.c, and the sum u1*G + u2*Q and the comparison of its x
// with r on p256_wide_verify_point.c, whose points are Jacobian and
// variable time (docs/decisions.md 104).
//
// Every value here is public, so the branches below read them freely:
// each one is a verdict the caller sees.
#include "p256_wide_verify.h"

#ifdef CH_CPU_RUNTIME

#include <string.h>

#include "p256_point.h"
#include "p256_scalar.h"
#include "p256_wide_point.h"
#include "p256_wide_scalar.h"
#include "p256_wide_verify_point.h"

// 1 when a is in 1..n-1.
static int scalar_in_range(const p256_scalar *a) {
    return p256_scalar_zero_mask(a) == 0 && p256_scalar_reduced_mask(a) != 0;
}

int p256_wide_verify_rs(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t r_be[32],
                        const uint8_t s_be[32]) {
    p256_scalar r;
    p256_scalar s;
    p256_scalar_from_bytes(&r, r_be);
    p256_scalar_from_bytes(&s, s_be);
    if (!scalar_in_range(&r) || !scalar_in_range(&s)) {
        return 0;
    }

    // The key as SEC 1's uncompressed point, the encoding the wide decoder
    // reads. It refuses a coordinate at or above p and a pair that is not
    // on the curve. Infinity has no X||Y encoding, so those are all the
    // checks a public key takes.
    uint8_t encoded[P256_POINT_LEN];
    p256_point q;
    encoded[0] = 0x04;
    memcpy(encoded + 1, pub, 64);
    if (p256_wide_point_from_bytes(&q, encoded) == 0) {
        return 0;
    }

    // e = the hash as a big-endian integer mod n, w = s^-1, u1 = e*w and
    // u2 = r*w.
    p256_scalar e;
    p256_scalar w;
    p256_scalar u1;
    p256_scalar u2;
    p256_scalar_from_bytes(&e, msg_hash);
    p256_scalar_reduce(&e, &e);
    p256_wide_scalar_inverse(&w, &s);
    p256_wide_scalar_mul(&u1, &e, &w);
    p256_wide_scalar_mul(&u2, &r, &w);

    // R = u1*G + u2*Q, and the signature holds when R is a finite point
    // whose x is r modulo n.
    p256_wide_jacobian key;
    p256_wide_jacobian sum;
    p256_wide_jacobian_from_key(&key, &q);
    p256_wide_jacobian_double_mul(&sum, &u1, &u2, &key);
    if (p256_wide_jacobian_is_infinity(&sum)) {
        return 0;
    }
    return p256_wide_jacobian_x_is_r(&sum, &r);
}

#endif // CH_CPU_RUNTIME
