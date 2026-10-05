// ECDSA P-256 verification over the wide files, which a host object holds
// (p256_wide_verify.h): FIPS 186-4 6.4.2's check of one signature, with
// the scalars on p256_wide_scalar.c, the two scalar multiplications on
// p256_wide_mul.c and their sum on p256_wide_point.c's complete addition.
//
// Every value here is public, so the branches below read them freely:
// each one is a verdict the caller sees.
#include "p256_wide_verify.h"

#ifdef CH_CPU_RUNTIME

#include <string.h>

#include "ct.h"
#include "p256_point.h"
#include "p256_scalar.h"
#include "p256_wide_mul.h"
#include "p256_wide_point.h"
#include "p256_wide_scalar.h"

// 1 when a is in 1..n-1.
static int scalar_in_range(const p256_scalar *a) {
    return p256_scalar_zero_mask(a) == 0 && p256_scalar_reduced_mask(a) != 0;
}

// o = u1*G + u2*q. The addition is the complete one, so u1*G equal to
// u2*q, or to its negative, takes no case of its own.
static void double_scalar_mul(p256_point *o, const p256_scalar *u1, const p256_scalar *u2,
                              const p256_point *q) {
    p256_point base_part;
    p256_point key_part;
    p256_wide_point sum;
    p256_wide_point addend;
    p256_wide_base_mul(&base_part, u1);
    p256_wide_mul(&key_part, u2, q);
    p256_wide_point_from_portable(&sum, &base_part);
    p256_wide_point_from_portable(&addend, &key_part);
    p256_wide_point_add(&sum, &sum, &addend);
    p256_wide_point_to_portable(o, &sum);
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

    // R = u1*G + u2*Q, and v = R's affine X mod n. R at infinity has no
    // X. X is below p, and p is below 2n, so p256_scalar_reduce's one
    // subtraction reduces it.
    p256_point result;
    uint8_t x[P256_FE_LEN];
    double_scalar_mul(&result, &u1, &u2, &q);
    if (p256_wide_point_affine(x, NULL, &result) == 0) {
        return 0;
    }
    p256_scalar v;
    uint8_t v_be[P256_SCALAR_LEN];
    p256_scalar_from_bytes(&v, x);
    p256_scalar_reduce(&v, &v);
    p256_scalar_to_bytes(v_be, &v);
    return ct_memeq(v_be, r_be, P256_SCALAR_LEN) != 0;
}

#endif // CH_CPU_RUNTIME
