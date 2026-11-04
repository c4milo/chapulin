// ECDSA P-384 verification for a host object (p384_wide_verify.h): p384.c's
// verify equation on six 64-bit words, the scalars on p384_wide_field.c
// and the points on p384_wide_point.c. Variable time on purpose — every
// input is public (see p384.h).
#include "p384_wide_verify.h"

#ifdef CH_CPU_RUNTIME

#include "p384_wide_field.h"
#include "p384_wide_point.h"

#define WORDS P384_WIDE_WORDS

static int scalar_in_range(const uint64_t a[WORDS]) {
    return !p384_wide_is_zero(a) && p384_wide_compare(a, p384_wide_modn.m) < 0;
}

int p384_wide_verify_rs(const uint8_t pub[P384_PUB_LEN], const uint8_t msg_hash[P384_LEN],
                        const uint8_t r_be[P384_LEN], const uint8_t s_be[P384_LEN]) {
    uint64_t r[WORDS];
    uint64_t s[WORDS];
    p384_wide_from_bytes(r, r_be);
    p384_wide_from_bytes(s, s_be);
    if (!scalar_in_range(r) || !scalar_in_range(s)) {
        return 0;
    }

    p384_wide_point q;
    if (!p384_wide_point_decode(&q, pub)) {
        return 0;
    }

    // e = the hash as a big-endian integer mod n; one subtract is enough
    // because n > 2^383, so 2n > 2^384.
    uint64_t e[WORDS];
    p384_wide_from_bytes(e, msg_hash);
    if (p384_wide_compare(e, p384_wide_modn.m) >= 0) {
        (void)p384_wide_sub_raw(e, e, p384_wide_modn.m);
    }

    uint64_t w[WORDS];
    uint64_t u1[WORDS];
    uint64_t u2[WORDS];
    p384_wide_mod_inverse(w, s, &p384_wide_modn); // w = s^-1
    p384_wide_mod_mul(u1, e, w, &p384_wide_modn);
    p384_wide_mod_mul(u2, r, w, &p384_wide_modn);

    // R = u1*G + u2*Q, and the signature holds when R is a point whose x
    // is r modulo n.
    p384_wide_point sum;
    p384_wide_double_mul(&sum, u1, u2, &q);
    if (p384_wide_point_is_infinity(&sum)) {
        return 0;
    }
    return p384_wide_point_x_is_r(&sum, r);
}

#endif // CH_CPU_RUNTIME
