// The cases of bin/p256_verify_equiv_test whose keys meet the sum inside
// the host arm's pass over both scalars' digits (docs/decisions.md 104).
// Included by test/p256_verify_equiv_test.c alone, after the helpers it
// calls: scalar_small, scalar_random, scalar_negate, base_point and
// both_rs.
#ifndef CH_P256_VERIFY_EQUIV_JOINT_H
#define CH_P256_VERIFY_EQUIV_JOINT_H

// Five cases over four keys whose multiples meet the sum a verifier
// builds, so that an addition inside the computation of u1*G + u2*Q has two
// equal operands or two negatives, and not only the last one. The host arm
// computes the sum in one pass over both scalars' digits, most significant
// first, and adds a position's multiple of G before its multiple of the
// key (docs/decisions.md 104):
//
//   - The key G and a hash of r, so u1 = u2 and the two scalars have the
//     same digits: at the top digit the multiple of the key is added to
//     the same multiple of G, a doubling. (r, s) is a signature.
//   - The key -G and the same r, s and hash: the multiple of the key is
//     the negative of the same multiple of G, and R is the point at
//     infinity.
//   - The key -G, r the X of 2G, any s, and u1 = u2 + 2: the two scalars
//     have the same top digits, so the sum is the point at infinity after
//     the pass's first two additions, and the low digits then make R = 2G.
//     (r, s) is a signature.
//   - The key G/2, u1 = 1 and u2 = 2: the key's digit sits one position
//     above G's, so the sum is 2 (G/2) = G when G is added to it, a
//     doubling in the addition of an entry of the table of multiples of G.
//     R is 2G, and (r, s) is a signature.
//   - The key -G/2 and the same r, s and hash: the sum is -G when G is
//     added to it, and R is the point at infinity.
static void joint_case(void) {
    p256_scalar one;
    p256_scalar two;
    p256_scalar half;
    p256_scalar d;
    p256_scalar k;
    p256_scalar k_inverse;
    p256_scalar r;
    p256_scalar s;
    p256_scalar ignored;
    uint8_t key[64];
    uint8_t hash[32];
    uint8_t r_be[32];
    uint8_t s_be[32];
    scalar_small(&one, 1);
    scalar_small(&two, 2);
    p256_scalar_inverse(&half, &two);

    // s = 2r/k, so that (r + r * 1) / s = k.
    scalar_random(&k);
    base_point(&r, NULL, &k);
    p256_scalar_inverse(&k_inverse, &k);
    p256_scalar_mul(&s, &r, &two);
    p256_scalar_mul(&s, &s, &k_inverse);
    p256_scalar_to_bytes(hash, &r);
    p256_scalar_to_bytes(r_be, &r);
    p256_scalar_to_bytes(s_be, &s);
    base_point(&ignored, key, &one);
    both_rs("the key G with u1 equal to u2", key, hash, r_be, s_be, 1);
    scalar_negate(&d, &one);
    base_point(&ignored, key, &d);
    both_rs("the key -G with u1 equal to u2", key, hash, r_be, s_be, 0);

    // The hash r + 2s gives u1 = r/s + 2 and u2 = r/s, so R = 2G.
    p256_scalar e;
    base_point(&r, NULL, &two);
    scalar_random(&s);
    p256_scalar_mul(&e, &two, &s);
    p256_scalar_add(&e, &e, &r);
    p256_scalar_to_bytes(hash, &e);
    p256_scalar_to_bytes(r_be, &r);
    p256_scalar_to_bytes(s_be, &s);
    both_rs("the key -G with u1 = u2 + 2", key, hash, r_be, s_be, 1);

    // r is 2G's X, s = r / 2 and the hash is s, so u1 = 1 and u2 = 2.
    base_point(&r, NULL, &two);
    p256_scalar_mul(&s, &r, &half);
    p256_scalar_to_bytes(hash, &s);
    p256_scalar_to_bytes(r_be, &r);
    p256_scalar_to_bytes(s_be, &s);
    base_point(&ignored, key, &half);
    both_rs("the key G/2 with u1 = 1 and u2 = 2", key, hash, r_be, s_be, 1);
    scalar_negate(&d, &half);
    base_point(&ignored, key, &d);
    both_rs("the key -G/2 with u1 = 1 and u2 = 2", key, hash, r_be, s_be, 0);
}

#endif
