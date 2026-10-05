// What the two units of bin/p384_equiv_test share.
#ifndef CH_TEST_P384_EQUIV_H
#define CH_TEST_P384_EQUIV_H

#include <stddef.h>
#include <stdint.h>

#include "p384.h"

// n bytes from the seeded generator (test/p384_equiv_test.c).
void p384_equiv_rng_bytes(uint8_t *out, size_t n);

// Compares p384_wide_field.c with p384_field.c: the constants, and every
// routine on operands at the edges of each modulus and on random ones
// (test/p384_equiv_field.c). Returns the count of comparisons it made and
// adds the ones that differed to *failures.
unsigned long p384_equiv_field(int *failures);

// What follows is test/p384_equiv_sign.c's.

// 0, n and p as 48 big-endian bytes, and three points as X||Y: G, the
// point whose x is n + 2 and the point whose x is 0. sign_setup writes
// all but the first.
extern const uint8_t ZERO[P384_LEN];
extern uint8_t ORDER[P384_LEN];
extern uint8_t PRIME[P384_LEN];
extern uint8_t GENERATOR[P384_PUB_LEN];
extern uint8_t LARGE[P384_PUB_LEN];
extern uint8_t SMALL[P384_PUB_LEN];
void sign_setup(void);

// The longest DER ECDSA-Sig-Value: two INTEGERs of 49 content bytes.
#define SIG_MAX (2 + 2 * (2 + P384_LEN + 1))

// The DER ECDSA-Sig-Value of (r, s). Returns its length, SIG_MAX at most.
size_t der_signature(uint8_t out[SIG_MAX], const uint8_t r[P384_LEN], const uint8_t s[P384_LEN]);
// One minimal DER INTEGER of the 48 bytes at v, at out. Returns its length.
size_t der_integer(uint8_t *out, const uint8_t v[P384_LEN]);

// A key, a hash and a signature of it, the scalars as 48 big-endian bytes.
typedef struct {
    uint8_t pub[P384_PUB_LEN];
    uint8_t hash[P384_LEN];
    uint8_t r[P384_LEN];
    uint8_t s[P384_LEN];
} signed_hash;

// Stops the run with what when ok is 0: a step of a case's own arithmetic
// that cannot fail unless the case is wrong.
void must(int ok, const char *what);

// Arithmetic modulo n, on operands below n. scalar_reduce takes any 48
// bytes, scalar_random writes a value in 1..n-1, and plain_add and
// plain_sub are the sum and the difference modulo 2^384.
void scalar_mul(uint8_t o[P384_LEN], const uint8_t a[P384_LEN], const uint8_t b[P384_LEN]);
void scalar_add(uint8_t o[P384_LEN], const uint8_t a[P384_LEN], const uint8_t b[P384_LEN]);
void scalar_sub(uint8_t o[P384_LEN], const uint8_t a[P384_LEN], const uint8_t b[P384_LEN]);
void scalar_inverse(uint8_t o[P384_LEN], const uint8_t a[P384_LEN]);
void scalar_reduce(uint8_t v[P384_LEN]);
void scalar_random(uint8_t v[P384_LEN]);
void scalar_small(uint8_t v[P384_LEN], uint8_t value);
void plain_add(uint8_t o[P384_LEN], const uint8_t a[P384_LEN], const uint8_t b[P384_LEN]);
void plain_sub(uint8_t o[P384_LEN], const uint8_t a[P384_LEN], const uint8_t b[P384_LEN]);
// 1 when v is in 1..n-1.
int in_range(const uint8_t v[P384_LEN]);

// pub = d*G.
void key_of(uint8_t pub[P384_PUB_LEN], const uint8_t d[P384_LEN]);
// The three ways a case gets a signature; the unit states each.
int from_scalars(signed_hash *m, const uint8_t u1[P384_LEN], const uint8_t u2[P384_LEN],
                 const uint8_t key[P384_PUB_LEN]);
void sign(signed_hash *m, const uint8_t d[P384_LEN], const uint8_t k[P384_LEN],
          const uint8_t hash[P384_LEN]);
void from_point(signed_hash *m, const uint8_t xy[P384_PUB_LEN], const uint8_t r[P384_LEN]);

#endif
