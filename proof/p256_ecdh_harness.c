// Proves, for p256_ecdh.c's three entries:
//
//   memory safety and absence of UB over unconstrained inputs at the
//   module's real bound -- 65 peer bytes, 32 scalar bytes, and output
//   buffers that arrive holding anything;
//
//   that each entry answers 0 or 1 rather than some other int;
//
//   that a refusal leaves no bytes behind. Both headers state it -- "on
//   0 both outputs are zeroed", "on 0 out is zeroed" -- and it is the
//   contract a caller that ignores the return code rests on. The stubs
//   answer an unconstrained mask, so this holds for every verdict the
//   arithmetic could give, not for the one it usually gives.
//
// Layered proof, in the shape hkdf_harness.c uses. The scalar
// arithmetic and the point arithmetic are the stub contracts in
// proof/p256_scalar_stubs.h and proof/p256_point_stubs.h, whose real
// bodies are proven by their own harnesses. proof/p256_sign_harness.c
// shares both headers.
//
// That layering is what makes this formula solvable. One key exchange
// runs 512 complete point additions of real Montgomery multiplies, and
// a harness that unrolled them returned no verdict in 854 seconds
// before the arithmetic moved to p256_point.c -- the shape
// docs/proofs.md says never converges. Nothing left in this file
// touches a coordinate: what it owns is the range check, the output
// masking and the refusal paths.
#include "harness.h"

#include "p256_point_stubs.h"
#include "p256_scalar_stubs.h"

#include "p256_ecdh.c"

// True when every byte of p is zero.
static int all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != 0) {
            return 0;
        }
    }
    return 1;
}

int main(void) {
    uint8_t draw[P256_SCALAR_LEN];
    uint8_t priv[P256_SCALAR_LEN];
    uint8_t pub[P256_POINT_LEN];
    uint8_t peer[P256_POINT_LEN];
    uint8_t out[P256_SECRET_LEN];

    // Any 65 bytes a peer can send, including the encodings this file
    // refuses.
    fill_nondet(peer, sizeof peer);
    int valid = p256_ecdh_point_valid(peer);
    __CPROVER_assert(valid == 0 || valid == 1, "p256_ecdh_point_valid returns 0 or 1");

    // Any draw, in range or not. Both outputs are freshly havocked, the
    // way a caller's uninitialized buffers arrive.
    fill_nondet(draw, sizeof draw);
    fill_nondet(priv, sizeof priv);
    fill_nondet(pub, sizeof pub);
    int rc = p256_ecdh_keygen(draw, priv, pub);
    __CPROVER_assert(rc == 0 || rc == 1, "p256_ecdh_keygen returns 0 or 1");
    __CPROVER_assert(rc == 1 || all_zero(priv, sizeof priv),
                     "p256_ecdh_keygen: a refusal leaves no private key");
    __CPROVER_assert(rc == 1 || all_zero(pub, sizeof pub),
                     "p256_ecdh_keygen: a refusal leaves no public key");

    // Any private key against any peer bytes, with every buffer
    // unconstrained again so no earlier call's state carries into this
    // one.
    fill_nondet(priv, sizeof priv);
    fill_nondet(peer, sizeof peer);
    fill_nondet(out, sizeof out);
    rc = p256_ecdh(priv, peer, out);
    __CPROVER_assert(rc == 0 || rc == 1, "p256_ecdh returns 0 or 1");
    __CPROVER_assert(rc == 1 || all_zero(out, sizeof out),
                     "p256_ecdh: a refusal leaves no shared secret");
    return 0;
}
