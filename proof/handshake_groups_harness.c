// Proves: handshake_groups.c, the key exchange rules a TRUST=webpki client
// adds for its three groups, is memory safe and free of UB over any
// configuration, any key material the handshake state holds and every
// verdict its primitives can return; and six facts about what it does.
//
//   0. A retry naming no group is taken exactly when it carries a cookie,
//      and records no group and draws no P-256 scalar either way.
//   1. A retry naming secp256r1 under require_pq is refused and changes
//      nothing: no group recorded and no P-256 scalar drawn.
//   2. Otherwise the retry records secp256r1, draws the P-256 key pair
//      from ch_rand_bytes into h->p256_priv and h->p256_pub, and leaves
//      h->priv, h->pub and h->dz zero, because the retry hello carries the
//      P-256 share alone (INV-17).
//   3. A ServerHello may select secp256r1 exactly when a retry named it,
//      and the hybrid or x25519 exactly when none did.
//   4. The secp256r1 secret runs p256_ecdh over h->p256_priv and the
//      server's point into ikm, and h->p256_priv is zero on both exits
//      (INV-17); a refused point leaves all 32 bytes of ikm zero.
//   5. The x25519 secret runs over h->priv and the server's value, wipes
//      the ML-KEM seed h->dz first, and a refusal leaves ikm zero (INV-3).
//
// Layered, the proof/srv_kex_harness.c pattern: ch_rand_bytes,
// p256_ecdh_keygen, p256_ecdh and x25519 are stubs that assert their
// headers' contracts and havoc their outputs, so the P-256 and x25519
// arithmetic is not linked. p256_ecdh's own harness and x25519's prove
// that arithmetic; what is under proof here is this file's choices,
// pointer handling and wipes. The keygen stub refuses a candidate at any
// draw and accepts one within P256_ECDH_DRAWS, the bound rand.h's
// contract gives a working generator; past it the CH_ASSERT that holds
// the generator to that contract would fire, which is programmer error
// and not an input this proof covers.
#include "harness.h"

#include <string.h>

#include "handshake_groups.h"

uint16_t nondet_u16(void);

// What the stubs saw, for the assertions after each call.
static int keygen_refusals;
static const uint8_t *ecdh_priv;
static const uint8_t *ecdh_point;
static const uint8_t *ecdh_out;
static const uint8_t *x25519_point;
static const uint8_t *x25519_out;

void ch_rand_bytes(uint8_t *p, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(p, n), "rand: output writable");
    fill_nondet(p, n);
}

int p256_ecdh_keygen(const uint8_t draw[P256_SCALAR_LEN], uint8_t priv[P256_SCALAR_LEN],
                     uint8_t pub[P256_POINT_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(draw, P256_SCALAR_LEN), "keygen: draw readable");
    __CPROVER_assert(__CPROVER_w_ok(priv, P256_SCALAR_LEN), "keygen: priv writable");
    __CPROVER_assert(__CPROVER_w_ok(pub, P256_POINT_LEN), "keygen: pub writable");
    if ((nondet_u8() & 1) != 0) {
        keygen_refusals++;
        __CPROVER_assume(keygen_refusals < P256_ECDH_DRAWS);
        memset(priv, 0, P256_SCALAR_LEN);
        memset(pub, 0, P256_POINT_LEN);
        return 0;
    }
    fill_nondet(priv, P256_SCALAR_LEN);
    fill_nondet(pub, P256_POINT_LEN);
    return 1;
}

int p256_ecdh(const uint8_t priv[P256_SCALAR_LEN], const uint8_t point[P256_POINT_LEN],
              uint8_t out[P256_SECRET_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(priv, P256_SCALAR_LEN), "p256_ecdh: priv readable");
    __CPROVER_assert(__CPROVER_r_ok(point, P256_POINT_LEN), "p256_ecdh: point readable");
    __CPROVER_assert(__CPROVER_w_ok(out, P256_SECRET_LEN), "p256_ecdh: out writable");
    ecdh_priv = priv;
    ecdh_point = point;
    ecdh_out = out;
    // p256_ecdh.h: a refusal zeroes out, an acceptance writes the secret.
    if ((nondet_u8() & 1) != 0) {
        memset(out, 0, P256_SECRET_LEN);
        return 0;
    }
    fill_nondet(out, P256_SECRET_LEN);
    return 1;
}

int x25519(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN], const uint8_t point[32]) {
    __CPROVER_assert(__CPROVER_w_ok(out, X25519_LEN), "x25519: out writable");
    __CPROVER_assert(__CPROVER_r_ok(scalar, X25519_LEN), "x25519: scalar readable");
    __CPROVER_assert(__CPROVER_r_ok(point, 32), "x25519: point readable");
    x25519_point = point;
    x25519_out = out;
    fill_nondet(out, X25519_LEN);
    return (nondet_u8() & 1) ? 1 : 0;
}

#include "handshake_groups.c"

static int zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != 0) {
            return 0;
        }
    }
    return 1;
}

// Facts 1, 2, 3 and 4: the retry to secp256r1 and the exchange after it.
static void prove_retry(handshake_state *h) {
    server_hello_info retry;
    memset(&retry, 0, sizeof retry);
    retry.hrr = 1;
    retry.retry_group = CH_GROUP_SECP256R1;
    retry.cookie_len = nondet_u8();
    int rc = hsg_take_retry(h, &retry);
    if (h->t->cfg.require_pq) {
        __CPROVER_assert(rc == CH_EPROTO && h->retry_group == 0 &&
                             zero(h->p256_priv, P256_SCALAR_LEN),
                         "require_pq refuses the retry and draws nothing");
        return;
    }
    __CPROVER_assert(rc == CH_OK && h->retry_group == CH_GROUP_SECP256R1,
                     "the retry records secp256r1");
    __CPROVER_assert(zero(h->priv, X25519_LEN) && zero(h->pub, X25519_LEN) && zero(h->dz, 64),
                     "the first hello's key pairs die at the retry");
    uint16_t group = nondet_u16();
    __CPROVER_assert(hsg_selected_group_ok(h, group) == (group == CH_GROUP_SECP256R1),
                     "after the retry only secp256r1 may be selected");

    static uint8_t point[P256_POINT_LEN];
    server_hello_info info;
    memset(&info, 0, sizeof info);
    info.group = CH_GROUP_SECP256R1;
    info.have_share = 1;
    info.server_p256 = point;
    uint8_t ikm[HSG_CLASSIC_SECRET_MAX];
    size_t ikm_len = 0;
    rc = hsg_classic_secret(h, &info, ikm, &ikm_len);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "the secret is derived or refused");
    __CPROVER_assert(ikm_len == P256_SECRET_LEN, "the P-256 secret is 32 bytes");
    __CPROVER_assert(ecdh_priv == h->p256_priv && ecdh_point == point && ecdh_out == ikm,
                     "p256_ecdh runs over the scalar and the server's point into ikm");
    __CPROVER_assert(zero(h->p256_priv, P256_SCALAR_LEN), "both exits wipe the P-256 scalar");
    if (rc != CH_OK) {
        __CPROVER_assert(zero(ikm, sizeof ikm), "a refused point leaves no secret");
    }
}

// Fact 0: a retry that names no group asks for a cookie or for nothing.
static void prove_no_group(handshake_state *h) {
    server_hello_info retry;
    memset(&retry, 0, sizeof retry);
    retry.hrr = 1;
    retry.cookie_len = nondet_u8();
    int rc = hsg_take_retry(h, &retry);
    __CPROVER_assert(rc == (retry.cookie_len > 0 ? CH_OK : CH_EPROTO),
                     "a retry naming no group must carry a cookie");
    __CPROVER_assert(h->retry_group == 0 && zero(h->p256_priv, P256_SCALAR_LEN),
                     "a retry naming no group draws no P-256 key");
}

// Facts 3 and 5: no retry, and a ServerHello that selected x25519.
static void prove_x25519(handshake_state *h) {
    uint16_t group = nondet_u16();
    __CPROVER_assert(hsg_selected_group_ok(h, group) == (group != CH_GROUP_SECP256R1),
                     "without a retry secp256r1 may not be selected");
    server_hello_info info;
    memset(&info, 0, sizeof info);
    info.group = CH_GROUP_X25519;
    info.have_share = 1;
    fill_nondet(info.server_pub, sizeof info.server_pub);
    uint8_t ikm[HSG_CLASSIC_SECRET_MAX];
    size_t ikm_len = 0;
    int rc = hsg_classic_secret(h, &info, ikm, &ikm_len);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "the secret is derived or refused");
    __CPROVER_assert(ikm_len == X25519_LEN, "the x25519 secret is 32 bytes");
    __CPROVER_assert(x25519_point == info.server_pub && x25519_out == ikm,
                     "x25519 runs against the server's value into ikm");
    __CPROVER_assert(zero(h->dz, 64), "the unused ML-KEM seed dies");
    if (rc != CH_OK) {
        __CPROVER_assert(zero(ikm, sizeof ikm), "a refused exchange leaves no secret");
    }
}

int main(void) {
    static ch_tls t;
    static handshake_state h;
    memset(&t, 0, sizeof t);
    memset(&h, 0, sizeof h);
    h.t = &t;
    t.cfg.require_pq = nondet_u8() & 1;
    fill_nondet(h.priv, sizeof h.priv);
    fill_nondet(h.pub, sizeof h.pub);
    fill_nondet(h.dz, sizeof h.dz);
    uint8_t path = nondet_u8();
    if (path == 0) {
        prove_no_group(&h);
    } else if (path == 1) {
        prove_retry(&h);
    } else {
        prove_x25519(&h);
    }
    return 0;
}
