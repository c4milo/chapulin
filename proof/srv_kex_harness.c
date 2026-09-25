// Proves: srv_kex.c, the server's key exchange, is memory safe and free of
// UB over any supported_groups and key_share a parsed ClientHello can
// report, any server scalar and public value, and every verdict its
// primitives can return; and six facts about what it computes.
//
//   1. The preference: X25519MLKEM768 whenever the client listed it,
//      x25519 when it listed x25519 and not the hybrid, secp256r1 when it
//      listed secp256r1 and neither of the others, and 0 when it listed
//      none of the three.
//   2. srv_kex_shared reports exactly the shares the parser recorded.
//   3. An x25519 share is h->pub. A hybrid share is the ciphertext the
//      encapsulation wrote, then h->pub, and the encapsulation read the
//      client's encapsulation key where the hello carried it. A secp256r1
//      share is the point p256_ecdh_keygen wrote, P256_POINT_LEN bytes,
//      and keygen runs only after the client's point passed its check.
//   4. A refused encapsulation, FIPS 203 §7.2's modulus check, leaves the
//      ML-KEM secret zero and writes no share length; a refused client
//      point draws no P-256 key, leaves h->p256_priv zero and writes no
//      share length.
//   5. The input keying material is the ML-KEM secret the encapsulation
//      produced, then the x25519 secret, which x25519 computed into the
//      second half against the x25519 value that ends the client's
//      hybrid share: RFC 10024's order. For x25519 it is the x25519
//      secret alone, against the client's x25519 share. For secp256r1 it
//      is the 32 bytes p256_ecdh computed over h->p256_priv and the
//      client's point.
//   6. The key exchange's secrets die on both exits of srv_kex_secret:
//      h->priv, h->pub, h->mlkem_ss and h->p256_priv are zero, and a
//      refused exchange leaves all SRV_KEX_SECRET_MAX bytes of ikm zero
//      (INV-3, INV-17).
//
// Layered, the proof/hybrid_secret_harness.c pattern: mlkem_encaps_derand,
// x25519, the three p256_ecdh entries and ch_rand_bytes are stubs
// asserting their headers' contracts and havocing their outputs, so
// mlkem.c, mlkem_poly.c, sha3.c, x25519.c and the P-256 sources are not
// linked. What is under proof is srv_kex.c's own choice,
// pointer handling, byte order and wipe discipline; mlkem's six harnesses
// and x25519's seven prove the arithmetic, and driving the real ones here
// would put a 1184-byte encapsulation key and 256 symbolic multiplies in
// one formula, the shape docs/proofs.md says not to build.
//
// The client's shares are never filled. Their bytes reach only the stubs,
// which read none of them, so a fill would add 1248 loop iterations and no
// coverage; the proof holds for every content, because none is assumed.
#include "harness.h"

#include <string.h>

#include "srv_kex.h"

uint16_t nondet_u16(void);

// The client's three shares as the parser leaves them: inside the
// message, at the length each group fixes.
static uint8_t hybrid_bytes[CH_HYBRID_CLIENT_SHARE];
static uint8_t x25519_bytes[X25519_LEN];
static uint8_t p256_bytes[P256_POINT_LEN];

// What the stubs saw and wrote, for the assertions after each call.
static const uint8_t *encaps_ek;
static uint8_t encaps_ss[MLKEM_SS_LEN];
static const uint8_t *x25519_point;
static const uint8_t *x25519_out;
static const uint8_t *point_checked;
static int keygen_calls;
static int keygen_refusals;
static const uint8_t *keygen_pub;
static const uint8_t *ecdh_priv;
static const uint8_t *ecdh_point;
static const uint8_t *ecdh_out;

void ch_rand_bytes(uint8_t *p, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(p, n), "rand: output writable");
    fill_nondet(p, n);
    // rand.h's contract: a draw writes every byte, so it is never the
    // all-zero value a hook that wrote nothing leaves.
    __CPROVER_assume(n == 0 || p[0] != 0);
}

// FIPS 203 Algorithm 17 behind §7.2's modulus check, as mlkem.h states it:
// nonzero and nothing written for a refused key, otherwise a ciphertext and
// a shared secret. The ciphertext is not filled, for the reason the shares
// are not.
int mlkem_encaps_derand(uint8_t ct[MLKEM_CT_LEN], uint8_t ss[MLKEM_SS_LEN],
                        const uint8_t ek[MLKEM_EK_LEN], const uint8_t m[32]) {
    __CPROVER_assert(__CPROVER_w_ok(ct, MLKEM_CT_LEN), "encaps: ciphertext writable");
    __CPROVER_assert(__CPROVER_w_ok(ss, MLKEM_SS_LEN), "encaps: secret writable");
    __CPROVER_assert(__CPROVER_r_ok(ek, MLKEM_EK_LEN), "encaps: key readable");
    __CPROVER_assert(__CPROVER_r_ok(m, 32), "encaps: randomness readable");
    encaps_ek = ek;
    if ((nondet_u8() & 1) != 0) {
        return 1;
    }
    fill_nondet(ss, MLKEM_SS_LEN);
    memcpy(encaps_ss, ss, MLKEM_SS_LEN);
    return 0;
}

int x25519(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN], const uint8_t point[32]) {
    __CPROVER_assert(__CPROVER_w_ok(out, X25519_LEN), "x25519: out writable");
    __CPROVER_assert(__CPROVER_r_ok(scalar, X25519_LEN), "x25519: scalar readable");
    __CPROVER_assert(__CPROVER_r_ok(point, 32), "x25519: point readable");
    x25519_point = point;
    x25519_out = out;
    fill_nondet(out, X25519_LEN);
    // Both arms: the all-zero refusal and the accepting path.
    return (nondet_u8() & 1) ? 1 : 0;
}

// p256_ecdh.h's three entries. The point check answers either way. Keygen
// refuses a candidate at any draw and accepts one within P256_ECDH_DRAWS,
// the bound rand.h's contract gives a working generator, and a refusal
// zeroes both outputs. The exchange's refusal zeroes its 32 bytes.
int p256_ecdh_point_valid(const uint8_t point[P256_POINT_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(point, P256_POINT_LEN), "point check: point readable");
    point_checked = point;
    return nondet_u8() & 1;
}

int p256_ecdh_keygen(const uint8_t draw[P256_SCALAR_LEN], uint8_t priv[P256_SCALAR_LEN],
                     uint8_t pub[P256_POINT_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(draw, P256_SCALAR_LEN), "keygen: draw readable");
    __CPROVER_assert(__CPROVER_w_ok(priv, P256_SCALAR_LEN), "keygen: priv writable");
    __CPROVER_assert(__CPROVER_w_ok(pub, P256_POINT_LEN), "keygen: pub writable");
    keygen_calls++;
    keygen_pub = pub;
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
    if ((nondet_u8() & 1) != 0) {
        memset(out, 0, P256_SECRET_LEN);
        return 0;
    }
    fill_nondet(out, P256_SECRET_LEN);
    return 1;
}

#include "srv_kex.c"

// Whether n bytes at a and b are equal, and whether n bytes at p are zero.
static int same(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static int zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != 0) {
            return 0;
        }
    }
    return 1;
}

// Facts 1 and 2, over every groups and shares pair the parser can report:
// a share's pointer set exactly when its bit is, and no share for a group
// supported_groups did not list (srv_parser.h).
static uint16_t prove_choice(client_hello *ch) {
    ch->groups = nondet_u8();
    ch->shares = nondet_u8();
    __CPROVER_assume((ch->shares & (uint8_t)~ch->groups) == 0);
    ch->x25519_share = (ch->shares & SRV_GROUP_X25519) != 0 ? x25519_bytes : NULL;
    ch->hybrid_share = (ch->shares & SRV_GROUP_X25519MLKEM768) != 0 ? hybrid_bytes : NULL;
    ch->p256_share = (ch->shares & SRV_GROUP_SECP256R1) != 0 ? p256_bytes : NULL;

    int listed_pq = (ch->groups & SRV_GROUP_X25519MLKEM768) != 0;
    int listed_x = (ch->groups & SRV_GROUP_X25519) != 0;
    int listed_p = (ch->groups & SRV_GROUP_SECP256R1) != 0;
    uint16_t group = srv_kex_group(ch);
    __CPROVER_assert((group == CH_GROUP_X25519MLKEM768) == listed_pq,
                     "the hybrid is chosen exactly when the client listed it");
    __CPROVER_assert((group == CH_GROUP_X25519) == (listed_x && !listed_pq),
                     "x25519 is chosen exactly when the client listed it and not the hybrid");
    __CPROVER_assert((group == CH_GROUP_SECP256R1) == (listed_p && !listed_x && !listed_pq),
                     "secp256r1 is chosen exactly when the client listed it and neither other");
    __CPROVER_assert(group != 0 || (!listed_x && !listed_pq && !listed_p),
                     "no group only when the client listed none of the three");

    __CPROVER_assert(srv_kex_shared(ch, CH_GROUP_X25519MLKEM768) == (ch->hybrid_share != NULL),
                     "shared reports the hybrid share");
    __CPROVER_assert(srv_kex_shared(ch, CH_GROUP_X25519) == (ch->x25519_share != NULL),
                     "shared reports the x25519 share");
    __CPROVER_assert(srv_kex_shared(ch, CH_GROUP_SECP256R1) == (ch->p256_share != NULL),
                     "shared reports the secp256r1 share");
    uint16_t other = nondet_u16();
    __CPROVER_assume(other != CH_GROUP_X25519 && other != CH_GROUP_X25519MLKEM768 &&
                     other != CH_GROUP_SECP256R1);
    __CPROVER_assert(srv_kex_shared(ch, other) == 0,
                     "a group this build does not hold is unshared");
    return group;
}

// Facts 3 and 4 for secp256r1: the share is the point keygen wrote, drawn
// only after the client's point passed its check, and a refused point
// draws nothing. Returns srv_kex_share's answer.
static int prove_p256_share(handshake_state *h, const client_hello *ch, uint8_t *share,
                            size_t *share_len) {
    int rc = srv_kex_share(h, ch, CH_GROUP_SECP256R1, share, share_len);
    __CPROVER_assert(point_checked == p256_bytes, "the client's point is checked");
    if (rc == CH_OK) {
        __CPROVER_assert(*share_len == P256_POINT_LEN && keygen_pub == share,
                         "a secp256r1 share is the point keygen wrote");
    } else {
        __CPROVER_assert(*share_len == 0 && keygen_calls == 0 &&
                             zero(h->p256_priv, P256_SCALAR_LEN),
                         "a refused point draws no key and writes no length");
    }
    return rc;
}

int main(void) {
    static ch_tls t;
    static handshake_state h;
    memset(&t, 0, sizeof t);
    memset(&h, 0, sizeof h);
    h.t = &t;
    client_hello ch;
    memset(&ch, 0, sizeof ch);
    uint16_t group = prove_choice(&ch);

    // Facts 3 and 4, on the call order srv_select guarantees: a group it
    // chose, and a hello that carried a share for it, or it would have
    // sent a HelloRetryRequest instead.
    __CPROVER_assume(group != 0 && srv_kex_shared(&ch, group));
    fill_nondet(h.priv, sizeof h.priv);
    fill_nondet(h.pub, sizeof h.pub);
    uint8_t pub[X25519_LEN];
    memcpy(pub, h.pub, sizeof pub);
    static uint8_t share[SRV_KEX_SHARE_MAX];
    size_t share_len = 0;
    if (group == CH_GROUP_SECP256R1) {
        if (prove_p256_share(&h, &ch, share, &share_len) != CH_OK) {
            return 0;
        }
        uint8_t ikm[SRV_KEX_SECRET_MAX];
        size_t ikm_len = 0;
        int rc = srv_kex_secret(&h, &ch, group, ikm, &ikm_len);
        __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "the secret is derived or refused");
        __CPROVER_assert(zero(h.p256_priv, P256_SCALAR_LEN) && zero(h.priv, X25519_LEN) &&
                             zero(h.pub, X25519_LEN),
                         "both exits wipe the P-256 scalar and the x25519 key pair");
        __CPROVER_assert(ecdh_priv == h.p256_priv && ecdh_point == p256_bytes && ecdh_out == ikm,
                         "p256_ecdh runs over the scalar and the client's point into ikm");
        __CPROVER_assert(rc != CH_OK || ikm_len == P256_SECRET_LEN, "the P-256 secret is 32 bytes");
        __CPROVER_assert(rc == CH_OK || zero(ikm, SRV_KEX_SECRET_MAX),
                         "a refusal leaves no part of the secret");
        return 0;
    }
    int rc = srv_kex_share(&h, &ch, group, share, &share_len);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "the share is written or refused");
    if (group == CH_GROUP_X25519) {
        __CPROVER_assert(rc == CH_OK && share_len == X25519_LEN && same(share, pub, X25519_LEN),
                         "an x25519 share is h->pub");
    } else if (rc == CH_OK) {
        __CPROVER_assert(share_len == CH_HYBRID_SERVER_SHARE, "a hybrid share is 1120 bytes");
        __CPROVER_assert(same(share + MLKEM_CT_LEN, pub, X25519_LEN),
                         "a hybrid share ends with h->pub, after the ciphertext");
        __CPROVER_assert(encaps_ek == hybrid_bytes, "the encapsulation read the client's key");
        __CPROVER_assert(same(h.mlkem_ss, encaps_ss, MLKEM_SS_LEN),
                         "the ML-KEM secret is kept for the key schedule");
    } else {
        __CPROVER_assert(share_len == 0 && zero(h.mlkem_ss, MLKEM_SS_LEN),
                         "a refused key writes no length and keeps no secret");
        return 0;
    }

    // Facts 5 and 6.
    uint8_t ikm[SRV_KEX_SECRET_MAX];
    size_t ikm_len = 0;
    rc = srv_kex_secret(&h, &ch, group, ikm, &ikm_len);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "the secret is derived or refused");
    __CPROVER_assert(zero(h.mlkem_ss, MLKEM_SS_LEN), "both exits wipe the ML-KEM secret");
    __CPROVER_assert(zero(h.priv, X25519_LEN) && zero(h.pub, X25519_LEN),
                     "both exits wipe the x25519 key pair");
    if (rc != CH_OK) {
        __CPROVER_assert(zero(ikm, SRV_KEX_SECRET_MAX), "a refusal leaves no half of the secret");
    } else if (group == CH_GROUP_X25519MLKEM768) {
        __CPROVER_assert(ikm_len == SRV_KEX_SECRET_MAX, "the hybrid secret is 64 bytes");
        __CPROVER_assert(same(ikm, encaps_ss, MLKEM_SS_LEN), "the ML-KEM secret comes first");
        __CPROVER_assert(x25519_out == ikm + MLKEM_SS_LEN, "the x25519 secret comes second");
        __CPROVER_assert(x25519_point == hybrid_bytes + MLKEM_EK_LEN,
                         "x25519 runs against the value that ends the client's hybrid share");
    } else {
        __CPROVER_assert(ikm_len == X25519_LEN && x25519_out == ikm,
                         "the x25519 secret is the whole input");
        __CPROVER_assert(x25519_point == x25519_bytes, "x25519 runs against the client's share");
    }
    return 0;
}
