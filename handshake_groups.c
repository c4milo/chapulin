// The key exchange rules of a client that offers more than one group.
// handshake_groups.h states each contract; the comments here say what the
// header does not.
#include "handshake_groups.h"

#ifdef CH_KEX_TWO_GROUPS

#include "ch_assert.h"
#include "ct.h"
#include "rand.h"

// Draws the P-256 key pair into h->p256_priv and h->p256_pub. Each draw
// is a candidate scalar, and p256_ecdh_keygen refuses one outside
// [1, n-1] and zeroes both outputs, so the loop draws again, up to
// P256_ECDH_DRAWS draws in all. The loop's exit reads whether the last
// candidate was refused, which says nothing about the one kept. The
// candidate buffer is zeroed before each draw, so a hook that returns
// without writing leaves the zero candidate, which keygen refuses, and
// the assertion after the loop fires on it.
static void draw_p256_key(handshake_state *h) {
    uint8_t draw[P256_SCALAR_LEN];
    int drawn = 0;
    for (int i = 0; i < P256_ECDH_DRAWS && !drawn; i++) {
        ct_wipe(draw, sizeof draw);
        ch_rand_bytes(draw, sizeof draw);
        drawn = p256_ecdh_keygen(draw, h->p256_priv, h->p256_pub);
    }
    ct_wipe(draw, sizeof draw);
    // rand.h's contract: a working generator refuses P256_ECDH_DRAWS
    // candidates in a row with probability below 2^-128, so this is a
    // hook that wrote nothing or wrote a constant, which is programmer
    // error, not peer input.
    CH_ASSERT(drawn);
}

int hsg_take_retry(handshake_state *h, const server_hello_info *info) {
    if (info->retry_group == 0) {
        return info->cookie_len > 0 ? CH_OK : CH_EPROTO;
    }
    CH_ASSERT(info->retry_group == CH_GROUP_SECP256R1);
    if (h->t->cfg.require_pq) {
        // The hello listed the hybrid alone, so secp256r1 is a group it
        // never listed (rfc9846.txt:2205-2212).
        return CH_EPROTO;
    }
    h->retry_group = info->retry_group;
    draw_p256_key(h);
    ct_wipe(h->priv, sizeof h->priv);
    ct_wipe(h->pub, sizeof h->pub);
    ct_wipe(h->dz, sizeof h->dz);
    return CH_OK;
}

int hsg_selected_group_ok(const handshake_state *h, uint16_t group) {
    if (h->retry_group != 0) {
        return group == h->retry_group;
    }
    return group != CH_GROUP_SECP256R1;
}

// The x25519 arm of hsg_classic_secret. The ML-KEM seed dies first,
// because the hybrid share it made goes unused.
static int x25519_secret(handshake_state *h, const server_hello_info *info,
                         uint8_t ikm[X25519_LEN]) {
    ct_wipe(h->dz, sizeof h->dz);
    if (!x25519(ikm, h->priv, info->server_pub)) {
        ct_wipe(ikm, X25519_LEN);
        return CH_EPROTO;
    }
    return CH_OK;
}

// The secp256r1 arm. p256_ecdh zeroes ikm when it refuses the point, so a
// refusal leaves no part of a secret behind, and the scalar dies on both
// exits.
static int p256_secret(handshake_state *h, const server_hello_info *info,
                       uint8_t ikm[P256_SECRET_LEN]) {
    CH_ASSERT(h->retry_group == CH_GROUP_SECP256R1 && info->server_p256 != NULL);
    int shared_ok = p256_ecdh(h->p256_priv, info->server_p256, ikm);
    ct_wipe(h->p256_priv, sizeof h->p256_priv);
    return shared_ok ? CH_OK : CH_EPROTO;
}

int hsg_classic_secret(handshake_state *h, const server_hello_info *info,
                       uint8_t ikm[HSG_CLASSIC_SECRET_MAX], size_t *ikm_len) {
    *ikm_len = HSG_CLASSIC_SECRET_MAX;
    if (info->group == CH_GROUP_SECP256R1) {
        return p256_secret(h, info, ikm);
    }
    CH_ASSERT(info->group == CH_GROUP_X25519);
    return x25519_secret(h, info, ikm);
}

#endif // CH_KEX_TWO_GROUPS
