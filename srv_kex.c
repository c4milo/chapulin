// The server's key exchange. srv_kex.h states each contract, the group
// preference and the byte order RFC 10024 fixes; the comments here say
// what the header does not.
//
// Three lines below compute an offset into a fixed layout, where the
// hybrid's second half starts: share + MLKEM_CT_LEN, ikm + MLKEM_SS_LEN
// and ch->hybrid_share + MLKEM_EK_LEN. They are the concatenations RFC
// 10024 defines, over arrays that hold both halves, and
// handshake_flight.c's hybrid_secret writes ikm + MLKEM_SS_LEN the same
// way. The third reads peer bytes, and the parser held the client's
// share to exactly CH_HYBRID_CLIENT_SHARE bytes before this file sees
// it, so the x25519 half is the X25519_LEN bytes that end it.
#include "srv_kex.h"

#ifdef CH_ROLE_SERVER

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "rand.h"

// FIPS 203's encapsulation takes 32 bytes of randomness, m (mlkem.h).
#define SRV_KEX_ENCAPS_RANDOM 32

uint16_t srv_kex_group(const client_hello *ch) {
    if ((ch->groups & SRV_GROUP_X25519MLKEM768) != 0) {
        return CH_GROUP_X25519MLKEM768;
    }
    if ((ch->groups & SRV_GROUP_X25519) != 0) {
        return CH_GROUP_X25519;
    }
    return 0;
}

int srv_kex_shared(const client_hello *ch, uint16_t group) {
    uint8_t bit = srv_group_bit(group);
    return bit != 0 && (ch->shares & bit) != 0;
}

// Encapsulates to the client's encapsulation key: the ciphertext into
// share, the ML-KEM shared secret into h->mlkem_ss. The randomness is
// drawn here and nowhere earlier, so a server that selects x25519 draws
// none, and it dies on both exits.
static int encapsulate(handshake_state *h, const client_hello *ch,
                       uint8_t share[SRV_KEX_SHARE_MAX]) {
    static const uint8_t unwritten[SRV_KEX_ENCAPS_RANDOM] = {0};
    uint8_t m[SRV_KEX_ENCAPS_RANDOM];
    ch_rand_bytes(m, sizeof m);
    // rand.h's contract: the draw writes every byte, so all-zero is a hook
    // that returned without writing, which is programmer error.
    CH_ASSERT(!ct_memeq(m, unwritten, sizeof m));
    // mlkem_encaps_derand runs FIPS 203 §7.2's modulus check on the
    // encapsulation key before it writes anything, and answers nonzero
    // when a coefficient is at or above the modulus. The key is public,
    // so the branch on that verdict leaks nothing.
    int refused = mlkem_encaps_derand(share, h->mlkem_ss, ch->hybrid_share, m);
    ct_wipe(m, sizeof m);
    if (refused != 0) {
        ct_wipe(h->mlkem_ss, sizeof h->mlkem_ss);
        return CH_EPROTO;
    }
    return CH_OK;
}

int srv_kex_share(handshake_state *h, const client_hello *ch, uint16_t group,
                  uint8_t share[SRV_KEX_SHARE_MAX], size_t *share_len) {
    if (group == CH_GROUP_X25519) {
        memcpy(share, h->pub, X25519_LEN);
        *share_len = X25519_LEN;
        return CH_OK;
    }
    CH_ASSERT(group == CH_GROUP_X25519MLKEM768 && ch->hybrid_share != NULL);
    int rc = encapsulate(h, ch, share);
    if (rc != CH_OK) {
        return rc;
    }
    memcpy(share + MLKEM_CT_LEN, h->pub, X25519_LEN);
    *share_len = CH_HYBRID_SERVER_SHARE;
    return CH_OK;
}

int srv_kex_secret(handshake_state *h, const client_hello *ch, uint16_t group,
                   uint8_t ikm[SRV_KEX_SECRET_MAX], size_t *ikm_len) {
    // Where the x25519 shared secret lands, and whose public value it is
    // computed against.
    uint8_t *ecdhe = ikm;
    const uint8_t *peer = ch->x25519_share;
    *ikm_len = X25519_LEN;
    if (group == CH_GROUP_X25519MLKEM768) {
        CH_ASSERT(ch->hybrid_share != NULL);
        // RFC 10024's order: the ML-KEM shared secret, then the x25519 one.
        memcpy(ikm, h->mlkem_ss, MLKEM_SS_LEN);
        ecdhe = ikm + MLKEM_SS_LEN;
        peer = ch->hybrid_share + MLKEM_EK_LEN;
        *ikm_len = SRV_KEX_SECRET_MAX;
    }
    CH_ASSERT(peer != NULL);
    ct_wipe(h->mlkem_ss, sizeof h->mlkem_ss);
    int shared_ok = x25519(ecdhe, h->priv, peer) != 0;
    ct_wipe(h->priv, sizeof h->priv);
    ct_wipe(h->pub, sizeof h->pub);
    if (!shared_ok) {
        ct_wipe(ikm, SRV_KEX_SECRET_MAX);
        return CH_EPROTO;
    }
    return CH_OK;
}

#endif // CH_ROLE_SERVER
