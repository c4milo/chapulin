// The mock server's side of the key exchange in
// test/webpki_session_test.c: the key_exchange its ServerHello carries
// for the group it selects, and the input keying material both sides
// extract from, the client's own derivation mirrored. Included by that
// file after the mock server and server_scalar, before the ServerHello
// that reads it.
#ifndef CH_TEST_WEBPKI_MOCK_KEX_H
#define CH_TEST_WEBPKI_MOCK_KEX_H

#include "mlkem.h"
#include "p256_ecdh.h"

// How the mock writes a secp256r1 share (RFC 9846 §4.3.8.2,
// rfc9846.txt:2261-2286). MOCK_P256_VALID is the server's point, and each
// other value is a shape the client must refuse with illegal_parameter: a
// Y coordinate with its last bit flipped, which no longer satisfies the
// curve equation; the pair (0, 0), which does not either; the form byte
// 0x05 in place of 0x04; the point without its form byte, 64 bytes; the
// point with one byte after it, 66 bytes; and 0x00 alone, the one-byte
// encoding SEC 1 gives the point at infinity.
enum {
    MOCK_P256_VALID,
    MOCK_P256_OFF_CURVE,
    MOCK_P256_ZERO_POINT,
    MOCK_P256_FORM_BYTE,
    MOCK_P256_LEN_64,
    MOCK_P256_LEN_66,
    MOCK_P256_INFINITY,
    MOCK_P256_MODES
};

// The mock's P-256 scalar, a fixed value in [1, n-1].
static const uint8_t server_p256_draw[P256_SCALAR_LEN] = {0x2a, 0x17, 0x5e};

// One key exchange: the server share, and the input keying material,
// which is all zero when the client never offered a share for the group,
// because the client refuses that selection before it derives a key.
typedef struct {
    uint8_t share[CH_HYBRID_SERVER_SHARE];
    size_t share_len;
    uint8_t ecdhe[MLKEM_SS_LEN + X25519_LEN];
    size_t ecdhe_len;
} mock_kex;

// secp256r1: the server's point, rewritten into mode's shape, against the
// client's point when the hello carried one.
static void mock_p256(mock_kex *k, int mode, const uint8_t *client_point) {
    uint8_t priv[P256_SCALAR_LEN];
    CHECK(p256_ecdh_keygen(server_p256_draw, priv, k->share) == 1);
    k->share_len = P256_POINT_LEN;
    k->ecdhe_len = P256_SECRET_LEN;
    if (client_point != NULL) {
        CHECK(p256_ecdh(priv, client_point, k->ecdhe) == 1);
    }
    if (mode == MOCK_P256_OFF_CURVE) {
        k->share[P256_POINT_LEN - 1] ^= 1;
    } else if (mode == MOCK_P256_ZERO_POINT) {
        memset(k->share + 1, 0, P256_POINT_LEN - 1);
    } else if (mode == MOCK_P256_FORM_BYTE) {
        k->share[0] = 0x05;
    } else if (mode == MOCK_P256_LEN_64) {
        memmove(k->share, k->share + 1, P256_POINT_LEN - 1);
        k->share_len = P256_POINT_LEN - 1;
    } else if (mode == MOCK_P256_LEN_66) {
        k->share[P256_POINT_LEN] = 0;
        k->share_len = P256_POINT_LEN + 1;
    } else if (mode == MOCK_P256_INFINITY) {
        k->share[0] = 0x00;
        k->share_len = 1;
    }
}

// Fills k for group against the shares the hello carried. The hybrid
// runs RFC 10024's two halves, ML-KEM first. x25519 runs over the hello's
// x25519 entry, or over the hybrid entry's x25519 half when require_pq
// left that entry out, so a row can still send the selection the client
// must refuse. A group the hello carried no share for gets a well-formed
// share and a zero secret.
static void mock_key_exchange(mock_kex *k, uint16_t group, int p256_mode, const uint8_t *hello,
                              size_t hello_len) {
    memset(k, 0, sizeof *k);
    size_t len = 0;
    const uint8_t *hybrid = hello_key_share(hello, hello_len, CH_GROUP_X25519MLKEM768, &len);
    const uint8_t *x25519_value = hello_key_share(hello, hello_len, CH_GROUP_X25519, &len);
    const uint8_t *point = hello_key_share(hello, hello_len, CH_GROUP_SECP256R1, &len);
    if (x25519_value == NULL && hybrid != NULL) {
        x25519_value = hybrid + MLKEM_EK_LEN;
    }
    if (group == CH_GROUP_SECP256R1) {
        mock_p256(k, p256_mode, point);
        return;
    }
    uint8_t server_pub[X25519_LEN];
    x25519_base(server_pub, server_scalar);
    uint8_t *ecdhe = k->ecdhe;
    uint8_t *pub_at = k->share;
    k->share_len = X25519_LEN;
    k->ecdhe_len = X25519_LEN;
    if (group == CH_GROUP_X25519MLKEM768) {
        static const uint8_t m[32] = {0x4b};
        if (hybrid != NULL) {
            CHECK(mlkem_encaps_derand(k->share, k->ecdhe, hybrid, m) == 0);
        }
        ecdhe += MLKEM_SS_LEN;
        pub_at += MLKEM_CT_LEN;
        k->share_len = CH_HYBRID_SERVER_SHARE;
        k->ecdhe_len = MLKEM_SS_LEN + X25519_LEN;
    }
    memcpy(pub_at, server_pub, X25519_LEN);
    if (x25519_value != NULL) {
        CHECK(x25519(ecdhe, server_scalar, x25519_value) == 1);
    }
}

#endif
