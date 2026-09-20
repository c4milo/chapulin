// The four P-256 suites, in their own header for the reason
// test/quic_initial_tests.h is: test/wycheproof_test.c holds the helpers
// they read and every other suite, and it passed 500 lines when the key
// exchange and the signer joined the three verify arms. This file uses
// fail and check_verdict from that file and is included after them.
#ifndef CH_WYCHEPROOF_P256_H
#define CH_WYCHEPROOF_P256_H

// P-256 ECDH over the "ecpoint" suite: the peer's key is the SEC 1 point
// a key share carries. The invalid cases are the ones that matter here —
// sixteen points off the curve, the invalid-curve attack this file's
// point validation exists to refuse.
//
// A case whose public key is not 65 bytes never reaches p256_ecdh: a
// compressed or empty encoding fails the length its fixed-size argument
// states, which is the same refusal the key-share parser makes. Those
// are counted, and a valid case among them would be a failure.
static void run_ecdh_p256(void) {
    size_t refused_length = 0;
    size_t rejected = 0;
    size_t accepted_ok = 0;
    for (size_t i = 0; i < COUNT(wp_ecdh_p256); i++) {
        const uint8_t *p = wp_ecdh_p256_data + wp_ecdh_p256[i].off;
        const uint8_t *priv = p;
        const uint8_t *shared = p + P256_SCALAR_LEN;
        const uint8_t *pub = shared + P256_SECRET_LEN;
        uint8_t out[P256_SECRET_LEN];
        if (wp_ecdh_p256[i].pub_len != P256_POINT_LEN) {
            if (wp_ecdh_p256[i].kind == 0) {
                fail("ecdh-p256", wp_ecdh_p256[i].tc, "valid case is not a 65-byte point");
            } else {
                refused_length++;
            }
            continue;
        }
        int ok = p256_ecdh(priv, pub, out);
        // The two entries agree by construction: p256_ecdh refuses
        // exactly the points p256_ecdh_point_valid refuses, because it
        // calls the same check, and every private key here is in range.
        if (ok != p256_ecdh_point_valid(pub)) {
            fail("ecdh-p256", wp_ecdh_p256[i].tc, "p256_ecdh and point_valid disagree");
        }
        switch (wp_ecdh_p256[i].kind) {
        case 0: // valid: must accept and match
            if (!ok || memcmp(out, shared, P256_SECRET_LEN) != 0) {
                fail("ecdh-p256", wp_ecdh_p256[i].tc, "valid case rejected or mismatched");
            }
            break;
        case 1: // invalid: must reject
            if (ok) {
                fail("ecdh-p256", wp_ecdh_p256[i].tc, "invalid point accepted");
            } else {
                rejected++;
            }
            break;
        default: // acceptable: either verdict, but a match if accepted
            if (ok) {
                if (memcmp(out, shared, P256_SECRET_LEN) != 0) {
                    fail("ecdh-p256", wp_ecdh_p256[i].tc, "accepted with wrong shared secret");
                } else {
                    accepted_ok++;
                }
            }
            break;
        }
    }
    printf("wycheproof ecdh-p256: %zu cases, %zu invalid rejected, %zu refused by length,"
           " %zu acceptable matched\n",
           COUNT(wp_ecdh_p256), rejected, refused_length, accepted_ok);
}

static void run_ecdsa_p256_sha256(void) {
    for (size_t i = 0; i < COUNT(wp_ecdsa_p256_sha256); i++) {
        const uint8_t *pub = wp_ecdsa_p256_sha256_data + wp_ecdsa_p256_sha256[i].pub_off;
        const uint8_t *p = wp_ecdsa_p256_sha256_data + wp_ecdsa_p256_sha256[i].off;
        uint8_t hash[SHA256_LEN];
        sha256_of(p, wp_ecdsa_p256_sha256[i].msg_len, hash);
        int ok = p256_ecdsa_verify(pub, hash, p + wp_ecdsa_p256_sha256[i].msg_len,
                                   wp_ecdsa_p256_sha256[i].sig_len);
        check_verdict("ecdsa-p256-sha256", wp_ecdsa_p256_sha256[i].tc, ok,
                      wp_ecdsa_p256_sha256[i].valid);
    }
    printf("wycheproof ecdsa-p256-sha256: %zu cases\n", COUNT(wp_ecdsa_p256_sha256));
}

// The signer, over the same corpus. Wycheproof publishes no ECDSA
// SIGNING vectors -- every ECDSA file carries a public key, a message
// and a signature to check, and no private key -- so this arm is not a
// known-answer run and does not claim to be. What it is: the P-256
// suite's messages, every length and shape the corpus carries, signed
// with one fixed key and handed to p256_ecdsa_verify, which shares no
// arithmetic with the signer (p256.h says its own is variable time on
// purpose, and p256_sign.h says why it never calls into it). A signer
// that got a carry, a reduction or the DER minimal form wrong fails
// here on the first message that reaches it.
//
// The signer's known answers are RFC 6979 A.2.5 and Python's integers,
// in test/p256_sign_test.c.
//
// The key is RFC 6979 A.2.5's, the pair test/p256_tests.h already uses.
static const uint8_t SIGN_PRIV[32] = {
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
    0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};
static const uint8_t SIGN_PUB[64] = {
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
    0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
    0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
    0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};

static void run_ecdsa_p256_sign(void) {
    for (size_t i = 0; i < COUNT(wp_ecdsa_p256_sha256); i++) {
        const uint8_t *msg = wp_ecdsa_p256_sha256_data + wp_ecdsa_p256_sha256[i].off;
        uint32_t tc = wp_ecdsa_p256_sha256[i].tc;
        uint8_t hash[SHA256_LEN];
        uint8_t sig[P256_SIG_MAX];
        uint8_t again[P256_SIG_MAX];
        size_t sig_len = 0;
        size_t again_len = 0;

        sha256_of(msg, wp_ecdsa_p256_sha256[i].msg_len, hash);
        if (!p256_sign(SIGN_PRIV, hash, sig, sizeof sig, &sig_len)) {
            fail("ecdsa-p256-sign", tc, "signing refused a message");
            continue;
        }
        if (p256_ecdsa_verify(SIGN_PUB, hash, sig, sig_len) != 1) {
            fail("ecdsa-p256-sign", tc, "the verifier rejected our own signature");
        }
        // The nonce is deterministic, so one hash signs the same way
        // every time.
        if (!p256_sign(SIGN_PRIV, hash, again, sizeof again, &again_len) || again_len != sig_len ||
            memcmp(again, sig, sig_len) != 0) {
            fail("ecdsa-p256-sign", tc, "two signatures over one message differ");
        }
    }
    printf("wycheproof ecdsa-p256-sign: %zu messages signed and verified\n",
           COUNT(wp_ecdsa_p256_sha256));
}

// A 64-byte digest under a P-256 key. FIPS 186-4 section 6.4 keeps the
// leftmost 256 bits of a digest longer than the order, so the verifier
// reads the first 32 bytes of the SHA-512 output and the rest is unused.
static void run_ecdsa_p256_sha512(void) {
    for (size_t i = 0; i < COUNT(wp_ecdsa_p256_sha512); i++) {
        const uint8_t *pub = wp_ecdsa_p256_sha512_data + wp_ecdsa_p256_sha512[i].pub_off;
        const uint8_t *p = wp_ecdsa_p256_sha512_data + wp_ecdsa_p256_sha512[i].off;
        uint8_t hash[SHA512_LEN];
        sha512_of(p, wp_ecdsa_p256_sha512[i].msg_len, hash);
        int ok = p256_ecdsa_verify(pub, hash, p + wp_ecdsa_p256_sha512[i].msg_len,
                                   wp_ecdsa_p256_sha512[i].sig_len);
        check_verdict("ecdsa-p256-sha512", wp_ecdsa_p256_sha512[i].tc, ok,
                      wp_ecdsa_p256_sha512[i].valid);
    }
    printf("wycheproof ecdsa-p256-sha512: %zu cases\n", COUNT(wp_ecdsa_p256_sha512));
}

#endif
