// The public-key cases of the Valgrind taint lane (test/ct_taint_test.c says how the lane
// works). Each private key, each nonce input and each key-exchange secret is marked undefined.
// A public key, a ciphertext, a signature and a verdict the caller acts on are marked defined
// again, each with its reason, before the case compares them with the expected bytes.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ct.h"
#include "ct_taint.h"
#include "ct_taint_cases.h"
#include "mlkem.h"
#include "mlkem_vectors.h"
#include "p256_ecdh.h"
#include "p256_ecdh_vectors.h"
#include "p256_sign.h"
#include "p256_sign_vectors.h"
#include "rsa_sign.h"
#include "rsa_sign_key.h"
#include "sha256.h"
#include "widemul.h"

static int failures;

static void check(int ok, const char *what) {
    if (!ok) {
        (void)printf("FAIL %s\n", what);
        failures++;
    }
}

// X25519 on the field cpu picks, the ladder and the key generation from the fixed base, each
// with a secret scalar. The public key travels in the key share, and the shared secret is
// published only to compare the two ends.
static void case_x25519(uint8_t widemul) {
    uint8_t a[X25519_LEN];
    uint8_t b[X25519_LEN];
    uint8_t pub_a[X25519_LEN];
    uint8_t pub_b[X25519_LEN];
    uint8_t shared_a[X25519_LEN];
    uint8_t shared_b[X25519_LEN];
    for (size_t i = 0; i < X25519_LEN; i++) {
        a[i] = (uint8_t)(0x5a + 13 * i);
        b[i] = (uint8_t)(0xa5 + 29 * i);
    }
    CT_SECRET(a, sizeof a);
    CT_SECRET(b, sizeof b);
    widemul_x25519_base(widemul, pub_a, a);
    widemul_x25519_base(widemul, pub_b, b);
    // Public: each public key travels in a key share.
    CT_PUBLIC(pub_a, sizeof pub_a);
    CT_PUBLIC(pub_b, sizeof pub_b);
    int ok_a = widemul_x25519(widemul, shared_a, a, pub_b);
    int ok_b = widemul_x25519(widemul, shared_b, b, pub_a);
    // Public: the verdict on an all-zero result is the one the handshake acts on (INV-3).
    CT_PUBLIC(&ok_a, sizeof ok_a);
    CT_PUBLIC(&ok_b, sizeof ok_b);
    CT_PUBLIC(shared_a, sizeof shared_a);
    CT_PUBLIC(shared_b, sizeof shared_b);
    check(ok_a == 1 && ok_b == 1 && memcmp(shared_a, shared_b, X25519_LEN) == 0, "x25519");
}

// P-256 key generation and ECDH with secret scalars (p256_ecdh.c), and both signers with a
// secret key and, for the hedged one, secret noise. The key generation's verdict and the
// signers' are the ones the caller acts on.
static void case_p256(uint32_t cpu, uint8_t widemul) {
    const p256_ecdh_keygen_case *one = &P256_ECDH_KEYGEN[3];
    const p256_ecdh_keygen_case *two = &P256_ECDH_KEYGEN[4];
    uint8_t draw_a[P256_SCALAR_LEN];
    uint8_t draw_b[P256_SCALAR_LEN];
    uint8_t priv_a[P256_SCALAR_LEN];
    uint8_t priv_b[P256_SCALAR_LEN];
    uint8_t pub_a[P256_POINT_LEN];
    uint8_t pub_b[P256_POINT_LEN];
    uint8_t shared_a[P256_SECRET_LEN];
    uint8_t shared_b[P256_SECRET_LEN];
    memcpy(draw_a, one->scalar, sizeof draw_a);
    memcpy(draw_b, two->scalar, sizeof draw_b);
    CT_SECRET(draw_a, sizeof draw_a);
    CT_SECRET(draw_b, sizeof draw_b);
    int kept_a = p256_ecdh_keygen(widemul, draw_a, priv_a, pub_a);
    int kept_b = p256_ecdh_keygen(widemul, draw_b, priv_b, pub_b);
    // Public: whether a draw was in range decides a second draw, which the caller sees; each
    // public key travels in a key share.
    CT_PUBLIC(&kept_a, sizeof kept_a);
    CT_PUBLIC(&kept_b, sizeof kept_b);
    CT_PUBLIC(pub_a, sizeof pub_a);
    CT_PUBLIC(pub_b, sizeof pub_b);
    check(kept_a == 1 && memcmp(pub_a, one->pub, P256_POINT_LEN) == 0, "p256 keygen");
    check(kept_b == 1 && memcmp(pub_b, two->pub, P256_POINT_LEN) == 0, "p256 keygen");
    int ok_a = p256_ecdh(widemul, priv_a, pub_b, shared_a);
    int ok_b = p256_ecdh(widemul, priv_b, pub_a, shared_b);
    // Public: the verdict is the one the handshake acts on.
    CT_PUBLIC(&ok_a, sizeof ok_a);
    CT_PUBLIC(&ok_b, sizeof ok_b);
    CT_PUBLIC(shared_a, sizeof shared_a);
    CT_PUBLIC(shared_b, sizeof shared_b);
    check(ok_a == 1 && ok_b == 1 && memcmp(shared_a, shared_b, P256_SECRET_LEN) == 0, "p256 ecdh");

    const p256_hedged_vector *h = &p256_hedged_vectors[0];
    uint8_t priv[P256_PRIV_LEN];
    uint8_t noise[P256_NOISE_LEN];
    uint8_t sig[P256_SIG_MAX];
    size_t sig_len = 0;
    memcpy(priv, h->priv, sizeof priv);
    memcpy(noise, h->noise, sizeof noise);
    CT_SECRET(priv, sizeof priv);
    CT_SECRET(noise, sizeof noise);
    int signed_hedged =
        p256_sign_hedged_cpu(cpu, priv, h->msg_hash, noise, sig, sizeof sig, &sig_len);
    // Public: the signature travels in CertificateVerify, and the verdict is the caller's.
    CT_PUBLIC(&signed_hedged, sizeof signed_hedged);
    CT_PUBLIC(&sig_len, sizeof sig_len);
    CT_PUBLIC(sig, sizeof sig);
    check(signed_hedged == 1 && sig_len == h->sig_len && memcmp(sig, h->sig, sig_len) == 0,
          "p256 hedged signature");

    const p256_sign_vector *v = &p256_sign_vectors[0];
    memcpy(priv, v->priv, sizeof priv);
    CT_SECRET(priv, sizeof priv);
    int signed_plain = p256_sign_cpu(cpu, priv, v->msg_hash, sig, sizeof sig, &sig_len);
    CT_PUBLIC(&signed_plain, sizeof signed_plain);
    CT_PUBLIC(&sig_len, sizeof sig_len);
    CT_PUBLIC(sig, sizeof sig);
    check(signed_plain == 1 && sig_len == v->sig_len && memcmp(sig, v->sig, sig_len) == 0,
          "p256 rfc6979 signature");
}

// RSA-PSS signing with a secret key and a secret salt, on the signer the answer picks: the
// ladder on n and d (rsa_sign.c), or the Chinese remainder theorem on 64-bit words with its
// check by the public exponent (rsa_sign64.c). The modulus and its length are public.
static void case_rsa(uint32_t cpu, uint8_t widemul, const test_rsa_sign_key *from,
                     const uint8_t *msg, size_t msg_len, const uint8_t *salt,
                     const uint8_t *expected) {
    static ch_rsa_priv key;
    test_rsa_sign_key_load(&key, from);
    uint8_t msg_hash[SHA256_LEN];
    sha256_of(msg, msg_len, msg_hash);
    uint8_t salt_copy[RSA_PSS_SALT_LEN];
    memcpy(salt_copy, salt, sizeof salt_copy);
    static uint8_t sig[CH_RSA_MODULUS_MAX];
    size_t sig_len = 0;
    CT_SECRET(key.d, sizeof key.d);
#ifdef CH_CPU_RUNTIME
    CT_SECRET(key.p, sizeof key.p);
    CT_SECRET(key.q, sizeof key.q);
    CT_SECRET(key.dp, sizeof key.dp);
    CT_SECRET(key.dq, sizeof key.dq);
    CT_SECRET(key.qinv, sizeof key.qinv);
#endif
    CT_SECRET(salt_copy, sizeof salt_copy);
    int key_ok = widemul_rsa_pss_sign_key_ok(widemul, &key);
    // Public: the key test's verdict is the one the server's configuration check reports.
    CT_PUBLIC(&key_ok, sizeof key_ok);
    check(key_ok == 1, "rsa key test");
    int signed_ok = widemul_rsa_pss_sign_cpu(cpu, widemul, &key, msg_hash, salt_copy, sig,
                                             sizeof sig, &sig_len);
    // Public: the signature travels in CertificateVerify, and the verdict is the caller's.
    CT_PUBLIC(&signed_ok, sizeof signed_ok);
    CT_PUBLIC(&sig_len, sizeof sig_len);
    CT_PUBLIC(sig, sizeof sig);
    check(signed_ok == 1 && sig_len == from->n_len && memcmp(sig, expected, sig_len) == 0,
          "rsa-pss signature");
    ct_wipe(&key, sizeof key);
}

// ML-KEM-768 key generation from a secret seed, encapsulation with a secret message, and
// decapsulation with a secret key, of a ciphertext that matches and of one that does not, whose
// implicit rejection selects the other secret in constant time.
static void case_mlkem(uint32_t cpu, uint8_t widemul) {
    static uint8_t dk[MLKEM_DK_LEN];
    static uint8_t ct[MLKEM_CT_LEN];
    uint8_t d[32];
    uint8_t z[32];
    uint8_t m[32];
    uint8_t ss[MLKEM_SS_LEN];
    uint8_t reject[MLKEM_SS_LEN];
    memcpy(d, mlk_kat_d[0], sizeof d);
    memcpy(z, mlk_kat_z[0], sizeof z);
    memcpy(m, mlk_kat_m[0], sizeof m);
    CT_SECRET(d, sizeof d);
    CT_SECRET(z, sizeof z);
    mlkem_keygen_dk_cpu(cpu, dk, d, z);
    // Public: the encapsulation key, which dk carries at MLKEM_DK_EK_AT, travels in the key
    // share, and the 32 bytes after it are its hash (FIPS 203 Algorithm 16). The secret
    // vector before it and z after the hash stay secret.
    CT_PUBLIC(dk + MLKEM_DK_EK_AT, MLKEM_EK_LEN + 32);
    check(memcmp(dk + MLKEM_DK_EK_AT, mlk_kat_ek[0], MLKEM_EK_LEN) == 0, "ml-kem keygen");
    CT_SECRET(m, sizeof m);
    int refused = mlkem_encaps_derand_cpu(cpu, widemul, ct, ss, dk + MLKEM_DK_EK_AT, m);
    // Public: the ciphertext travels in the key share, and the verdict on ek is the caller's.
    CT_PUBLIC(ct, sizeof ct);
    CT_PUBLIC(&refused, sizeof refused);
    CT_PUBLIC(ss, sizeof ss);
    check(refused == 0 && memcmp(ct, mlk_kat_ct[0], MLKEM_CT_LEN) == 0 &&
              memcmp(ss, mlk_kat_K[0], MLKEM_SS_LEN) == 0,
          "ml-kem encapsulation");
    mlkem_decaps_cpu(cpu, widemul, ss, ct, dk);
    CT_PUBLIC(ss, sizeof ss);
    check(memcmp(ss, mlk_kat_K[0], MLKEM_SS_LEN) == 0, "ml-kem decapsulation");
    ct[0] ^= 1;
    mlkem_decaps_cpu(cpu, widemul, reject, ct, dk);
    CT_PUBLIC(reject, sizeof reject);
    check(memcmp(reject, ss, MLKEM_SS_LEN) != 0, "ml-kem implicit rejection");
}

int ct_taint_public_key_cases(uint32_t cpu) {
    uint8_t widemul = widemul_of_cpu(cpu);
    case_x25519(widemul);
    case_p256(cpu, widemul);
    const test_rsa_sign_key k2048 = TEST_RSA_SIGN_KEY(2048);
    case_rsa(cpu, widemul, &k2048, rsa_sign_2048_msg, sizeof rsa_sign_2048_msg, rsa_sign_2048_salt,
             rsa_sign_2048_sig);
    const test_rsa_sign_key k3072 = TEST_RSA_SIGN_KEY(3072);
    case_rsa(cpu, widemul, &k3072, rsa_sign_3072_msg, sizeof rsa_sign_3072_msg, rsa_sign_3072_salt,
             rsa_sign_3072_sig);
    case_mlkem(cpu, widemul);
    return failures;
}
