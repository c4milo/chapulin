// The JWS signers in the Valgrind taint lane (test/ct_taint_test.c says how
// the lane works, docs/decisions.md 223). ch_jws_sign runs under RS256,
// ES256 and EdDSA with each private key and the noise marked undefined.
// The signature and the verdict are marked defined again before the case
// compares them, because the token carries the signature and the caller
// sees the verdict. Memcheck then reports a branch or an address that a
// key, a nonce or a scalar decides. The binary builds as a host object
// with CH_JWS and a server role, apart from bin/ct_taint_test, which
// builds without them.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "cpu_cfg.h"
#include "ct_taint.h"
#include "jws.h"
#include "jws_rfc_vectors.h"
#include "rsa_key.h"
#include "test_cpu.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures;

static void check(int ok, const char *what) {
    if (!ok) {
        (void)printf("FAIL %s\n", what);
        failures++;
    }
}

// Signs RFC 7515 A.2's or A.3's input, or an RFC 8032 message, with key
// and noise marked secret, and checks the signature against want when one
// is given, or with ch_jws_verify.
static void case_sign(uint32_t cpu, uint8_t algorithm, void *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len, const uint8_t *want, size_t want_len,
                      const uint8_t *public_key, size_t public_key_len, const char *what) {
    uint8_t noise[CH_JWS_NOISE_LEN];
    for (size_t i = 0; i < sizeof noise; i++) {
        noise[i] = (uint8_t)(0x91 + 7 * i);
    }
    static uint8_t sig[CH_JWS_SIG_LEN_MAX];
    size_t sig_len = 0;
    if (algorithm == CH_JWS_RS256) {
        // An RSA key's modulus and its length are public: the certificate
        // carries them. The private exponent and the five CRT values are
        // secret, as test/ct_taint_keys.c's RSA case marks them.
        ch_rsa_priv *rsa = key;
        CT_SECRET(rsa->d, sizeof rsa->d);
        CT_SECRET(rsa->p, sizeof rsa->p);
        CT_SECRET(rsa->q, sizeof rsa->q);
        CT_SECRET(rsa->dp, sizeof rsa->dp);
        CT_SECRET(rsa->dq, sizeof rsa->dq);
        CT_SECRET(rsa->qinv, sizeof rsa->qinv);
    } else {
        CT_SECRET(key, key_len);
    }
    CT_SECRET(noise, sizeof noise);
    int rc = ch_jws_sign(cpu, algorithm, key, key_len, noise, msg, msg_len, sig, sizeof sig,
                         &sig_len);
    // Public: the verdict is the caller's, and the signature travels in the token.
    CT_PUBLIC(&rc, sizeof rc);
    CT_PUBLIC(&sig_len, sizeof sig_len);
    CT_PUBLIC(sig, sizeof sig);
    CT_PUBLIC(key, key_len);
    check(rc == CH_OK, what);
    if (want != NULL) {
        check(sig_len == want_len && memcmp(sig, want, want_len) == 0, what);
    } else {
        check(ch_jws_verify(algorithm, public_key, public_key_len, msg, msg_len, sig, sig_len) ==
                  CH_OK,
              what);
    }
}

int main(int argc, char **argv) {
    test_take_cpu(argc, argv);
    uint32_t cpu = test_cpu;
    (void)printf("%s Valgrind\n", CT_UNDER_VALGRIND() ? "under" : "not under");
    static ch_rsa_priv rsa;
    memset(&rsa, 0, sizeof rsa);
    memcpy(rsa.n, rfc7515_a2_n, sizeof rfc7515_a2_n);
    memcpy(rsa.d, rfc7515_a2_d, sizeof rfc7515_a2_d);
    rsa.n_len = sizeof rfc7515_a2_n;
    memcpy(rsa.p, rfc7515_a2_p, sizeof rfc7515_a2_p);
    memcpy(rsa.q, rfc7515_a2_q, sizeof rfc7515_a2_q);
    memcpy(rsa.dp, rfc7515_a2_dp, sizeof rfc7515_a2_dp);
    memcpy(rsa.dq, rfc7515_a2_dq, sizeof rfc7515_a2_dq);
    memcpy(rsa.qinv, rfc7515_a2_qinv, sizeof rfc7515_a2_qinv);
    const jws_vector *a2 = &jws_rfc_vectors[0];
    const jws_vector *a3 = &jws_rfc_vectors[1];
    // The key's lengths are public: n_len sizes the signature.
    case_sign(cpu, CH_JWS_RS256, &rsa, sizeof rsa, (const uint8_t *)a2->token, a2->input_len,
              a2->sig, a2->sig_len, NULL, 0, "rs256 signature");
    uint8_t scalar[32];
    memcpy(scalar, rfc7515_a3_d, sizeof scalar);
    case_sign(cpu, CH_JWS_ES256, scalar, sizeof scalar, (const uint8_t *)a3->token, a3->input_len,
              NULL, 0, a3->key, a3->key_len, "es256 signature");
    if ((cpu & CH_CPU_CONSTANT_TIME_MULTIPLY) != 0) {
        for (size_t i = 0; i < sizeof rfc8032_vectors / sizeof rfc8032_vectors[0]; i++) {
            uint8_t seed[32];
            memcpy(seed, rfc8032_vectors[i].secret, sizeof seed);
            case_sign(cpu, CH_JWS_EDDSA, seed, sizeof seed, rfc8032_vectors[i].message,
                      rfc8032_vectors[i].message_len, rfc8032_vectors[i].signature, 64, NULL, 0,
                      "eddsa signature");
        }
    }
    if (failures != 0) {
        (void)printf("ct_taint_jws_test: %d cases failed\n", failures);
        return 1;
    }
    (void)printf("ct_taint_jws_test: every case ran\n");
    return 0;
}
