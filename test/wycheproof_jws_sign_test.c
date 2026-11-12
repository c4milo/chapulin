// ch_jws_sign against Wycheproof (docs/decisions.md 223): the SHA-256
// groups of the five rsa_pkcs1_*_sig_gen_test.json suites, and the valid
// tokens of json_web_signature_test.json whose private JWK a caller signs
// with. An RS256 signature is a function of the key and the input, so
// each one must come out byte for byte. A key under 2048 bits or with a
// public exponent other than 65537 must be refused, with no byte written.
// An ES256 signature takes fresh noise, so each one must verify under the
// JWK's public key through ch_jws_verify. The header is
// bin/wycheproof_jws_sign_vectors.h, which make wycheproof writes, and
// test/gen_wycheproof_jws_sign.py states how the script picks each row.
// The binary builds as a host object with CH_JWS and a server role, and
// takes the ch_cfg.cpu value that picks the signers as its one argument.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "jws.h"
#include "rsa_key.h"
#include "test_cpu.h"
#include "wycheproof_jws_sign_vectors.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#define COUNT(a) (sizeof(a) / sizeof(a)[0])
#define ROOM_FILL 0x5a
#define ES256_SIG_LEN 64

static size_t failures;

static void fail(const char *suite, int tc_id, const char *what) {
    printf("FAIL Wycheproof %s tcId %d: %s\n", suite, tc_id, what);
    failures++;
}

// Noise that differs from one row to the next. It blinds the RSA
// exponents and changes no byte of an RS256 signature.
static void noise_of(uint8_t noise[CH_JWS_NOISE_LEN], size_t row) {
    for (size_t i = 0; i < CH_JWS_NOISE_LEN; i++) {
        noise[i] = (uint8_t)(7 * row + 3 * i + 1);
    }
}

static ch_rsa_priv rsa_key;

// Writes row k of wp_jws_sign_rsa_keys into rsa_key. Every row's n_len is
// CH_RSA_MODULUS_MAX or less: the largest key is 4096 bits.
static void load_rsa_key(size_t k) {
    size_t n_len = wp_jws_sign_rsa_keys[k].n_len;
    memset(&rsa_key, 0, sizeof rsa_key);
    memcpy(rsa_key.n, wp_jws_sign_rsa_keys[k].n, n_len);
    memcpy(rsa_key.d, wp_jws_sign_rsa_keys[k].d, n_len);
    rsa_key.n_len = n_len;
    memcpy(rsa_key.p, wp_jws_sign_rsa_keys[k].p, n_len / 2);
    memcpy(rsa_key.q, wp_jws_sign_rsa_keys[k].q, n_len / 2);
    memcpy(rsa_key.dp, wp_jws_sign_rsa_keys[k].dp, n_len / 2);
    memcpy(rsa_key.dq, wp_jws_sign_rsa_keys[k].dq, n_len / 2);
    memcpy(rsa_key.qinv, wp_jws_sign_rsa_keys[k].qinv, n_len / 2);
}

// 1 when every byte of the room still holds ROOM_FILL.
static int room_untouched(const uint8_t *room, size_t room_len) {
    for (size_t i = 0; i < room_len; i++) {
        if (room[i] != ROOM_FILL) {
            return 0;
        }
    }
    return 1;
}

// One RS256 row: the suite's signature byte for byte, or a refusal that
// writes nothing.
static void rs256_case(size_t i) {
    const char *suite = wp_jws_sign_rsa_cases[i].suite;
    int tc_id = wp_jws_sign_rsa_cases[i].tc_id;
    uint8_t noise[CH_JWS_NOISE_LEN];
    uint8_t sig[CH_JWS_SIG_LEN_MAX + 1];
    size_t sig_len = 0;
    noise_of(noise, i);
    memset(sig, ROOM_FILL, sizeof sig);
    load_rsa_key(wp_jws_sign_rsa_cases[i].key);
    int rc = ch_jws_sign(test_cpu, CH_JWS_RS256, &rsa_key, sizeof rsa_key, noise,
                         wp_jws_sign_rsa_cases[i].msg, wp_jws_sign_rsa_cases[i].msg_len, sig,
                         CH_JWS_SIG_LEN_MAX, &sig_len);
    if (!wp_jws_sign_rsa_cases[i].want) {
        if (rc != CH_EINVAL || sig_len != 0 || !room_untouched(sig, sizeof sig)) {
            fail(suite, tc_id, "a key with no signer was not refused, or the call wrote a byte");
        }
        return;
    }
    if (rc != CH_OK || sig_len != wp_jws_sign_rsa_cases[i].sig_len ||
        memcmp(sig, wp_jws_sign_rsa_cases[i].sig, sig_len) != 0) {
        fail(suite, tc_id, "the RS256 signature is not the suite's");
        return;
    }
    if (!room_untouched(sig + sig_len, sizeof sig - sig_len)) {
        fail(suite, tc_id, "RS256 wrote a byte past the signature");
    }
}

// One ES256 row: a signature under the JWK's d that verifies under its X
// and Y.
static void es256_case(size_t i) {
    int tc_id = wp_jws_sign_es256_cases[i].tc_id;
    uint8_t noise[CH_JWS_NOISE_LEN];
    uint8_t sig[ES256_SIG_LEN + 1];
    size_t sig_len = 0;
    noise_of(noise, i);
    memset(sig, ROOM_FILL, sizeof sig);
    int rc = ch_jws_sign(test_cpu, CH_JWS_ES256, wp_jws_sign_es256_cases[i].d, 32, noise,
                         wp_jws_sign_es256_cases[i].input, wp_jws_sign_es256_cases[i].input_len,
                         sig, ES256_SIG_LEN, &sig_len);
    if (rc != CH_OK || sig_len != ES256_SIG_LEN || sig[ES256_SIG_LEN] != ROOM_FILL) {
        fail("json_web_signature", tc_id, "ES256 did not sign under the JWK's d");
        return;
    }
    if (ch_jws_verify(CH_JWS_ES256, wp_jws_sign_es256_cases[i].key, 2 * 32,
                      wp_jws_sign_es256_cases[i].input, wp_jws_sign_es256_cases[i].input_len, sig,
                      sig_len) != CH_OK) {
        fail("json_web_signature", tc_id, "the ES256 signature fails under the JWK's X and Y");
    }
}

int main(int argc, char **argv) {
    test_take_cpu(argc, argv);
    size_t written = 0;
    for (size_t i = 0; i < COUNT(wp_jws_sign_rsa_cases); i++) {
        rs256_case(i);
        written += (size_t)wp_jws_sign_rsa_cases[i].want;
    }
    for (size_t i = 0; i < COUNT(wp_jws_sign_es256_cases); i++) {
        es256_case(i);
    }
    if (failures != 0) {
        return 1;
    }
    printf("Wycheproof JWS signer: %zu RS256 signatures are the suites' byte for byte, %zu RS256 "
           "cases of a key with no signer were refused, and %zu ES256 signatures verify under "
           "the JWK's public key; %d valid tokens of a key with no signer were not run\n",
           written, COUNT(wp_jws_sign_rsa_cases) - written, COUNT(wp_jws_sign_es256_cases),
           WP_JWS_SIGN_TOKENS_SKIPPED);
    return 0;
}
