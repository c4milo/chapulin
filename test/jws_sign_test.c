// ch_jws_sign (docs/decisions.md 223) with the two private keys RFC 7515
// prints (test/gen_jws_rfc_vectors.py), under each ch_cfg.cpu value that
// picks another signer, and at each refusal jws.h states. An RS256
// signature is a function of the key and the input, so the signature of
// appendix A.2's input must be the RFC's own bytes. An ES256 signature
// takes fresh noise, so each one must verify under the RFC's public key
// through ch_jws_verify. The binary builds as a host object with CH_JWS
// and a server role.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "cpu_cfg.h"
#include "jws.h"
#include "jws_rfc_vectors.h"
#include "rsa_key.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures;

static void expect(int got, int want, const char *what) {
    if (got != want) {
        printf("FAIL jws_sign: %s: got %d, want %d\n", what, got, want);
        failures++;
    }
}

// The rows of test/jws_rfc_vectors.h: RFC 7515 appendix A.2 and A.3.
#define A2 (&jws_rfc_vectors[0])
#define A3 (&jws_rfc_vectors[1])

// The values of ch_cfg.cpu that pick each signer: the ladder and the
// 32-bit P-256 files without the multiply bit, and the CRT signer and
// the wide P-256 files with it.
static const uint32_t cpus[] = {CH_CPU_PROBED, CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY};
#define CPU_COUNT (sizeof cpus / sizeof cpus[0])

static ch_rsa_priv a2_key;

static void load_a2_key(void) {
    memset(&a2_key, 0, sizeof a2_key);
    memcpy(a2_key.n, rfc7515_a2_n, sizeof rfc7515_a2_n);
    memcpy(a2_key.d, rfc7515_a2_d, sizeof rfc7515_a2_d);
    a2_key.n_len = sizeof rfc7515_a2_n;
    memcpy(a2_key.p, rfc7515_a2_p, sizeof rfc7515_a2_p);
    memcpy(a2_key.q, rfc7515_a2_q, sizeof rfc7515_a2_q);
    memcpy(a2_key.dp, rfc7515_a2_dp, sizeof rfc7515_a2_dp);
    memcpy(a2_key.dq, rfc7515_a2_dq, sizeof rfc7515_a2_dq);
    memcpy(a2_key.qinv, rfc7515_a2_qinv, sizeof rfc7515_a2_qinv);
}

// Noise that differs from one call to the next.
static void noise_of(uint8_t noise[CH_JWS_NOISE_LEN], uint8_t seed) {
    for (size_t i = 0; i < CH_JWS_NOISE_LEN; i++) {
        noise[i] = (uint8_t)(seed + 3 * i + 1);
    }
}

// RS256: the RFC's signature, byte for byte, under each signer and under
// two values of the noise, which blinds the exponents and changes no
// byte of the signature.
static void rs256(void) {
    for (size_t c = 0; c < CPU_COUNT; c++) {
        for (uint8_t seed = 0; seed < 2; seed++) {
            uint8_t noise[CH_JWS_NOISE_LEN];
            uint8_t sig[CH_JWS_SIG_LEN_MAX + 1];
            size_t sig_len = 0;
            noise_of(noise, seed);
            memset(sig, 0x5a, sizeof sig);
            expect(ch_jws_sign(cpus[c], CH_JWS_RS256, &a2_key, sizeof a2_key, noise,
                               (const uint8_t *)A2->token, A2->input_len, sig, sizeof sig,
                               &sig_len),
                   CH_OK, "RS256 signs RFC 7515 A.2's input");
            expect(sig_len == A2->sig_len && memcmp(sig, A2->sig, sig_len) == 0, 1,
                   "the RS256 signature is the RFC's");
            expect(sig[sig_len], 0x5a, "RS256 writes no byte past the signature");
            expect(ch_jws_verify(CH_JWS_RS256, A2->key, A2->key_len, (const uint8_t *)A2->token,
                                 A2->input_len, sig, sig_len),
                   CH_OK, "the RS256 signature verifies");
        }
    }
}

// ES256: each signature verifies under the RFC's public key, the same
// noise gives the same signature, and other noise gives another.
static void es256(void) {
    for (size_t c = 0; c < CPU_COUNT; c++) {
        uint8_t noise[CH_JWS_NOISE_LEN];
        uint8_t first[65];
        uint8_t again[64];
        uint8_t other[64];
        size_t sig_len = 0;
        noise_of(noise, 0);
        memset(first, 0x5a, sizeof first);
        expect(ch_jws_sign(cpus[c], CH_JWS_ES256, rfc7515_a3_d, sizeof rfc7515_a3_d, noise,
                           (const uint8_t *)A3->token, A3->input_len, first, 64, &sig_len),
               CH_OK, "ES256 signs RFC 7515 A.3's input into a room of 64 bytes");
        expect((int)sig_len, 64, "an ES256 signature is 64 bytes");
        expect(first[64], 0x5a, "ES256 writes no byte past the signature");
        expect(ch_jws_verify(CH_JWS_ES256, A3->key, A3->key_len, (const uint8_t *)A3->token,
                             A3->input_len, first, 64),
               CH_OK, "the ES256 signature verifies under the RFC's public key");
        expect(ch_jws_sign(cpus[c], CH_JWS_ES256, rfc7515_a3_d, sizeof rfc7515_a3_d, noise,
                           (const uint8_t *)A3->token, A3->input_len, again, sizeof again,
                           &sig_len),
               CH_OK, "ES256 signs again");
        expect(memcmp(first, again, 64), 0, "the same noise gives the same signature");
        noise_of(noise, 1);
        expect(ch_jws_sign(cpus[c], CH_JWS_ES256, rfc7515_a3_d, sizeof rfc7515_a3_d, noise,
                           (const uint8_t *)A3->token, A3->input_len, other, sizeof other,
                           &sig_len),
               CH_OK, "ES256 signs under other noise");
        expect(memcmp(first, other, 64) != 0, 1, "other noise gives another signature");
        expect(ch_jws_verify(CH_JWS_ES256, A3->key, A3->key_len, (const uint8_t *)A3->token,
                             A3->input_len, other, 64),
               CH_OK, "and it verifies too");
        expect(ch_jws_sign(cpus[c], CH_JWS_ES256, rfc7515_a3_d, sizeof rfc7515_a3_d, noise, NULL,
                           0, other, sizeof other, &sig_len),
               CH_OK, "ES256 signs an empty input");
        expect(ch_jws_verify(CH_JWS_ES256, A3->key, A3->key_len, NULL, 0, other, 64), CH_OK,
               "and that signature verifies over no bytes");
    }
}

// EdDSA: an Ed25519 signature is a function of the key and the message,
// so each of RFC 8032 section 7.1's five must come out byte for byte, and
// verify under the RFC's public key. The signer runs on the wide field
// alone, so a cpu value without the multiply bit is refused. EdDSA reads
// no noise.
static void eddsa(void) {
    uint32_t cpu = CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY;
    for (size_t i = 0; i < sizeof rfc8032_vectors / sizeof rfc8032_vectors[0]; i++) {
        uint8_t sig[65];
        size_t sig_len = 0;
        memset(sig, 0x5a, sizeof sig);
        expect(ch_jws_sign(cpu, CH_JWS_EDDSA, rfc8032_vectors[i].secret, 32, NULL,
                           rfc8032_vectors[i].message, rfc8032_vectors[i].message_len, sig, 64,
                           &sig_len),
               CH_OK, "EdDSA signs an RFC 8032 message");
        expect(sig_len == 64 && memcmp(sig, rfc8032_vectors[i].signature, 64) == 0, 1,
               "the EdDSA signature is the RFC's");
        expect(sig[64], 0x5a, "EdDSA writes no byte past the signature");
        expect(ch_jws_verify(CH_JWS_EDDSA, rfc8032_vectors[i].public_key, 32,
                             rfc8032_vectors[i].message, rfc8032_vectors[i].message_len, sig, 64),
               CH_OK, "the EdDSA signature verifies under the RFC's public key");
    }
    uint8_t sig[64];
    size_t sig_len = 99;
    memset(sig, 0x5a, sizeof sig);
    const uint8_t *seed = rfc8032_vectors[1].secret;
    const uint8_t *message = rfc8032_vectors[1].message;
    expect(ch_jws_sign(CH_CPU_PROBED, CH_JWS_EDDSA, seed, 32, NULL, message, 1, sig, 64, &sig_len),
           CH_EINVAL, "EdDSA under a cpu value without the multiply bit is refused");
    expect(ch_jws_sign(cpu, CH_JWS_EDDSA, seed, 31, NULL, message, 1, sig, 64, &sig_len), CH_EINVAL,
           "an EdDSA seed of 31 bytes");
    expect(ch_jws_sign(cpu, CH_JWS_EDDSA, seed, 32, NULL, message, 1, sig, 63, &sig_len), CH_ECAP,
           "an EdDSA room of 63 bytes");
    expect(sig_len == 99 && sig[0] == 0x5a && sig[63] == 0x5a, 1, "a refused call writes nothing");
}

// A refused call writes nothing: the room and the length stay as they
// were.
static int refused(uint32_t cpu, uint8_t algorithm, const void *priv, size_t priv_len,
                   const uint8_t *noise, size_t sig_cap) {
    uint8_t sig[CH_JWS_SIG_LEN_MAX];
    size_t sig_len = 99;
    memset(sig, 0x5a, sizeof sig);
    int rc = ch_jws_sign(cpu, algorithm, priv, priv_len, noise, (const uint8_t *)A3->token,
                         A3->input_len, sig, sig_cap, &sig_len);
    if (rc != CH_OK) {
        expect((int)sig_len, 99, "a refused call reports no length");
        for (size_t i = 0; i < sizeof sig; i++) {
            expect(sig[i], 0x5a, "a refused call writes nothing");
        }
    }
    return rc;
}

static void refusals(void) {
    uint8_t noise[CH_JWS_NOISE_LEN];
    noise_of(noise, 0);
    uint32_t cpu = CH_CPU_PROBED;
    const uint8_t *d = rfc7515_a3_d;
    expect(refused(cpu, CH_JWS_ES256, d, 32, noise, 64), CH_OK, "the call these refusals change");
    expect(refused(0, CH_JWS_ES256, d, 32, noise, 64), CH_EINVAL, "a cpu value with no probe bit");
    expect(refused(cpu | 0x80000000U, CH_JWS_ES256, d, 32, noise, 64), CH_EINVAL,
           "a cpu value with a bit the object does not define");
    expect(refused(cpu, 0, d, 32, noise, 64), CH_EINVAL, "algorithm 0");
    expect(refused(cpu, 255, d, 32, noise, 64), CH_EINVAL, "algorithm 255");
    expect(refused(cpu, CH_JWS_ES256, NULL, 32, noise, 64), CH_EINVAL, "a NULL key");
    expect(refused(cpu, CH_JWS_ES256, d, 31, noise, 64), CH_EINVAL, "an ES256 key of 31 bytes");
    expect(refused(cpu, CH_JWS_ES256, d, 33, noise, 64), CH_EINVAL, "an ES256 key of 33 bytes");
    expect(refused(cpu, CH_JWS_ES256, d, 32, NULL, 64), CH_EINVAL, "ES256 with no noise");
    expect(refused(cpu, CH_JWS_ES256, d, 32, noise, 63), CH_ECAP, "an ES256 room of 63 bytes");
    // The scalars outside 1 to n-1: zero, and the group order itself.
    static const uint8_t zero[32] = {0};
    static const uint8_t order[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                                      0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
    expect(refused(cpu, CH_JWS_ES256, zero, 32, noise, 64), CH_EINVAL, "the ES256 scalar 0");
    expect(refused(cpu, CH_JWS_ES256, order, 32, noise, 64), CH_EINVAL,
           "the ES256 scalar n, the group order");

    expect(refused(cpu, CH_JWS_RS256, &a2_key, sizeof a2_key, noise, 256), CH_OK,
           "RS256 into a room of exactly the modulus's length");
    expect(refused(cpu, CH_JWS_RS256, &a2_key, sizeof a2_key, noise, 255), CH_ECAP,
           "an RS256 room one byte short");
    expect(refused(cpu, CH_JWS_RS256, &a2_key, sizeof a2_key - 1, noise, 256), CH_EINVAL,
           "an RS256 key of another size");
    expect(refused(cpu, CH_JWS_RS256, &a2_key, sizeof a2_key, NULL, 256), CH_EINVAL,
           "RS256 with no noise");
    // A key the signer's test refuses: an even modulus, and a length that
    // is no multiple of 8 bytes.
    ch_rsa_priv bad = a2_key;
    bad.n[bad.n_len - 1] &= 0xfe;
    expect(refused(cpu, CH_JWS_RS256, &bad, sizeof bad, noise, 512), CH_EINVAL, "an even modulus");
    bad = a2_key;
    bad.n_len = 252;
    expect(refused(cpu, CH_JWS_RS256, &bad, sizeof bad, noise, 512), CH_EINVAL,
           "a modulus of 252 bytes");
    bad = a2_key;
    bad.n_len = CH_JWS_RSA_MODULUS_LEN_MAX + 8;
    expect(refused(cpu, CH_JWS_RS256, &bad, sizeof bad, noise, 1024), CH_EINVAL,
           "a modulus length above the bound");
    // A private exponent that is not the key's: the signature fails its
    // check under the modulus, and nothing leaves.
    bad = a2_key;
    bad.d[255] ^= 2;
    expect(refused(cpu, CH_JWS_RS256, &bad, sizeof bad, noise, 512), CH_EINVAL,
           "a private exponent that does not match the modulus");
}

int main(void) {
    load_a2_key();
    rs256();
    es256();
    eddsa();
    refusals();
    if (failures != 0) {
        return 1;
    }
    printf("jws_sign: RS256 writes RFC 7515 A.2's signature and ES256 signatures verify, under "
           "%zu cpu values, EdDSA writes RFC 8032's five signatures, and every refusal jws.h "
           "states holds\n",
           CPU_COUNT);
    return 0;
}
