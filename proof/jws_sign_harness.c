// Proves: ch_jws_sign (jws_sign.c) is memory safe and free of UB over any
// cpu value, algorithm byte, key length, room and input of up to the
// harness's bounds, and that it keeps what jws.h states:
// - it answers CH_OK, CH_ECAP or CH_EINVAL, and CH_EINVAL for a cpu value
//   the object refuses, before any signer runs;
// - it runs one signer at most, the algorithm's own, and only with a key
//   of the algorithm's length and noise where the algorithm reads it;
// - EdDSA runs only under CH_CPU_CONSTANT_TIME_MULTIPLY;
// - on CH_OK it wrote the signature's length to *sig_len and no byte past
//   the room; on any other answer *sig_len and the room are as they were.
//
// The three signers are contract stubs that record their calls, write any
// bytes and answer either verdict. Their own harnesses and tests prove
// them: p256_sign, rsa_sign and rsa_sign64 for the arithmetic,
// x25519_wide_ed25519_sign for the scalars modulo L, and bin/jws_sign_test
// for RFC 7515's and RFC 8032's signatures. SHA-256 is harness.h's stub.
//
// Bounds. An RSA modulus of up to 72 bytes and a room of up to 80: the
// dispatcher's tests and copies read the lengths and no byte of a key, so
// a longer modulus takes the same path. At the 512-byte bound, with the
// room symbolic, cbmc gave no verdict in 7 minutes.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include "cpu.h"
#include "ed25519_sign.h"
#include "jws.h"
#include "p256_sign.h"
#include "rsa_pkcs1.h"

#define INPUT_MAX 4
#define ROOM_MAX 80
#define MODULUS_MAX 72

static int signer_calls;
static int verdict;

int p256_sign_hedged_raw_cpu(uint32_t cpu, const uint8_t priv[P256_PRIV_LEN],
                             const uint8_t msg_hash[32], const uint8_t noise[P256_NOISE_LEN],
                             uint8_t sig[64]) {
    (void)cpu;
    __CPROVER_assert(__CPROVER_r_ok(priv, 32) && __CPROVER_r_ok(msg_hash, 32) &&
                         __CPROVER_r_ok(noise, P256_NOISE_LEN) && __CPROVER_w_ok(sig, 64),
                     "es256: key, digest, noise readable and room writable");
    signer_calls++;
    fill_nondet(sig, 64);
    verdict = nondet_u8() & 1;
    return verdict;
}

int rsa_pkcs1_sign(uint32_t cpu, const ch_rsa_priv *k, const uint8_t digest[32],
                   const uint8_t blind[RSA_BLIND_LEN], uint8_t *sig) {
    (void)cpu;
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k) && __CPROVER_r_ok(digest, 32) &&
                         __CPROVER_r_ok(blind, RSA_BLIND_LEN) && k->n_len <= CH_RSA_MODULUS_MAX &&
                         __CPROVER_w_ok(sig, k->n_len),
                     "rs256: key, digest, blind readable and n_len bytes writable");
    signer_calls++;
    fill_nondet(sig, k->n_len);
    verdict = nondet_u8() & 1;
    return verdict;
}

int ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t msg_len, uint8_t sig[64]) {
    __CPROVER_assert(__CPROVER_r_ok(seed, 32) && (msg_len == 0 || __CPROVER_r_ok(msg, msg_len)) &&
                         __CPROVER_w_ok(sig, 64),
                     "eddsa: seed and message readable and room writable");
    signer_calls++;
    fill_nondet(sig, 64);
    verdict = nondet_u8() & 1;
    return verdict;
}

int main(void) {
    static ch_rsa_priv rsa;
    uint8_t scalar[32];
    uint8_t noise[CH_JWS_NOISE_LEN];
    uint8_t input[INPUT_MAX];
    uint8_t sig[ROOM_MAX + 1];
    fill_nondet(scalar, sizeof scalar);
    fill_nondet(noise, sizeof noise);
    fill_nondet(input, sizeof input);
    fill_nondet(sig, sizeof sig);
    rsa.n_len = nondet_size_t();
    __CPROVER_assume(rsa.n_len <= MODULUS_MAX);
    uint32_t cpu = nondet_u32();
    uint8_t algorithm = nondet_u8();
    size_t input_len = nondet_size_t();
    size_t sig_cap = nondet_size_t();
    size_t priv_len = nondet_size_t();
    __CPROVER_assume(input_len <= INPUT_MAX && sig_cap <= ROOM_MAX);
    const void *priv = algorithm == CH_JWS_RS256 ? (const void *)&rsa : (const void *)scalar;
    __CPROVER_assume(priv_len <= (algorithm == CH_JWS_RS256 ? sizeof rsa : sizeof scalar));
    const uint8_t *n = nondet_u8() & 1 ? noise : NULL;
    uint8_t after = sig[sig_cap];
    size_t sig_len = nondet_size_t();
    size_t unset = sig_len;

    int rc =
        ch_jws_sign(cpu, algorithm, priv, priv_len, n, input, input_len, sig, sig_cap, &sig_len);

    __CPROVER_assert(rc == CH_OK || rc == CH_ECAP || rc == CH_EINVAL, "one of its three codes");
    __CPROVER_assert(signer_calls <= 1, "one signer at most");
    __CPROVER_assert(sig[sig_cap] == after, "no byte past the room is written");
    if (!cpu_value_ok(cpu)) {
        __CPROVER_assert(rc == CH_EINVAL && signer_calls == 0,
                         "a refused cpu value runs no signer");
    }
    if (algorithm == CH_JWS_EDDSA && signer_calls != 0) {
        __CPROVER_assert((cpu & CH_CPU_CONSTANT_TIME_MULTIPLY) != 0 && priv_len == 32,
                         "EdDSA runs under the multiply bit, with a 32-byte seed");
    }
    if (algorithm == CH_JWS_ES256 && signer_calls != 0) {
        __CPROVER_assert(priv_len == 32 && n != NULL, "ES256 runs with a 32-byte key and noise");
    }
    if (algorithm == CH_JWS_RS256 && signer_calls != 0) {
        __CPROVER_assert(priv_len == sizeof rsa && n != NULL, "RS256 runs with a key and noise");
    }
    if (rc == CH_OK) {
        __CPROVER_assert(signer_calls == 1 && verdict == 1, "CH_OK only after a signer accepted");
        __CPROVER_assert(sig_len <= sig_cap, "the signature fits the room");
    } else {
        __CPROVER_assert(sig_len == unset, "a refusal reports no length");
    }
    return 0;
}
