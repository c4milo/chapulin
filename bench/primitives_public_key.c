// The per-operation rows of bench/primitives.c: key exchange, the KEM,
// signatures and their verification. Every input is a known answer the
// tree already carries, and each row's prepare checks the call gives
// that answer before any sample is taken, so a broken build fails
// instead of timing garbage.
//
// Two groups, split the way the aead and hash groups are. verify runs
// p256.c, p384.c, rsa.c and rsa_pkcs1.c, whose inputs are all public and
// whose products use the compiler's own multiply, so CH_NATIVE_WIDEMUL
// compiles them to the same code. secret_key runs x25519.c,
// mlkem_poly.c, p256_field.c, p256_scalar.c and rsa_sign.c, whose
// products go through ct.h's ct_widemul, so bench/primitives.sh times
// it under both builds.
//
// The program is built with CH_RSA_MODULUS_MAX at 512, the value
// TRUST=webpki gives it, so the RSA-4096 rows run. rsa_mont.c's loops
// run over the modulus length, not that bound, so the 2048 and 3072 rows
// time the same work a device build does.
#include <string.h>

#include "mlkem.h"
#include "p256.h"
#include "p256_ecdh.h"
#include "p256_sign.h"
#include "p384.h"
#include "primitives.h"
#include "rsa.h"
#include "rsa_pkcs1.h"
#include "rsa_sign.h"
#include "sha256.h"
#include "x25519.h"

#include "insn_vectors.h"
#include "p256_ecdh_vectors.h"
#include "p256_sign_vectors.h"
#include "rsa_pkcs1_vectors.h"
#include "rsa_pkcs1_wide_vectors.h"
#include "rsa_sign_vectors.h"
#include "rsa_wide_vectors.h"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

// Every row here takes fixed-size inputs, so its one size is 0.
static const size_t NO_SIZE[] = {0};

// RFC 6979 A.2.6, P-384 with SHA-384 over "sample": the public key, the
// digest and the DER signature test/p384_test.c checks.
static const char P384_PUB_HEX[] =
    "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64"
    "def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c62189"
    "6708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720";
static const char P384_HASH_HEX[] =
    "9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312"
    "313bca4a9b5b890efee42c77b1ee25fe";
static const char P384_SIG_HEX[] =
    "306602310094edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4"
    "ea95ad133c81a648152e44acf96e36dd1e80fabe4602310099ef4aeb15f178ce"
    "a1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e"
    "7b82c71a38628ac8";

static uint8_t p384_pub[P384_PUB_LEN];
static uint8_t p384_hash[P384_LEN];
static uint8_t p384_sig[104]; // the DER signature above is 104 bytes
static size_t p384_sig_len;
// SHA-256 of rsa_sign_2048_msg: what the 2048-bit PSS vector signs, and
// what both signing rows sign.
static uint8_t rsa_message_hash[SHA256_LEN];
static ch_rsa_priv rsa_2048_key;
static ch_rsa_priv rsa_3072_key;
static uint8_t mlkem_ek[MLKEM_EK_LEN];
static uint8_t mlkem_dk[MLKEM_DK_LEN];
static uint8_t mlkem_ct[MLKEM_CT_LEN];

static uint8_t nibble(char c) {
    return (uint8_t)(c <= '9' ? c - '0' : c - 'a' + 10);
}

static size_t unhex(const char *hex, uint8_t *out, size_t cap) {
    size_t n = strlen(hex) / 2;
    if (n > cap) {
        bench_fail("a hex vector is longer than its buffer");
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    }
    return n;
}

static void expect(int ok, const char *what) {
    if (!ok) {
        bench_fail(what);
    }
}

static void run_x25519(size_t n) {
    (void)n;
    uint8_t out[X25519_LEN];
    expect(x25519(out, X25519_SCALAR, X25519_POINT) == 1, "x25519 refused its vector");
    bench_consume(out, 1);
}

static void prepare_x25519(size_t n) {
    (void)n;
    uint8_t out[X25519_LEN];
    expect(x25519(out, X25519_SCALAR, X25519_POINT) == 1, "x25519 refused its vector");
    expect(memcmp(out, X25519_WANT, sizeof out) == 0, "x25519 missed RFC 7748 §5.2");
}

static void run_x25519_base(size_t n) {
    (void)n;
    uint8_t out[X25519_LEN];
    x25519_base(out, X25519_SCALAR);
    bench_consume(out, 1);
}

static void prepare_nothing(size_t n) {
    (void)n;
}

static void run_mlkem_keygen(size_t n) {
    (void)n;
    mlkem_keygen_derand(mlkem_ek, mlkem_dk, MLKEM_D, MLKEM_Z);
    bench_consume(mlkem_dk, 1);
}

static void prepare_mlkem(size_t n) {
    (void)n;
    uint8_t ss[MLKEM_SS_LEN];
    uint8_t decapsulated[MLKEM_SS_LEN];
    mlkem_keygen_derand(mlkem_ek, mlkem_dk, MLKEM_D, MLKEM_Z);
    expect(mlkem_encaps_derand(mlkem_ct, ss, mlkem_ek, MLKEM_M) == 0, "encaps refused its ek");
    mlkem_decaps(decapsulated, mlkem_ct, mlkem_dk);
    expect(memcmp(ss, decapsulated, sizeof ss) == 0, "decaps disagrees with encaps");
    expect(memcmp(ss, MLKEM_K_WANT, sizeof ss) == 0, "ML-KEM missed its FIPS 203 answer");
}

static void run_mlkem_encaps(size_t n) {
    (void)n;
    uint8_t ss[MLKEM_SS_LEN];
    expect(mlkem_encaps_derand(mlkem_ct, ss, mlkem_ek, MLKEM_M) == 0, "encaps refused its ek");
    bench_consume(ss, 1);
}

static void run_mlkem_decaps(size_t n) {
    (void)n;
    uint8_t ss[MLKEM_SS_LEN];
    mlkem_decaps(ss, mlkem_ct, mlkem_dk);
    bench_consume(ss, 1);
}

static void run_p256_verify(size_t n) {
    (void)n;
    expect(p256_ecdsa_verify(P256_PUB, P256_HASH, P256_SIG, sizeof P256_SIG) == 1,
           "p256_ecdsa_verify refused RFC 6979 A.2.5");
}

static void run_p256_sign(size_t n) {
    (void)n;
    uint8_t sig[P256_SIG_MAX];
    size_t sig_len = 0;
    const p256_sign_vector *v = &p256_sign_vectors[0];
    expect(p256_sign(v->priv, v->msg_hash, sig, sizeof sig, &sig_len) == 1, "p256_sign failed");
    bench_consume(sig, 1);
}

static void prepare_p256_sign(size_t n) {
    (void)n;
    uint8_t sig[P256_SIG_MAX];
    size_t sig_len = 0;
    const p256_sign_vector *v = &p256_sign_vectors[0];
    expect(p256_sign(v->priv, v->msg_hash, sig, sizeof sig, &sig_len) == 1, "p256_sign failed");
    expect(sig_len == v->sig_len && memcmp(sig, v->sig, sig_len) == 0,
           "p256_sign missed RFC 6979 A.2.5");
}

// A random scalar from test/p256_ecdh_vectors.h, (1 of 3) in each table.
#define ECDH_KEYGEN_CASE 5
#define ECDH_SHARED_CASE 2

static void run_p256_ecdh_keygen(size_t n) {
    (void)n;
    uint8_t priv[P256_SCALAR_LEN];
    uint8_t pub[P256_POINT_LEN];
    expect(p256_ecdh_keygen(P256_ECDH_KEYGEN[ECDH_KEYGEN_CASE].scalar, priv, pub) == 1,
           "p256_ecdh_keygen refused its draw");
    bench_consume(pub, 1);
}

static void prepare_p256_ecdh_keygen(size_t n) {
    (void)n;
    uint8_t priv[P256_SCALAR_LEN];
    uint8_t pub[P256_POINT_LEN];
    const p256_ecdh_keygen_case *c = &P256_ECDH_KEYGEN[ECDH_KEYGEN_CASE];
    expect(p256_ecdh_keygen(c->scalar, priv, pub) == 1, "p256_ecdh_keygen refused its draw");
    expect(memcmp(pub, c->pub, sizeof pub) == 0, "p256_ecdh_keygen missed its vector");
}

static void run_p256_ecdh(size_t n) {
    (void)n;
    uint8_t shared[P256_SECRET_LEN];
    const p256_ecdh_shared_case *c = &P256_ECDH_SHARED[ECDH_SHARED_CASE];
    expect(p256_ecdh(c->priv, c->peer, shared) == 1, "p256_ecdh refused its vector");
    bench_consume(shared, 1);
}

static void prepare_p256_ecdh(size_t n) {
    (void)n;
    uint8_t shared[P256_SECRET_LEN];
    const p256_ecdh_shared_case *c = &P256_ECDH_SHARED[ECDH_SHARED_CASE];
    expect(p256_ecdh(c->priv, c->peer, shared) == 1, "p256_ecdh refused its vector");
    expect(memcmp(shared, c->shared, sizeof shared) == 0, "p256_ecdh missed its vector");
}

static void prepare_p384(size_t n) {
    (void)n;
    (void)unhex(P384_PUB_HEX, p384_pub, sizeof p384_pub);
    (void)unhex(P384_HASH_HEX, p384_hash, sizeof p384_hash);
    p384_sig_len = unhex(P384_SIG_HEX, p384_sig, sizeof p384_sig);
}

static void run_p384_verify(size_t n) {
    (void)n;
    expect(p384_ecdsa_verify(p384_pub, p384_hash, p384_sig, p384_sig_len) == 1,
           "p384_ecdsa_verify refused RFC 6979 A.2.6");
}

static void prepare_rsa_message_hash(size_t n) {
    (void)n;
    sha256_of(rsa_sign_2048_msg, sizeof rsa_sign_2048_msg, rsa_message_hash);
}

static void run_rsa_pss_verify_2048(size_t n) {
    (void)n;
    expect(rsa_pss_verify(rsa_sign_2048_n, sizeof rsa_sign_2048_n, rsa_message_hash,
                          rsa_sign_2048_sig, sizeof rsa_sign_2048_sig) == 1,
           "rsa_pss_verify refused its 2048-bit vector");
}

static void run_rsa_pss_verify_3072(size_t n) {
    (void)n;
    expect(rsa_pss_verify(RSA_N, sizeof RSA_N, RSA_HASH, RSA_SIG, sizeof RSA_SIG) == 1,
           "rsa_pss_verify refused its 3072-bit vector");
}

static void run_rsa_pss_verify_4096(size_t n) {
    (void)n;
    expect(rsa_pss_verify(n4096, sizeof n4096, rsa4096_sha256_digest, rsa4096_pss_sig,
                          sizeof rsa4096_pss_sig) == 1,
           "rsa_pss_verify refused its 4096-bit vector");
}

static void run_rsa_pkcs1_verify_2048(size_t n) {
    (void)n;
    expect(rsa_pkcs1_verify(n2048, sizeof n2048, rsa2048_sha256_digest,
                            sizeof rsa2048_sha256_digest, rsa2048_sha256_sig,
                            sizeof rsa2048_sha256_sig) == 1,
           "rsa_pkcs1_verify refused its 2048-bit vector");
}

static void run_rsa_pkcs1_verify_3072(size_t n) {
    (void)n;
    expect(rsa_pkcs1_verify(n3072, sizeof n3072, rsa3072_sha256_digest,
                            sizeof rsa3072_sha256_digest, rsa3072_sha256_sig,
                            sizeof rsa3072_sha256_sig) == 1,
           "rsa_pkcs1_verify refused its 3072-bit vector");
}

static void run_rsa_pkcs1_verify_4096(size_t n) {
    (void)n;
    expect(rsa_pkcs1_verify(n4096, sizeof n4096, rsa4096_sha256_digest,
                            sizeof rsa4096_sha256_digest, rsa4096_sha256_sig,
                            sizeof rsa4096_sha256_sig) == 1,
           "rsa_pkcs1_verify refused its 4096-bit vector");
}

static void load_rsa_key(ch_rsa_priv *k, const uint8_t *n, const uint8_t *d, size_t len) {
    memset(k, 0, sizeof *k);
    k->n_len = len;
    memcpy(k->n, n, len);
    memcpy(k->d, d, len);
}

// The salt comes from ch_rand_bytes, drbg.c here, so the signature
// differs from the vector's; prepare checks the verifier takes it.
static void sign_and_check(const ch_rsa_priv *k, const uint8_t hash[SHA256_LEN]) {
    uint8_t sig[CH_RSA_MODULUS_MAX];
    size_t sig_len = 0;
    expect(rsa_pss_sign(k, hash, sig, sizeof sig, &sig_len) == 1, "rsa_pss_sign failed");
    expect(rsa_pss_verify(k->n, k->n_len, hash, sig, sig_len) == 1,
           "rsa_pss_verify refused rsa_pss_sign's signature");
}

static void prepare_rsa_sign_2048(size_t n) {
    prepare_rsa_message_hash(n);
    load_rsa_key(&rsa_2048_key, rsa_sign_2048_n, rsa_sign_2048_d, sizeof rsa_sign_2048_n);
    sign_and_check(&rsa_2048_key, rsa_message_hash);
}

static void prepare_rsa_sign_3072(size_t n) {
    prepare_rsa_message_hash(n);
    load_rsa_key(&rsa_3072_key, rsa_sign_3072_n, rsa_sign_3072_d, sizeof rsa_sign_3072_n);
    sign_and_check(&rsa_3072_key, rsa_message_hash);
}

static void run_rsa_sign(const ch_rsa_priv *k) {
    uint8_t sig[CH_RSA_MODULUS_MAX];
    size_t sig_len = 0;
    expect(rsa_pss_sign(k, rsa_message_hash, sig, sizeof sig, &sig_len) == 1,
           "rsa_pss_sign failed");
    bench_consume(sig, 1);
}

static void run_rsa_pss_sign_2048(size_t n) {
    (void)n;
    run_rsa_sign(&rsa_2048_key);
}

static void run_rsa_pss_sign_3072(size_t n) {
    (void)n;
    run_rsa_sign(&rsa_3072_key);
}

#define OP_ROW(name, prepare, run) {name, "op", NO_SIZE, COUNT(NO_SIZE), prepare, run}

static const bench_row VERIFY_ROWS[] = {
    OP_ROW("p256_ecdsa_verify", prepare_nothing, run_p256_verify),
    OP_ROW("p384_ecdsa_verify", prepare_p384, run_p384_verify),
    OP_ROW("rsa_pss_verify_2048", prepare_rsa_message_hash, run_rsa_pss_verify_2048),
    OP_ROW("rsa_pss_verify_3072", prepare_nothing, run_rsa_pss_verify_3072),
    OP_ROW("rsa_pss_verify_4096", prepare_nothing, run_rsa_pss_verify_4096),
    OP_ROW("rsa_pkcs1_verify_2048", prepare_nothing, run_rsa_pkcs1_verify_2048),
    OP_ROW("rsa_pkcs1_verify_3072", prepare_nothing, run_rsa_pkcs1_verify_3072),
    OP_ROW("rsa_pkcs1_verify_4096", prepare_nothing, run_rsa_pkcs1_verify_4096),
};

static const bench_row SECRET_KEY_ROWS[] = {
    OP_ROW("x25519", prepare_x25519, run_x25519),
    OP_ROW("x25519_base", prepare_nothing, run_x25519_base),
    OP_ROW("mlkem768_keygen", prepare_mlkem, run_mlkem_keygen),
    OP_ROW("mlkem768_encaps", prepare_mlkem, run_mlkem_encaps),
    OP_ROW("mlkem768_decaps", prepare_mlkem, run_mlkem_decaps),
    OP_ROW("p256_ecdh_keygen", prepare_p256_ecdh_keygen, run_p256_ecdh_keygen),
    OP_ROW("p256_ecdh", prepare_p256_ecdh, run_p256_ecdh),
    OP_ROW("p256_sign", prepare_p256_sign, run_p256_sign),
    OP_ROW("rsa_pss_sign_2048", prepare_rsa_sign_2048, run_rsa_pss_sign_2048),
    OP_ROW("rsa_pss_sign_3072", prepare_rsa_sign_3072, run_rsa_pss_sign_3072),
};

const bench_group BENCH_VERIFY = {"verify", VERIFY_ROWS, COUNT(VERIFY_ROWS), NULL};
const bench_group BENCH_SECRET_KEY = {"secret_key", SECRET_KEY_ROWS, COUNT(SECRET_KEY_ROWS), NULL};
