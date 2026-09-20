// Proves: the five entries of srv_auth.c read and write only inside
// their own buffers and commit no undefined behavior, over an
// unconstrained configuration, an unconstrained transcript hash at every
// length the contract admits, and every SignatureScheme code point.
//
// The domain. srv_auth.c holds no parser and no loop of its own, so its
// whole input domain is the two identity slots, the sigalg code point,
// hash_len and cap, and this harness varies all five. Each slot is
// written field by field rather than filled through a byte pointer, so
// every pointer in it is a real object or NULL and a dereference
// srv_auth.c makes is a question about srv_auth.c.
//
// Each key pointer names one of four objects: the one its scheme wants,
// the one the other scheme wants, an object too short for either, or
// NULL. The caller's contract is that priv_len and pub_len are the
// sizes of the objects they measure, so this harness sets each length
// from the object it chose. Under that contract, key_lengths_match is
// the only line that keeps srv_auth.c from handing a signer a buffer
// shorter than the signer reads, and the stubs' readability assertions
// are what fail if it stops.
//
// The two signers and the two verifiers are contract stubs below, for
// the reason SHA-256 is one: each has its own harness, and compiling
// the real arithmetic into this formula would hold the exponentiation
// rather than this file. Each stub asserts what the real function reads
// and writes, so the assertion that a signer's key buffer is readable
// at the length it reads is what this proof says about the length test
// in key_lengths_match. p256_sign_harness.c and rsa_sign_harness.c
// prove the real signers.
//
// What this does not reach: any claim that a signature is correct. The
// stubs return an unconstrained verdict, so the proof covers both
// answers and neither is evidence about the arithmetic.
//
// SHA-256 is a contract stub (CH_PROOF_STUB_SHA256 in proof/harness.h),
// so this formula holds the assembly and not the compression function.
// sha256_harness.c proves the real one.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include "srv_auth.c"

// The signer and verifier contracts, asserted. Each one states the
// buffers the real function reads and writes at the lengths it uses,
// and then havocs its outputs, so the proof considers every answer the
// real function could give.
int p256_sign(const uint8_t priv[P256_PRIV_LEN], const uint8_t msg_hash[32], uint8_t *sig,
              size_t cap, size_t *sig_len) {
    __CPROVER_assert(__CPROVER_r_ok(priv, P256_PRIV_LEN), "p256_sign: key readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, SHA256_LEN), "p256_sign: digest readable");
    __CPROVER_assert(__CPROVER_w_ok(sig, cap), "p256_sign: output writable");
    __CPROVER_assert(__CPROVER_w_ok(sig_len, sizeof *sig_len), "p256_sign: length writable");
    if (!nondet_u8()) {
        return 0;
    }
    size_t n = nondet_size_t();
    __CPROVER_assume(n > 0 && n <= P256_SIG_MAX && n <= cap);
    fill_nondet(sig, n);
    *sig_len = n;
    return 1;
}

int rsa_pss_sign(const ch_rsa_priv *k, const uint8_t msg_hash[32], uint8_t *sig, size_t cap,
                 size_t *sig_len) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "rsa_pss_sign: key readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, SHA256_LEN), "rsa_pss_sign: digest readable");
    __CPROVER_assert(__CPROVER_w_ok(sig, cap), "rsa_pss_sign: output writable");
    __CPROVER_assert(__CPROVER_w_ok(sig_len, sizeof *sig_len), "rsa_pss_sign: length writable");
    if (!nondet_u8()) {
        return 0;
    }
    size_t n = nondet_size_t();
    __CPROVER_assume(n > 0 && n <= CH_RSA_MODULUS_MAX && n <= cap);
    fill_nondet(sig, n);
    *sig_len = n;
    return 1;
}

int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t *sig_der,
                      size_t sig_len) {
    __CPROVER_assert(__CPROVER_r_ok(pub, SRV_P256_PUB_LEN), "p256_ecdsa_verify: point readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, SHA256_LEN), "p256_ecdsa_verify: digest readable");
    __CPROVER_assert(sig_len == 0 || __CPROVER_r_ok(sig_der, sig_len),
                     "p256_ecdsa_verify: signature readable");
    return nondet_u8() ? 1 : 0;
}

int rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t msg_hash[32], const uint8_t *sig,
                   size_t sig_len) {
    __CPROVER_assert(n_len == 0 || __CPROVER_r_ok(n, n_len), "rsa_pss_verify: modulus readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, SHA256_LEN), "rsa_pss_verify: digest readable");
    __CPROVER_assert(sig_len == 0 || __CPROVER_r_ok(sig, sig_len),
                     "rsa_pss_verify: signature readable");
    return nondet_u8() ? 1 : 0;
}

// One certificate a chain pointer can name. srv_auth.c reads no byte of
// it: identity_provisioned tests the pointer and the count alone.
static const ch_cert cert = {NULL, 0};

// The objects a provisioned slot's key pointers name: the ECDSA scalar
// and point, the RSA private key and modulus, and one object shorter
// than any of them.
static uint8_t ecdsa_priv[P256_PRIV_LEN];
static uint8_t ecdsa_pub[SRV_P256_PUB_LEN];
static ch_rsa_priv rsa_priv;
static uint8_t rsa_modulus[CH_RSA_MODULUS_MAX];
static uint8_t short_key[8];

// Fresh key bytes before every call, stored through each object's own
// type rather than through a byte pointer over the struct.
static void havoc_keys(void) {
    fill_nondet(ecdsa_priv, sizeof ecdsa_priv);
    fill_nondet(ecdsa_pub, sizeof ecdsa_pub);
    fill_nondet(rsa_priv.n, sizeof rsa_priv.n);
    fill_nondet(rsa_priv.d, sizeof rsa_priv.d);
    rsa_priv.n_len = nondet_size_t();
    __CPROVER_assume(rsa_priv.n_len <= CH_RSA_MODULUS_MAX);
    fill_nondet(rsa_modulus, sizeof rsa_modulus);
    fill_nondet(short_key, sizeof short_key);
}

// The private key a slot names, with the length the caller's contract
// gives it.
static const void *nondet_priv(size_t *len) {
    switch (nondet_u8() & 3) {
    case 0:
        *len = sizeof ecdsa_priv;
        return ecdsa_priv;
    case 1:
        *len = sizeof rsa_priv;
        return &rsa_priv;
    case 2:
        *len = sizeof short_key;
        return short_key;
    default:
        *len = 0;
        return NULL;
    }
}

// The public key a slot names, the same four ways.
static const uint8_t *nondet_pub(size_t *len) {
    switch (nondet_u8() & 3) {
    case 0:
        *len = sizeof ecdsa_pub;
        return ecdsa_pub;
    case 1:
        *len = sizeof rsa_modulus;
        return rsa_modulus;
    case 2:
        *len = sizeof short_key;
        return short_key;
    default:
        *len = 0;
        return NULL;
    }
}

// One identity slot, provisioned or not as nondet chooses. Each pointer
// names a real object or is NULL, never a nondet address.
static void make_identity(ch_identity *id) {
    id->chain = nondet_u8() ? &cert : NULL;
    id->chain_count = nondet_u8();
    id->priv = nondet_priv(&id->priv_len);
    id->pub = nondet_pub(&id->pub_len);
}

// Both slots and the bytes behind them, havocked again. Every call
// below gets fresh operands.
static void make_identities(ch_cfg *cfg) {
    havoc_keys();
    make_identity(&cfg->srv.ecdsa_p256);
    make_identity(&cfg->srv.rsa_pss);
}

// One of the two schemes this build signs, which is the domain
// srv_hash_signed_content, srv_sign_certificate_verify and
// srv_identity_check state.
static uint16_t nondet_scheme(void) {
    return nondet_u8() ? SIGALG_ECDSA_P256_SHA256 : SIGALG_RSA_PSS_RSAE_SHA256;
}

// Any transcript hash length the contract admits.
static size_t nondet_hash_len(void) {
    size_t n = nondet_size_t();
    __CPROVER_assume(n >= SHA256_LEN && n <= SRV_COOKIE_HASH_MAX);
    return n;
}

int main(void) {
    ch_cfg cfg;
    uint8_t transcript[SRV_COOKIE_HASH_MAX];
    uint8_t digest[SHA256_LEN];
    uint8_t sig[SRV_SIG_MAX];

    make_identities(&cfg);
    (void)srv_identity_live(&cfg);

    // Every code point, not only the two this build signs:
    // srv_identity_for answers for all of them.
    make_identities(&cfg);
    uint16_t any_sigalg = (uint16_t)(((uint16_t)nondet_u8() << 8) | nondet_u8());
    (void)srv_identity_for(&cfg, any_sigalg);

    fill_nondet(transcript, sizeof transcript);
    srv_hash_signed_content(nondet_scheme(), transcript, nondet_hash_len(), digest);

    make_identities(&cfg);
    fill_nondet(transcript, sizeof transcript);
    fill_nondet(sig, sizeof sig);
    size_t sig_len = nondet_size_t();
    uint8_t alert = nondet_u8();
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof sig);
    (void)srv_sign_certificate_verify(&cfg, nondet_scheme(), transcript, nondet_hash_len(), sig,
                                      cap, &sig_len, &alert);

    make_identities(&cfg);
    (void)srv_identity_check(&cfg, nondet_scheme());
    return 0;
}
