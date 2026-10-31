// Proves: rsa_pkcs1_verify_exponent, the DNSSEC RSA check
// (https://github.com/c4milo/chapulin/issues/189), is memory safe and
// free of UB over any modulus length up to N_MAX, any exponent, digest
// length, signature length and bytes. And that it
// answers 1 only past every check rsa_pkcs1.h states: a 32-byte or
// 64-byte digest, a modulus from CH_DNSSEC_RSA_MODULUS_MIN bytes that leaves
// PS its 8 bytes, begins with a nonzero byte and is odd, an odd exponent
// of at least 3, and a signature of the modulus's length below it. It
// hands the public operation that exponent and the signature as its base.
//
// rsa_mont64_modulus_init and rsa_mont64_public_exp are contract stubs:
// each asserts what rsa_mont64.h requires and the second havocs em, a
// superset of any power. The rsa_mont64 and rsa_mont64_exp harnesses
// prove them, and bin/dnssec_test runs the check against OpenSSL's
// signatures. ct.c is real.
//
// Bounds. N_MAX is 129 bytes: it holds the 64-byte floor, the 94 bytes
// SHA-512's encoding needs, and lengths that are no whole number of
// 8-byte words. The launch line sets CH_RSA_MODULUS_MAX to 136, the next
// whole number of words, so the verifier's own buffers are no longer than
// the lengths the harness runs. A longer modulus runs the same checks over
// longer fills: at 384 bytes, with the length free, kissat ran out of
// memory. The rsa_pkcs1 harness runs the encoder and the compare at 384.
#include "harness.h"

#include "ct.h"
#include "rsa.h"
#include "rsa_mont64.h"

uint64_t nondet_u64(void);

#define N_MAX 129

#include "rsa_pkcs1.c"

static int public_calls;
static uint64_t public_e;
static const uint8_t *public_base;

void rsa_mont64_modulus_init(rsa_mont64_modulus *mod, const uint8_t *m, size_t m_len, size_t bits) {
    __CPROVER_assert(m_len >= 1 && m_len <= CH_RSA_MODULUS_MAX && __CPROVER_r_ok(m, m_len),
                     "init: the modulus is readable");
    __CPROVER_assert(bits >= 8 * m_len - 7 && bits <= 8 * m_len, "init: bits is the top bit's");
    __CPROVER_assert((m[0] >> ((bits - 1) % 8)) == 1, "init: the top bit is set");
    mod->words = (m_len + 7) / 8;
}

void rsa_mont64_public_exp(uint8_t *out, const uint8_t *base, size_t len,
                           const rsa_mont64_modulus *mod, uint64_t e) {
    __CPROVER_assert(len <= 8 * mod->words && __CPROVER_w_ok(out, len) && __CPROVER_r_ok(base, len),
                     "public: the bytes fit the modulus");
    __CPROVER_assert(e >= 3 && (e & 1) == 1, "public: an odd exponent of at least 3");
    public_calls++;
    public_e = e;
    public_base = base;
    fill_nondet(out, len);
}

int main(void) {
    uint8_t n[N_MAX];
    uint8_t sig[N_MAX];
    uint8_t digest[SHA512_LEN];
    fill_nondet(n, sizeof n);
    fill_nondet(sig, sizeof sig);
    fill_nondet(digest, sizeof digest);
    size_t n_len = nondet_size_t();
    size_t digest_len = nondet_size_t();
    size_t sig_len = nondet_size_t();
    __CPROVER_assume(n_len <= N_MAX && digest_len <= SHA512_LEN);
    uint64_t e = nondet_u64();

    int ok = rsa_pkcs1_verify_exponent(n, n_len, e, digest, digest_len, sig, sig_len);

    if (ok) {
        __CPROVER_assert(digest_len == SHA256_LEN || digest_len == SHA512_LEN,
                         "a digest of SHA-256's or SHA-512's length");
        __CPROVER_assert(n_len >= CH_DNSSEC_RSA_MODULUS_MIN &&
                             n_len >= EM_OVERHEAD + PS_MIN + DIGEST_INFO_LEN + digest_len,
                         "a modulus that holds the encoding");
        __CPROVER_assert(n[0] != 0 && (n[n_len - 1] & 1) == 1, "an odd modulus, no leading zero");
        __CPROVER_assert(sig_len == n_len && !greater_or_equal(sig, n, n_len),
                         "a signature of the modulus's length, below it");
        __CPROVER_assert(public_calls == 1 && public_e == e && public_base == sig,
                         "the signature raised to the key's exponent");
    }
    return 0;
}
