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
// What this does not reach. No signer exists in this tree, so
// srv_sign_certificate_verify never produces a signature and
// srv_identity_check never reaches a verifier; this proof says nothing
// about either. What it does cover: the slot selection over every code
// point, the signed-content assembly of RFC 9846 section 4.4.3 at every
// admitted hash_len, both refusals srv_sign_certificate_verify
// documents, and the wipes. The commit that lands a signer widens this
// harness with it.
//
// SHA-256 is a contract stub (CH_PROOF_STUB_SHA256 in proof/harness.h),
// so this formula holds the assembly and not the compression function.
// sha256_harness.c proves the real one.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include "srv_auth.c"

// One certificate a chain pointer can name. srv_auth.c reads no byte of
// it: identity_provisioned tests the pointer and the count alone.
static const ch_cert cert = {NULL, 0};

// The bytes a provisioned slot's two key pointers name. SRV_SIG_MAX is
// longer than any key a slot holds, and no line of srv_auth.c reads one
// today.
static uint8_t key_bytes[SRV_SIG_MAX];

// One identity slot, provisioned or not as nondet chooses. Each pointer
// names a real object or is NULL, never a nondet address, and the two
// lengths stay inside the object the caller's contract says they
// measure.
static void make_identity(ch_identity *id) {
    id->chain = nondet_u8() ? &cert : NULL;
    id->chain_count = nondet_u8();
    id->priv = nondet_u8() ? key_bytes : NULL;
    id->priv_len = nondet_size_t();
    id->pub = nondet_u8() ? key_bytes : NULL;
    id->pub_len = nondet_size_t();
    __CPROVER_assume(id->priv_len <= sizeof key_bytes);
    __CPROVER_assume(id->pub_len <= sizeof key_bytes);
}

// Both slots, havocked again. Every call below gets fresh operands.
static void make_identities(ch_cfg *cfg) {
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
