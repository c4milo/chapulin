// Proves: the entries of srv_mldsa.c, the PROFILE=cnsa2 server's
// authentication (docs/decisions.md 162), read and write only inside their
// own buffers and commit no undefined behavior, over an unconstrained
// mldsa87 slot, every SignatureScheme code point and every hash length a
// selection can carry.
//
// The domain. srv_mldsa.c holds no parser and one loop, the 64 bytes of
// padding, so its input domain is the slot, the sigalg code point and the
// selection's hash_len. The slot is written field by field, so every
// pointer in it is a real object or NULL. A key pointer names one of three
// objects: one of the length ch_mldsa_key_from_pem writes, an object too
// short for either key, or NULL, and the length is the size of the object
// it names, the caller's contract. Under that contract key_lengths_match
// is the line that keeps srv_mldsa.c from handing mldsa87_sign a buffer
// shorter than it reads, and the stub's readability assertions are what
// fail if it stops.
//
// What is a stub. mldsa87_sign and mldsa87_verify have their own
// harnesses (mldsa_signer_harness.c and the mldsa harnesses), so each is a
// contract stub that asserts what the real function reads and writes and
// returns an unconstrained verdict. So are the transcript snapshot, the
// two srv_frag calls, the CertificateVerify head and the chain rule:
// handshake_record_harness.c, srv_flight_harness.c and
// srv_message_harness.c prove the real ones. ch_rand_bytes asserts the
// buffer writable and fills it with nondet bytes.
//
// What this does not reach: any claim that a signature is correct.
#include "harness.h"

#include "srv_mldsa.c"

int mldsa87_sign(uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk, size_t sk_len, const uint8_t *pk,
                 size_t pk_len, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                 size_t ctx_len, const uint8_t rnd[MLDSA87_RND_LEN]) {
    __CPROVER_assert(sk_len == MLDSA87_SK_LEN && __CPROVER_r_ok(sk, sk_len),
                     "mldsa87_sign: secret key readable at its length");
    __CPROVER_assert(pk_len == MLDSA87_PK_LEN && __CPROVER_r_ok(pk, pk_len),
                     "mldsa87_sign: public key readable at its length");
    __CPROVER_assert(__CPROVER_r_ok(msg, msg_len), "mldsa87_sign: content readable");
    __CPROVER_assert(ctx == NULL && ctx_len == 0, "mldsa87_sign: the context is empty");
    __CPROVER_assert(__CPROVER_r_ok(rnd, MLDSA87_RND_LEN), "mldsa87_sign: rnd readable");
    __CPROVER_assert(__CPROVER_w_ok(sig, MLDSA87_SIG_LEN), "mldsa87_sign: signature writable");
    fill_nondet(sig, MLDSA87_SIG_LEN);
    return nondet_u8() ? 1 : 0;
}

int mldsa87_verify(const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                   const uint8_t *ctx, size_t ctx_len, const uint8_t *sig, size_t sig_len) {
    __CPROVER_assert(__CPROVER_r_ok(pk, pk_len), "mldsa87_verify: key readable");
    __CPROVER_assert(__CPROVER_r_ok(msg, msg_len), "mldsa87_verify: content readable");
    __CPROVER_assert(ctx == NULL && ctx_len == 0, "mldsa87_verify: the context is empty");
    __CPROVER_assert(__CPROVER_r_ok(sig, sig_len), "mldsa87_verify: signature readable");
    return nondet_u8() ? 1 : 0;
}

void ch_rand_bytes(uint8_t *p, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(p, n), "ch_rand_bytes: output writable");
    fill_nondet(p, n);
}

int hsr_transcript_hash(handshake_state *h, size_t hash_len, uint8_t *out) {
    (void)h;
    __CPROVER_assert(__CPROVER_w_ok(out, hash_len), "hsr_transcript_hash: output writable");
    fill_nondet(out, hash_len);
    return CH_OK;
}

void srv_frag_bytes(srv_frag *f, const uint8_t *p, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(f, sizeof *f), "srv_frag_bytes: writer writable");
    __CPROVER_assert(__CPROVER_r_ok(p, n), "srv_frag_bytes: bytes readable");
    f->rc = nondet_u8() ? CH_OK : CH_EIO;
}

void srv_frag_flush(srv_frag *f) {
    __CPROVER_assert(__CPROVER_w_ok(f, sizeof *f), "srv_frag_flush: writer writable");
}

size_t srv_build_certificate_verify_head(uint8_t *out, size_t cap, uint16_t sigalg,
                                         size_t sig_len) {
    (void)sigalg;
    __CPROVER_assert(sig_len == MLDSA87_SIG_LEN, "the head names one signature length");
    if (cap < SRV_CERT_VERIFY_HEAD_LEN) {
        return 0;
    }
    __CPROVER_assert(__CPROVER_w_ok(out, SRV_CERT_VERIFY_HEAD_LEN), "head writable");
    fill_nondet(out, SRV_CERT_VERIFY_HEAD_LEN);
    return SRV_CERT_VERIFY_HEAD_LEN;
}

int srv_certificate_fits(const ch_identity *id) {
    __CPROVER_assert(__CPROVER_r_ok(id->chain, (size_t)id->chain_count * sizeof *id->chain),
                     "srv_certificate_fits: chain readable");
    return nondet_u8() ? 1 : 0;
}

static const ch_cert certs[255];
static uint8_t sk[MLDSA87_SK_LEN];
static uint8_t pk[MLDSA87_PK_LEN];
static uint8_t short_key[8];

// The objects a key pointer can name, with the length the caller's
// contract gives it.
static const uint8_t *nondet_key(uint8_t *full, size_t full_len, size_t *len) {
    switch (nondet_u8() % 3) {
    case 0:
        *len = full_len;
        return full;
    case 1:
        *len = sizeof short_key;
        return short_key;
    default:
        *len = 0;
        return NULL;
    }
}

static void make_identity(ch_cfg *cfg) {
    ch_identity *id = &cfg->srv.mldsa87;
    id->chain = nondet_u8() ? certs : NULL;
    id->chain_count = nondet_u8();
    id->priv = nondet_key(sk, sizeof sk, &id->priv_len);
    id->pub = nondet_key(pk, sizeof pk, &id->pub_len);
}

int main(void) {
    static ch_tls t;
    handshake_state h;
    selection sel;

    make_identity(&t.cfg);
    (void)srv_identity_live(&t.cfg);
    int usable = srv_identities_usable(&t.cfg);
    __CPROVER_assert(usable == 0 || usable == 1, "srv_identities_usable answers 0 or 1");

    make_identity(&t.cfg);
    uint16_t any_sigalg = (uint16_t)(((uint16_t)nondet_u8() << 8) | nondet_u8());
    (void)srv_identity_for(&t.cfg, any_sigalg);
    (void)srv_select_sigalg(&t.cfg, nondet_u8());

    make_identity(&t.cfg);
    h.t = &t;
    h.alert = nondet_u8();
    sel.sigalg = nondet_u8() ? SIGALG_MLDSA87 : any_sigalg;
    sel.hash_len = nondet_u8();
    int rc = srv_mldsa_send_certificate_verify(&h, &sel);
    __CPROVER_assert(rc == CH_OK || h.alert == ALERT_INTERNAL_ERROR || rc == CH_EIO,
                     "a refusal names internal_error");

    make_identity(&t.cfg);
    (void)srv_identity_check(&t.cfg, nondet_u8() ? SIGALG_MLDSA87 : any_sigalg);
    return 0;
}
