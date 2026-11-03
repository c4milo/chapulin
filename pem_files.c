// The calls that decode the files an operator provisions. Contracts in
// pem_files.h.
//
// Each call composes readers: pem_blocks.c for the text, x509_pem.c for
// the DER, p256_ecdh.c for a P-256 key's point, mldsa_signer.c for an
// ML-DSA-87 key's expansion, and an RSA key's signer and verifier
// (widemul.h, rsa.h) for its one check signature. It decides nothing of
// its own beyond the order, the labels, the caller's rooms and the cpu
// value. No library source calls these, and
// no session calls them (.semgrep/invariants.yml).
#include "pem_files.h"

#include "buf.h"
#include "cfg.h"
#include "ch_assert.h"
#include "ct.h"
#include "pem.h"
#include "pem_blocks.h"
#include "x509_pem.h"

#ifdef CH_ROLE_SERVER
#include "cpu.h"
#include "p256_ecdh.h"
#include "widemul.h"
#endif

#if defined(CH_ROLE_SERVER) && defined(CH_SIGN_MLDSA)
#include "mldsa_signer.h"
#endif

#ifdef CH_ROLE_SERVER
// Whether cert reads as a certificate's outer fields (x509_pem.h). The
// call keeps neither the Name nor the key it finds.
static int is_certificate(const uint8_t *cert, size_t cert_len) {
    const uint8_t *name = NULL;
    const uint8_t *spki = NULL;
    size_t name_len = 0;
    size_t spki_len = 0;
    return x509_pem_read_subject_key(cert, cert_len, &name, &name_len, &spki, &spki_len);
}

// A key file's blocks, under pem_blocks.h's text rule: one block of first,
// with its DER in first_der, then, when second_der is not NULL, one block
// of second, with its DER in second_der, and no block after them. A BEGIN
// line of any other label, or a further block, refuses the file. Each
// label is public, and pem.c decodes each body in constant time.
static int read_blocks(const uint8_t *pem, size_t pem_len, uint8_t first, wbuf *first_der,
                       uint8_t second, wbuf *second_der) {
    pem_blocks blocks;
    pem_blocks_init(&blocks, pem, pem_len);
    const uint8_t *block = NULL;
    size_t block_len = 0;
    if (pem_blocks_next(&blocks, first, first_der, &block, &block_len) != PEM_BLOCKS_READ) {
        return 0;
    }
    if (second_der != NULL &&
        pem_blocks_next(&blocks, second, second_der, &block, &block_len) != PEM_BLOCKS_READ) {
        return 0;
    }
    // The text ends with no block: a further block of first's label reads
    // and fails the test, and a BEGIN line of any other label refuses.
    return pem_blocks_next(&blocks, first, first_der, &block, &block_len) == PEM_BLOCKS_END;
}

int ch_chain_from_pem(const uint8_t *pem, size_t pem_len, uint8_t *der, size_t der_len,
                      ch_cert *chain, size_t chain_max, uint8_t *chain_count) {
    CH_ASSERT(chain_count != NULL);
    CH_ASSERT(pem != NULL || pem_len == 0);
    CH_ASSERT(der != NULL || der_len == 0);
    CH_ASSERT(chain != NULL || chain_max == 0);
    *chain_count = 0;
    wbuf w;
    wb_init(&w, der, der_len);
    pem_blocks blocks;
    pem_blocks_init(&blocks, pem, pem_len);
    size_t count = 0;
    for (;;) {
        const uint8_t *cert = NULL;
        size_t cert_len = 0;
        int next = pem_blocks_next(&blocks, PEM_LABEL_CERTIFICATE, &w, &cert, &cert_len);
        if (next == PEM_BLOCKS_END) {
            break;
        }
        // The blocks share der's room, so one block may fill it. The
        // count stops at the caller's entries and at chain_count's 255.
        if (next != PEM_BLOCKS_READ || count == chain_max || count == UINT8_MAX ||
            !is_certificate(cert, cert_len)) {
            return CH_EINVAL;
        }
        chain[count].der = cert;
        chain[count].len = cert_len;
        count++;
    }
    if (count == 0) {
        return CH_EINVAL;
    }
    *chain_count = (uint8_t)count;
    return CH_OK;
}
#endif

#ifdef CH_PEM_P256_KEY_CALL
// The answer the key's point is computed under (widemul.h). A device
// object runs every operation under the one its build states. A host
// object runs under the one that cpu gives, as a session runs under its
// ch_cfg.cpu. CH_CPU_CONSTANT_TIME_MULTIPLY gives the wide P-256 field,
// as p256_sign_cpu signs, and a value without it gives ct.h's 16x16
// decomposition.
#ifdef CH_CPU_RUNTIME
#define KEY_WIDEMUL(cpu) widemul_of_cpu(cpu)
#else
#define KEY_WIDEMUL(cpu) ((void)(cpu), WIDEMUL_BUILD_ANSWER)
#endif

// The key file's blocks, read by the reader of the form that the key's
// label names. The file holds one of three shapes, with text around and
// between the blocks (pem_blocks.h):
//  - a PRIVATE KEY block alone;
//  - an EC PRIVATE KEY block alone;
//  - an EC PARAMETERS block and then an EC PRIVATE KEY block. The
//    parameters must name prime256v1, and they are public.
// Writes the scalar to scalar. Points *point at a publicKey
// field's X||Y in der, or leaves it NULL.
static int read_key(const uint8_t *pem, size_t pem_len, uint8_t der[CH_PEM_KEY_DER_MAX],
                    uint8_t scalar[32], const uint8_t **point) {
    wbuf w;
    wb_init(&w, der, CH_PEM_KEY_DER_MAX);
    if (read_blocks(pem, pem_len, PEM_LABEL_PRIVATE_KEY, &w, 0, NULL)) {
        return x509_pem_read_pkcs8(der, w.len, scalar, point);
    }
    wb_init(&w, der, CH_PEM_KEY_DER_MAX);
    if (read_blocks(pem, pem_len, PEM_LABEL_EC_PRIVATE_KEY, &w, 0, NULL)) {
        return x509_pem_read_sec1(der, w.len, scalar, point);
    }
    // A longer parameters DER outgrows its room, and pem_read_block
    // refuses it.
    uint8_t parameters[CH_PEM_PARAMETERS_DER_MAX];
    wbuf p;
    wb_init(&p, parameters, sizeof parameters);
    wb_init(&w, der, CH_PEM_KEY_DER_MAX);
    return read_blocks(pem, pem_len, PEM_LABEL_EC_PARAMETERS, &p, PEM_LABEL_EC_PRIVATE_KEY, &w) &&
           x509_pem_parameters_are_p256(parameters, p.len) &&
           x509_pem_read_sec1(der, w.len, scalar, point);
}

// The key pair. p256_ecdh_keygen_cpu holds scalar to 1 to n - 1, copies it
// to priv, and writes its point in SEC 1's uncompressed form. This copies
// the point's X||Y to pub. The point is public.
static int key_pair(uint32_t cpu, const uint8_t scalar[32], uint8_t priv[32], uint8_t pub[64]) {
    uint8_t point[P256_POINT_LEN];
    if (!p256_ecdh_keygen_cpu(cpu, KEY_WIDEMUL(cpu), scalar, priv, point)) {
        return 0;
    }
    rbuf r;
    rb_init(&r, point, sizeof point);
    uint8_t marker = rb_u8(&r);
    const uint8_t *xy = rb_bytes(&r, 64);
    if (marker != 0x04 || xy == NULL || rb_left(&r) != 0) {
        return 0;
    }
    for (size_t i = 0; i < 64; i++) {
        pub[i] = xy[i];
    }
    return 1;
}

// Whether leaf is a certificate whose key is P-256's with the point pub.
static int leaf_holds(const uint8_t *leaf, size_t leaf_len, const uint8_t pub[64]) {
    const uint8_t *name = NULL;
    const uint8_t *spki = NULL;
    size_t name_len = 0;
    size_t spki_len = 0;
    return x509_pem_read_subject_key(leaf, leaf_len, &name, &name_len, &spki, &spki_len) &&
           x509_pem_spki_is_p256(spki, spki_len, pub);
}

int ch_p256_key_from_pem(uint32_t cpu, const uint8_t *pem, size_t pem_len, const uint8_t *leaf,
                         size_t leaf_len, uint8_t priv[32], uint8_t pub[64]) {
    CH_ASSERT(priv != NULL && pub != NULL);
    CH_ASSERT(pem != NULL || pem_len == 0);
    CH_ASSERT(leaf != NULL || leaf_len == 0);
    uint8_t der[CH_PEM_KEY_DER_MAX];
    uint8_t scalar[32] = {0};
    const uint8_t *file_point = NULL;
    // file_point points into der, so the call compares it before it wipes
    // der.
    int ok = cpu_value_ok(cpu) && read_key(pem, pem_len, der, scalar, &file_point) &&
             key_pair(cpu, scalar, priv, pub) &&
             (file_point == NULL || ct_memeq(file_point, pub, 64) != 0) &&
             leaf_holds(leaf, leaf_len, pub);
    ct_wipe(der, sizeof der);
    ct_wipe(scalar, sizeof scalar);
    if (!ok) {
        ct_wipe(priv, 32);
        ct_wipe(pub, 64);
        return CH_EINVAL;
    }
    return CH_OK;
}
#endif

#ifdef CH_PEM_RSA_KEY_CALL
// The digest the call signs, and the salt it signs under. Both are
// public, and so is the signature. The salt is not all zero, which
// rsa_pss_sign refuses (rsa_sign.h). The call draws nothing, as
// ch_p256_key_from_pem draws nothing.
static const uint8_t rsa_check_digest[32] = {
    0x63, 0x68, 0x5f, 0x72, 0x73, 0x61, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x66, 0x72, 0x6f, 0x6d, 0x5f,
    0x70, 0x65, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t rsa_check_salt[RSA_PSS_SALT_LEN] = {
    0x73, 0x61, 0x6c, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

// Where the five CRT integers go, each n_len / 2 bytes. A host object's
// key holds them. A device object's key does not, so the call reads them
// into rooms on its own frame, which it wipes.
typedef struct {
    uint8_t *p;
    uint8_t *q;
    uint8_t *dp;
    uint8_t *dq;
    uint8_t *qinv;
} rsa_crt;

// The modulus, which is public: a zero octet, then n_len octets whose top
// bit is set. The rest of rsa_pss_sign_key_ok's test runs in key_usable.
static int read_modulus(x509_pem_integer n, ch_rsa_priv *key) {
    if (n.len < 2 || n.len - 1 < 256 || n.len - 1 > CH_RSA_MODULUS_MAX) {
        return 0;
    }
    key->n_len = n.len - 1;
    return x509_pem_integer_to_bytes(n, key->n, key->n_len);
}

// The secret integers, each into a field of its own length. Each prime
// fills its n_len / 2 bytes and has its top bit set, as rsa_sign.h
// requires. The top bits are read with no branch.
static int read_secrets(const x509_pem_rsa_key *v, size_t n_len, uint8_t *d, const rsa_crt *crt) {
    size_t half = n_len / 2;
    int ok = x509_pem_integer_to_bytes(v->d, d, n_len) &
             x509_pem_integer_to_bytes(v->p, crt->p, half) &
             x509_pem_integer_to_bytes(v->q, crt->q, half) &
             x509_pem_integer_to_bytes(v->dp, crt->dp, half) &
             x509_pem_integer_to_bytes(v->dq, crt->dq, half) &
             x509_pem_integer_to_bytes(v->qinv, crt->qinv, half);
    uint32_t tops = (uint32_t)(crt->p[0] & crt->q[0]) >> 7;
    CT_DECLASSIFY(&tops, sizeof tops);
    return ok & (int)tops;
}

// Whether leaf is a certificate whose key is RSA's with the modulus n and
// the exponent 65537.
static int leaf_holds_rsa(const uint8_t *leaf, size_t leaf_len, const ch_rsa_priv *key) {
    const uint8_t *name = NULL;
    const uint8_t *spki = NULL;
    size_t name_len = 0;
    size_t spki_len = 0;
    return x509_pem_read_subject_key(leaf, leaf_len, &name, &name_len, &spki, &spki_len) &&
           x509_pem_spki_is_rsa(spki, spki_len, key->n, key->n_len);
}

// The key test of the signer that the answer widemul picks, then one
// signature with that signer, verified under the modulus, which
// leaf_holds_rsa has matched to the leaf's.
static int signs(uint32_t cpu, uint8_t widemul, const ch_rsa_priv *key) {
    if (!widemul_rsa_pss_sign_key_ok(widemul, key)) {
        return 0;
    }
    uint8_t sig[CH_RSA_MODULUS_MAX];
    size_t sig_len = 0;
    return widemul_rsa_pss_sign_cpu(cpu, widemul, key, rsa_check_digest, rsa_check_salt, sig,
                                    sizeof sig, &sig_len) &&
           RSA_PSS_VERIFY_CPU(cpu, key->n, key->n_len, rsa_check_digest, sig, sig_len);
}

// The ladder reads n and d, and every object holds it, so the call signs
// with it under every cpu value. Where cpu picks the 64-bit signer, which
// reads p, q and the three CRT values, the call signs with that one too.
// A device object holds the ladder alone.
static int key_usable(uint32_t cpu, const ch_rsa_priv *key) {
    if (!signs(cpu, WIDEMUL_NOT_STATED, key)) {
        return 0;
    }
#ifdef CH_CPU_RUNTIME
    uint8_t widemul = widemul_of_cpu(cpu);
    return !widemul_native(widemul) || signs(cpu, widemul, key);
#else
    return 1;
#endif
}

int ch_rsa_key_from_pem(uint32_t cpu, const uint8_t *pem, size_t pem_len, const uint8_t *leaf,
                        size_t leaf_len, ch_rsa_priv *key) {
    CH_ASSERT(key != NULL);
    CH_ASSERT(pem != NULL || pem_len == 0);
    CH_ASSERT(leaf != NULL || leaf_len == 0);
    // Every byte past an integer's n_len or n_len / 2 bytes stays zero.
    ct_wipe(key, sizeof *key);
    uint8_t der[CH_PEM_RSA_KEY_DER_MAX];
    x509_pem_rsa_key fields;
    wbuf w;
    wb_init(&w, der, sizeof der);
#ifdef CH_CPU_RUNTIME
    const rsa_crt crt = {key->p, key->q, key->dp, key->dq, key->qinv};
#else
    uint8_t crt_room[5][CH_RSA_MODULUS_MAX / 2];
    const rsa_crt crt = {crt_room[0], crt_room[1], crt_room[2], crt_room[3], crt_room[4]};
#endif
    int ok = cpu_value_ok(cpu) && read_blocks(pem, pem_len, PEM_LABEL_PRIVATE_KEY, &w, 0, NULL) &&
             x509_pem_read_rsa_pkcs8(der, w.len, &fields) && read_modulus(fields.n, key) &&
             read_secrets(&fields, key->n_len, key->d, &crt) &&
             leaf_holds_rsa(leaf, leaf_len, key) && key_usable(cpu, key);
    ct_wipe(der, sizeof der);
#ifndef CH_CPU_RUNTIME
    ct_wipe(crt_room, sizeof crt_room);
#endif
    if (!ok) {
        ct_wipe(key, sizeof *key);
        return CH_EINVAL;
    }
    return CH_OK;
}
#endif

#if defined(CH_ROLE_SERVER) && defined(CH_SIGN_MLDSA)
_Static_assert(MLDSA87_SK_LEN == 4896 && MLDSA87_PK_LEN == 2592, "pem_files.h's ML-DSA-87 rooms");

// The expansion of seed. A host object runs it under cpu, as a session
// signs under its ch_cfg.cpu: on arm64, CH_CPU_CONSTANT_TIME_MULTIPLY
// gives mldsa_vector.c's lanes (mldsa87_keygen_cpu). Every other object
// runs ct.h's 16x16 decomposition and reads no cpu.
static int expand_seed(uint32_t cpu, uint8_t sk[4896], uint8_t pk[2592],
                       const uint8_t seed[MLDSA87_SEED_LEN]) {
#ifdef CH_CPU_RUNTIME
    return mldsa87_keygen_cpu(cpu, sk, pk, seed);
#else
    (void)cpu;
    return mldsa87_keygen(sk, pk, seed);
#endif
}

// Whether leaf is a certificate whose key is ML-DSA-87's key pk.
static int leaf_holds_mldsa(const uint8_t *leaf, size_t leaf_len, const uint8_t pk[2592]) {
    const uint8_t *name = NULL;
    const uint8_t *spki = NULL;
    size_t name_len = 0;
    size_t spki_len = 0;
    return x509_pem_read_subject_key(leaf, leaf_len, &name, &name_len, &spki, &spki_len) &&
           x509_pem_spki_is_mldsa87(spki, spki_len, pk);
}

int ch_mldsa_key_from_pem(uint32_t cpu, const uint8_t *pem, size_t pem_len, const uint8_t *leaf,
                          size_t leaf_len, uint8_t sk[4896], uint8_t pk[2592]) {
    CH_ASSERT(sk != NULL && pk != NULL);
    CH_ASSERT(pem != NULL || pem_len == 0);
    CH_ASSERT(leaf != NULL || leaf_len == 0);
    uint8_t der[CH_PEM_MLDSA_KEY_DER_MAX];
    uint8_t seed[MLDSA87_SEED_LEN] = {0};
    const uint8_t *expanded = NULL;
    wbuf w;
    wb_init(&w, der, sizeof der);
    // expanded points into der, so the call compares it before it wipes
    // der. sk is written only by the expansion.
    int ok = cpu_value_ok(cpu) && read_blocks(pem, pem_len, PEM_LABEL_PRIVATE_KEY, &w, 0, NULL) &&
             x509_pem_read_mldsa87_pkcs8(der, w.len, seed, &expanded) &&
             expand_seed(cpu, sk, pk, seed) &&
             (expanded == NULL || ct_memeq(expanded, sk, MLDSA87_SK_LEN) == 1) &&
             leaf_holds_mldsa(leaf, leaf_len, pk);
    ct_wipe(der, sizeof der);
    ct_wipe(seed, sizeof seed);
    if (!ok) {
        ct_wipe(sk, MLDSA87_SK_LEN);
        ct_wipe(pk, MLDSA87_PK_LEN);
        return CH_EINVAL;
    }
    return CH_OK;
}
#endif

#ifdef CH_TRUST_WEBPKI
int ch_anchors_from_pem(const uint8_t *pem, size_t pem_len, uint8_t *der, size_t der_len,
                        ch_trust_anchor *anchors, size_t anchor_max, size_t *anchor_count) {
    CH_ASSERT(anchor_count != NULL);
    CH_ASSERT(pem != NULL || pem_len == 0);
    CH_ASSERT(der != NULL || der_len == 0);
    CH_ASSERT(anchors != NULL || anchor_max == 0);
    *anchor_count = 0;
    wbuf w;
    wb_init(&w, der, der_len);
    pem_blocks blocks;
    pem_blocks_init(&blocks, pem, pem_len);
    size_t count = 0;
    for (;;) {
        const uint8_t *cert = NULL;
        size_t cert_len = 0;
        int next = pem_blocks_next(&blocks, PEM_LABEL_CERTIFICATE, &w, &cert, &cert_len);
        if (next == PEM_BLOCKS_END) {
            break;
        }
        // The blocks share der's room, as a chain's do.
        if (next != PEM_BLOCKS_READ || count == anchor_max) {
            return CH_EINVAL;
        }
        ch_trust_anchor *a = &anchors[count];
        if (!x509_pem_read_subject_key(cert, cert_len, &a->name, &a->name_len, &a->spki,
                                       &a->spki_len)) {
            return CH_EINVAL;
        }
        count++;
    }
    if (count == 0) {
        return CH_EINVAL;
    }
    *anchor_count = count;
    return CH_OK;
}
#endif
