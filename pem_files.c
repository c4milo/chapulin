// The three calls that decode the files an operator provisions.
// Contracts in pem_files.h.
//
// Each call composes three readers: pem_blocks.c or pem.c for the text,
// x509_pem.c for the DER, and for the key p256_ecdh.c for the point. It
// decides nothing of its own beyond the order, the caller's rooms, the
// cpu value and the key's text cap. No library source calls these, and
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
    pem_blocks_init(&blocks, pem, pem_len, PEM_TEXT_REFUSED);
    size_t count = 0;
    for (;;) {
        const uint8_t *cert = NULL;
        size_t cert_len = 0;
        int next = pem_blocks_next(&blocks, &w, &cert, &cert_len);
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

// An EC PARAMETERS block that names prime256v1, at r's position, and the
// line breaks after it, the last of them LF. The parameters are public.
static int read_parameters(rbuf *r) {
    uint8_t parameters[CH_PEM_PARAMETERS_DER_MAX];
    wbuf w;
    wb_init(&w, parameters, sizeof parameters);
    // A longer DER outgrows the room, and pem_read_block refuses it.
    return pem_read_block(r, PEM_LABEL_EC_PARAMETERS, &w) &&
           x509_pem_parameters_are_p256(parameters, w.len) && pem_skip_line_breaks(r) == '\n';
}

// The key file's blocks, read by the reader of the form that the key's
// label names. The file holds one of three shapes:
//  - a PRIVATE KEY block alone;
//  - an EC PRIVATE KEY block alone;
//  - an EC PARAMETERS block and then an EC PRIVATE KEY block.
// Writes the scalar to scalar. Points *point at a publicKey
// field's X||Y in der, or leaves it NULL.
static int read_key(const uint8_t *pem, size_t pem_len, uint8_t der[CH_PEM_KEY_DER_MAX],
                    uint8_t scalar[32], const uint8_t **point) {
    wbuf w;
    wb_init(&w, der, CH_PEM_KEY_DER_MAX);
    if (pem_decode_one(pem, pem_len, PEM_LABEL_PRIVATE_KEY, &w)) {
        return x509_pem_read_pkcs8(der, w.len, scalar, point);
    }
    wb_init(&w, der, CH_PEM_KEY_DER_MAX);
    if (pem_decode_one(pem, pem_len, PEM_LABEL_EC_PRIVATE_KEY, &w)) {
        return x509_pem_read_sec1(der, w.len, scalar, point);
    }
    rbuf r;
    rb_init(&r, pem, pem_len);
    if (!read_parameters(&r)) {
        return 0;
    }
    // The rest of the file is the key's block alone, as in a file that
    // holds no parameters.
    size_t rest_len = rb_left(&r);
    const uint8_t *rest = rb_bytes(&r, rest_len);
    wb_init(&w, der, CH_PEM_KEY_DER_MAX);
    return pem_decode_one(rest, rest_len, PEM_LABEL_EC_PRIVATE_KEY, &w) &&
           x509_pem_read_sec1(der, w.len, scalar, point);
}

// The key pair. p256_ecdh_keygen holds scalar to 1 to n - 1, copies it
// to priv, and writes its point in SEC 1's uncompressed form. This copies
// the point's X||Y to pub. The point is public.
static int key_pair(uint32_t cpu, const uint8_t scalar[32], uint8_t priv[32], uint8_t pub[64]) {
    uint8_t point[P256_POINT_LEN];
    if (!p256_ecdh_keygen(KEY_WIDEMUL(cpu), scalar, priv, point)) {
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
    int ok = cpu_value_ok(cpu) && pem_len <= CH_PEM_KEY_TEXT_MAX &&
             read_key(pem, pem_len, der, scalar, &file_point) && key_pair(cpu, scalar, priv, pub) &&
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
    pem_blocks_init(&blocks, pem, pem_len, PEM_TEXT_SKIPPED);
    size_t count = 0;
    for (;;) {
        const uint8_t *cert = NULL;
        size_t cert_len = 0;
        int next = pem_blocks_next(&blocks, &w, &cert, &cert_len);
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
