// DER that the PEM tests build. It builds certificates of any length
// whose outer fields x509_pem_read_subject_key reads. It builds P-256
// private keys in both forms, with each optional field present or absent.
// Test-side only: the readers under test share nothing with it. Included
// by test/pem_files_test.c alone.
#ifndef CH_TEST_PEM_FILES_DER_H
#define CH_TEST_PEM_FILES_DER_H

#include <stdint.h>
#include <string.h>

#include "buf.h"

// A DER tag and its minimal length.
static void pfd_header(wbuf *w, uint8_t tag, size_t len) {
    wb_u8(w, tag);
    if (len >= 0x100) {
        wb_u8(w, 0x82);
        wb_u16(w, (uint16_t)len);
    } else if (len >= 0x80) {
        wb_u8(w, 0x81);
        wb_u8(w, (uint8_t)len);
    } else {
        wb_u8(w, (uint8_t)len);
    }
}

// One TLV around content.
static void pfd_tlv(wbuf *w, uint8_t tag, const uint8_t *content, size_t len) {
    pfd_header(w, tag, len);
    wb_bytes(w, content, len);
}

// P-256's SubjectPublicKeyInfo header and AlgorithmIdentifier, then the
// BIT STRING header and the uncompressed-point marker: 27 bytes that X||Y
// follows.
static const uint8_t pfd_p256_spki_head[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
                                             0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
                                             0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04};
// The largest extensions content pfd_tbs pads with, and the largest
// certificate pfd_cert builds. Both are past the 12,288-byte room the
// tests give a chain. So a test can build one certificate that fills that
// room and one that overflows it.
#define PFD_PAD_MAX 12400
#define PFD_CERT_MAX 12600

// A subject Name: one RDN, commonName "pem".
static const uint8_t pfd_name[] = {0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03,
                                   0x55, 0x04, 0x03, 0x0c, 0x03, 0x70, 0x65, 0x6d};

// What a synthetic certificate carries around its key.
typedef struct {
    int version;      // 1: the [0] version field; 0: a version 1 certificate
    int unique_id;    // 1: an issuerUniqueID [1] after the key
    size_t pad;       // bytes of an extensions [3] TLV's content, or 0 for none
    int tbs_trailing; // 1: a byte after the last TBS field
} pfd_cert_shape;

// The TBSCertificate. It holds a version, serial 1, and three empty
// SEQUENCEs for the signature, the issuer and the validity. Then it holds
// pfd_name, the P-256 key of point, and the fields that shape adds.
static size_t pfd_tbs(uint8_t *out, size_t cap, const uint8_t point[64], pfd_cert_shape shape) {
    static const uint8_t version[] = {0xa0, 0x03, 0x02, 0x01, 0x02};
    static const uint8_t serial_and_empties[] = {0x02, 0x01, 0x01, 0x30, 0x00,
                                                 0x30, 0x00, 0x30, 0x00};
    static uint8_t pad[PFD_PAD_MAX];
    wbuf w;
    wb_init(&w, out, cap);
    if (shape.version) {
        wb_bytes(&w, version, sizeof version);
    }
    wb_bytes(&w, serial_and_empties, sizeof serial_and_empties);
    wb_bytes(&w, pfd_name, sizeof pfd_name);
    wb_bytes(&w, pfd_p256_spki_head, sizeof pfd_p256_spki_head);
    wb_bytes(&w, point, 64);
    if (shape.unique_id) {
        static const uint8_t unique_id[] = {0x81, 0x02, 0x00, 0x2a};
        wb_bytes(&w, unique_id, sizeof unique_id);
    }
    if (shape.pad != 0) {
        memset(pad, 0x5a, sizeof pad);
        pfd_tlv(&w, 0xa3, pad, shape.pad);
    }
    if (shape.tbs_trailing) {
        wb_u8(&w, 0x00);
    }
    return w.err ? 0 : w.len;
}

// A certificate around pfd_tbs: an empty signatureAlgorithm SEQUENCE and
// a BIT STRING of one zero octet. Returns its length, or 0 when cap is
// short.
static size_t pfd_cert(uint8_t *out, size_t cap, const uint8_t point[64], pfd_cert_shape shape) {
    static uint8_t tbs[PFD_CERT_MAX];
    static uint8_t body[PFD_CERT_MAX];
    size_t tbs_len = pfd_tbs(tbs, sizeof tbs, point, shape);
    wbuf b;
    wb_init(&b, body, sizeof body);
    pfd_tlv(&b, 0x30, tbs, tbs_len);
    static const uint8_t signature[] = {0x30, 0x00, 0x03, 0x01, 0x00};
    wb_bytes(&b, signature, sizeof signature);
    wbuf w;
    wb_init(&w, out, cap);
    pfd_tlv(&w, 0x30, body, b.len);
    return (tbs_len == 0 || b.err || w.err) ? 0 : w.len;
}

// The pad that makes pfd_cert exactly want bytes long, with the [0]
// version field and nothing else. The headers grow by one byte at each
// step of the length of a length. So the search tries every pad near the
// answer. The fields around the pad take under 200 bytes.
static inline size_t pfd_pad_for(size_t want, const uint8_t point[64]) {
    static uint8_t scratch[PFD_CERT_MAX];
    size_t first = want > 200 ? want - 200 : 1;
    for (size_t pad = first; pad < PFD_PAD_MAX && pad < want; pad++) {
        pfd_cert_shape shape = {1, 0, pad, 0};
        if (pfd_cert(scratch, sizeof scratch, point, shape) == want) {
            return pad;
        }
    }
    return 0;
}

// What a synthetic private key carries.
typedef struct {
    int curve;         // 1: ECPrivateKey's parameters [0], which name prime256v1
    int point;         // 1: ECPrivateKey's publicKey [1]
    int scalar_len;    // the privateKey OCTET STRING's length, 32 for a real key
    int attributes;    // 1: PKCS #8 attributes [0] after privateKey
    int pkcs8_version; // PrivateKeyInfo's version, 0 for a real key
} pfd_key_shape;

static const pfd_key_shape pfd_key_full = {1, 1, 32, 0, 0};

// An ECPrivateKey (RFC 5915 section 3) over scalar and point.
static size_t pfd_ec_private_key(uint8_t *out, size_t cap, const uint8_t scalar[32],
                                 const uint8_t point[64], pfd_key_shape shape) {
    static const uint8_t version[] = {0x02, 0x01, 0x01};
    static const uint8_t curve[] = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86,
                                    0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    static const uint8_t point_head[] = {0xa1, 0x44, 0x03, 0x42, 0x00, 0x04};
    uint8_t body[160];
    uint8_t padded[40] = {0};
    wbuf b;
    wb_init(&b, body, sizeof body);
    wb_bytes(&b, version, sizeof version);
    // A shorter scalar drops its first bytes. A longer one starts with zeros.
    size_t n = (size_t)shape.scalar_len;
    if (n <= 32) {
        pfd_tlv(&b, 0x04, scalar + (32 - n), n);
    } else {
        memcpy(padded + (n - 32), scalar, 32);
        pfd_tlv(&b, 0x04, padded, n);
    }
    if (shape.curve) {
        wb_bytes(&b, curve, sizeof curve);
    }
    if (shape.point) {
        wb_bytes(&b, point_head, sizeof point_head);
        wb_bytes(&b, point, 64);
    }
    wbuf w;
    wb_init(&w, out, cap);
    pfd_tlv(&w, 0x30, body, b.len);
    return (b.err || w.err) ? 0 : w.len;
}

// A PrivateKeyInfo (RFC 5958 section 2) around pfd_ec_private_key.
static size_t pfd_pkcs8(uint8_t *out, size_t cap, const uint8_t scalar[32], const uint8_t point[64],
                        pfd_key_shape shape) {
    static const uint8_t algorithm[] = {0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
                                        0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
                                        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    static const uint8_t attributes[] = {0xa0, 0x00};
    uint8_t inner[160];
    uint8_t body[200];
    size_t inner_len = pfd_ec_private_key(inner, sizeof inner, scalar, point, shape);
    wbuf b;
    wb_init(&b, body, sizeof body);
    wb_u8(&b, 0x02);
    wb_u8(&b, 0x01);
    wb_u8(&b, (uint8_t)shape.pkcs8_version);
    wb_bytes(&b, algorithm, sizeof algorithm);
    pfd_tlv(&b, 0x04, inner, inner_len);
    if (shape.attributes) {
        wb_bytes(&b, attributes, sizeof attributes);
    }
    wbuf w;
    wb_init(&w, out, cap);
    pfd_tlv(&w, 0x30, body, b.len);
    return (inner_len == 0 || b.err || w.err) ? 0 : w.len;
}

#endif
