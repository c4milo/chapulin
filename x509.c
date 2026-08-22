// The certificate profile walker (own-CA mode). Accepts exactly one
// chain shape — the leaf alone or leaf plus its intermediate — and
// verifies the signatures up to the pinned CA key; everything else
// fails closed with the alert that names why. The DER primitives live
// in x509_der.c; the profile's argument lives in docs/decisions.md.
#include "x509.h"

#include <string.h>

#include "buf.h"
#include "cfg.h"
#include "ct.h"
#include "hsmsg.h"
#include "sha256.h"

#ifdef CH_PIN_ECDSA
#include "p256.h"
#else
#include "rsa.h"
#endif

// version [0] EXPLICIT INTEGER 2: the one admitted v3 encoding.
static const uint8_t version_v3[] = {0xa0, 0x03, 0x02, 0x01, 0x02};

// The build's one signature AlgorithmIdentifier, byte-compared in
// both places it appears. RFC 4055 lets the RSA-PSS inner SHA-256
// identifiers carry absent or NULL parameters and DER does not pick
// one, so the profile pins the NULL-params encoding OpenSSL emits
// and rejects the other.
#ifdef CH_PIN_ECDSA
// ecdsa-with-SHA256, parameters absent (RFC 5758 §3.2).
static const uint8_t pinned_sigalg[] = {0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
                                        0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
#else
// RSASSA-PSS, SHA-256 both places, MGF1, saltLength 32, trailerField
// absent (RFC 4055 §3.1; measured from OpenSSL 3 issuance).
static const uint8_t pinned_sigalg[] = {
    0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30,
    0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20};
#endif

// Extension OID contents (2.5.29.x) and the exact values the profile
// admits for the decoded ones.
static const uint8_t oid_key_usage[] = {0x55, 0x1d, 0x0f};
static const uint8_t oid_ext_key_usage[] = {0x55, 0x1d, 0x25};
static const uint8_t oid_basic_constraints[] = {0x55, 0x1d, 0x13};
// ExtKeyUsageSyntax holding exactly id-kp-serverAuth: only server
// certificates authenticate a server, whatever else the CA signs.
static const uint8_t eku_server_auth[] = {0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06,
                                          0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
// BasicConstraints with CA=FALSE: the DEFAULT is absent in DER, so
// the content is the empty SEQUENCE.
static const uint8_t bc_not_ca[] = {0x30, 0x00};
// BasicConstraints for the intermediate: CA=TRUE with pathLen 0, so
// the hierarchy's depth is pinned at issuance, not only at parse.
static const uint8_t bc_ca_pathlen0[] = {0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00};

// Whole-buffer equality against a pinned encoding: OIDs and
// extnValues alike are exact byte compares, nothing more.
static int bytes_are(const uint8_t *got, size_t n, const uint8_t *want, size_t want_n) {
    return n == want_n && ct_memeq(got, want, want_n) != 0;
}

// Judges one decoded extension. Returns the seen bit (1 = keyUsage,
// 2 = extendedKeyUsage, 4 = basicConstraints), 0 for an unknown
// extnID, or -1 when the value is off-profile.
static int check_extension_value(const uint8_t *oid, size_t oid_len, const uint8_t *val,
                                 size_t vlen, int is_ca) {
    if (bytes_are(oid, oid_len, oid_key_usage, sizeof oid_key_usage)) {
        // The leaf signs handshakes; the intermediate signs certs.
        return x509_read_keyusage(val, vlen, is_ca ? 0x04 : 0x80) ? 1 : -1;
    }
    if (bytes_are(oid, oid_len, oid_ext_key_usage, sizeof oid_ext_key_usage)) {
        // Purpose fields belong to end entities: forbidden on the
        // intermediate, exactly serverAuth on the leaf.
        int ok = !is_ca && bytes_are(val, vlen, eku_server_auth, sizeof eku_server_auth);
        return ok ? 2 : -1;
    }
    if (bytes_are(oid, oid_len, oid_basic_constraints, sizeof oid_basic_constraints)) {
        int ok = is_ca ? bytes_are(val, vlen, bc_ca_pathlen0, sizeof bc_ca_pathlen0)
                       : bytes_are(val, vlen, bc_not_ca, sizeof bc_not_ca);
        return ok ? 4 : -1;
    }
    return 0;
}

// One extension: read its parts, judge the value, record its bit.
static int parse_one_extension(rbuf *e, int is_ca, uint8_t *seen, uint8_t *alert) {
    x509_extension ext;
    if (!x509_read_extension(e, CH_X509_EXT_TLV_MAX, &ext)) {
        return CH_EPROTO;
    }
    int bit = check_extension_value(ext.oid, ext.oid_len, ext.value, ext.value_len, is_ca);
    if (bit < 0) {
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    if (bit == 0) {
        // RFC 5280 §4.2: an unrecognized critical extension MUST be
        // rejected; unknown non-critical ones are skipped unread.
        if (!ext.critical) {
            return CH_OK;
        }
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    if (*seen & (uint8_t)bit) {
        // A duplicate extnID is well-formed DER breaking an RFC 5280
        // §4.2 rule: off-profile, not malformed.
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    *seen |= (uint8_t)bit;
    return CH_OK;
}

// extensions [3] EXPLICIT Extensions. Required: the profile's
// keyUsage and extendedKeyUsage rules have to bind somewhere.
static int parse_extensions(rbuf *t, int is_ca, uint8_t *alert) {
    size_t wrap_len = 0;
    if (!x509_read_header(t, 0xa3, &wrap_len)) {
        return CH_EPROTO;
    }
    const uint8_t *wrap = rb_bytes(t, wrap_len);
    if (wrap == NULL) {
        return CH_EPROTO;
    }
    rbuf w;
    rb_init(&w, wrap, wrap_len);
    size_t list_len = 0;
    if (!x509_read_header(&w, 0x30, &list_len) || list_len == 0 || list_len != rb_left(&w)) {
        return CH_EPROTO; // Extensions is SIZE (1..MAX) and fills its wrapper
    }
    uint8_t seen = 0;
    int count = 0;
    while (rb_left(&w) > 0) {
        if (++count > CH_X509_EXT_COUNT_MAX) {
            *alert = ALERT_UNSUPPORTED_CERTIFICATE;
            return CH_EPROTO;
        }
        // Any reader failure inside the walk already returned; the
        // loop can only exit with the container exactly consumed.
        int rc = parse_one_extension(&w, is_ca, &seen, alert);
        if (rc != CH_OK) {
            return rc;
        }
    }
    // The purpose binding is mandatory: keyUsage + extendedKeyUsage
    // on the leaf, keyUsage + basicConstraints on the intermediate.
    uint8_t need = is_ca ? (1 | 4) : (1 | 2);
    if ((seen & need) != need) {
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    return CH_OK;
}

// validity: SEQUENCE of exactly two Times. No clock exists to compare
// them against. For a leaf, notBefore also serves as the revocation
// epoch; its number goes to leaf->epoch.
static int read_validity(rbuf *t, x509_leaf_info *leaf) {
    size_t validity_len = 0;
    if (!x509_read_header(t, 0x30, &validity_len)) {
        return 0;
    }
    const uint8_t *validity = rb_bytes(t, validity_len);
    if (validity == NULL) {
        return 0;
    }
    rbuf v;
    rb_init(&v, validity, validity_len);
    if (leaf != NULL) {
        int epoch_ok = 0;
        if (!x509_read_time_epoch(&v, &leaf->epoch, &epoch_ok)) {
            return 0;
        }
        leaf->epoch_ok = (uint8_t)epoch_ok;
    } else if (!x509_read_time(&v)) {
        return 0;
    }
    if (!x509_read_time(&v)) {
        return 0;
    }
    return !v.err && rb_left(&v) == 0;
}

// The TBSCertificate body, first byte to last, exact-consume. "TBS"
// is RFC 5280's name for the part of a certificate the CA signs: the
// serial, the algorithm, the names, the validity, the public key, and
// the extensions. The signature that follows covers exactly these
// bytes, which is why the caller hashes the range rather than
// re-encoding what it parsed.
static int parse_tbs(const uint8_t *tbs, size_t tbs_len, int is_ca, const uint8_t **key,
                     size_t *key_len, x509_leaf_info *leaf, uint8_t *alert) {
    rbuf t;
    rb_init(&t, tbs, tbs_len);
    if (!x509_read_exact(&t, version_v3, sizeof version_v3)) {
        return CH_EPROTO; // v3 and nothing else
    }
    if (!x509_read_serial(&t)) {
        return CH_EPROTO;
    }
    if (!x509_read_exact(&t, pinned_sigalg, sizeof pinned_sigalg)) {
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    if (!x509_skip(&t, 0x30)) {
        return CH_EPROTO; // issuer: opaque, bound by the CA signature
    }
    if (!read_validity(&t, leaf)) {
        return CH_EPROTO;
    }
    if (!x509_skip(&t, 0x30)) {
        return CH_EPROTO; // subject: opaque, no name matching by design
    }
    if (!x509_read_spki(&t, key, key_len)) {
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    int rc = parse_extensions(&t, is_ca, alert);
    if (rc != CH_OK) {
        return rc;
    }
    if (t.err || rb_left(&t) != 0) {
        return CH_EPROTO; // trailing TBS fields are off-profile
    }
    return CH_OK;
}

// One whole certificate: SEQUENCE { tbs, sigAlg, sigValue }. Yields
// the SPKI key, the hash of the exact TBS bytes, and the signature —
// all pointers into the caller's buffer — for the chain step.
static int parse_certificate(const uint8_t *cert, size_t cert_len, int is_ca, const uint8_t **key,
                             size_t *key_len, x509_leaf_info *leaf, uint8_t tbs_hash[SHA256_LEN],
                             const uint8_t **sig_out, size_t *sig_len_out, uint8_t *alert) {
    rbuf r;
    rb_init(&r, cert, cert_len);
    size_t body_len = 0;
    if (!x509_read_header(&r, 0x30, &body_len) || body_len != rb_left(&r)) {
        return CH_EPROTO;
    }
    size_t tbs_len = 0;
    if (!x509_read_header(&r, 0x30, &tbs_len)) {
        return CH_EPROTO;
    }
    const uint8_t *tbs = rb_bytes(&r, tbs_len);
    if (tbs == NULL) {
        return CH_EPROTO;
    }
    int rc = parse_tbs(tbs, tbs_len, is_ca, key, key_len, leaf, alert);
    if (rc != CH_OK) {
        return rc;
    }
    if (!x509_read_exact(&r, pinned_sigalg, sizeof pinned_sigalg)) {
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    const uint8_t *sig = NULL;
    size_t sig_len = 0;
    if (!x509_read_bitstring(&r, &sig, &sig_len) || sig_len == 0) {
        return CH_EPROTO; // signature bits always fill whole bytes
    }
    if (r.err || rb_left(&r) != 0) {
        return CH_EPROTO;
    }

    // The signed bytes are the TBS with its own header, re-emitted
    // rather than re-sliced so no pointer walks backwards.
    uint8_t hdr[4];
    sha256 h;
    sha256_init(&h);
    size_t hdr_len = x509_emit_header(0x30, tbs_len, hdr);
    sha256_update(&h, hdr, hdr_len);
    sha256_update(&h, tbs, tbs_len);
    sha256_final(&h, tbs_hash);
    *sig_out = sig;
    *sig_len_out = sig_len;
    return CH_OK;
}

// One signature check. Public inputs throughout: variable time is
// deliberate and fine here.
static int verify_one(const uint8_t *key, size_t key_len, const uint8_t hash[SHA256_LEN],
                      const uint8_t *sig, size_t sig_len) {
#ifdef CH_PIN_ECDSA
    // The pins are validated at ch_connect and the SPKI reader emits
    // exactly 64 bytes; the check makes the contract local anyway.
    return key_len == 64 && p256_ecdsa_verify(key, hash, sig, sig_len);
#else
    return key_len == sig_len && rsa_pss_verify(key, key_len, hash, sig, sig_len);
#endif
}

// One CertificateEntry: u24 length, the certificate, u16 empty
// per-entry extensions.
static int read_entry(rbuf *r, const uint8_t **cert, size_t *cert_len) {
    size_t n = rb_u24(r);
    if (r->err || n == 0 || n > CH_X509_MAX) {
        return 0;
    }
    *cert = rb_bytes(r, n);
    if (*cert == NULL) {
        return 0;
    }
    *cert_len = n;
    return rb_u16(r) == 0 && !r->err;
}

// The pins' target: the hash and signature the CA key must verify,
// plus the intermediate's key when one is present (then the leaf
// verifies under it instead).
typedef struct {
    const uint8_t *hash;
    const uint8_t *sig;
    size_t sig_len;
    const uint8_t *int_key;
    size_t int_key_len;
} chain_head;

// Reads and parses the second CertificateEntry — the intermediate —
// and points the chain head at it. int_hash is the caller's storage
// because the caller's verify runs after this returns.
static int read_intermediate(rbuf *r, uint8_t int_hash[SHA256_LEN], chain_head *head,
                             uint8_t *alert) {
    const uint8_t *inter = NULL;
    size_t inter_len = 0;
    if (!read_entry(r, &inter, &inter_len)) {
        return CH_EPROTO;
    }
    if (rb_left(r) != 0) {
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    const uint8_t *int_sig = NULL;
    size_t int_sig_len = 0;
    int rc = parse_certificate(inter, inter_len, 1, &head->int_key, &head->int_key_len, NULL,
                               int_hash, &int_sig, &int_sig_len, alert);
    if (rc != CH_OK) {
        return rc;
    }
    head->hash = int_hash;
    head->sig = int_sig;
    head->sig_len = int_sig_len;
    return CH_OK;
}

int x509_verify_leaf(const uint8_t *list, size_t list_len, const uint8_t *ca_key_a, size_t ca_a_len,
                     const uint8_t *ca_key_b, size_t ca_b_len, x509_leaf_info *out,
                     uint8_t *alert) {
    rbuf r;
    rb_init(&r, list, list_len);
    const uint8_t *leaf = NULL;
    size_t leaf_len = 0;
    if (!read_entry(&r, &leaf, &leaf_len)) {
        return CH_EPROTO;
    }
    const uint8_t *leaf_key = NULL;
    size_t leaf_key_len = 0;
    uint8_t leaf_hash[SHA256_LEN];
    const uint8_t *leaf_sig = NULL;
    size_t leaf_sig_len = 0;
    out->epoch = 0;
    out->epoch_ok = 0;
    int rc = parse_certificate(leaf, leaf_len, 0, &leaf_key, &leaf_key_len, out, leaf_hash,
                               &leaf_sig, &leaf_sig_len, alert);
    if (rc != CH_OK) {
        return rc;
    }

    // The chain head is what the pins vouch for: the intermediate
    // when one follows the leaf, the leaf itself otherwise. A third
    // certificate is off-profile — the root never travels.
    chain_head head = {leaf_hash, leaf_sig, leaf_sig_len, NULL, 0};
    uint8_t int_hash[SHA256_LEN];
    if (rb_left(&r) != 0) {
        rc = read_intermediate(&r, int_hash, &head, alert);
        if (rc != CH_OK) {
            return rc;
        }
    }

    const uint8_t *ca_keys[2] = {ca_key_a, ca_key_b};
    const size_t ca_lens[2] = {ca_a_len, ca_b_len};
    uint8_t slot = 0;
    for (int i = 0; i < 2 && ca_keys[i] != NULL; i++) {
        if (verify_one(ca_keys[i], ca_lens[i], head.hash, head.sig, head.sig_len)) {
            slot = (uint8_t)(i + 1);
            break;
        }
    }
    if (slot == 0) {
        *alert = ALERT_UNKNOWN_CA;
        return CH_EAUTH;
    }
    if (head.int_key != NULL &&
        !verify_one(head.int_key, head.int_key_len, leaf_hash, leaf_sig, leaf_sig_len)) {
        // The pins vouch for the intermediate, but the leaf does not
        // check out under it: a corrupt chain, not an unknown CA.
        *alert = ALERT_BAD_CERTIFICATE;
        return CH_EAUTH;
    }
    memcpy(out->key, leaf_key, leaf_key_len);
    out->key_len = leaf_key_len;
    out->ca_slot = slot;
    return CH_OK;
}
