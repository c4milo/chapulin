// The chain walk for the web PKI trust mode (TRUST=webpki): the
// Certificate message's CertificateEntry list, the leaf's clock and
// hostname checks, and the walk from the leaf to a trust anchor the
// caller configured. Contract in webpki.h; the order of the steps in
// docs/webpki.md, "The chain walk". x509.c's x509_verify_leaf is the ca
// mode's walk over the same message, and this file keeps its entry
// reading and its alert convention.
//
// Every byte here is public: a certificate the peer sent, a Name, a
// public key and the caller's own anchors. The code is variable time
// and reads no secret.
#include "webpki.h"

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "handshake_message.h"
#include "rsa.h" // CH_RSA_MODULUS_MAX, the widest key webpki_read_spki returns

// webpki_leaf_info.key holds whatever key the leaf carried, so the
// largest modulus webpki_read_spki admits must fit it. The two EC keys
// are 64 and 96 bytes and fit under any value this assertion admits.
_Static_assert(CH_WEBPKI_KEY_MAX >= CH_RSA_MODULUS_MAX,
               "webpki_leaf_info.key must hold the widest modulus webpki_read_spki returns");

// One CertificateEntry list, framed but not parsed: one pointer and one
// length per certificate. The walk indexes this array and parses only
// the entries it needs, so the bytes of a trailing entry are framed and
// never read (docs/webpki.md, "The chain walk").
typedef struct {
    const uint8_t *cert[CH_WEBPKI_FLIGHT_ENTRIES];
    size_t cert_len[CH_WEBPKI_FLIGHT_ENTRIES];
    size_t count;
} certificate_list;

// The CertificateEntry list of RFC 9846 §4.5.1: each entry is a u24
// certificate length, that many bytes, and a u16 extensions vector.
// Returns CH_OK when the list holds 1 to CH_WEBPKI_FLIGHT_ENTRIES
// entries of at most CH_WEBPKI_CERT_MAX bytes each, every extensions
// vector is empty, and the entries fill the list exactly. Otherwise
// CH_EPROTO, with *alert naming which rule failed: bad_certificate for
// the framing, unsupported_extension for a non-empty extensions vector.
// The framing of every entry is read, the trailing ones included, so a
// CertificateEntry extension is refused wherever it sits: this client
// offers no extension a CertificateEntry could answer, and RFC 9846
// §4.3 names unsupported_extension for a reply to an extension the
// peer never sent (docs/webpki.md, "Decisions").
static int read_entries(const uint8_t *list, size_t list_len, certificate_list *out,
                        uint8_t *alert) {
    rbuf r;
    rb_init(&r, list, list_len);
    out->count = 0;
    *alert = ALERT_BAD_CERTIFICATE;
    while (rb_left(&r) > 0) {
        if (out->count == CH_WEBPKI_FLIGHT_ENTRIES) {
            return CH_EPROTO;
        }
        size_t cert_len = rb_u24(&r);
        if (r.err || cert_len == 0 || cert_len > CH_WEBPKI_CERT_MAX) {
            return CH_EPROTO;
        }
        const uint8_t *cert = rb_bytes(&r, cert_len);
        size_t extensions_len = rb_u16(&r);
        if (cert == NULL || r.err) {
            return CH_EPROTO;
        }
        if (extensions_len != 0) {
            *alert = ALERT_UNSUPPORTED_EXTENSION;
            return CH_EPROTO;
        }
        out->cert[out->count] = cert;
        out->cert_len[out->count] = cert_len;
        out->count++;
    }
    return out->count > 0 ? CH_OK : CH_EPROTO;
}

// Two whole Name TLVs, byte for byte. RFC 5280 §7.1 allows a richer
// comparison of the strings inside a Name; this mode compares the
// encodings, which is what every chain docs/webpki.md captures needs.
static int names_equal(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len) {
    return a_len == b_len && ct_memeq(a, b, a_len) != 0;
}

// notBefore <= now <= notAfter, both ends inclusive (RFC 5280 §4.1.2.5
// and docs/webpki.md, "Validity"). The dates and the clock are packed
// decimal numbers, so each end is one integer compare.
static int validity_covers(const webpki_cert *cert, uint64_t now) {
    return cert->not_before <= now && now <= cert->not_after;
}

// One anchor's DER SubjectPublicKeyInfo. The caller configured these
// bytes, so an anchor the reader refuses is a provisioning mistake
// rather than peer input: the walk skips that anchor, and a chain that
// reaches no other one ends at unknown_ca.
static int read_anchor_key(const ch_trust_anchor *anchor, webpki_spki *key) {
    rbuf r;
    rb_init(&r, anchor->spki, anchor->spki_len);
    return webpki_read_spki(&r, key) && !r.err && rb_left(&r) == 0;
}

// Step 6a: the anchors, consulted before any further entry is read. For
// every anchor whose subject Name equals cert's issuer Name, this
// verifies cert's signature under that anchor's key, and the first
// anchor that verifies ends the walk. Every anchor naming the issuer is
// tried, so a root re-keyed under one Name works.
static int anchor_verifies(const ch_cfg *cfg, const webpki_cert *cert) {
    for (size_t i = 0; i < cfg->anchor_count; i++) {
        const ch_trust_anchor *anchor = &cfg->anchors[i];
        if (!names_equal(anchor->name, anchor->name_len, cert->issuer, cert->issuer_len)) {
            continue;
        }
        webpki_spki key;
        if (read_anchor_key(anchor, &key) && webpki_verify(cert, &key)) {
            return 1;
        }
    }
    return 0;
}

// RFC 5280 §6.1: a certificate is self-issued when its subject Name
// equals its issuer Name. A CA re-keying under its own Name issues one
// for the new key under the old key, and RFC 5280 §6.1.4 (l) leaves it
// out of the pathLenConstraint count (docs/webpki.md, "Decisions").
static int self_issued(const webpki_cert *cert) {
    return names_equal(cert->subject, cert->subject_len, cert->issuer, cert->issuer_len);
}

// RFC 5280 §4.2.1.9 and §6.1.4 (l): pathLenConstraint is the number of
// CA certificates that may follow this one on the path down to the end
// entity, the self-issued ones not counted. below is that count for
// the issuer in hand: the certificates the walk read as issuers so far
// that are not self-issued. An absent constraint, which webpki_ext.c
// records as -1, admits any count.
static int path_len_admits(const webpki_cert *issuer, size_t below) {
    return issuer->path_len < 0 || (size_t)issuer->path_len >= below;
}

// Steps 6c to 6f for the entry at index, which the walk reads as the
// issuer of the certificate in hand: parse it under the issuer arm,
// check the clock against its validity, check it is the certificate
// this one names, check its pathLenConstraint admits the below CA
// certificates under it, and verify this certificate's signature under
// its key.
static int read_issuer(const certificate_list *entries, size_t index, size_t below, uint64_t now,
                       const webpki_cert *cert, webpki_cert *issuer, uint8_t *alert) {
    int rc =
        webpki_parse_certificate(entries->cert[index], entries->cert_len[index], 1, issuer, alert);
    if (rc != CH_OK) {
        return rc;
    }
    if (!validity_covers(issuer, now)) {
        *alert = ALERT_CERTIFICATE_EXPIRED;
        return CH_EAUTH;
    }
    if (!names_equal(issuer->subject, issuer->subject_len, cert->issuer, cert->issuer_len)) {
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    if (!path_len_admits(issuer, below)) {
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    if (!webpki_verify(cert, &issuer->spki)) {
        *alert = ALERT_BAD_CERTIFICATE;
        return CH_EAUTH;
    }
    return CH_OK;
}

// Steps 2 to 5 for entry 0: parse it under the leaf arm, check the
// clock against its validity, and match the hostname against its
// subjectAltName. webpki_match_san refuses an extnValue that is not a
// GeneralNames, so a leaf whose subjectAltName holds anything else
// fails as a hostname that does not match.
static int read_leaf(const certificate_list *entries, const ch_cfg *cfg, uint64_t now,
                     webpki_cert *leaf, uint8_t *alert) {
    int rc = webpki_parse_certificate(entries->cert[0], entries->cert_len[0], 0, leaf, alert);
    if (rc != CH_OK) {
        return rc;
    }
    if (!validity_covers(leaf, now)) {
        *alert = ALERT_CERTIFICATE_EXPIRED;
        return CH_EAUTH;
    }
    if (!webpki_match_san(leaf->san, leaf->san_len, cfg->hostname, cfg->hostname_len)) {
        *alert = ALERT_BAD_CERTIFICATE;
        return CH_EAUTH;
    }
    return CH_OK;
}

// The leaf's key, copied out of the message buffer, which the session
// reuses before CertificateVerify arrives.
static void copy_leaf_key(const webpki_spki *leaf_key, webpki_leaf_info *out) {
    out->alg = leaf_key->alg;
    out->key_len = leaf_key->key_len;
    memcpy(out->key, leaf_key->key, leaf_key->key_len);
}

int webpki_verify_chain(const uint8_t *list, size_t list_len, const ch_cfg *cfg,
                        webpki_leaf_info *out, uint8_t *alert) {
    certificate_list entries;
    // The caller seeds an alert, and read_entries writes its own on
    // every refusal: a refusal that names its alert here is one the
    // proof reads, rather than one that rests on what the caller left.
    int rc = read_entries(list, list_len, &entries, alert);
    if (rc != CH_OK) {
        return rc;
    }
    // The one division in the mode, on the caller's clock and never on
    // peer input (docs/webpki.md, "Validity").
    uint64_t now = webpki_pack_seconds(cfg->now_seconds);
    webpki_cert cert;
    rc = read_leaf(&entries, cfg, now, &cert, alert);
    if (rc != CH_OK) {
        return rc;
    }
    const webpki_spki leaf_key = cert.spki;

    // read counts the certificates parsed so far; the leaf is the first.
    // CH_WEBPKI_CHAIN_MAX caps them, so an unauthenticated peer forces
    // at most that many signature checks before the walk gives up.
    // below counts the issuers among them that are not self-issued, the
    // number a pathLenConstraint bounds.
    size_t below = 0;
    for (size_t read = 1; read <= CH_WEBPKI_CHAIN_MAX; read++) {
        if (anchor_verifies(cfg, &cert)) {
            copy_leaf_key(&leaf_key, out);
            return CH_OK;
        }
        if (read == CH_WEBPKI_CHAIN_MAX || read == entries.count) {
            break; // the walk's cap, or the entries ran out
        }
        webpki_cert issuer;
        rc = read_issuer(&entries, read, below, now, &cert, &issuer, alert);
        if (rc != CH_OK) {
            return rc;
        }
        below += self_issued(&issuer) ? 0U : 1U;
        cert = issuer;
    }
    *alert = ALERT_UNKNOWN_CA;
    return CH_EAUTH;
}
