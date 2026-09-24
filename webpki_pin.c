// SPKI pins and RFC 7250 raw public keys for a TRUST=webpki client.
// Contract in webpki_pin.h. A pin is the SHA-256 of a whole DER
// SubjectPublicKeyInfo (RFC 7858 §4.2), and this file compares the pins
// against two kinds of server key: the one entry of a RawPublicKey
// Certificate message, and each key on the path webpki_verify_chain
// validated.
//
// Every byte here is public: a server's public key, the hash of a public
// key, and the caller's anchors. The pin compare still goes through
// ct_memeq and still reads every pin, because webpki_pin.h promises it.
#include "webpki_pin.h"

#include <string.h>

#include "buf.h"
#include "ct.h"
#include "handshake_message.h"
#include "rsa.h" // CH_RSA_MODULUS_MAX, the widest key webpki_read_spki returns
#include "sha256.h"

// The raw entry's bound is the largest SubjectPublicKeyInfo
// webpki_read_spki accepts, an RSA key at CH_RSA_MODULUS_MAX: 38 bytes
// of headers, AlgorithmIdentifier, pad octet and exponent around the
// modulus (webpki.h). A larger entry cannot hold a key this client
// accepts, so the framing refuses it before the reader runs.
_Static_assert(CH_WEBPKI_SPKI_MAX == CH_RSA_MODULUS_MAX + 38,
               "CH_WEBPKI_SPKI_MAX is the RSA SubjectPublicKeyInfo at CH_RSA_MODULUS_MAX");
// The copied key fits webpki_leaf_info.key, as in the walk (webpki.c).
_Static_assert(CH_WEBPKI_KEY_MAX >= CH_RSA_MODULUS_MAX,
               "webpki_leaf_info.key must hold the widest modulus webpki_read_spki returns");

uint8_t webpki_cert_types_offered(const ch_cfg *cfg) {
    if (cfg->psk != NULL || cfg->spki_pin_count == 0) {
        return 0;
    }
    uint8_t offered = 1U << CH_CERT_TYPE_RAW_PUBLIC_KEY;
    if (cfg->anchor_count > 0) {
        offered |= 1U << CH_CERT_TYPE_X509;
    }
    return offered;
}

int webpki_spki_pinned(const ch_cfg *cfg, const uint8_t *spki, size_t spki_len) {
    uint8_t digest[SHA256_LEN];
    sha256_of(spki, spki_len, digest);
    uint32_t pinned = 0;
    const uint8_t *pin = cfg->spki_pins;
    for (size_t i = 0; i < cfg->spki_pin_count; i++) {
        pinned |= ct_memeq(digest, pin, SHA256_LEN);
        pin += SHA256_LEN;
    }
    return pinned != 0;
}

// A whole DER SubjectPublicKeyInfo: webpki_read_spki, then nothing after
// it, so the bytes the pin hashes are exactly the key the reader decoded.
static int read_whole_spki(const uint8_t *spki, size_t spki_len, webpki_spki *key) {
    rbuf r;
    rb_init(&r, spki, spki_len);
    return webpki_read_spki(&r, key) && !r.err && rb_left(&r) == 0;
}

int webpki_verify_raw_key(const uint8_t *list, size_t list_len, const ch_cfg *cfg,
                          webpki_leaf_info *out, uint8_t *alert) {
    rbuf r;
    rb_init(&r, list, list_len);
    const uint8_t *spki = NULL;
    size_t spki_len = 0;
    int rc = webpki_read_entry(&r, CH_WEBPKI_SPKI_MAX, &spki, &spki_len, alert);
    if (rc != CH_OK) {
        return rc;
    }
    if (rb_left(&r) != 0) {
        // A second entry, or bytes that frame none (RFC 7250 §3: the
        // list holds exactly one entry under this type).
        *alert = ALERT_BAD_CERTIFICATE;
        return CH_EPROTO;
    }
    webpki_spki key;
    if (!read_whole_spki(spki, spki_len, &key)) {
        *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        return CH_EPROTO;
    }
    if (!webpki_spki_pinned(cfg, spki, spki_len)) {
        *alert = ALERT_BAD_CERTIFICATE;
        return CH_EAUTH;
    }
    out->alg = key.alg;
    out->key_len = key.key_len;
    memcpy(out->key, key.key, key.key_len);
    out->path_entries = 0;
    out->anchor_index = 0;
    return CH_OK;
}

// Whether a pin names the key of the certificate at index on the path,
// parsed under the arm the walk read it under: the leaf's for index 0 and
// the issuer's after it. A certificate the walk accepted parses again the
// same way; one that does not counts as no match, so the caller fails
// closed.
static int certificate_pinned(const uint8_t *cert, size_t cert_len, size_t index,
                              const ch_cfg *cfg) {
    webpki_cert parsed;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    if (webpki_parse_certificate(cert, cert_len, index != 0, &parsed, &alert) != CH_OK) {
        return 0;
    }
    return webpki_spki_pinned(cfg, parsed.spki_tlv, parsed.spki_tlv_len);
}

int webpki_path_pinned(const uint8_t *list, size_t list_len, const ch_cfg *cfg,
                       const webpki_leaf_info *leaf) {
    // Values webpki_verify_chain cannot write fail closed, so no leaf
    // makes this read past the list or the anchors.
    if (leaf->path_entries > CH_WEBPKI_CHAIN_MAX || leaf->anchor_index >= cfg->anchor_count) {
        return 0;
    }
    rbuf r;
    rb_init(&r, list, list_len);
    int pinned = 0;
    for (size_t i = 0; i < leaf->path_entries; i++) {
        // The walk framed these entries already, so a framing failure
        // here means list is not the list it walked: fail closed rather
        // than read the bytes after it as another entry.
        const uint8_t *cert = NULL;
        size_t cert_len = 0;
        uint8_t alert = ALERT_BAD_CERTIFICATE;
        if (webpki_read_entry(&r, CH_WEBPKI_CERT_MAX, &cert, &cert_len, &alert) != CH_OK) {
            return 0;
        }
        pinned |= certificate_pinned(cert, cert_len, i, cfg);
    }
    const ch_trust_anchor *anchor = &cfg->anchors[leaf->anchor_index];
    pinned |= webpki_spki_pinned(cfg, anchor->spki, anchor->spki_len);
    return pinned;
}
