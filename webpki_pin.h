// SPKI pins and RFC 7250 raw public keys for a TRUST=webpki client
// (docs/webpki.md, "Raw public keys and SPKI pins").
//
// A pin is the SHA-256 of a DER SubjectPublicKeyInfo (RFC 7858 §4.2),
// configured in ch_cfg.spki_pins. With pins set, the client offers the
// RawPublicKey certificate type (RFC 7250), and it accepts a server key
// only when a pin names it:
//  - a raw public key, which the server sends in place of a chain, is
//    judged by the pins alone;
//  - a chain, which a configuration with anchors also accepts, must
//    verify as before, and a pin must name a key on the path it verified.
// RFC 8310 §6.4 asks a client configured with both a name and pins to
// require both to pass, and the second rule is how this client does.
#ifndef CH_WEBPKI_PIN_H
#define CH_WEBPKI_PIN_H
#ifdef CH_TRUST_WEBPKI

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "webpki.h"

// The certificate types the ClientHello offers in server_certificate_type
// (RFC 7250 §4.1), as a bit set of (1 << CH_CERT_TYPE_*): the RawPublicKey
// bit when cfg carries SPKI pins, and the X509 bit beside it when cfg
// carries anchors too. 0 means the extension is not sent: a configuration
// with no pins, whose server sends the X.509 type RFC 9846 §4.5.1 defaults
// to. A resumption makes the same offer, because a server that declines
// the ticket sends a Certificate after all (docs/decisions.md 55).
// handshake_message.c writes the offer, the raw key first, and the
// EncryptedExtensions parser admits a selection only from this set.
uint8_t webpki_cert_types_offered(const ch_cfg *cfg);

// Whether the SHA-256 of spki, a whole DER SubjectPublicKeyInfo TLV of
// spki_len bytes, equals one of cfg's spki_pins. Every pin is compared, in
// constant time, whichever one matches.
int webpki_spki_pinned(const ch_cfg *cfg, const uint8_t *spki, size_t spki_len);

// A Certificate message's CertificateEntry list under the RawPublicKey
// type (RFC 9846 §4.5.1, RFC 7250 §3): exactly one entry, whose data is a
// DER SubjectPublicKeyInfo that webpki_read_spki accepts and that fills it
// exactly, with an empty extensions vector. One of cfg's pins must name
// the key. On CH_OK out carries the key, with path_entries and
// anchor_index 0. The caller seeds *alert with ALERT_BAD_CERTIFICATE; the
// call overwrites it only when it knows better:
//   framing, or a count of entries other than one -> ALERT_BAD_CERTIFICATE, CH_EPROTO
//   a non-empty per-entry extensions vector       -> ALERT_UNSUPPORTED_EXTENSION, CH_EPROTO
//   a key the mode refuses, or malformed DER      -> ALERT_UNSUPPORTED_CERTIFICATE, CH_EPROTO
//   no pin names the key                          -> ALERT_BAD_CERTIFICATE, CH_EAUTH
int webpki_verify_raw_key(const uint8_t *list, size_t list_len, const ch_cfg *cfg,
                          webpki_leaf_info *out, uint8_t *alert);

// Whether one of cfg's pins names a key on the path webpki_verify_chain
// validated in list: the SubjectPublicKeyInfo of each of the first
// leaf->path_entries entries, or the spki of
// cfg->anchors[leaf->anchor_index]. A certificate the server sent beyond
// the path does not count, so a pinned certificate appended to a chain
// another CA signed does not pass: RFC 7858 §4.2 pins the validated chain.
//
// Requires: list is the list webpki_verify_chain returned CH_OK on, still
// unchanged, and leaf is what it wrote.
int webpki_path_pinned(const uint8_t *list, size_t list_len, const ch_cfg *cfg,
                       const webpki_leaf_info *leaf);

#endif // CH_TRUST_WEBPKI
#endif
