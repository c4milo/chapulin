// The caller-facing declarations of a TRUST=webpki build, and the rules
// of the ch_cfg fields only that build has. cfg.h includes this header
// under CH_TRUST_WEBPKI alone, so a raw or ca build declares none of it
// and keeps the ch_cfg and ch_tls layout it had before the mode. A raw
// or ca build that sets one of these fields fails to compile, which is
// stricter than a CH_EINVAL from ch_connect.
//
// The fields, at the end of ch_cfg (docs/webpki.md):
//  - anchors: anchor_count entries, 1 to CH_WEBPKI_ANCHOR_MAX, each with
//    a non-empty name and spki. The server's chain must verify up to one
//    of them.
//  - hostname: hostname_len bytes of an ASCII hostname that
//    webpki_hostname_ok (webpki.h) accepts: 1 to 253 bytes of
//    [A-Za-z0-9.-], no NUL, no empty label and no IP literal. A caller
//    with an internationalized name converts each U-label to its A-label
//    first. A dNSName in the leaf's subjectAltName must match it, and the
//    client sends it as the ClientHello's server_name.
//  - now_seconds: the caller's clock, in seconds since
//    1970-01-01T00:00:00Z. Every certificate the walk reads must be valid
//    at it, compared exactly with no skew tolerance. 0 means the caller
//    never set the clock.
//  - ticket_binding: SHA256_LEN bytes, set with resumption alone: the
//    ch_ticket.binding of the ticket in psk and psk_id. It must match
//    this configuration (webpki_ticket.h).
//  - spki_pins: spki_pin_count SPKI pins, 0 to CH_SPKI_PIN_MAX, each the
//    SHA-256 of a DER SubjectPublicKeyInfo (RFC 7858 §4.2). With pins
//    set, the client offers RFC 7250 raw public keys, and a server key
//    is accepted only when a pin names it (webpki_pin.h). Pins without
//    anchors are a whole configuration: the client then offers raw keys
//    alone, reads no clock, and takes a hostname only as the server_name
//    to send.
//
// ch_connect returns CH_EINVAL before it sends a byte when any of those
// rules fails, when now_seconds is 0 in a configuration with anchors,
// and for any other PSK, a pin slot (server_pubkey) or an epoch callback.
#ifndef CH_WEBPKI_CFG_H
#define CH_WEBPKI_CFG_H

#include <stddef.h>
#include <stdint.h>

// A trust anchor: a root's subject Name and its public key, each the
// whole DER TLV the root certificate carries — the Name SEQUENCE and the
// SubjectPublicKeyInfo SEQUENCE, header included. Nothing else is read
// from the root, not even its dates. The caller embeds the roots it
// trusts; the array is the whole trust boundary, and any anchor may
// certify any name (docs/webpki.md, "Trust anchors").
typedef struct {
    const uint8_t *name;
    size_t name_len;
    const uint8_t *spki;
    size_t spki_len;
} ch_trust_anchor;

// Anchors one configuration may carry. The number is a measurement: nine
// roots cover the endpoints docs/webpki.md captures, five of them Amazon
// Trust Services'.
#define CH_WEBPKI_ANCHOR_MAX 12

// SPKI pins one configuration may carry. RFC 7858 §4.2 asks for a
// primary pin and a backup pin, and a rotation holds the old primary for
// a while beside both, so four leaves room for one more.
#define CH_SPKI_PIN_MAX 4

// The CertificateType values of RFC 9846 §4.5.1 (RFC 7250 §3). The client
// offers them in the server_certificate_type extension, and
// ch_tls.server_cert_type reports the one the server's
// EncryptedExtensions selected, or CH_CERT_TYPE_X509 when it sent none.
#define CH_CERT_TYPE_X509 0
#define CH_CERT_TYPE_RAW_PUBLIC_KEY 2

#endif
