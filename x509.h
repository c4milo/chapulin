// Profiled certificate verification (own-CA mode). The device pins
// one CA public key and accepts exactly one chain shape: an X.509 v3
// leaf signed by the pin, or that leaf plus the one intermediate that
// signed it, itself signed by the pin — the build's one algorithm
// throughout, canonical DER on every decoded field. No chain
// building, no names, no clock. The profile and its trade-offs live
// in docs/decisions.md and docs/ca.md.
#ifndef CH_X509_H
#define CH_X509_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "x509_der.h"

// Largest single certificate the parser admits. Measured realistic
// leaves and intermediates: 412..449 bytes (P-256), 1168..1205 bytes
// (RSA-3072); the cap leaves margin for longer names and extra
// extensions. A build with bigger certificates raises it; the
// receive buffer must hold the whole Certificate flight, up to two
// certificates plus framing.
#ifndef __cplusplus
_Static_assert(CH_X509_MAX >= 512, "the smallest real leaf needs room");
_Static_assert(CH_X509_MAX <= 0x3fe0, "a Certificate message must fit one handshake message");
#endif

// Extension walk bounds. Enforced by the code and used as the proof
// bounds, so the proved domain equals the accepted domain.
#define CH_X509_EXT_COUNT_MAX 8
#define CH_X509_EXT_TLV_MAX 256

// Extracted leaf identity: the SPKI key bytes, copied out because the
// message buffer is reused before CertificateVerify arrives.
#ifdef CH_PIN_ECDSA
#define CH_X509_KEY_MAX 64
#else
#define CH_X509_KEY_MAX 384
#endif

typedef struct {
    uint8_t key[CH_X509_KEY_MAX];
    size_t key_len;
    uint8_t ca_slot; // 1 = pin slot A anchors the chain, 2 = slot B
    // The certificate's notBefore as an epoch number when it is
    // epoch-shaped (epoch_ok = 1); the driver enforces the monotonic
    // rule only when the epoch callbacks are configured.
    uint32_t epoch;
    uint8_t epoch_ok;
} x509_leaf_info;

// Parses the Certificate message's CertificateEntry list — the leaf
// alone, or the leaf followed by the intermediate that signed it —
// checks each certificate against its profile arm, verifies the
// chain up to pin slot A or B, and copies the leaf key into out.
// The caller seeds *alert; the parser overwrites it only when it
// knows better:
//   any deviation from the single admitted byte shape — DER form,
//   version, serial, an over-cap or truncated
//   entry                      -> ALERT_BAD_CERTIFICATE (caller's seed)
//   a recognized off-profile fact — wrong algorithm, an SPKI rule
//   (modulus range, oddness, exponent, point form), unknown critical
//   or duplicate extension, missing KU/EKU, entry
//   count                      -> ALERT_UNSUPPORTED_CERTIFICATE
//   leaf fails its intermediate-> ALERT_BAD_CERTIFICATE + CH_EAUTH
//   chain head fails the pins  -> ALERT_UNKNOWN_CA + CH_EAUTH
// Returns CH_OK, CH_EPROTO (parse/profile), or CH_EAUTH (signature).
int x509_verify_leaf(const uint8_t *list, size_t list_len, const uint8_t *ca_key_a, size_t ca_a_len,
                     const uint8_t *ca_key_b, size_t ca_b_len, x509_leaf_info *out, uint8_t *alert);

#endif
