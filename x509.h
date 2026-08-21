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

#include "buf.h"

// Largest single certificate the parser admits. Measured realistic
// leaves and intermediates: 412..449 bytes (P-256), 1168..1205 bytes
// (RSA-3072); the cap leaves margin for longer names and extra
// extensions. A build with bigger certificates raises it; the
// receive buffer must hold the whole Certificate flight, up to two
// certificates plus framing.
// The per-algorithm defaults, named so the mirrors derive from one
// definition: the differential driver and the mutation kit size
// their material from these, and spec/Spec/X509.lean pins the same
// two numbers as the spec's modeled caps.
#define CH_X509_DEFAULT_MAX_RSA 1536
#define CH_X509_DEFAULT_MAX_ECDSA 768
#ifndef CH_X509_MAX
#ifdef CH_PIN_ECDSA
#define CH_X509_MAX CH_X509_DEFAULT_MAX_ECDSA
#else
#define CH_X509_MAX CH_X509_DEFAULT_MAX_RSA
#endif
#endif
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

// DER primitives, defined in x509_der.c. The INV-5 tripwire bans
// calls to x509_* names outside the cert files, so these are the
// module's internals even with external linkage (which the proof,
// fuzz, and strictness builds need). All return 1 on success, 0 on
// any deviation from canonical DER.
int x509_read_len(rbuf *r, size_t *out_len);
int x509_read_header(rbuf *r, uint8_t tag, size_t *out_len);
int x509_read_exact(rbuf *r, const uint8_t *want, size_t n);
int x509_skip(rbuf *r, uint8_t tag);
int x509_read_serial(rbuf *r);
int x509_read_bitstring(rbuf *r, const uint8_t **bytes, size_t *n);

// One decoded Extension TLV: pointers into the caller's buffer.
typedef struct {
    const uint8_t *oid;
    size_t oid_len;
    const uint8_t *value;
    size_t value_len;
    int critical;
} x509_extension;

int x509_read_extension(rbuf *e, size_t tlv_cap, x509_extension *out);
int x509_read_time(rbuf *r);
int x509_read_keyusage(const uint8_t *v, size_t n, uint8_t required);
int x509_read_spki(rbuf *r, const uint8_t **key, size_t *key_len);
// Re-emits the canonical tag+length header for hashing; returns its
// size (2..4 bytes).
size_t x509_emit_header(uint8_t tag, size_t len, uint8_t out[4]);

#endif
