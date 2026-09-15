// Canonical-DER primitives, called by both certificate files: x509.c's
// profile walker and x509_ca.c's provisioning walk. Each reader
// decodes one DER shape and rejects a non-minimal or malformed
// encoding before it interprets any field, so no decoded value has a
// second accepted representation. Bodies in x509_der.c.
#ifndef CH_X509_DER_H
#define CH_X509_DER_H

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

// The INV-5 tripwire bans calls to x509_* names outside the cert
// files, so these are the module's internals even with external
// linkage (which the proof, fuzz, and strictness builds need). All
// return 1 on success, 0 on any deviation from canonical DER.
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
int x509_read_time_epoch(rbuf *r, uint32_t *index, int *ok);
int x509_read_keyusage(const uint8_t *v, size_t n, uint8_t required);
int x509_read_spki(rbuf *r, const uint8_t **key, size_t *key_len);
// Re-emits the canonical tag+length header for hashing; returns its
// size (2..4 bytes).
size_t x509_emit_header(uint8_t tag, size_t len, uint8_t out[4]);

#endif
