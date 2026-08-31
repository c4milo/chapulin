// Provisioning: one PEM certificate to the public key it carries.
//
// ch_cfg.server_pubkey takes raw key bytes, and a device is handed a
// certificate. This bridges the two. It is built only under
// CH_TRUST_CA, because it rests on the certificate parser that only
// that mode links -- the gate is a dependency, not a difference in
// behaviour. The key it returns is a CA key or a server key depending
// on nothing but which slot the caller assigns it to, so the name says
// public key and not CA.
//
// DECODING IS NOT AUTHENTICATING. The certificate's own signature goes
// unread, its validity dates go unread, and its names go unread. A
// block that decodes proves nothing about who sent it. The key is
// trusted because an operator pushed it over the existing TLS session
// (docs/rotation.md), exactly as a raw pin is. Nothing here is a
// substitute for that step.
//
// Sender-side conversion stays the default. If the fleet server can
// run one openssl command, docs/ca.md's recipe is better on every
// axis: no parser on the device, no second entry point, no proof. This
// path earns its place only where the server relays an operator-signed
// blob it does not itself parse.
#ifndef CH_X509_CA_H
#define CH_X509_CA_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "x509.h"

// Reads one "-----BEGIN CERTIFICATE-----" block and copies out the
// SubjectPublicKeyInfo key bytes: the RSA modulus, or the P-256 point
// as X||Y -- the exact bytes ch_cfg.server_pubkey takes.
//
// der is scratch. It holds the decoded certificate during the call and
// nothing after it. It must NOT be ch_cfg.buf while a session is live:
// ch_read serves unread plaintext out of that buffer across calls, so
// decoding there corrupts the session.
//
// The certificate must assert basicConstraints CA:TRUE. That check
// catches an operator who pushes a leaf by mistake; it stops no
// attacker, because whoever can substitute the blob can set the bit.
//
// Returns CH_OK with *key_len set, or CH_EINVAL with *key_len 0 and
// key wiped. One error code: the device's response is the same in
// every case, and it has no console to read a reason from.
int ch_pubkey_from_pem(const uint8_t *pem, size_t pem_len, uint8_t der[CH_X509_MAX],
                       uint8_t key[CH_X509_KEY_MAX], size_t *key_len);

#endif
