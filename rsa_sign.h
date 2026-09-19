// RSA-PSS signature generation (RFC 8017 8.1.1), the signing half of the
// rsa_pss_rsae_sha256 scheme a server proves its identity with in
// CertificateVerify (RFC 9846 §4.5.2). The exponent here is secret, so
// every step is constant time in it. rsa.[ch] verifies with the public
// exponent 65537 and says why its own arithmetic is deliberately variable
// time (rsa.h:4-8); this file shares none of that arithmetic, as
// docs/server.md records under "rsa_sign.[ch]: RSA-PSS with a secret
// exponent".
//
// One scheme and no choices, the same three constants the verifier fixes:
// SHA-256 over the signed content, MGF1-SHA256, and a 32-byte salt.
#ifndef CH_RSA_SIGN_H
#define CH_RSA_SIGN_H

#include <stddef.h>
#include <stdint.h>

#include "rsa.h" // CH_RSA_MODULUS_MAX

// The private key, whole, in one caller-owned struct: no heap here and
// none behind it. Both integers are raw big-endian bytes of exactly
// n_len bytes, the shape ch_cfg.server_pubkey already uses for a
// modulus, so a provisioning step writes them without a parser.
//
// n_len is 256 to CH_RSA_MODULUS_MAX and a multiple of 8, the bound
// rsa.h defines for the verifier. d is left-padded with zero bytes to
// n_len whatever its own value is; rsa_pss_sign reads all 8 * n_len bit
// positions either way, so the padding costs time and leaks nothing.
//
// The struct is 2 * CH_RSA_MODULUS_MAX + sizeof(size_t) bytes: 776 with
// the device bound of 384, 1,032 with the TRUST=webpki bound of 512. A
// caller that holds it in .bss holds it for the life of the image, so
// wipe it with ct_wipe when a key is retired.
//
// What this file leaves out of the key is the CRT: no p, q, dP, dQ or
// qInv, and no code that reads them. One exponentiation over the whole
// modulus costs about four times a CRT signature, and buys three things
// the tree values more -- the key stays two integers a provisioning
// step can write, there is one arithmetic path for an auditor to read
// instead of two plus a recombination, and the Bellcore fault attack,
// which factors the modulus from a single faulted CRT signature, has
// nothing to work on here.
typedef struct {
    uint8_t n[CH_RSA_MODULUS_MAX]; // modulus, big-endian, n_len bytes
    uint8_t d[CH_RSA_MODULUS_MAX]; // private exponent, big-endian, n_len bytes
    size_t n_len;                  // 256..CH_RSA_MODULUS_MAX, a multiple of 8
} ch_rsa_priv;

// What the constant-time claim covers, and what it does not.
//
// Covered. The exponentiation is a Montgomery ladder whose trip count is
// exactly 8 * n_len iterations, so neither the value of d nor its bit
// length changes how long a signature takes. Every iteration runs the
// same two Montgomery multiplications over the same addresses. The one
// place a bit of d decides anything selects with mask arithmetic and
// never an if, the form x25519.c's cswap already uses. No memory index
// in this file comes from a secret, so there is no table for a cache
// attacker to watch. Every product goes through ct.h's ct_widemul, so a
// core whose wide multiply is variable time (the Cortex-M3's umull)
// does not see one. That covers a remote attacker who times signatures
// and a local attacker who watches the data cache.
//
// Not covered, first: this file does not blind the base. Blinding
// multiplies the input by r^e and the result by r^-1 for a fresh random
// r, and the inverse is the problem -- computing r^-1 mod a composite
// modulus in constant time needs a modular inversion this tree does not
// have, and adding one is a module of its own. Without it, an attacker
// who measures power or electromagnetic emissions across many
// signatures, on inputs they choose, can correlate the intermediate
// values with d. The ladder's fixed pattern of one square and one
// multiply per bit already denies simple power analysis the shape of d;
// what is missing is the defense against the differential form.
//
// Not covered, second: fault injection. This file does not verify the
// signature before returning it, so a fault during the exponentiation
// produces a wrong signature. The peer rejects it and the handshake
// fails, which costs the server a connection; it does not hand out the
// key, because there is no CRT recombination here for a fault to split.
//
// Not covered, third: the modulus and the encoded message are public,
// and the code treats them as public. Their bit lengths steer loop
// counts here exactly as they do in rsa.c.

// Signs msg_hash, the 32-byte SHA-256 of the content RFC 9846 §4.5.2
// defines, and writes n_len bytes to sig. cap is the room sig has;
// sig_len takes the length written. Returns 1 on success and 0 when the
// key is malformed or when cap is short. A key is malformed here when
// its length is outside the bound or not a multiple of 8, when the
// modulus is even, which has no Montgomery inverse, or when the
// modulus has its top bit clear, which every RSA key generator sets and
// which rsa_sign.c needs to make emLen exactly n_len. The 1-or-0 return
// is rsa_pss_verify's, because a caller that holds both calls should
// read one convention; the caller turns a 0 into the alert it sends.
//
// The salt is 32 fresh bytes from ch_rand_bytes. A device without
// entropy must not get this far (rand.h).
int rsa_pss_sign(const ch_rsa_priv *k, const uint8_t msg_hash[32], uint8_t *sig, size_t cap,
                 size_t *sig_len);

// Internal split boundary: sig = em^d mod n (RSASP1, RFC 8017 5.2.1),
// with em and sig both n_len big-endian bytes. rsa_pss_sign checks the
// key and builds em; the caller here guarantees em < n, which the PSS
// encoding gives by construction. Exposed so the Wycheproof suite can
// drive the exponentiation against third-party vectors, which carry a
// private key but no PSS signature. Not part of the public API.
void rsa_sp1(const ch_rsa_priv *k, const uint8_t *em, uint8_t *sig);

#endif
