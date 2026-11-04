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
// none behind it. Every integer is raw big-endian bytes of a fixed
// length, the shape ch_cfg.server_pubkey already uses for a modulus, so
// a provisioning step writes them without a parser.
//
// n_len is 256 to CH_RSA_MODULUS_MAX and a multiple of 8, the bound
// rsa.h defines for the verifier. n and d are n_len bytes each. d is
// left-padded with zero bytes to n_len whatever its own value is;
// rsa_pss_sign reads all 8 * n_len bit positions either way, so the
// padding costs time and leaks nothing.
//
// A device object's key is those two integers, 2 * CH_RSA_MODULUS_MAX +
// sizeof(size_t) bytes: 776 with the device bound of 384. Its signer is
// the ladder in rsa_sign.c, one exponentiation over the whole modulus,
// with no CRT: no p, q, dP, dQ or qInv in the key and no code that reads
// them. That costs about four times a CRT signature, and buys three
// things a device values more -- the key stays two integers a
// provisioning step can write, there is one arithmetic path for an
// auditor to read instead of two plus a recombination, and the Bellcore
// fault attack, which factors the modulus from a single faulted CRT
// signature, has nothing to work on. A device is also the part an
// attacker can hold, which is where a fault is cheapest to cause.
//
// A host object's key (-DCH_CPU_RUNTIME, cpu_cfg.h) holds five more
// integers, the CRT's, under the names and the meanings RFC 8017 3.2
// gives them: the primes p and q, dp = d mod (p - 1), dq = d mod (q - 1)
// and qinv = q^-1 mod p. Each is n_len / 2 bytes, left-padded with zero
// bytes, and each prime has the top bit of its n_len / 2 bytes set,
// which is the shape a key generator produces. A session that states its
// multiply (CH_CPU_CONSTANT_TIME_MULTIPLY) signs with the five, in
// rsa_sign64.c, and that signer checks each signature with the public
// exponent before it returns it, which is what answers the Bellcore
// attack there (rsa_sign64.h, docs/decisions.md 95). A session that does
// not state it signs with the ladder over n and d and reads none of the
// five, so a caller that never states its multiply may leave them zero.
// The struct is then 2 * CH_RSA_MODULUS_MAX + 5 * (CH_RSA_MODULUS_MAX /
// 2) + sizeof(size_t) bytes: 1,736 with the bound of 384 and 2,312 with
// the bound of 512. The five sit after n_len, so the ladder reads n, d
// and n_len where a device object's key has them.
//
// A caller that holds the struct in .bss holds it for the life of the
// image, so wipe it with ct_wipe when a key is retired.
typedef struct {
    uint8_t n[CH_RSA_MODULUS_MAX]; // modulus, big-endian, n_len bytes
    uint8_t d[CH_RSA_MODULUS_MAX]; // private exponent, big-endian, n_len bytes
    size_t n_len;                  // 256..CH_RSA_MODULUS_MAX, a multiple of 8
#ifdef CH_CPU_RUNTIME
    uint8_t p[CH_RSA_MODULUS_MAX / 2];    // first prime, big-endian, n_len / 2 bytes
    uint8_t q[CH_RSA_MODULUS_MAX / 2];    // second prime, n_len / 2 bytes
    uint8_t dp[CH_RSA_MODULUS_MAX / 2];   // d mod (p - 1), n_len / 2 bytes
    uint8_t dq[CH_RSA_MODULUS_MAX / 2];   // d mod (q - 1), n_len / 2 bytes
    uint8_t qinv[CH_RSA_MODULUS_MAX / 2]; // q^-1 mod p, n_len / 2 bytes
#endif
} ch_rsa_priv;

// Whether k is a key rsa_pss_sign signs with: n_len inside the bound
// above and a multiple of 8, and a modulus that is odd and has its top
// bit set. Montgomery arithmetic needs an odd modulus, and the encoder
// needs the top bit, which makes emLen exactly n_len and emBits exactly
// 8 * n_len - 1, the shape every RSA key generator produces. The
// verifier admits a shorter modulus because a peer's key comes from
// elsewhere; a server's own key is refused rather than signed with.
//
// It reads n_len and two bytes of the modulus, which is public, and no
// byte of d. rsa_pss_sign runs it first, and a server runs it when it
// checks its configuration (srv_auth.h), so a malformed key is refused
// before a session starts rather than inside the handshake. It is
// inline so that rsa_pss_sign compiles one copy of the test: rsa_sign.c
// is among the files lint-wide-multiply counts branches in. Returns 1 or
// 0.
static inline int rsa_pss_sign_key_ok(const ch_rsa_priv *k) {
    if (k->n_len < 256 || k->n_len > CH_RSA_MODULUS_MAX || k->n_len % 8 != 0) {
        return 0;
    }
    if ((k->n[k->n_len - 1] & 1) == 0 || (k->n[0] & 0x80) == 0) {
        return 0;
    }
    return 1;
}

// What the constant-time claim covers, and what it does not. This is the
// claim for the ladder in rsa_sign.c, which a device object runs and a
// host object runs for a session that does not state its multiply. A
// host object's session that states it signs with rsa_sign64.c, by the
// CRT, and rsa_sign64.h holds the claim for that signer.
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
// Not covered, second: fault injection. The ladder does not verify the
// signature before returning it, so a fault during the exponentiation
// produces a wrong signature. The peer rejects it and the handshake
// fails, which costs the server a connection; it does not hand out the
// key, because the ladder has no CRT recombination for a fault to
// split. rsa_sign64.c has one, and verifies every signature for that
// reason.
//
// Not covered, third: the modulus and the encoded message are public,
// and the code treats them as public. Their bit lengths steer loop
// counts here exactly as they do in rsa.c.

// The salt length rsa_pss_rsae_sha256 fixes, in bytes: the length of
// SHA-256's output (RFC 9846 §4.3.3, rfc9846.txt:1898-1899), sLen in RFC
// 8017 9.1.1.
#define RSA_PSS_SALT_LEN 32

// Signs msg_hash, the 32-byte SHA-256 of the content RFC 9846 §4.5.2
// defines, under the salt the caller drew, and writes n_len bytes to sig.
// cap is the room sig has; sig_len takes the length written. Returns 1
// on success and 0 when rsa_pss_sign_key_ok refuses the key or when cap
// is short. The 1-or-0 return is rsa_pss_verify's, because a caller that
// holds both calls should read one convention; the caller turns a 0 into
// the alert it sends.
//
// The salt is RSA_PSS_SALT_LEN bytes the caller drew for this signature
// alone. The signature is a function of the key, msg_hash and the salt,
// so this file draws nothing: the caller draws from its session's source
// (srv_auth.c, INV-4), as mlkem.h and p256_ecdh.h take their random bytes
// as arguments. The salt appears in the signature, so it is not secret.
// An all-zero salt is the one a source that returned without writing
// leaves, and CH_ASSERT fires on it: every signature over one message
// would then be the same bytes, and nothing downstream would notice.
int rsa_pss_sign(const ch_rsa_priv *k, const uint8_t msg_hash[32],
                 const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig, size_t cap, size_t *sig_len);

// Internal split boundary: sig = em^d mod n (RSASP1, RFC 8017 5.2.1),
// with em and sig both n_len big-endian bytes. rsa_pss_sign checks the
// key and builds em; the caller here guarantees em < n, which the PSS
// encoding gives by construction. Exposed so the Wycheproof suite can
// drive the exponentiation against third-party vectors, which carry a
// private key but no PSS signature. Not part of the public API.
void rsa_sp1(const ch_rsa_priv *k, const uint8_t *em, uint8_t *sig);

#endif
