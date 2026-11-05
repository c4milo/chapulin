// The RSA private key a server signs with, and the modulus bound that
// sizes it and the verifier. A caller holds the key: ch_rsa_key_from_pem
// writes one, and ch_identity points at one. rsa.h and rsa_sign.h include
// this header, so each name has one definition.
#ifndef CH_RSA_KEY_H
#define CH_RSA_KEY_H

#include <stddef.h>
#include <stdint.h>

// The largest modulus rsa_pss_verify and rsa_pkcs1_verify admit, in
// bytes; the smallest is 256 (RSA-2048) and the step is 8. The device
// modes, raw and CA, stop at 384 (RSA-3072). A TRUST=webpki
// build (-DCH_TRUST_WEBPKI) admits 512 (RSA-4096), because a public
// chain ends at a root that size: GTS Root R1 is RSA-4096, measured in
// docs/webpki.md under "Bounds". rsa_mont.c sizes its word arrays from
// this value, so it also sets rsa_vp1's stack frame.
#ifndef CH_RSA_MODULUS_MAX
#ifdef CH_TRUST_WEBPKI
#define CH_RSA_MODULUS_MAX 512
#else
#define CH_RSA_MODULUS_MAX 384
#endif
#endif

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

#endif
