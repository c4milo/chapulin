// The JSON Web Signature check a JWT login token needs (RFC 7515, RFC
// 7518, RFC 8037, docs/decisions.md 221): one call that checks a token's
// signature under a public key, and base64url, which a token writes its
// three parts in. A host TRUST=webpki object built with JWS=on, which
// defines CH_JWS, exports the calls below. The calls read no JSON: the
// caller splits the token at its two '.' characters and reads the header
// and the claims itself.
//
// No call keeps state, allocates or draws randomness. Each reads the
// bytes the caller passes, writes into a room the caller gives and sizes,
// and keeps no pointer once it returns.
//
// One image may link one object of each transport, so each call carries
// the object's transport in its symbol name, as ch_srv_check does
// (docs/decisions.md 61).
#ifndef CH_JWS_H
#define CH_JWS_H

#include <stddef.h>
#include <stdint.h>

#include "result.h"

#if defined(CH_JWS) && !defined(CH_CPU_RUNTIME)
#error "CH_JWS needs a host object: the RS256 check runs on rsa_mont64.c"
#endif
#if defined(CH_JWS) && !defined(CH_TRUST_WEBPKI)
#error "CH_JWS needs TRUST=webpki, whose object packages the PKCS#1 v1.5 verifier RS256 shares"
#endif

// The JWS algorithms ch_jws_verify takes (RFC 7518 section 3.1, RFC 8037
// section 3.1). A token's header names one as a string, "RS256", "ES256"
// or "EdDSA", and the caller maps it to a value here.
#define CH_JWS_RS256 1 // RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 section 3.3)
#define CH_JWS_ES256 2 // ECDSA P-256 with SHA-256 (RFC 7518 section 3.4)
#define CH_JWS_EDDSA 3 // Ed25519 (RFC 8037 section 3.1)

// The shortest and the longest RS256 modulus the check takes, in bytes.
// RFC 7518 section 3.3 requires a key of 2048 bits or more, and 512 bytes
// is rsa_key.h's bound for a TRUST=webpki object, RSA-4096.
#define CH_JWS_RSA_MODULUS_LEN_MIN 256
#define CH_JWS_RSA_MODULUS_LEN_MAX 512

// The longest RS256 public exponent the check takes, in bytes.
#define CH_JWS_RSA_EXPONENT_LEN_MAX 8

// The longest signature the check reads and the signer writes: an RS256
// signature under the largest modulus.
#define CH_JWS_SIG_LEN_MAX CH_JWS_RSA_MODULUS_LEN_MAX

// The bytes of noise ch_jws_sign takes from its caller.
#define CH_JWS_NOISE_LEN 32

// The length of the base64url text of n bytes (RFC 4648 section 5), with
// no padding, as RFC 7515 section 2 writes it: 4 characters for each 3
// bytes, and 2 or 3 characters for the last 1 or 2 bytes.
#define CH_BASE64URL_LEN(n) ((n) / 3 * 4 + ((n) % 3 * 4 + 2) / 3)

// The most bytes that text_len characters of base64url decode to.
#define CH_BASE64URL_DECODED_LEN_MAX(text_len) ((text_len) / 4 * 3 + (text_len) % 4 * 3 / 4)

// The most bytes ch_base64url_encode takes in one call: a quarter of the
// largest size_t, so that four times the length is a size_t too.
#define CH_BASE64URL_IN_LEN_MAX (SIZE_MAX / 4)

#ifdef CH_JWS

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_base64url_encode ch_base64url_encode_quic_nonblocking
#define ch_base64url_decode ch_base64url_decode_quic_nonblocking
#define ch_jws_verify ch_jws_verify_quic_nonblocking
#elif defined(CH_TRANSPORT_TCP_NONBLOCKING)
#define ch_base64url_encode ch_base64url_encode_tcp_nonblocking
#define ch_base64url_decode ch_base64url_decode_tcp_nonblocking
#define ch_jws_verify ch_jws_verify_tcp_nonblocking
#else
#define ch_base64url_encode ch_base64url_encode_tcp_blocking
#define ch_base64url_decode ch_base64url_decode_tcp_blocking
#define ch_jws_verify ch_jws_verify_tcp_blocking
#endif

// Writes the in_len bytes at in as base64url text to text (RFC 4648
// section 5): '-' and '_' are the characters of 62 and 63, and the text
// has no padding and no line break, as RFC 7515 section 2 writes a JWS
// part. Writes the text's length, CH_BASE64URL_LEN(in_len), to *text_len.
// in may be NULL when in_len is 0.
//
// Returns CH_OK. Returns CH_ECAP, with nothing written, when text_cap is
// below CH_BASE64URL_LEN(in_len), or when in_len is above
// CH_BASE64URL_IN_LEN_MAX. The bytes may be secret: no branch and no
// memory index reads their values.
int CH_MUST_USE ch_base64url_encode(const uint8_t *in, size_t in_len, uint8_t *text,
                                    size_t text_cap, size_t *text_len);

// Decodes base64url text (RFC 4648 section 5) to out, and writes the
// decoded length to *out_len. The text must be canonical. So the call
// refuses:
//  - a character outside the alphabet, '=', '+', '/' and a line break
//    among them;
//  - a text_len whose remainder by 4 is 1;
//  - a last group with a bit set where it ends short (section 3.5).
// text may be NULL when text_len is 0.
//
// Returns CH_OK. Returns CH_ECAP when out_cap is below the decoded
// length, CH_BASE64URL_DECODED_LEN_MAX(text_len), with nothing written to
// out. Returns CH_EINVAL for text that the call refuses, and then out
// holds zeros where the call wrote. *out_len is 0 after each refusal. The
// characters may be secret, because a token is a bearer credential: the
// call branches on text_len and, once, on whether it refused the text,
// and no branch or memory index reads a character's value.
int CH_MUST_USE ch_base64url_decode(const uint8_t *text, size_t text_len, uint8_t *out,
                                    size_t out_cap, size_t *out_len);

// Checks sig, a JWS signature, over input under key with algorithm (RFC
// 7515 section 5.2). input is the JWS Signing Input: the base64url
// header, '.', and the base64url payload, as the token carries them. sig
// is the signature after ch_base64url_decode. key is a public key in the
// algorithm's form:
//  - CH_JWS_RS256: RFC 3110 section 2's form, as ch_dnssec_verify takes
//    an RSA key (dnssec.h). That is one byte that holds the exponent's
//    length, or a zero byte and two bytes that hold it. Then the
//    exponent, then the modulus, which runs to the end of key. A JWK
//    holds the two integers as "e" and "n" (RFC 7518 section 6.3.1). The
//    modulus is CH_JWS_RSA_MODULUS_LEN_MIN to CH_JWS_RSA_MODULUS_LEN_MAX
//    bytes, odd, with no leading zero byte. The exponent is odd, at
//    least 3, at most CH_JWS_RSA_EXPONENT_LEN_MAX bytes, with no leading
//    zero byte. A valid sig is as long as the modulus.
//  - CH_JWS_ES256: 64 bytes, X then Y, the JWK's "x" and "y" (RFC 7518
//    section 6.2.1). A valid sig is 64 bytes, R then S (section 3.4).
//  - CH_JWS_EDDSA: 32 bytes, the JWK's "x" (RFC 8037 section 2). A valid
//    sig is 64 bytes, R then S. The rule is RFC 8032's cofactorless
//    equation. It refuses what libsodium refuses, and a key outside the
//    subgroup of prime order too, as dnssec.h's algorithm 15 does.
//
// Take algorithm from the configuration that holds the key, never from
// the token's header alone (RFC 8725 section 3.1). A caller that lets the
// header choose lets whoever wrote the token choose. A caller that reads
// its keys from a JWK Set owes three checks before this call, because the
// call sees the key's bytes and not its JWK (RFC 7517 sections 4.2 to
// 4.4):
//  - the JWK's "use" is absent or "sig", and its "key_ops" is absent or
//    holds "verify";
//  - the JWK's "alg", when present, is the algorithm the caller passes;
//  - the token header's "alg" is that algorithm too.
// A signature that is true under the key's bytes verifies here whatever
// the JWK says the key is for.
//
// Returns CH_OK for a valid signature. Returns CH_EAUTH for a signature
// that the key does not verify, one of the wrong length among them. The
// token supplies the signature, so a bad one is the token's fault.
// Returns CH_EINVAL for an algorithm the call does not take or a key it
// refuses, which are the caller's to correct. input may be NULL when
// input_len is 0. Every input is public to the check, so its arithmetic
// is variable time, as dnssec.h's is, and its hashes run the portable
// code.
int CH_MUST_USE ch_jws_verify(uint8_t algorithm, const uint8_t *key, size_t key_len,
                              const uint8_t *input, size_t input_len, const uint8_t *sig,
                              size_t sig_len);

#ifdef CH_ROLE_SERVER
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_jws_sign ch_jws_sign_quic_nonblocking
#elif defined(CH_TRANSPORT_TCP_NONBLOCKING)
#define ch_jws_sign ch_jws_sign_tcp_nonblocking
#else
#define ch_jws_sign ch_jws_sign_tcp_blocking
#endif

// Writes the JWS signature of input under priv with algorithm to sig, and
// its length to *sig_len (RFC 7515 section 5.1). It is for the tests and
// the tools that make tokens. An object with a server role alone defines
// it, ROLE=both under this axis, because the signers are a server's.
// input is the JWS Signing Input, as for ch_jws_verify. priv is a private
// key in the algorithm's form:
//  - CH_JWS_RS256: one ch_rsa_priv (rsa_key.h), so priv_len is
//    sizeof(ch_rsa_priv). ch_rsa_key_from_pem writes one (pem_files.h).
//    The modulus is 256 bytes or more and a multiple of 8, and the public
//    exponent is 65537. The signature is as long as the modulus.
//  - CH_JWS_ES256: 32 bytes, the scalar d, big-endian, the JWK's "d" (RFC
//    7518 section 6.2.2), from 1 to the group order less 1. The signature
//    is 64 bytes, R then S.
//  - CH_JWS_EDDSA: 32 bytes, the private key of RFC 8032 section 5.1.5,
//    the JWK's "d" (RFC 8037 section 2). The signature is 64 bytes, R
//    then S. The signer runs on the wide field alone, so cpu must hold
//    CH_CPU_CONSTANT_TIME_MULTIPLY (cpu_cfg.h).
//
// noise is CH_JWS_NOISE_LEN bytes that the caller draws for each call
// from a strong random source. ES256 adds them to RFC 6979's nonce
// (draft-irtf-cfrg-det-sigs-with-noise), and RS256 blinds its exponents
// with them. The signature does not show them: an RS256 signature is the
// same bytes whatever the noise holds. EdDSA draws nothing (RFC 8032
// section 5.1.6) and reads no noise, so noise may be NULL for it alone.
//
// cpu describes the CPU, as for ch_p256_key_from_pem (pem_files.h), and
// the call refuses the same values. It picks the multiply that the
// signer runs. Each signer checks its signature before the call writes
// it: ES256 checks the nonce's point and the signature's equation
// (docs/decisions.md 153), and RS256 and EdDSA verify the signature under
// the public key.
//
// Returns CH_OK. Returns CH_ECAP, with nothing written, when sig_cap is
// below the signature's length. Returns CH_EINVAL, with nothing written,
// for a cpu value the object refuses, an algorithm the call does not
// take, a NULL priv, a NULL noise for RS256 or ES256, a priv of the wrong
// length, a key the signer refuses, EdDSA under a cpu value without the
// multiply bit, or a signature that failed its check. input may be
// NULL when input_len is 0. priv, noise and every value derived from them
// are secret: no branch and no memory index reads them, and the call
// wipes each copy that it makes. The signature is public.
int CH_MUST_USE ch_jws_sign(uint32_t cpu, uint8_t algorithm, const void *priv, size_t priv_len,
                            const uint8_t noise[CH_JWS_NOISE_LEN], const uint8_t *input,
                            size_t input_len, uint8_t *sig, size_t sig_cap, size_t *sig_len);
#endif // CH_ROLE_SERVER

#endif // CH_JWS

#endif
