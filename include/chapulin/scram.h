// The parts SCRAM-SHA-256 is made of (RFC 5802, RFC 7677,
// docs/decisions.md 222): SHA-256, HMAC-SHA-256, PBKDF2-HMAC-SHA-256, a
// compare in constant time, base64, and the tls-server-end-point channel
// binding of SCRAM-SHA-256-PLUS (RFC 5929). A host TRUST=webpki object
// built with SCRAM=on, which defines CH_SCRAM, exports the calls below.
// The calls run no SCRAM exchange and read no SCRAM message: the caller
// writes and reads the messages, and computes each value with these
// calls.
//
// No call keeps state, allocates or draws randomness. Each reads the
// bytes the caller passes, writes into a room the caller gives and
// sizes, and keeps no pointer once it returns. A SCRAM client or server
// draws its nonce and its salt from its own random source.
//
// One image may link one object of each transport, so each call carries
// the object's transport in its symbol name, as ch_srv_check does
// (docs/decisions.md 61).
#ifndef CH_SCRAM_H
#define CH_SCRAM_H

#include <stddef.h>
#include <stdint.h>

#include "result.h"

#if defined(CH_SCRAM) && !defined(CH_CPU_RUNTIME)
#error "CH_SCRAM needs a host object: no device object has a measured budget for these calls"
#endif
#if defined(CH_SCRAM) && !defined(CH_TRUST_WEBPKI)
#error "CH_SCRAM needs TRUST=webpki, whose object packages SHA-384, SHA-512 and the DER reader"
#endif

// The length of a SHA-256 digest and of an HMAC-SHA-256 tag, in bytes.
#define CH_SHA256_LEN 32

// The length of the base64 text of n bytes (RFC 4648 section 4): 4
// characters for each group of 3 bytes, and '=' fills the last group.
#define CH_BASE64_LEN(n) (((n) + 2) / 3 * 4)

// The most bytes that text_len characters of base64 decode to. A text
// that ends with '=' decodes to 1 or 2 bytes fewer.
#define CH_BASE64_DECODED_LEN_MAX(text_len) ((text_len) / 4 * 3)

// The longest tls-server-end-point value, in bytes: a SHA-512 digest.
#define CH_TLS_SERVER_END_POINT_LEN_MAX 64

// The most bytes one ch_pbkdf2_hmac_sha256 call writes. RFC 8018 section
// 5.2 permits (2^32 - 1) blocks of 32 bytes. This bound is 2^16 blocks,
// far above any key a caller derives: SCRAM asks for 32 bytes.
#define CH_PBKDF2_OUT_LEN_MAX (65536 * CH_SHA256_LEN)

#ifdef CH_SCRAM

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_sha256 ch_sha256_quic_nonblocking
#define ch_hmac_sha256 ch_hmac_sha256_quic_nonblocking
#define ch_pbkdf2_hmac_sha256 ch_pbkdf2_hmac_sha256_quic_nonblocking
#define ch_ct_compare ch_ct_compare_quic_nonblocking
#define ch_base64_encode ch_base64_encode_quic_nonblocking
#define ch_base64_decode ch_base64_decode_quic_nonblocking
#define ch_tls_server_end_point ch_tls_server_end_point_quic_nonblocking
#elif defined(CH_TRANSPORT_TCP_NONBLOCKING)
#define ch_sha256 ch_sha256_tcp_nonblocking
#define ch_hmac_sha256 ch_hmac_sha256_tcp_nonblocking
#define ch_pbkdf2_hmac_sha256 ch_pbkdf2_hmac_sha256_tcp_nonblocking
#define ch_ct_compare ch_ct_compare_tcp_nonblocking
#define ch_base64_encode ch_base64_encode_tcp_nonblocking
#define ch_base64_decode ch_base64_decode_tcp_nonblocking
#define ch_tls_server_end_point ch_tls_server_end_point_tcp_nonblocking
#else
#define ch_sha256 ch_sha256_tcp_blocking
#define ch_hmac_sha256 ch_hmac_sha256_tcp_blocking
#define ch_pbkdf2_hmac_sha256 ch_pbkdf2_hmac_sha256_tcp_blocking
#define ch_ct_compare ch_ct_compare_tcp_blocking
#define ch_base64_encode ch_base64_encode_tcp_blocking
#define ch_base64_decode ch_base64_decode_tcp_blocking
#define ch_tls_server_end_point ch_tls_server_end_point_tcp_blocking
#endif

// Writes the SHA-256 digest (FIPS 180-4) of the n bytes at p to out.
// SCRAM calls it H(), and StoredKey is H(ClientKey) (RFC 5802 section 3).
// p may be NULL when n is 0. The bytes may be secret: the call wipes its
// hash state before it returns. It runs the portable code, with no hash
// instruction, so it takes no ch_cfg.cpu value.
void ch_sha256(const uint8_t *p, size_t n, uint8_t out[CH_SHA256_LEN]);

// Writes HMAC-SHA-256 (RFC 2104) of msg under key to out. A key longer
// than 64 bytes is hashed first, as RFC 2104 section 2 states. Either
// pointer may be NULL when its length is 0. The key is secret: the call
// wipes each copy of it that it makes, and its hash states.
void ch_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                    uint8_t out[CH_SHA256_LEN]);

// Writes out_len bytes of PBKDF2 (RFC 8018 section 5.2) to out, with
// HMAC-SHA-256 as the pseudorandom function. SCRAM calls it Hi(), with
// 32 bytes of output (RFC 5802 section 2.2). A tool calls it to make a
// SCRAM verifier, and a client calls it at each login. A server that
// keeps verifiers never calls it. password or salt may be NULL when its
// length is 0.
//
// The call runs 2 SHA-256 compressions for each iteration of each
// 32-byte block. RFC 7677 section 4 asks for an iteration_count of at
// least 4096, which is 8,192 compressions. The count is the caller's: a
// server that takes it from a peer bounds it first.
//
// Returns CH_OK. Returns CH_EINVAL, with nothing written, when
// iteration_count is 0, when out_len is 0, or when out_len is above
// CH_PBKDF2_OUT_LEN_MAX. The password and every value derived from it
// are secret: no branch and no memory index reads them, and the call
// wipes each copy that it makes.
int CH_MUST_USE ch_pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                                      const uint8_t *salt, size_t salt_len,
                                      uint32_t iteration_count, uint8_t *out, size_t out_len);

// Compares the n bytes at a with the n bytes at b. Returns CH_OK when
// they are equal and CH_EAUTH when they differ. Zero means equal, as in
// memcmp, and as every call here reports success. The call reads every
// byte of both, and no branch and no memory index reads a byte's value,
// so its time does not show where the two differ. A SCRAM server
// compares the StoredKey it computed from a ClientProof with it, and a
// client the ServerSignature, never with memcmp. a and b may be NULL
// when n is 0, and the call then returns CH_OK.
int CH_MUST_USE ch_ct_compare(const uint8_t *a, const uint8_t *b, size_t n);

// Writes the in_len bytes at in as base64 text to text (RFC 4648 section
// 4), with '=' after a last group of 1 or 2 bytes (section 3.2), and no
// line break. Writes the text's length, CH_BASE64_LEN(in_len), to
// *text_len. in may be NULL when in_len is 0.
//
// Returns CH_OK. Returns CH_ECAP, with nothing written, when text_cap is
// below CH_BASE64_LEN(in_len). The bytes may be secret: no branch and no
// memory index reads their values.
int CH_MUST_USE ch_base64_encode(const uint8_t *in, size_t in_len, uint8_t *text, size_t text_cap,
                                 size_t *text_len);

// Decodes base64 text (RFC 4648 section 4) to out, and writes the
// decoded length to *out_len. The text must be canonical. So the call
// refuses:
//  - a text_len that is not a multiple of 4;
//  - a character outside the alphabet, '-', '_' and a line break among
//    them;
//  - '=' anywhere but as the last character or the last two;
//  - a last group with a bit set where its padding drops it (section
//    3.5).
// text may be NULL when text_len is 0.
//
// Returns CH_OK. Returns CH_ECAP when out_cap is below the decoded
// length, with nothing written to out. Returns CH_EINVAL for text that
// the call refuses, and then out holds zeros where the call wrote.
// *out_len is 0 after each refusal. The characters may be secret: the
// call branches on text_len and on the count of '=' at the end, and once
// on whether it refused the text. No other branch and no memory index
// reads a character's value.
int CH_MUST_USE ch_base64_decode(const uint8_t *text, size_t text_len, uint8_t *out, size_t out_cap,
                                 size_t *out_len);

// Writes the tls-server-end-point channel binding of cert to out (RFC
// 5929 section 4.1), and its length to *out_len. cert is the server's
// end-entity certificate in DER, as the TLS Certificate message carries
// it: chain[0] of ch_chain_from_pem on a server, and the first
// certificate a client reads. SCRAM-SHA-256-PLUS puts the value in its
// channel binding data (RFC 5802 section 6.1).
//
// The value is a hash of the whole certificate. The hash is the one the
// certificate's signatureAlgorithm names:
//  - SHA-256 for sha256WithRSAEncryption and ecdsa-with-SHA256;
//  - SHA-384 and SHA-512 for the RSA and ECDSA algorithms that name them;
//  - SHA-256 in place of MD5 or SHA-1, for md5WithRSAEncryption,
//    sha1WithRSAEncryption and ecdsa-with-SHA1, as section 4.1 states;
//  - for RSASSA-PSS, the hash its parameters name, and SHA-256 in place
//    of SHA-1, which absent parameters name too (RFC 4055 section 3.1).
// So *out_len is 32, 48 or 64.
//
// The call reads the certificate's outer fields alone, in canonical DER:
// a Certificate SEQUENCE that fills cert, and in it a TBSCertificate
// SEQUENCE, the signatureAlgorithm and a signature BIT STRING, with
// nothing after them. It judges nothing: no signature, date or name. A
// certificate that it hashes is not one that it trusts.
//
// Returns CH_OK. Returns CH_EINVAL, with nothing written, for a cert that
// is not such a Certificate, or whose signature algorithm names no hash
// this rule takes: Ed25519, ML-DSA and the SHA-224 algorithms among
// them. RFC 5929 defines no value for those. The certificate is public,
// so the call branches on its bytes.
int CH_MUST_USE ch_tls_server_end_point(const uint8_t *cert, size_t cert_len,
                                        uint8_t out[CH_TLS_SERVER_END_POINT_LEN_MAX],
                                        size_t *out_len);

#endif // CH_SCRAM

#endif
