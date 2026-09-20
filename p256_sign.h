// ECDSA P-256 signature generation (FIPS 186-4, SEC 1), the signing half
// of ecdsa_secp256r1_sha256, which a server proves its identity with in
// CertificateVerify (RFC 9846 §4.5.2). p256.[ch] verifies, and says why
// its own arithmetic is deliberately variable time: every input it sees
// is public (p256.h:2-5). This file shares none of that arithmetic. It
// computes over p256_scalar.c and p256_point.c, and it calls nothing in
// p256.c.
//
// That separation is the whole point of the file, so it is stated once
// plainly: p256.c's Montgomery multiply branches on its operands
// (p256.c:142) and its modular inverse is built out of that multiply. A
// nonce routed through either one leaks through the conditional
// subtraction, and one leaked nonce recovers the private key outright.
// The build makes the mistake unavailable as well as forbidden --
// `nm -gU p256.o` prints one symbol, p256_ecdsa_verify -- but the rule is
// written here because a future edit could export more.
//
// The scheme this file signs names the hash, not the cipher suite.
// ecdsa_secp256r1_sha256 is SHA-256 over the content RFC 9846 §4.5.2
// defines, whatever suite the handshake selected;
// handshake_auth.c's hash_signed_content branches on the scheme and not
// on the suite for the same reason. msg_hash is therefore always 32
// bytes. A suite whose transcript hash is 48 bytes changes what the
// caller hashes, not what this file receives.
#ifndef CH_P256_SIGN_H
#define CH_P256_SIGN_H

#include <stddef.h>
#include <stdint.h>

// The longest DER ECDSA-Sig-Value over this curve: SEQUENCE header 2,
// then two INTEGERs of 2 header bytes plus at most 33 content bytes each,
// the 33rd being the leading zero a value with its top bit set needs.
#define P256_SIG_MAX 72

// The private scalar, 32 big-endian bytes, the shape SEC 1 gives a
// P-256 private key and the shape a provisioning step writes.
#define P256_PRIV_LEN 32

// What the constant-time claim covers, and what it does not.
//
// Covered. Every value derived from the private scalar or from the nonce
// moves through p256_scalar.c and p256_point.c, whose routines have no
// operand-dependent branch and no operand-dependent memory index. The
// scalar multiplication runs a literal 256 rounds with the same two
// point additions in each, so neither the value of the nonce nor its bit
// length changes how long a signature takes. There is no precomputed
// multiple of the generator, so there is no table for a cache attacker
// to watch. The nonce generator runs a literal number of candidates and
// picks one with mask arithmetic, so a rejected candidate costs the same
// as an accepted one. Every product goes through ct.h's ct_widemul, so a
// core whose widening multiply is variable time does not see one.
//
// Not covered, first: the outputs. r and s are public -- they go on the
// wire -- so the DER writer's leading-zero handling reads their values
// and their lengths, and the two checks that reject a zero r or s are
// ordinary branches. Nothing there reads the key or the nonce.
//
// Not covered, second: whether the configured key is in range. A key at
// or above the group order, or zero, makes this function return 0, and
// the branch that does so reads the key. It reveals that the server's
// provisioned key is unusable, which the failed handshake reveals
// anyway, and it does not vary from one signature to the next.
//
// Not covered, third: fault injection. A deterministic nonce signs one
// message the same way every time, which is the shape a differential
// fault attack wants: one correct signature and one faulted signature
// over the same message recover the key. This file does not verify its
// own output before returning it. docs/server.md records the trade
// against a randomized nonce, whose own failure mode -- a repeated nonce
// from a weak entropy source -- is also full key recovery and needs no
// fault to reach.

// Signs msg_hash, the 32-byte SHA-256 of the content RFC 9846 §4.5.2
// defines, and writes the DER ECDSA-Sig-Value to sig. cap is the room
// sig has, and sig_len takes the number of bytes written. Returns 1 on
// success and 0 when the key is out of range, when cap is below the
// length the signature needs, or when the nonce generator produced no
// candidate below the group order in its fixed number of tries. The
// 1-or-0 return is p256_ecdsa_verify's, because a caller that holds both
// should read one convention; the caller turns a 0 into the alert it
// sends.
//
// The nonce is RFC 6979 deterministic, derived from the private scalar
// and msg_hash by HMAC-SHA-256 (hkdf.h:13). No entropy is drawn here, so
// a weak generator at signing time cannot repeat a nonce, and two
// signatures over one message under one key are byte-identical. The
// derivation stays on SHA-256 whatever the handshake selected, because
// it is this file's own construction and not a protocol value.
//
// One narrowing against RFC 6979 §3.2 step h, stated rather than
// silent: the RFC advances the generator again when the computed r or s
// is zero, and this file returns 0 instead. Reaching either needs a
// 256-bit value to land on zero, which is below 2^-127, and the retry
// would cost a second scalar multiplication on every signature to
// stay constant time. Rejection of an out-of-range candidate, the retry
// that a caller can actually reach at about 2^-32, is implemented in
// full.
int p256_sign(const uint8_t priv[P256_PRIV_LEN], const uint8_t msg_hash[32], uint8_t *sig,
              size_t cap, size_t *sig_len);

#endif
