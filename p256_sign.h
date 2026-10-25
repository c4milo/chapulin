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

// The fresh bytes p256_sign_hedged puts into the nonce, the random data
// Z of draft-irtf-cfrg-det-sigs-with-noise-05 section 4, which asks for
// the length of int2octets(x): 32 bytes on this curve.
#define P256_NOISE_LEN 32

// What the constant-time claim covers, and what it does not.
//
// Covered. Every value derived from the private scalar or from the nonce
// moves through p256_scalar.c and p256_point.c, or, in a host session
// whose caller stated its multiply, through the wide files that stand in
// for them (widemul.h, docs/decisions.md 94). Neither set of routines has
// an operand-dependent branch or an operand-dependent memory index. In
// p256_point.c the scalar multiplication runs a literal 256 rounds with
// the same two point additions in each, and reads no precomputed multiple
// of the generator. In the wide files it adds one entry of a table of
// multiples of the generator for each of 64 windows of the nonce, and
// reads that entry by scanning every entry of the window's row and
// keeping one by mask, so the addresses a cache attacker can watch are the
// same for every nonce. Either way neither the value of the nonce nor its
// bit length changes how long a signature takes. The nonce generator runs
// a literal number of candidates and picks one with mask arithmetic, so a
// rejected candidate costs the same as an accepted one. Every product of
// the two files goes through ct.h's ct_widemul, so a core whose widening
// multiply is variable time does not see one, and the wide files multiply
// only for a session whose caller stated that multiply's timing.
//
// Not covered, first: the outputs. r and s are public -- they go on the
// wire -- so the DER writer's leading-zero handling reads their values
// and their lengths, and the two checks that reject a zero r or s are
// ordinary branches. Nothing there reads the key or the nonce.
//
// Not covered, second: whether the configured key is in range. A key at
// or above the group order, or zero, makes p256_sign_key_ok answer 0 and
// p256_sign return 0, and the branch on that answer reads the key. It
// reveals that the server's provisioned key is unusable, which the
// refused configuration or the failed handshake reveals anyway, and it
// does not vary from one signature to the next.
//
// Fault injection (docs/decisions.md 153). A deterministic nonce signs
// one message the same way every time, which is the shape a differential
// fault attack wants: one correct signature and one faulted signature
// over the same message recover the key. p256_sign_hedged puts
// P256_NOISE_LEN fresh bytes into the nonce, so two signatures over one
// message use two nonces. A weak source of the noise costs nothing that
// RFC 6979 does not already give.
//
// Every entry runs two checks before it writes a byte of a signature,
// both constant time. The affine k*G must satisfy y^2 = x^3 - 3x + b
// before r is taken from it, and s*k must equal z + r*d mod n. A fault
// that moves k*G off the curve, or that changes s, the inverse of k or
// the product r*d, fails one of them, and the call writes nothing.
//
// What the checks miss. A fault that moves k*G to another point of the
// curve gives a consistent r and s for a nonce nobody chose. A fault in
// the key d, or in k after k*G, gives an s that the scalar check computes
// from the same wrong value. A fault that skips a check passes. A full
// verification under the public key would catch the first two, at about
// three times the cost of the signature on a host object, and decision
// 153 states why this file does not run one.

// Whether priv is a private scalar p256_sign signs with: a value from 1
// to n-1, read as 32 big-endian bytes. p256_sign runs this test first,
// and a server runs it when it checks its configuration (srv_auth.h), so
// a key out of range is refused before a session starts rather than
// inside the handshake. The verdict comes from p256_scalar.c's
// constant-time masks, and it reveals what "Not covered, second" above
// states and nothing more. Returns 1 or 0.
int p256_sign_key_ok(const uint8_t priv[P256_PRIV_LEN]);

// Signs msg_hash, the 32-byte SHA-256 of the content RFC 9846 §4.5.2
// defines, and writes the DER ECDSA-Sig-Value to sig. cap is the room
// sig has, and sig_len takes the number of bytes written. Returns 1 on
// success and 0 when p256_sign_key_ok refuses the key, when cap is
// below the length the signature needs, or when the nonce generator
// produced no candidate below the group order in its fixed number of
// tries, or when a check failed (above). On every 0 sig and *sig_len
// keep what they held. The 1-or-0 return is p256_ecdsa_verify's, because
// a caller that holds both should read one convention; the caller turns
// a 0 into the alert it sends.
//
// The nonce is RFC 6979 deterministic, derived from the private scalar
// and msg_hash by HMAC-SHA-256 (hkdf.h:13). No entropy is drawn here, and
// two signatures over one message under one key are byte-identical, so
// the RFC 6979 vectors and the differential check this call. No library
// call signs through it: a server signs through p256_sign_hedged. The
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
//
// widemul is the answer the scalar and point multiplies run under, a
// WIDEMUL_ value, which this call hands to widemul.h's dispatchers.
int p256_sign(uint8_t widemul, const uint8_t priv[P256_PRIV_LEN], const uint8_t msg_hash[32],
              uint8_t *sig, size_t cap, size_t *sig_len);

#ifdef CH_CPU_RUNTIME
// p256_sign for one session of a host object, with the session's
// ch_cfg.cpu first (cpu_cfg.h). It runs the scalar and point multiplies
// under widemul_of_cpu(cpu) (widemul.h), and each SHA-256 of the nonce
// generator's HMACs through sha256.h's entries: on the CPU's SHA-256
// instructions when cpu holds CH_CPU_CONSTANT_TIME_SHA256, the caller's
// statement that they run in constant time on this CPU, and on the
// portable code when it does not. Both paths compute the same HMAC, so
// the signature is the one p256_sign writes under the same answer. The
// RFC 6979 vectors hold both paths through this call; a server signs
// through p256_sign_hedged_cpu (docs/decisions.md 93, 102, 147 and 153).
int p256_sign_cpu(uint32_t cpu, const uint8_t priv[P256_PRIV_LEN], const uint8_t msg_hash[32],
                  uint8_t *sig, size_t cap, size_t *sig_len);
#endif

// p256_sign with the nonce hedged, the entry a server signs through
// (srv_auth.c, docs/decisions.md 153).
//
// The nonce. Steps d and f of RFC 6979 §3.2 take the hedged input of
// draft-irtf-cfrg-det-sigs-with-noise-05 section 4: V, the separator,
// noise, zero bytes to the end of the second SHA-256 block, priv, zero
// bytes to the end of the third block, and the reduced message hash. All
// other steps are RFC 6979's, so the same priv, msg_hash and noise give
// the same signature. noise is P256_NOISE_LEN bytes that the caller drew
// for this signature alone, through rand_draw (INV-4), and keeps secret.
// An all-zero noise is the mark of a source that wrote nothing, and
// CH_ASSERT fires on it, as rsa_pss_sign does on its salt.
//
// Returns what p256_sign returns, after the same two checks. widemul is
// the answer the multiplies run under, as for p256_sign, and the nonce's
// HMACs run on the portable code.
int p256_sign_hedged(uint8_t widemul, const uint8_t priv[P256_PRIV_LEN], const uint8_t msg_hash[32],
                     const uint8_t noise[P256_NOISE_LEN], uint8_t *sig, size_t cap,
                     size_t *sig_len);

#ifdef CH_CPU_RUNTIME
// p256_sign_hedged for one session of a host object, with the session's
// ch_cfg.cpu first, as p256_sign_cpu is p256_sign's. Both checks run on
// the field and the scalar arithmetic cpu picks, wide under the multiply
// bit and 32-bit without it.
int p256_sign_hedged_cpu(uint32_t cpu, const uint8_t priv[P256_PRIV_LEN],
                         const uint8_t msg_hash[32], const uint8_t noise[P256_NOISE_LEN],
                         uint8_t *sig, size_t cap, size_t *sig_len);
#endif

#ifdef CH_P256_SIGN_FAULT_TEST
#include "p256_point.h"
#include "p256_scalar.h"
// The two hooks a build with CH_P256_SIGN_FAULT_TEST calls, which
// test/p256_sign_fault_test.c defines: on k*G before its affine form, and
// on s before the scalar check. No library object takes the define.
void p256_sign_fault_point(p256_point *point);
void p256_sign_fault_scalar(p256_scalar *s);
#endif

#endif
