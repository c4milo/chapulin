// Server authentication: which provisioned identity signs, what the
// CertificateVerify signature covers, and the boot-time check that the
// provisioned keys work. It is the mirror of handshake_auth.[ch], which
// judges a peer's certificate; this file proves this endpoint's own
// identity and judges nothing. Only a ROLE=server build compiles it.
// docs/server.md states the role.
//
// A server object links no certificate reader at all: no x509*.c, no
// pem.c, no webpki*.c and no rsa_pkcs1.c. It writes the chain the
// caller provisioned out unread, so nothing here parses X.509 and
// nothing here reaches a verdict about a certificate. That is what
// keeps INV-5's "exactly one certificate verifier" true in a tree that
// now has two roles.
//
// What it does not check, stated rather than omitted. It requests no
// client certificate, which RFC 9846 §4.4.2 makes a MAY
// (rfc9846.txt:2675-2676), so it reaches no verdict about the peer and
// the application above the session authenticates its users. It reads
// no byte of its own chain, so it cannot tell that the chain's
// end-entity key is the key it signs with; a provisioning script does
// that off the device. And it does not meet RFC 9846 §4.5.1.2's sending
// rule that all certificates provided MUST be signed by an algorithm
// the peer advertised (rfc9846.txt:2948-2950): it selects an identity
// on the CertificateVerify scheme alone and reads neither chain's
// signatures. It takes the permission §4.5.1.2 gives a sender that
// cannot produce a conforming chain (rfc9846.txt:2954-2960), and the
// cost is a client that conformantly rejects the chain it receives.
// docs/server.md's open question twelve asks whether that stays the
// answer.
#ifndef CH_SRV_AUTH_H
#define CH_SRV_AUTH_H
#ifdef CH_ROLE_SERVER

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "rsa.h"
#include "sha256.h"
#include "srv_cookie.h"
#include "srv_message.h"

// The identity slots of ch_cfg, one bit each, as srv_identity_live
// reports them. Each bit names the one SignatureScheme that slot signs:
// ecdsa_p256 signs SIGALG_ECDSA_P256_SHA256 and rsa_pss signs
// SIGALG_RSA_PSS_RSAE_SHA256 (handshake_message.h). Both are RFC 9846
// §9.1 CertificateVerify obligations (rfc9846.txt:4545-4547), and a
// deployment that provisions one of them makes this server decline the
// other, which costs a client that offers only the missing scheme a
// handshake_failure.
#define SRV_IDENTITY_ECDSA_P256 0x01
#define SRV_IDENTITY_RSA_PSS 0x02

// The largest CertificateVerify signature this build writes, in bytes.
// An RSA-PSS signature is exactly as long as the modulus, so
// CH_RSA_MODULUS_MAX (rsa.h) bounds it at 384 in a device build; a DER
// ECDSA-Sig-Value over P-256 is at most 72. The staging buffer takes
// the larger whichever identity signs, because sizing it per identity
// would make one build's frame depend on a run-time choice.
#define SRV_SIG_MAX CH_RSA_MODULUS_MAX

// Which identity slots the caller provisioned, as the SRV_IDENTITY_
// bits above. A slot counts as provisioned when its chain holds at
// least one entry and its private and public key pointers are both
// set; a slot the caller zeroed contributes no bit and the server
// never selects the scheme it signs.
//
// It is a predicate over configuration and changes nothing. Returns 0
// for a ch_cfg with no identity at all, which is the configuration
// ch_srv_check refuses.
uint8_t srv_identity_live(const ch_cfg *cfg);

// The identity that signs one SignatureScheme.
//
// Requires a cfg the caller owns and a sigalg code point.
//
// Returns &cfg->srv.ecdsa_p256 for SIGALG_ECDSA_P256_SHA256 and
// &cfg->srv.rsa_pss for SIGALG_RSA_PSS_RSAE_SHA256, when that slot is
// provisioned. Returns NULL for an unprovisioned slot and for every
// other scheme, including the RSASSA-PKCS1-v1_5 code points, which RFC
// 9846 §4.3.3 says are not defined for use in signed TLS handshake
// messages (rfc9846.txt:1882-1884).
const ch_identity *srv_identity_for(const ch_cfg *cfg, uint16_t sigalg);

// Builds the CertificateVerify signed content of RFC 9846 §4.5.2 and
// hashes it, which is the message the identity's signer signs.
//
// The content is 64 bytes of 0x20, the context string "TLS 1.3, server
// CertificateVerify", one 0x00 separator byte, and then hash_len bytes
// of transcript hash. This call hashes that content with SHA-256 and
// writes the digest, because both schemes this server offers name
// SHA-256 as the hash over the signed content (rfc9846.txt:1888-1891
// for ecdsa_secp256r1_sha256, rfc9846.txt:1894-1898 for
// rsa_pss_rsae_sha256).
//
// Two hashes meet here and they are not the same hash, which is why
// hash_len is a parameter rather than a constant. The cipher suite
// fixes the transcript hash going in (rfc9846.txt:4055-4056), and the
// SignatureScheme fixes the hash run over the assembled content. Under
// this build's one suite both are SHA-256 and hash_len is always
// SHA256_LEN; under TLS_AES_256_GCM_SHA384 the transcript hash would
// be 48 bytes and the output would still be 32. A builder that read
// one length for both would produce a CertificateVerify no client can
// verify.
//
// The client builds the same content twice already, for the other
// direction's context string: hash_signed_content at
// handshake_auth.c:42 under TRUST=webpki, and inline at
// handshake_auth.c:132-143 otherwise. docs/server.md requires that
// construction to move to a file both roles compile, so one rule the
// RFC states once exists once. The move is owed and is not this
// header's to make; until it lands this is a third copy of the
// assembly with a different context string.
//
// Requires transcript_hash pointing at hash_len readable bytes, the
// transcript hash as it stands after the Certificate message;
// hash_len from SHA256_LEN to SRV_COOKIE_HASH_MAX; sigalg naming a
// scheme srv_identity_for accepts; out pointing at SHA256_LEN writable
// bytes that overlap no input.
//
// Writes SHA256_LEN bytes and cannot fail, so it returns nothing. It
// stages the content in its own frame and wipes that staging with
// ct_wipe before it returns, because the transcript hash inside it is
// derived from secrets.
void srv_hash_signed_content(uint16_t sigalg, const uint8_t *transcript_hash, size_t hash_len,
                             uint8_t out[SHA256_LEN]);

// Signs the CertificateVerify content for one connection: it builds
// the digest with srv_hash_signed_content and hands it to the signer
// the selected scheme names.
//
// The two signers are p256_sign.c for SIGALG_ECDSA_P256_SHA256 and
// rsa_sign.c for SIGALG_RSA_PSS_RSAE_SHA256, and srv_cfg.h states the
// type each one reads through ch_identity.priv. This call tests
// priv_len against the size of that type and passes the pointer on, so
// it reads no byte of a private key itself. An RSA-PSS signature draws
// its 32-byte salt from ch_rand_bytes, so a server signing with the RSA
// identity needs entropy per handshake; the ECDSA nonce is derived and
// draws none.
//
// Two obligations belong to the signer and are stated here because the
// caller cannot check them. Every routine that touches the private
// scalar or the nonce is constant time in both: no branch and no
// memory index depends on either, and neither signer may call into
// p256.c or rsa.c, whose arithmetic is deliberately variable time
// because every input it reads is public (p256.h, rsa.h). And the
// ECDSA nonce is derived from the key and the message with RFC 6979
// rather than drawn from ch_rand_bytes, so two signatures can never
// share a nonce; docs/server.md's open question seven settles whether
// the default hedges that derivation with fresh bytes.
//
// Requires a cfg whose selected identity srv_identity_for accepts;
// sigalg and hash_len from the selection; transcript_hash pointing at
// hash_len readable bytes; cap bytes writable at sig, for which
// SRV_SIG_MAX always suffices; sig_len pointing at a writable size_t.
//
// Returns CH_OK, writes the signature at sig and its length at
// *sig_len.
//
// Returns CH_EINVAL and writes neither output when the identity is not
// provisioned or its key lengths are not the ones srv_cfg.h states, and
// CH_ECAP and writes neither when cap is below the signature the
// identity produces. That length is exact for the RSA identity, whose
// signature is as long as the modulus in ch_identity.pub_len, and is
// the 72-byte longest DER ECDSA-Sig-Value for the ECDSA one, whose
// three possible lengths the signature values choose between.
//
// Returns CH_EINVAL and writes a zero *sig_len when the signer itself
// refused, after wiping cap bytes at sig, because a refusing signer may
// have written part of a signature first.
//
// It writes ALERT_INTERNAL_ERROR into *alert on all three, because a
// server that cannot sign with a key it selected has a local fault and
// not a peer one, and RFC 9846 §6.2 describes internal_error as an
// error unrelated to the correctness of the protocol
// (rfc9846.txt:3979-3981). It never returns CH_OK with a zero-length
// signature.
int srv_sign_certificate_verify(const ch_cfg *cfg, uint16_t sigalg, const uint8_t *transcript_hash,
                                size_t hash_len, uint8_t *sig, size_t cap, size_t *sig_len,
                                uint8_t *alert);

// Checks one provisioned identity at boot: signs a fixed message with
// the private key and verifies the result under the public key in the
// same slot. It is the boot-time replacement for parsing the chain.
//
// The verifier is the one already in the object: p256_ecdsa_verify
// (p256.h) for the ECDSA identity and rsa_pss_verify (rsa.h) for the
// RSA one. A ROLE=server object carries both, which is why the ROLE
// arm leaves PIN_FILTER empty, because TRUST selects nothing in it.
//
// It catches a broken signer and a key the operator paired with the
// wrong slot, once, at boot, with a local error code instead of a
// client-side alert on every connection. It catches neither a chain
// whose end-entity key is not this public key nor a fallback chain
// signed with the SHA-1 RFC 9846 §4.5.1.2 forbids (rfc9846.txt:2958-2960),
// because it reads no chain bytes.
//
// The fixed message is the CertificateVerify content of a transcript
// hash of SHA256_LEN zero bytes, so the check signs the content a
// handshake signs and a pass here is evidence about the handshake.
//
// Requires a cfg the caller owns and a sigalg srv_identity_for
// accepts. Runs no I/O and touches no session. It draws entropy for the
// RSA identity, because rsa_pss_sign salts every signature, so a device
// seeds its generator before it calls this.
//
// Returns CH_OK when the signature verified. Returns CH_EINVAL when
// the slot is not provisioned, when its key lengths are not the ones
// srv_cfg.h states, when the signer refused, or when the verifier
// rejected what the signer produced.
int srv_identity_check(const ch_cfg *cfg, uint16_t sigalg);

#endif // CH_ROLE_SERVER
#endif
