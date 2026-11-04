// A server's ML-DSA-87 identity, the CertificateVerify that identity
// signs, and the boot-time check of the key pair. Every object that signs
// ML-DSA-87 compiles it (CH_SIGN_MLDSA): each host server, beside its
// ECDSA P-256 and RSA-PSS identities (docs/decisions.md 180), and the
// PROFILE=cnsa2 server, where it is the one identity (docs/decisions.md
// 162). Under the profile srv_mldsa.c also defines srv_auth.h's calls, in
// place of srv_auth.c, which signs ECDSA P-256 and RSA-PSS and compiles
// to nothing there. CNSA 2.0 admits no ECDSA or RSA key, so the profile
// holds neither. In every other host server srv_auth.c calls the four
// calls below for the mldsa87 slot.
//
// The signature. The scheme is mldsa87 (0x0906, draft-ietf-tls-mldsa):
// pure ML-DSA-87 over the whole signed content of RFC 9846 §4.5.2, with
// an empty context. The content is 64 bytes of 0x20, the context string
// with its NUL separator, and the transcript hash of the selected suite:
// 146 bytes under SHA-384 and 130 under SHA-256. Nothing hashes it first.
// The client builds the same bytes in hsa_signed_content
// (handshake_auth.h) and checks them with mldsa87_verify.
//
// The hedge. Each signature takes 32 bytes of rnd that this file draws
// through rand_draw from the source the configuration names (INV-4), as
// srv_auth.c draws the ECDSA signer's noise. mldsa87_sign refuses rnd of 32
// zero bytes with CH_ASSERT. So a server needs entropy for each handshake
// that signs.
//
// The check before a signature leaves. mldsa87_sign verifies each
// signature under the identity's public key before it returns it
// (mldsa_signer.h), and gives no signature when the check fails.
//
// The frame. A signature is MLDSA87_SIG_LEN bytes, 4,627, which is past the
// 4 kB that every other server frame keeps. So the CertificateVerify
// stages the signature here, in a file of its own with a measured ceiling
// of its own (Makefile STACK_BUDGET_SRV_MLDSA), and streams the message
// through srv_frag rather than staging it whole.
#ifndef CH_SRV_MLDSA_H
#define CH_SRV_MLDSA_H
#if defined(CH_ROLE_SERVER) && defined(CH_SIGN_MLDSA)

#include "handshake_record.h"
#include "srv_auth.h"
#include "srv_message.h"

// Whether the caller provisioned the mldsa87 slot: a chain of at least one
// entry and both key pointers set. It reads no byte of either key or the
// chain. It is a predicate over configuration and changes nothing.
int srv_mldsa_live(const ch_cfg *cfg);

// Whether the flight can use the mldsa87 slot: 1 when the slot is not
// provisioned, or when its key lengths are 4,896 and 2,592 and a
// Certificate message can carry its chain (srv_certificate_fits). The
// key's coefficients are mldsa87_sign's to judge, which srv_mldsa_check
// asks at boot. It is a predicate over configuration and changes nothing.
int srv_mldsa_usable(const ch_cfg *cfg);

// Signs this connection's CertificateVerify with the mldsa87 identity and
// sends it, hashed into the transcript, through srv_frag (srv_out.h).
//
// Requires sel->sigalg to be SIGALG_MLDSA87, which srv_select_sigalg
// names only for a provisioned slot, and the Certificate to have gone out,
// so sel->hash_len names the selected hash.
//
// Returns CH_OK. Returns CH_EAUTH with ALERT_INTERNAL_ERROR when sigalg is
// another scheme, when the slot is not provisioned, when its key lengths
// are not 4,896 and 2,592, when hash_len is neither SHA256_LEN nor
// SHA384_LEN, or when mldsa87_sign refused: a key whose s1 or s2 is out of
// range, or a signature that its own check refused. The configuration
// check refuses the slot's faults before a session starts, and
// ch_srv_check signs once at boot, so the flight meets them only for a
// key the caller changed or a fault. Returns what srv_frag returns when a
// record does not go out.
int srv_mldsa_send_certificate_verify(handshake_state *h, const selection *sel);

// Checks the mldsa87 identity at boot: signs the content of a SHA-384
// transcript hash of zero bytes, then verifies the signature under the
// slot's public key, as srv_identity_check does for the other slots.
// Draws rnd from the source cfg names, so the caller's source must work
// first. Returns CH_OK when the signature verified, and CH_EINVAL when the
// slot is not provisioned, when its key lengths are not 4,896 and 2,592,
// when the signer refused, or when the verifier rejected its signature.
int srv_mldsa_check(const ch_cfg *cfg);

#endif // CH_ROLE_SERVER && CH_SIGN_MLDSA
#endif
