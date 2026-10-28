// A PROFILE=cnsa2 server's authentication: its one ML-DSA-87 identity, the
// CertificateVerify that identity signs, and the boot-time check of the key
// pair (docs/decisions.md 162). srv_mldsa.c defines srv_auth.h's calls for
// the profile, in place of srv_auth.c, which signs ECDSA P-256 and RSA-PSS
// and compiles to nothing under the profile. CNSA 2.0 admits no ECDSA or
// RSA key, so the profile holds neither.
//
// The signature. The scheme is mldsa87 (0x0906, draft-ietf-tls-mldsa):
// pure ML-DSA-87 over the whole signed content of RFC 9846 §4.5.2, with
// an empty context. The content is 64 bytes of 0x20, the context string
// with its NUL separator, and the SHA-384 transcript hash, 146 bytes, and
// nothing hashes it first. The client builds the same 146 bytes in
// hsa_signed_content (handshake_auth.h) and checks them with
// mldsa87_verify.
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
// 4 kB that every other library frame of the profile keeps. So the
// CertificateVerify stages the signature here, in a file of its own with a
// measured ceiling of its own (Makefile STACK_BUDGET_SRV_MLDSA), and
// streams the message through srv_frag rather than staging it whole.
#ifndef CH_SRV_MLDSA_H
#define CH_SRV_MLDSA_H
#if defined(CH_ROLE_SERVER) && defined(CH_PROFILE_CNSA2)

#include "handshake_record.h"
#include "srv_auth.h"
#include "srv_message.h"

// Signs this connection's CertificateVerify with the mldsa87 identity and
// sends it, hashed into the transcript, through srv_frag (srv_out.h).
//
// Requires sel->sigalg to be SIGALG_MLDSA87, which srv_select_sigalg
// names only for a provisioned slot, and the Certificate to have gone out,
// so ch_tls.hash_len names the selected hash.
//
// Returns CH_OK. Returns CH_EAUTH with ALERT_INTERNAL_ERROR when the slot is
// not provisioned, when its key lengths are not 4,896 and 2,592, or when
// mldsa87_sign refused: a key whose s1 or s2 is out of range, or a
// signature that its own check refused. The configuration check refuses the
// first two before a session starts, and ch_srv_check signs once at boot,
// so the flight meets them only for a key the caller changed or a fault.
// Returns what srv_frag returns when a record does not go out.
int srv_mldsa_send_certificate_verify(handshake_state *h, const selection *sel);

#endif // CH_ROLE_SERVER && CH_PROFILE_CNSA2
#endif
