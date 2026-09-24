// TLS 1.3 key schedule (RFC 9846 §7.1), specialized to one PSK. Pure
// functions over secrets of hash_len bytes; the handshake owns where they
// live and when they die.
//
// hash_len is the cipher suite's hash, SHA256_LEN or, in a build with
// CH_HASH_SHA384 (hkdf.h), SHA384_LEN, and every secret, transcript hash
// and MAC below is that many bytes: RFC 9846 §7.1 sizes each one at
// Hash.length (rfc9846.txt:4055-4056). The caller passes the same value to
// every call of one handshake.
#ifndef CH_KEYSCHED_H
#define CH_KEYSCHED_H

#include <stddef.h>
#include <stdint.h>

#include "hkdf.h"

// early_secret = Extract(0, psk); binder_key = Derive-Secret(early,
// "ext binder" | "res binder", ""). resumption selects the label.
void ks_early(size_t hash_len, const uint8_t *psk, size_t psk_len, int resumption, uint8_t *early,
              uint8_t *binder_key);

// binder/finished MAC: HMAC(Expand-Label(key, "finished"), transcript).
void ks_verify_data(size_t hash_len, const uint8_t *key, const uint8_t *transcript, uint8_t *out);

// handshake_secret = Extract(Derive-Secret(early, "derived", ""), ecdhe);
// c/s handshake traffic secrets from the CH..SH transcript.
void ks_handshake(size_t hash_len, const uint8_t *early, const uint8_t *ecdhe, size_t ecdhe_len,
                  const uint8_t *transcript, uint8_t *handshake_secret, uint8_t *c_hs,
                  uint8_t *s_hs);

// master = Extract(Derive-Secret(handshake_secret, "derived", ""), 0); c/s application
// traffic secrets from the CH..server-Finished transcript.
void ks_master(size_t hash_len, const uint8_t *handshake_secret, const uint8_t *transcript,
               uint8_t *master, uint8_t *c_ap, uint8_t *s_ap);

// resumption_master from the CH..client-Finished transcript; a ticket's
// PSK is Expand-Label(res_master, "resumption", ticket_nonce, Hash.length).
void ks_res_master(size_t hash_len, const uint8_t *master, const uint8_t *transcript,
                   uint8_t *res_master);
void ks_res_psk(size_t hash_len, const uint8_t *res_master, const uint8_t *nonce, size_t nonce_len,
                uint8_t *psk);

#ifdef CH_EXPORTER
// The exporter is a record-layer call: ch_export sits in tls.c, which a
// QUIC build does not compile, and quic.h declares no counterpart
// because RFC 9001 keys QUIC from the handshake secrets and uses no TLS
// exporter. The Makefile's EXPORTER axis refuses the pair by name; this
// is the same refusal for a tree that builds these sources its own way,
// and it sits here rather than in cfg.h because cfg.h is at the
// 500-line cap and this header is the one every build compiles that
// also declares the exporter's own calls.
#ifdef CH_TRANSPORT_QUIC
#error "CH_EXPORTER has no QUIC entry point: ch_export is a record-layer call"
#endif
// The axis is what raises hkdf's label cap, and this is where that is
// held: a build that defines CH_EXPORTER without the cap would compile
// ks_exporter against a 12-byte label buffer and refuse RFC 9266's
// 24-byte label at run time. tls.c asserts the public cap and hkdf's
// are one number; this asserts the floor the axis needs.
#if HKDF_LABEL_MAX < 24
#error "CH_EXPORTER needs HKDF_LABEL_MAX >= 24: RFC 9266's exporter label is 24 bytes"
#endif

// exporter_master from the CH..server-Finished transcript, which is the
// transcript ks_master already takes (RFC 9846 §7.5).
void ks_exp_master(size_t hash_len, const uint8_t *master, const uint8_t *transcript,
                   uint8_t *exp_master);

// TLS-Exporter(label, context, out_len) of RFC 9846 §7.5:
// Expand-Label(Derive-Secret(exp_master, label, ""), "exporter",
// Hash(context), out_len), where Hash is the suite's, hash_len bytes.
//
// The two steps are why one exporter_master serves every label: the
// first binds the label and the second the context, so a caller asking
// for two labels gets two unrelated keys from one stored secret.
//
// label is the caller's and is at most HKDF_LABEL_MAX bytes, which this
// axis raises for the reason hkdf.h states. An empty context hashes to
// the same value an empty transcript does; RFC 9846 §7.5 gives a caller
// no way to distinguish an empty context from none, so neither does this.
void ks_exporter(size_t hash_len, const uint8_t *exp_master, const char *label,
                 const uint8_t *context, size_t context_len, uint8_t *out, size_t out_len);
#endif

#endif
