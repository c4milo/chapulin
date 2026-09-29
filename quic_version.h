// The QUIC versions whose packet protection keys this build derives, and the HKDF labels each
// version derives them under. RFC 9001 defines version 1. RFC 9369's version 2 changes the
// Initial salt, the four labels below and the Retry integrity key and nonce, and no other input
// of the keys chapulin holds (rfc9369.txt:156-188). aes.c holds each version's salt and Retry
// key and quic_retry.c its Retry nonce, which keeps INV-26's key holders where they are; this
// header holds the rule that says which versions a build derives, and the labels, which aes.c
// and quic_keys.c both read. Only a TRANSPORT=quic-nonblocking build compiles it.
#ifndef CH_QUIC_VERSION_H
#define CH_QUIC_VERSION_H
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

#include <stdint.h>

#include "cfg.h"

// Whether this build derives the keys of version, a QUIC Version field value (quic_cfg.h).
// It is the one place that answers the question, and every call that takes a version from
// the caller asks it: ch_quic_init and ch_srv_quic_init refuse an original version it answers
// 0 for, ch_quic_switch_version refuses a switch to one, ch_srv_quic_retry_tag refuses a tag
// under one, and quic_initial.c and quic_retry.c refuse one before they choose a salt, a label
// or a key. This build derives version 1 alone, so it answers 1 for CH_QUIC_VERSION_1 and 0
// for every other value, CH_QUIC_VERSION_2 and 0 among them.
static inline int quic_version_derived(uint32_t version) {
    return version == CH_QUIC_VERSION_1;
}

// The four HKDF labels one QUIC version derives its packet protection keys under: RFC 9001
// §5.1's "quic key", "quic iv" and "quic hp" (rfc9001.txt:1029-1032), and §6.1's "quic ku",
// which derives the next 1-RTT secret (rfc9001.txt:1612-1613). RFC 9369 §3.3.2 gives version
// 2 four others (rfc9369.txt:167-174). hkdf_expand_label adds TLS 1.3's "tls13 " prefix to
// each, as RFC 9001 §5.1 asks, so none carries it here.
typedef struct {
    const char *key;
    const char *iv;
    const char *hp;
    const char *ku;
} quic_labels;

// The labels version derives its keys under. version is one quic_version_derived admits:
// every entry that takes a version from the caller refuses the rest before a key is derived,
// and the Handshake and 1-RTT keys are derived under ch_tls.quic_negotiated_version, which
// only such a version is written into. Version 1 is the one version this build admits, so
// every call answers version 1's labels.
static inline quic_labels quic_version_labels(uint32_t version) {
    (void)version;
    quic_labels version_1 = {"quic key", "quic iv", "quic hp", "quic ku"};
    return version_1;
}

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
#endif
