// The layout of one packaged object, for the header make writes beside it (docs/decisions.md 185).
// A caller declares ch_tls, ch_tcp, ch_quic and ch_dnssec_hash as storage of the size and
// alignment of the structs the library writes into them (session_storage.h). Those structs sit in
// src/, which a caller does not include, so make compiles this file under the object's own
// compiler, flags and defines and writes each number into the object's chapulin.h. CH_TX_STAGE is
// the length of the ClientHello staging array, which the build record compares (build.h).
//
// make compiles it to assembly alone: nothing here runs, so a cross compiler measures its own
// target. Each LAYOUT line puts its value into the assembly as the immediate operand of an
// .ascii directive, "->NAME value", and make reads those lines back. The Linux kernel's
// asm-offsets.c measures its struct offsets the same way. The operand prints with the target's
// immediate prefix, such as # or $, which make drops.
#include "session.h"
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
#include "tcp_nonblocking_session.h"
#endif
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#include "quic_session.h"
#endif
#ifdef CH_DNSSEC
#include "dnssec_hash.h"
#endif

#define LAYOUT(name, value) __asm__ volatile("\n.ascii \"->" #name " %0\"" : : "i"(value))

void layout_probe(void);

void layout_probe(void) {
    LAYOUT(CH_TLS_SIZE, sizeof(ch_tls_priv));
    LAYOUT(CH_TLS_ALIGN, _Alignof(ch_tls_priv));
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
    LAYOUT(CH_TCP_SIZE, sizeof(ch_tcp_priv));
    LAYOUT(CH_TCP_ALIGN, _Alignof(ch_tcp_priv));
#endif
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    LAYOUT(CH_QUIC_SIZE, sizeof(ch_quic_priv));
    LAYOUT(CH_QUIC_ALIGN, _Alignof(ch_quic_priv));
#endif
#ifdef CH_DNSSEC
    LAYOUT(CH_DNSSEC_HASH_SIZE, sizeof(ch_dnssec_hash_priv));
    LAYOUT(CH_DNSSEC_HASH_ALIGN, _Alignof(ch_dnssec_hash_priv));
#endif
    LAYOUT(CH_TX_STAGE, CH_TX_STAGE);
}
