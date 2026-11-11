// The storage a caller declares for each session (docs/decisions.md 185): a ch_tls, and a ch_tcp
// or a ch_quic in the transport that has one. The bytes are the library's: a caller reads a
// session through the calls its header declares, session_report.h's and alert.h's, and through no
// byte of these structs. The struct the library writes into each is ch_tls_priv in session.h,
// ch_tcp_priv in tcp_nonblocking_session.h and ch_quic_priv in quic_session.h.
//
// Each _SIZE and _ALIGN is the object's size and alignment of that struct. A program that compiles
// with -Isrc and defines none of them gets them from those headers.
//
// A header comment that writes t->, r->, q-> or q->t. names a field of ch_tls_priv, ch_tcp_priv
// or ch_quic_priv, which the library reads and writes. No caller reads such a field.
#ifndef CH_SESSION_STORAGE_H
#define CH_SESSION_STORAGE_H

// C11 spells alignment _Alignas and _Alignof, and C++11 alignas and alignof. chapulin.hpp
// compiles these headers as C++.
#ifdef __cplusplus
#define CH_ALIGNAS(n) alignas(n)
#define CH_ALIGNOF(type) alignof(type)
#else
#define CH_ALIGNAS(n) _Alignas(n)
#define CH_ALIGNOF(type) _Alignof(type)
#endif

#ifndef CH_TLS_SIZE
#include "session.h"
#define CH_TLS_SIZE sizeof(ch_tls_priv)
#define CH_TLS_ALIGN CH_ALIGNOF(ch_tls_priv)
#endif

typedef struct ch_tls {
    CH_ALIGNAS(CH_TLS_ALIGN) unsigned char opaque[CH_TLS_SIZE];
} ch_tls;

#ifdef CH_TRANSPORT_TCP_NONBLOCKING
#ifndef CH_TCP_SIZE
#include "tcp_nonblocking_session.h"
#define CH_TCP_SIZE sizeof(ch_tcp_priv)
#define CH_TCP_ALIGN CH_ALIGNOF(ch_tcp_priv)
#endif

typedef struct ch_tcp {
    CH_ALIGNAS(CH_TCP_ALIGN) unsigned char opaque[CH_TCP_SIZE];
} ch_tcp;
#endif

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#ifndef CH_QUIC_SIZE
#include "quic_session.h"
#define CH_QUIC_SIZE sizeof(ch_quic_priv)
#define CH_QUIC_ALIGN CH_ALIGNOF(ch_quic_priv)
#endif

typedef struct ch_quic {
    CH_ALIGNAS(CH_QUIC_ALIGN) unsigned char opaque[CH_QUIC_SIZE];
} ch_quic;
#endif

#endif
