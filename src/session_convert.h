// The conversions between a caller's ch_tls storage (session_storage.h) and the ch_tls_priv in it
// (session.h). Each public call converts its pointer once, through tls_priv or tls_priv_const, and
// every other function takes ch_tls_priv. The library compiles with -fno-strict-aliasing, so no
// optimizer reads the caller's storage and this struct as two objects (docs/decisions.md 185).
#ifndef CH_SESSION_CONVERT_H
#define CH_SESSION_CONVERT_H

#include "session.h"

typedef struct ch_tls ch_tls;

// The struct in a caller's storage, and the storage of a struct this library holds.
static inline ch_tls_priv *tls_priv(ch_tls *t) {
    return (ch_tls_priv *)(void *)t;
}
static inline const ch_tls_priv *tls_priv_const(const ch_tls *t) {
    return (const ch_tls_priv *)(const void *)t;
}
static inline ch_tls *tls_public(ch_tls_priv *t) {
    return (ch_tls *)(void *)t;
}
static inline const ch_tls *tls_public_const(const ch_tls_priv *t) {
    return (const ch_tls *)(const void *)t;
}

#endif
