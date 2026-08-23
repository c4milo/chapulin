// The handshake driver's state and its record pump. The state lives
// on ch_handshake's stack and is wiped wholesale when the handshake
// ends either way; the pump yields records and whole messages out of
// cfg.buf, where pointers die at the next pump call.
#ifndef CH_HSPUMP_H
#define CH_HSPUMP_H

#include <stddef.h>
#include <stdint.h>

#include "hsparse.h"
#include "session.h"
#include "sha256.h"
#include "x25519.h"
#ifdef CH_TRUST_CA
#include "x509.h"
#endif

// Everything the handshake needs beyond the session, on one stack frame;
// wiped wholesale when the handshake ends either way.
typedef struct {
    ch_tls *t;
    uint8_t priv[X25519_LEN];
    uint8_t pub[X25519_LEN];
    uint8_t random[32];
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    uint8_t handshake_secret[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN];
    uint8_t master[SHA256_LEN];
    uint8_t cookie[HSP_COOKIE_MAX];
    size_t cookie_len;
    uint16_t record_size_limit;
    int encrypted;
    uint8_t ccs_seen; // compat-mode CCS records tolerated so far
    uint8_t quiet;    // records that added no handshake bytes
    uint8_t alert;    // what to tell the peer if we abort
    // Set by expect_finished once the server Finished MAC compared
    // equal. epoch_commit asserts on it, so a commit moved earlier
    // faults instead of raising state the peer never authenticated.
    uint8_t server_finished_ok;
#ifdef CH_TRUST_CA
    x509_leaf_info leaf; // the chain's verified leaf key, for CertificateVerify
#endif
} handshake_state;

// Reads records until one carrying handshake bytes lands; appends its
// plaintext to the unconsumed bytes in cfg.buf.
int hsr_fetch_record(handshake_state *h);
// Yields the next complete handshake message, raw (header included)
// for the transcript. Pointers die at the next call.
int hsr_next_msg(handshake_state *h, uint8_t *type, const uint8_t **raw, size_t *raw_len);

#endif
