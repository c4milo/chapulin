// The session: one static struct holding record protection for both
// directions, the transcript, and the TX staging area — plus the
// teardown and alert primitives every layer above record shares. Sits
// between record and handshake in the include graph.
#ifndef CH_SESSION_H
#define CH_SESSION_H

#include "cfg.h"
#include "record.h"
#include "sha256.h"

// Receive loops tolerate this many consecutive records that add no bytes
// before failing the session. A build-time constant so proof harnesses can
// verify the same loop bodies at a smaller bound.
#ifndef CH_QUIET_CAP
#define CH_QUIET_CAP 32
#endif

#define CH_ST_START 0
#define CH_ST_CONNECTED 1
#define CH_ST_CLOSED 2
#define CH_ST_FAILED 3

typedef struct {
    ch_cfg cfg;
    rec_dir rd;                    // server -> client protection
    rec_dir wr;                    // client -> server protection
    uint8_t rd_secret[SHA256_LEN]; // current traffic secrets, for KeyUpdate
    uint8_t wr_secret[SHA256_LEN];
    uint8_t res_master[SHA256_LEN];
    sha256 transcript;
    uint16_t peer_limit; // max plaintext per record the peer accepts
    uint8_t state;
    uint8_t keys; // record protection live; alerts encrypt iff set
    // Which pin authenticated the server: 1 = cfg.server_pubkey, 2 =
    // cfg.server_pubkey2, 0 before a pinned handshake completes. Public
    // information — operators read it to watch key rotation progress.
    uint8_t pin_slot;
    // Unread plaintext of the current record, inside cfg.buf.
    size_t pt_off;
    size_t pt_len;
    uint8_t tx[REC_HDR + CH_TX_PT + 1 + AEAD_TAG];
} ch_tls;

// Sends an alert — encrypted iff keys are live, plaintext only before any
// keys exist, nothing at all once they are wiped.
int tlsi_send_alert(ch_tls *t, uint8_t level, uint8_t desc);

// Alert (best effort), wipe all key material, mark the session failed.
void tlsi_fail(ch_tls *t, uint8_t desc);

// Wipe all key material and buffered plaintext; keys go dead.
void tlsi_wipe(ch_tls *t);

#endif
