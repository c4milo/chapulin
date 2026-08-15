// The session: one static struct holding record protection for both
// directions, the transcript, and the TX staging area — plus the
// teardown and alert primitives every layer above record shares. Sits
// between record and handshake in the include graph.
#ifndef MS_SESSION_H
#define MS_SESSION_H

#include "cfg.h"
#include "record.h"
#include "sha256.h"

#define MS_ST_START 0
#define MS_ST_CONNECTED 1
#define MS_ST_CLOSED 2
#define MS_ST_FAILED 3

typedef struct {
    ms_cfg cfg;
    rec_dir rd;                    // server -> client protection
    rec_dir wr;                    // client -> server protection
    uint8_t rd_secret[SHA256_LEN]; // current traffic secrets, for KeyUpdate
    uint8_t wr_secret[SHA256_LEN];
    uint8_t res_master[SHA256_LEN];
    sha256 transcript;
    uint16_t peer_limit; // max plaintext per record the peer accepts
    uint8_t state;
    uint8_t keys; // record protection live; alerts encrypt iff set
    // Unread plaintext of the current record, inside cfg.buf.
    size_t pt_off;
    size_t pt_len;
    uint8_t tx[REC_HDR + MS_TX_PT + 1 + AEAD_TAG];
} ms_tls;

// Sends an alert — encrypted iff keys are live, plaintext only before any
// keys exist, nothing at all once they are wiped.
int tlsi_send_alert(ms_tls *t, uint8_t level, uint8_t desc);

// Alert (best effort), wipe all key material, mark the session failed.
void tlsi_fail(ms_tls *t, uint8_t desc);

// Wipe all key material and buffered plaintext; keys go dead.
void tlsi_wipe(ms_tls *t);

#endif
