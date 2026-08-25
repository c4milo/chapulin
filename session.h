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

// TX staging past the record header. One array serves two lifetimes
// that never overlap: ClientHello construction, then sealed-record
// staging. A build whose hello outgrows one sealed record (a PQ key
// share) raises this for that build alone. See docs/decisions.md 22.
//
// This constant sets sizeof(ch_tls). The library object and every
// build that includes this header must agree on it.
#ifndef CH_TX_STAGE
#ifdef CH_KEX_PQ
// The hybrid ClientHello outgrows the sealed-record staging: 163
// bytes of PSK-mode fixed part, the 1216-byte share in place of 32
// (+1184), the largest ticket identity (CH_TICKET_ID_MAX, 320), and
// the largest retry cookie with its framing (6 + 128). 1801 bytes;
// larger than CH_TX_PT + 1 + AEAD_TAG, so it sets the array here.
#define CH_TX_STAGE 1801
#else
#define CH_TX_STAGE (CH_TX_PT + 1 + AEAD_TAG)
#endif
#endif
// The library builds as C, so the guards always run. The ceiling is
// RFC 9846's 2^14 record-body cap; the hello ships as one record.
#ifndef __cplusplus
_Static_assert(CH_TX_STAGE >= CH_TX_PT + 1 + AEAD_TAG,
               "TX staging must hold at least one sealed record");
_Static_assert(CH_TX_STAGE <= 0x4000, "a handshake record body caps at 2^14");
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
    // Highest epoch accepted: loaded at ch_connect, raised once a verified
    // leaf authenticates the server. epoch_store_failed marks a failed
    // persist; the session stays up. Both stay zero outside CA builds.
    uint32_t epoch;
    uint8_t epoch_store_failed;
    // What the peer presented and how the rule judged it (CH_EPOCH_* in
    // cfg.h). epoch_seen stays zero when the certificate carried no
    // allowed date; epoch_status is then CH_EPOCH_UNTRUSTED.
    uint32_t epoch_seen;
    uint8_t epoch_status;
    uint64_t send_epochs; // KeyUpdates we have sent; capped per §4.7.3
    // Unread plaintext of the current record, inside cfg.buf.
    size_t pt_off;
    size_t pt_len;
    uint8_t tx[REC_HDR + CH_TX_STAGE];
} ch_tls;

// Sends an alert — encrypted iff keys are live, plaintext only before any
// keys exist, nothing at all once they are wiped.
int tlsi_send_alert(ch_tls *t, uint8_t level, uint8_t description);

// Alert (best effort), wipe all key material, mark the session failed.
void tlsi_fail(ch_tls *t, uint8_t description);

// Wipe all key material and buffered plaintext; keys go dead.
void tlsi_wipe(ch_tls *t);

#endif
