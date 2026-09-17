// The handshake driver's state and the reader that turns arriving bytes
// into whole handshake messages. Under TRANSPORT=tls the state lives on
// ch_handshake's stack and is wiped wholesale when the handshake ends
// either way; it yields records and whole messages out of cfg.buf,
// where pointers die at the next record read.
//
// Under CH_TRANSPORT_QUIC there is no record layer to read: RFC 9001
// §4.1.3 takes the unprotected content of TLS handshake records as the
// content of CRYPTO frames and uses no TLS record protection
// (rfc9001.txt:462-464). The state then lives inside ch_quic, which
// outlives every call, and the reader takes the caller's CRYPTO bytes
// instead of driving a socket. Pointers still die at the next call that
// writes cfg.buf.
#ifndef CH_HANDSHAKE_RECORD_H
#define CH_HANDSHAKE_RECORD_H

#include <stddef.h>
#include <stdint.h>

#include "handshake_parser.h"
#include "session.h"
#include "sha256.h"
#include "x25519.h"
#ifdef CH_TRUST_CA
#include "x509.h"
#endif
#ifdef CH_TRUST_WEBPKI
#include "webpki.h"
#endif

// Everything the handshake needs beyond the session, wiped wholesale
// when the handshake ends either way. Under TRANSPORT=tls it sits on
// ch_handshake's one stack frame. Under CH_TRANSPORT_QUIC it sits
// inside ch_quic, because the driver returns to its caller between
// messages, and the wipe comes one round trip earlier, at the step that
// reaches HSQ_STEP_COMPLETE.
typedef struct {
    ch_tls *t;
    uint8_t priv[X25519_LEN];
    uint8_t pub[X25519_LEN];
#ifdef CH_KEX_PQ
    // ML-KEM (d, z) seed. The key pair re-expands from it on demand
    // (build and decapsulation), so the share the HRR retry resends is
    // identical by construction and no 2400-byte key lives in state.
    uint8_t dz[64];
#endif
    uint8_t random[32];
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    uint8_t handshake_secret[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN];
    uint8_t master[SHA256_LEN];
    uint8_t cookie[HSP_COOKIE_MAX];
    size_t cookie_len;
#ifndef CH_TRANSPORT_QUIC
    // The four fields the record layer owns. Only the TLS ClientHello
    // builder and the TLS record reader write or read them, and a QUIC
    // build has neither: RFC 9001 §4.1.3 removes the record layer
    // (rfc9001.txt:462-464), §8.4 forbids a client from requesting
    // compatibility mode, so no ChangeCipherSpec record arrives
    // (rfc9001.txt:1976-1979), and record_size_limit sizes a record
    // stream this build does not have.
    uint16_t record_size_limit;
    int encrypted;
    uint8_t ccs_seen; // compat-mode CCS records tolerated so far
    uint8_t quiet;    // records that added no handshake bytes
#endif
    uint8_t alert; // what to tell the peer if we abort
    // Set by hsf_read_finished once the server Finished MAC compared
    // equal. hsa_epoch_commit asserts on it, so a commit moved earlier
    // faults instead of raising state the peer never authenticated.
    uint8_t server_finished_ok;
#ifdef CH_TRUST_CA
    x509_leaf_info leaf; // the chain's verified leaf key, for CertificateVerify
#endif
#ifdef CH_TRUST_WEBPKI
    // The verified leaf's key and its family, which webpki_verify_chain
    // copies out and CertificateVerify's scheme must match.
    webpki_leaf_info leaf;
#endif
} handshake_state;

#ifndef CH_TRANSPORT_QUIC
// Reads records until one carrying handshake bytes lands; appends its
// plaintext to the unconsumed bytes in cfg.buf.
int hsr_fetch_record(handshake_state *h);
#endif

#ifdef CH_TRANSPORT_QUIC
// hsr_peek_message's answer when the bytes in cfg.buf stop short of a
// whole message. The value is positive, so it collides with no ch_err
// code: CH_OK is 0 and every error is negative, so a caller that tests
// for CH_OK and a caller that tests for a negative code both read this
// answer correctly. RFC 9001 §4.1.3 expects a TLS stack to give this
// answer, because TLS provides no bytes while the messages it has
// received are incomplete (rfc9001.txt:495-497).
#define HSR_INCOMPLETE 1

// Appends up to n bytes of one encryption level's CRYPTO stream to the
// unread bytes already in cfg.buf, and returns how many bytes it took.
// It compacts first, moving the unread bytes down to cfg.buf and
// setting pt_off to 0, the way the TLS reader compacts before it reads
// a record, then copies min(n, cfg.buf_len - pt_len) bytes and raises
// pt_len by that many. RFC 9001 §4.1.3 gives TLS this job: TLS buffers
// the handshake bytes that arrived in order, and QUIC buffers the rest
// (rfc9001.txt:501-504).
//
// Requires n bytes readable at p, and p outside cfg.buf. Requires the
// caller's contract on CRYPTO bytes, which cfg.h states: each level's
// bytes arrive once and in order, so these bytes continue the stream
// the last call left. This function stores no stream offset and cannot
// tell a retransmission from new data.
//
// Returns the count copied, which is 0 when cfg.buf already holds
// cfg.buf_len unread bytes, and less than n when the rest does not fit.
// A short count is not an error: the driver runs a step, which consumes
// a message, and calls again with the bytes that are left. The count is
// what makes the driver's loop terminate, because a full buffer holds
// at least one whole message or a header that hsr_peek_message refuses.
// It writes nothing outside cfg.buf, pt_off and pt_len, and it cannot
// fail.
size_t hsr_feed(handshake_state *h, const uint8_t *p, size_t n);

// Answers whether the unread bytes in cfg.buf hold a whole handshake
// message, and how long that message is. It reads the 4-byte handshake
// header at cfg.buf + pt_off and nothing else: it consumes no bytes,
// moves no offset and touches no session field, so the driver may call
// it before every step and after every hsr_feed.
//
// Requires h->t->cfg.buf to hold pt_len bytes with pt_off <= pt_len <=
// cfg.buf_len. alert points at the byte the driver reports on failure,
// which is h->alert for the driver and a local for a test; this
// function writes it only on a failure return.
//
// Returns CH_OK and writes *raw_len, the whole message length in bytes,
// header included, which is what hsr_next_msg then yields.
//
// Returns HSR_INCOMPLETE and leaves *raw_len alone when fewer than 4
// bytes are unread, or when the header is there and the body is not.
// The driver takes that as "deliver more bytes" and returns to its
// caller.
//
// Returns CH_EPROTO with ALERT_DECODE_ERROR when the header names a
// body longer than 0x4000 bytes, the largest message this client
// accepts, which is the TLS reader's ceiling kept unchanged; the TLS
// arm returns the same code and sets no alert, because its caller has
// a record-layer alert to send instead.
//
// Returns CH_ECAP with ALERT_INTERNAL_ERROR when the message is within
// that ceiling and still could never fit cfg.buf_len. A QUIC client
// sends no record_size_limit, so cfg.buf_len is the only bound a peer
// meets, and refusing at the header is what keeps the buffer from being
// the thing that has to grow. It is the check handshake_post.c already
// makes on a post-handshake message header.
int hsr_peek_message(const handshake_state *h, size_t *raw_len, uint8_t *alert);
#endif

// Yields the next complete handshake message, raw (header included)
// for the transcript. Pointers die at the next call. One name, one
// signature and one sentence of contract on both transports, and one
// difference an auditor must not read past: whether the call can wait
// on the wire.
//
// Under TRANSPORT=tls it waits. It calls hsr_fetch_record until the
// message is whole, so it drives the caller's recv callback and can
// spend arbitrary wall-clock time inside one call. It returns CH_OK, or
// CH_EIO, CH_EPROTO, CH_EAUTH or CH_ECAP from the record reading
// underneath it.
//
// Under CH_TRANSPORT_QUIC it never waits, and it reads no record. It
// yields the message the driver has already found whole with
// hsr_peek_message, and it returns as soon as it has one. There is
// nothing to wait for: the caller owns the transport and hands CRYPTO
// bytes in through hsr_feed, which is what RFC 9001 §4.1.3 requires of
// a TLS stack in QUIC (rfc9001.txt:495-497). It returns neither CH_EIO
// nor CH_EAUTH, because no socket and no record MAC sit under it. It
// returns CH_OK, CH_EPROTO with ALERT_DECODE_ERROR for a header naming
// a body longer than 0x4000 bytes, or CH_EINVAL when the unread bytes
// hold no whole message, which is the driver calling out of order: it
// writes no output, changes no field, and waits for nothing.
//
// On CH_OK both arms write *type, *raw and *raw_len, and advance pt_off
// past the message. On any other return the three outputs are
// untouched.
int hsr_next_msg(handshake_state *h, uint8_t *type, const uint8_t **raw, size_t *raw_len);

// The transcript hash as it stands now, without disturbing the running
// hash: both the state machine and the authentication flight need this
// snapshot at several points.
int hsr_transcript_hash(handshake_state *h, uint8_t out[SHA256_LEN]);

#endif
