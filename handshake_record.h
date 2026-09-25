// The handshake driver's state and the reader that turns arriving bytes
// into whole handshake messages. Under TRANSPORT=tcp-blocking the state lives on
// ch_handshake's stack and is wiped wholesale when the handshake ends
// either way; it yields records and whole messages out of cfg.buf,
// where pointers die at the next record read.
//
// Under CH_TRANSPORT_QUIC_NONBLOCKING there is no record layer to read: RFC 9001
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
#ifdef CH_ROLE_SERVER
#include "mlkem.h"
#endif
#if defined(CH_KEX_TWO_GROUPS) || defined(CH_ROLE_SERVER)
#include "p256_ecdh.h"
#endif
#ifdef CH_TRUST_CA
#include "x509.h"
#endif
#ifdef CH_TRUST_WEBPKI
#include "webpki.h"
#endif

// Everything the handshake needs beyond the session, wiped wholesale
// when the handshake ends either way. Under TRANSPORT=tcp-blocking it sits on
// ch_handshake's one stack frame. Under CH_TRANSPORT_QUIC_NONBLOCKING it sits
// inside ch_quic, because the driver returns to its caller between
// messages, and the wipe comes one round trip earlier, at the step that
// reaches HSQ_STEP_COMPLETE.
typedef struct {
    ch_tls *t;
    uint8_t priv[X25519_LEN];
    uint8_t pub[X25519_LEN];
#ifdef CH_KEX_HYBRID
    // ML-KEM (d, z) seed. The key pair re-expands from it on demand
    // (build and decapsulation), so the share the HRR retry resends is
    // identical by construction and no 2400-byte key lives in state.
    uint8_t dz[64];
#endif
#ifdef CH_KEX_TWO_GROUPS
    // The group a HelloRetryRequest named, CH_GROUP_SECP256R1, or 0 when
    // no retry named one. It is the one group the first hello lists
    // without a share, so the retry hello carries a share for it alone
    // and the ServerHello must select it (RFC 9846 §4.3.8,
    // rfc9846.txt:2205-2215 and 2233-2238). handshake_groups.c writes it.
    uint16_t retry_group;
    // The P-256 public point the retry hello carries, in the uncompressed
    // form of RFC 9846 §4.3.8.2. Public: it goes out in the clear.
    uint8_t p256_pub[P256_POINT_LEN];
#endif
#if defined(CH_KEX_TWO_GROUPS) || defined(CH_ROLE_SERVER)
    // The P-256 private scalar of a secp256r1 key exchange, drawn only
    // when that group is chosen: by a client once a retry names it
    // (handshake_groups.c), and by a server once it selects it
    // (srv_kex.c). Zero otherwise. The call that computes the shared
    // secret wipes it on both exits (INV-17).
    uint8_t p256_priv[P256_SCALAR_LEN];
#endif
#ifdef CH_SUITE_AES_GCM
    // The cipher suite the server named, 0 until a HelloRetryRequest or
    // the ServerHello names one. A ServerHello after a retry must repeat
    // the retry's suite (RFC 9846 §4.2.4, rfc9846.txt:1489-1491), and
    // every record direction the handshake keys runs it
    // (REC_DIR_INIT_SUITE).
    uint16_t suite;
#endif
    uint8_t random[32];
    // The key schedule's secrets, each as long as the hash it runs: the
    // suite's for all but the first two, and for those two the hash of
    // the PSK the client presents or the server selects (RFC 9846 §7.1).
    // The arrays are sized for the longest hash the build holds.
    uint8_t early[HKDF_HASH_MAX];
    uint8_t binder_key[HKDF_HASH_MAX];
    uint8_t handshake_secret[HKDF_HASH_MAX];
    uint8_t c_hs[HKDF_HASH_MAX];
    uint8_t s_hs[HKDF_HASH_MAX];
    uint8_t master[HKDF_HASH_MAX];
    uint8_t cookie[HSP_COOKIE_MAX];
    size_t cookie_len;
#ifdef CH_ROLE_SERVER
    // The ML-KEM-768 shared secret of a hybrid key exchange (mlkem.h's
    // ss). srv_kex_share writes it when it encapsulates for the
    // ServerHello, and srv_kex_secret copies it into the input keying
    // material and wipes it, so it lives from one message to the next and
    // no longer (INV-17). It stays zero when the server selected x25519
    // or secp256r1.
    uint8_t mlkem_ss[MLKEM_SS_LEN];
    // The auth_seconds of the ticket this handshake resumed (srv_ticket.h),
    // which srv_select_auth writes and srv_send_new_session_ticket carries
    // into the ticket it issues, so a chain of resumptions keeps the instant
    // of the full handshake it started from. Meaningful only while
    // ch_tls.psk_selected is set. Not secret: the server wrote it, and
    // nothing derives a key from it.
    uint64_t ticket_auth_seconds;
#endif
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
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
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    // The encryption level the bytes this handler produces belong to, a
    // CH_LEVEL_ value. The driver writes it before each step and
    // srv_flight.c passes it to ch_srv_cfg.on_crypto_out, because a
    // handler knows which message it is writing and not which level the
    // driver has reached. A client build needs no such field: it stages
    // one message and ch_quic.tx_level names the level.
    uint8_t level;
#endif
#ifdef CH_KEYLOG
    // The ClientHello's random, which every key log line is filed under.
    // Both roles keep a copy, because both lose the original before they
    // log the application secrets: a client wipes h->random once the key
    // exchange is done, and a server's parsed hello is out of scope by
    // srv_send_finished. The value crossed the wire in the clear, so the
    // copy exposes nothing, and the retry hello still cannot be rebuilt
    // from it, since that needs h->priv and h->pub as well.
    uint8_t client_random[32];
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

#if !defined(CH_TRANSPORT_QUIC_NONBLOCKING) && !defined(CH_TRANSPORT_TCP_NONBLOCKING)
// Reads records until one carrying handshake bytes lands; appends its
// plaintext to the unconsumed bytes in cfg.buf.
int hsr_fetch_record(handshake_state *h);
#endif

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_TRANSPORT_TCP_NONBLOCKING)
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

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
// Answers the type of the next unread handshake message, the byte at
// cfg.buf + pt_off, which opens a message because hsr_next_msg consumes
// whole ones. It reads that one byte and nothing else, and changes no
// field. The QUIC drivers call it to name the first message a refused
// delivery carries, because RFC 9001 section 6 gives a KeyUpdate its own
// error code (rfc9001.txt:1565-1568).
//
// Requires what hsr_peek_message requires. Returns CH_OK and writes
// *type when at least one byte is unread, and HSR_INCOMPLETE, leaving
// *type alone, when none is.
int hsr_peek_type(const handshake_state *h, uint8_t *type);
#endif

// Yields the next complete handshake message, raw (header included)
// for the transcript. Pointers die at the next call. One name, one
// signature and one sentence of contract on both transports, and one
// difference an auditor must not read past: whether the call can wait
// on the wire.
//
// Under TRANSPORT=tcp-blocking it waits. It calls hsr_fetch_record until the
// message is whole, so it drives the caller's recv callback and can
// spend arbitrary wall-clock time inside one call. It returns CH_OK, or
// CH_EIO, CH_EPROTO, CH_EAUTH or CH_ECAP from the record reading
// underneath it.
//
// Under CH_TRANSPORT_QUIC_NONBLOCKING it never waits, and it reads no record. It
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

// The hash length of the suite the server named, which every client
// derivation after the ServerHello runs at (rfc9846.txt:4055-4056). A
// build that holds one suite answers SHA256_LEN. A -DCH_SUITE_AES_GCM
// build answers suite_hash_len of h->suite, which the client's first
// HelloRetryRequest or ServerHello writes, so a client reads it after
// hsf_read_server_hello. A server reads its selection's hash_len
// instead, because it keeps no h->suite. The suite is public: the
// server named it in the clear.
static inline size_t hsr_suite_hash_len(const handshake_state *h) {
#ifdef CH_SUITE_AES_GCM
    return suite_hash_len(h->suite);
#else
    (void)h;
    return SHA256_LEN;
#endif
}

// The transcript hash as it stands now at hash_len, without disturbing
// the running hash: both the state machine and the authentication flight
// need this snapshot at several points. hash_len is the suite's:
// SHA256_LEN, or SHA384_LEN in a CH_HASH_SHA384 build, and out holds that
// many bytes. Always CH_OK.
int hsr_transcript_hash(handshake_state *h, size_t hash_len, uint8_t *out);

// Replaces the transcript after a HelloRetryRequest with RFC 9846
// §4.4.1's construction: a message_hash message whose body is the hash
// at hash_len of the first ClientHello, then the n bytes of the retry at
// retry. Both roles run it, a client over the retry it read and a server
// over the one it wrote. hash_len is the hash the retry's suite names.
void hsr_restart_transcript(handshake_state *h, size_t hash_len, const uint8_t *retry, size_t n);

#endif
