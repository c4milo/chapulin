// The session: one static struct holding record protection for both
// directions, the transcript, and the TX staging area — plus the
// teardown and alert primitives every layer above record shares. Sits
// between record and handshake in the include graph.
//
// A TRANSPORT=quic build declares a smaller struct and none of the
// three primitives. It has no record layer (RFC 9001 §4.1.3,
// rfc9001.txt:462-464) and compiles no session.c, so every field and
// call the record layer owns sits under #ifndef CH_TRANSPORT_QUIC with
// the reason beside it. The QUIC block at the end of this file lists
// what a QUIC build keeps and what quic.c wipes.
#ifndef CH_SESSION_H
#define CH_SESSION_H

#include "cfg.h"
#ifndef CH_TRANSPORT_QUIC
// The record layer, and with it rec_dir, REC_HDR and AEAD_TAG. A
// TRANSPORT=quic build reads none of the three: RFC 9001 §4.1.3 takes
// the unprotected content of a handshake record as the content of a
// CRYPTO frame and uses no TLS record protection (rfc9001.txt:462-464),
// and quic_keys.[ch] holds one direction of one encryption level where
// rec_dir holds one direction of record protection. A QUIC object
// compiles no record.c, so the declarations would name a file that is
// not there.
#include "record.h"
#endif
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
// TX staging holds two different things, and the array takes whichever
// is larger: one sealed application record (CH_TX_PT + 1 + AEAD_TAG),
// or the largest ClientHello this build can emit. The hello wins in
// every build. These are CH_HELLO_MAX's value per build, repeated here
// as literals because handshake_message.h sits above this header and
// cannot be included from it; handshake.c asserts the two agree, where
// both constants are visible, so a stale literal fails the build
// rather than shipping.
#ifndef CH_TX_STAGE
#ifdef CH_TRANSPORT_QUIC
// A QUIC hello differs from the TLS one by three extensions. It drops
// the 6-byte record_size_limit, because RFC 9001 §4.1.3 removes the
// record layer that extension sizes (rfc9001.txt:462-464). It adds
// quic_transport_parameters, 4 framing bytes over a body of at most
// CH_TRANSPORT_PARAMS_MAX (§8.2). And it adds the 270-byte ALPN offer
// in every trust mode, because §8.1 makes ALPN mandatory there
// (rfc9001.txt:1891-1895), where a TLS device build sends none. So each
// value is the TLS one plus 254, and plus 270 again in the two device
// modes. These are CH_HELLO_MAX's QUIC values, repeated as literals for
// the reason the TLS ones are, and quic.c asserts the two agree.
#if defined(CH_TRUST_WEBPKI) && defined(CH_KEX_PQ)
#define CH_TX_STAGE 2587
#elif defined(CH_TRUST_WEBPKI)
#define CH_TX_STAGE 1403
#elif defined(CH_KEX_PQ)
#define CH_TX_STAGE 2325
#else
#define CH_TX_STAGE 1141
#endif
#elif defined(CH_TRUST_WEBPKI) && defined(CH_KEX_PQ)
// The pq sum below plus the two extensions a TRUST=webpki hello adds:
// the 262-byte server_name at the longest hostname (4 type and length,
// 2 list length, 1 name_type, 2 name length, 253 name) and the 270-byte
// application_layer_protocol_negotiation at the longest offer (4 type
// and length, 2 list length, then 8 names of 1 length byte and 32 name
// bytes): 1801 + 262 + 270.
#define CH_TX_STAGE 2333
#elif defined(CH_TRUST_WEBPKI)
// The classic sum below plus the same two extensions: 617 + 262 + 270.
#define CH_TX_STAGE 1149
#elif defined(CH_KEX_PQ)
// 137 fixed + 320 ticket identity + 128 cookie with framing + the
// 1216-byte hybrid share.
#define CH_TX_STAGE 1801
#else
// The same sum with a 32-byte x25519 share: 617. Above the 529 a sealed record
// needs, which is why a maximum ticket identity plus a maximum retry cookie
// used to fail closed with CH_ECAP
// (https://github.com/c4milo/chapulin/issues/46).
#define CH_TX_STAGE 617
#endif
#endif
// The library builds as C, so the guards always run. The ceiling is
// RFC 9846's 2^14 record-body cap; the hello ships as one record.
#ifndef __cplusplus
#ifndef CH_TRANSPORT_QUIC
// A TRANSPORT=quic build stages no sealed record, so this floor has
// nothing to hold there, and AEAD_TAG comes from record.h, which that
// build does not read.
_Static_assert(CH_TX_STAGE >= CH_TX_PT + 1 + AEAD_TAG,
               "TX staging must hold at least one sealed record");
#endif
_Static_assert(CH_TX_STAGE <= 0x4000, "a handshake record body caps at 2^14");
#endif

#define CH_ST_START 0
#define CH_ST_CONNECTED 1
#define CH_ST_CLOSED 2
#define CH_ST_FAILED 3

typedef struct {
    ch_cfg cfg;
#ifndef CH_TRANSPORT_QUIC
    // Record protection, one rec_dir per direction. A TRANSPORT=quic
    // build declares neither: RFC 9001 §4.1.3 removes the record layer
    // (rfc9001.txt:462-464), and ch_quic holds one quic_keys per
    // direction per encryption level in their place. So a QUIC build
    // has no rec_dir at all, and quic_fail wipes none.
    rec_dir rd; // server -> client protection
    rec_dir wr; // client -> server protection
#endif
    uint8_t rd_secret[SHA256_LEN]; // current traffic secrets, for KeyUpdate
    uint8_t wr_secret[SHA256_LEN];
    uint8_t res_master[SHA256_LEN];
    sha256 transcript;
#ifndef CH_TRANSPORT_QUIC
    // The peer's record_size_limit. A TRANSPORT=quic build declares it
    // in neither direction: it sends no record_size_limit and receives
    // none, because RFC 9001 §4.1.3 removes the record layer the
    // extension sizes (rfc9001.txt:462-464). cfg.buf_len bounds one
    // encryption level's reassembled CRYPTO bytes instead.
    uint16_t peer_limit; // max plaintext per record the peer accepts
#endif
    uint8_t state;
#ifndef CH_TRANSPORT_QUIC
    // Whether record protection is live, which decides whether an alert
    // goes out encrypted. A TRANSPORT=quic build does not declare it,
    // because it sends no alert record at all: QUIC carries the failure
    // in a CONNECTION_CLOSE frame the caller writes (RFC 9001 §4.8),
    // and ch_quic_error_code reports the code that goes in it.
    uint8_t keys; // record protection live; alerts encrypt iff set
#endif
    // Which pin authenticated the server: 1 = cfg.server_pubkey, 2 =
    // cfg.server_pubkey2, 0 before a pinned handshake completes. Public
    // information — operators read it to watch key rotation progress.
    uint8_t pin_slot;
    // The NamedGroup of the key exchange that ran. hello_exchange
    // (handshake.c) writes it from the ServerHello: the code point
    // parse_key_share accepted — CH_GROUP_X25519 or
    // CH_GROUP_X25519MLKEM768 (cfg.h), one per build — and 0 before
    // any ServerHello or when it carried no key_share. Public
    // information, like pin_slot: a caller reads it to see which
    // exchange protected the session, and cfg.require_pq fails the
    // handshake when it is not the hybrid.
    uint16_t group;
#ifdef CH_ROLE_SERVER
    // What a ROLE=server build selected and must keep past the message that decided it.
    // A client needs none of these: it offers exactly one of everything, so its suite is
    // a compile-time literal (handshake_message.c) and its session id is empty. Every
    // value here is public: each one went out in the clear in the ServerHello or came in
    // in the clear in the ClientHello.
    //
    // session_id is the client's legacy_session_id, which the server echoes in
    // legacy_session_id_echo (RFC 9846 §4.1.3, rfc9846.txt:1365-1368) and which must
    // survive a HelloRetryRequest round trip (rfc9846.txt:1451), so it is copied rather
    // than pointed at. suite is the selected cipher suite and hash_len is the transcript
    // hash length that suite fixes (rfc9846.txt:4055-4056). sigalg is the scheme the
    // CertificateVerify carries. hrr_sent records that the one HelloRetryRequest this
    // flight allows has gone out. compat_ccs records that the client sent a non-empty
    // session id, so one dummy change_cipher_spec record is owed
    // (rfc9846.txt:6401-6403). sni_len is how many bytes of server_name the handshake
    // copied into cfg.sni_buf, and 0 when the client sent none or the name did not fit.
    uint8_t session_id[32];
    uint8_t session_id_len;
    uint16_t suite;
    uint8_t hash_len;
    uint16_t sigalg;
    uint8_t hrr_sent;
    uint8_t compat_ccs;
    size_t sni_len;
#endif
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC) || defined(CH_ROLE_SERVER)
    // Which protocol the server selected through ALPN (RFC 7301 §3.2):
    // the index in ch_cfg.alpn_protocols of the name the
    // EncryptedExtensions carried, or CH_ALPN_NONE (cfg.h) when the
    // caller offered none or the server sent no ALPN extension.
    // hsp_parse_encrypted_exts writes it, and ch_handshake seeds it
    // with CH_ALPN_NONE, because index 0 is a protocol. Public
    // information, like group: the caller reads it to choose which
    // protocol to speak. A TRUST=webpki build declares it, and so does
    // a TRANSPORT=quic build in every trust mode, because RFC 9001 §8.1
    // requires ALPN there (rfc9001.txt:1891-1895) and ch_quic_init
    // seeds the field where ch_handshake seeds it over TCP. A
    // ROLE=server build declares it in every trust mode as well, and
    // writes it from the other side: the index is the protocol this
    // server selected out of cfg.alpn_protocols, and CH_ALPN_NONE when
    // the caller offered none, the client sent no ALPN extension, or
    // the two lists did not intersect. A TRANSPORT=tls raw or ca client
    // object declares none of this and keeps the ch_tls layout it had.
    uint8_t alpn_selected;
#endif
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
#ifndef CH_TRANSPORT_QUIC
    // How many TLS KeyUpdate messages this client has sent. A
    // TRANSPORT=quic build does not declare it: RFC 9001 §6 forbids the
    // TLS KeyUpdate message on this transport (rfc9001.txt:1566-1568),
    // and the key update here is the packet-level one of §6.1, which
    // ch_quic_key_update runs and ch_quic.key_phase names.
    uint64_t send_epochs; // KeyUpdates we have sent; capped per §4.7.3
#endif
    // Unread plaintext of the current record, inside cfg.buf.
    size_t pt_off;
    size_t pt_len;
#ifdef CH_TRANSPORT_QUIC
    // The one handshake message the client owes, staged whole until
    // ch_quic_crypto_out hands it out. It carries no REC_HDR prefix:
    // RFC 9001 §4.1.3 takes the unprotected content of a handshake
    // record as the content of a CRYPTO frame, so nothing writes a
    // record header in front of it (rfc9001.txt:462-464). ch_quic's
    // tx_len counts the bytes staged here and its tx_level names the
    // encryption level they go out at.
    //
    // CH_TX_STAGE's QUIC values are above, and each one is the length
    // hs_build_client_hello emits for the largest hello its build can
    // write: 1141 raw and ca classic, 2325 under KEX=pq, 1403 under
    // TRUST=webpki and 2587 under both. quic.c asserts CH_HELLO_MAX
    // against this constant, where both are visible.
    uint8_t tx[CH_TX_STAGE];
#else
    uint8_t tx[REC_HDR + CH_TX_STAGE];
#endif
} ch_tls;

#ifndef CH_TRANSPORT_QUIC
// The three calls session.c defines. A TRANSPORT=quic object compiles
// no session.c, so it declares none of them: quic.c holds quic_fail and
// ch_quic_close, which wipe the fields the QUIC block below lists.

// Sends an alert — encrypted iff keys are live, plaintext only before any
// keys exist, nothing at all once they are wiped.
int tlsi_send_alert(ch_tls *t, uint8_t level, uint8_t description);

// Alert (best effort), wipe all key material, mark the session failed.
void tlsi_fail(ch_tls *t, uint8_t description);

// Whether a client configuration keeps every rule that does not depend on
// which driver runs it. tls.c holds the predicates; ch_connect and
// ch_rec_init both ask, and each checks the I/O callbacks itself.
int tlsi_config_ok(const ch_cfg *cfg);

// Loads the stored epoch and checks a resuming ticket against it, the
// step a CA build owes before its first handshake message. Returns CH_OK
// when no epoch is configured. Both client drivers call it.
int tlsi_epoch_init(ch_tls *t, const ch_cfg *cfg, int psk_ok);

// Wipe all key material and buffered plaintext; keys go dead.
void tlsi_wipe(ch_tls *t);
#endif

#ifdef CH_TRANSPORT_QUIC
// What survives a return under TRANSPORT=quic.
//
// The TLS driver runs one handshake to completion inside ch_connect and
// keeps its working state on ch_handshake's own stack frame. The QUIC
// driver returns to the caller between handshake messages, so every
// value a later call reads lives in the session struct instead. That
// struct is ch_quic, which quic.h declares: it holds one ch_tls, the
// handshake_state handshake_record.h declares, the step number, the
// levels, the staged length, the alert, the Key Phase bit, the packet
// protection key sets and the RFC 9001 §6.6 counters. No driver field
// is added to ch_tls; ch_quic embeds it.
//
// Five ch_tls fields carry the driver's state between calls, and each
// keeps the name it has above:
//
//   pt_off, pt_len   the unread CRYPTO bytes of one encryption level
//                    inside cfg.buf, the meaning the TLS record reader
//                    gives them. QUIC sends no record_size_limit, so
//                    cfg.buf_len is the only bound a peer meets, and
//                    the reader refuses, at the message header, a
//                    message that could never fit.
//   rd_secret        the two 1-RTT traffic secrets the "quic ku" step
//   wr_secret        reads and rewrites (RFC 9001 §6.1,
//                    rfc9001.txt:1605-1607). ks_master writes both, as
//                    it does over TCP, and the invariant below says
//                    which key set each one names afterwards.
//   tx               the one staged handshake message, above.
//
// Which key set each secret belongs to, stated once because the two
// sides differ and the difference is one update wide:
//
//   wr_secret is the traffic secret of ch_quic's app_tx.
//   rd_secret is the traffic secret of ch_quic's app_rx[CH_QUIC_KEY_NEXT].
//
// The asymmetry comes from quic_keys_update, which writes the advanced
// secret back over its argument and re-derives that set's packet
// protection key and IV in the same call (quic_keys.h). So one call
// with rd_secret always writes app_rx[CH_QUIC_KEY_NEXT] and leaves
// rd_secret naming it. The Finished step runs that call once, which is
// what makes the invariant true from the first 1-RTT packet on, and
// ch_quic_key_update runs it again after it moves current to previous
// and next to current. A build that kept the current phase's secret
// here would derive a next set one update behind, and every 1-RTT
// packet after the first peer-initiated key update would fail to open.
//
// What quic_fail wipes, in the names the code uses, so INV-17's claim
// that every failure path wipes can be checked against a list: hs,
// every key field ch_quic holds (handshake_rx, handshake_tx,
// handshake_hp_rx, handshake_hp_tx, app_tx, all CH_QUIC_KEY_SETS slots
// of app_rx, app_hp_rx and app_hp_tx), initial_dcid and
// initial_dcid_len, which hold no key and are zeroed with the rest
// rather than left naming a dead connection,
// t.rd_secret, t.wr_secret, t.res_master, tx_len, t.pt_off and
// t.pt_len. It clears levels_ready with them, so no later call seals or
// opens a packet. It wipes no rec_dir, because a TRANSPORT=quic build
// declares none. ch_quic_close wipes the same fields and sets
// CH_ST_CLOSED where quic_fail sets CH_ST_FAILED.
//
// docs/quic.md, "The state that survives a return", states the whole
// table and the bound each field's proof harness assumes.
#endif

#endif
