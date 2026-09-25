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
#include "hkdf.h"
#include "sha256.h"
#include "suite.h"
#include "transcript.h"

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
#if defined(CH_SUITE_AES_GCM) && defined(CH_TRUST_WEBPKI)
#define CH_TX_AES_SUITES (4 + 16)
#else
#define CH_TX_AES_SUITES 0
#endif
// A build with a server role stages its ServerHello in the same array, in
// the clear and before any record is sealed, so the array also holds the
// largest ServerHello: 1216 bytes, the one that carries the 1120-byte
// X25519MLKEM768 share after the longest legacy_session_id_echo and a
// pre_shared_key extension (SRV_SERVER_HELLO_MAX, srv_message.h, which
// srv_flight.h asserts equal to this literal). It raises the two values
// below it, the classic raw and ca ones over TLS and over QUIC; every
// other value is larger already.
#define CH_TX_SERVER_HELLO 1216
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
// the reason the TLS ones are, and quic.c asserts the two agree. The
// webpki one carries the 23 bytes of CH_HELLO_CERT_PATH_MAX, as the TLS
// one does, because the builder is the same; ch_quic_init refuses SPKI
// pins, so 7 of them never go out over QUIC. It takes CH_TX_AES_SUITES
// on top, as the TLS webpki value does.
#ifdef CH_TRUST_WEBPKI
#define CH_TX_STAGE (2648 + CH_TX_AES_SUITES)
#elif defined(CH_KEX_PQ)
#define CH_TX_STAGE 2325
#elif defined(CH_ROLE_SERVER)
#define CH_TX_STAGE CH_TX_SERVER_HELLO
#else
#define CH_TX_STAGE 1141
#endif
#elif defined(CH_TRUST_WEBPKI)
// The TRUST=webpki value takes CH_TX_AES_SUITES on top: 20 bytes for a
// SUITE=aesgcm webpki client (CH_CLIENT_AES_SUITES in suite.h), 0 in
// every other build. That client lists two more cipher suites, 4 bytes,
// and a ticket from a TLS_AES_256_GCM_SHA384 session carries a SHA-384
// binder, 16 bytes longer than the SHA-256 one the sum below counts.
// The pq sum below plus the two extensions a TRUST=webpki hello adds:
// the 262-byte server_name at the longest hostname (4 type and length,
// 2 list length, 1 name_type, 2 name length, 253 name) and the 270-byte
// application_layer_protocol_negotiation at the longest offer (4 type
// and length, 2 list length, then 8 names of 1 length byte and 32 name
// bytes). Then the second group every webpki hello offers beside the
// hybrid (docs/decisions.md 53): x25519 in supported_groups, 2 bytes,
// and its KeyShareEntry, 36 bytes. Then the certificate path every
// webpki hello offers, a resuming one included (docs/decisions.md 55):
// the 16-byte signature_algorithms of five schemes and the 7-byte
// server_certificate_type of a config with SPKI pins and anchors:
// 1801 + 262 + 270 + 2 + 36 + 16 + 7.
#define CH_TX_STAGE (2394 + CH_TX_AES_SUITES)
#elif defined(CH_KEX_PQ)
// 137 fixed + 320 ticket identity + 128 cookie with framing + the
// 1216-byte hybrid share.
#define CH_TX_STAGE 1801
#elif defined(CH_ROLE_SERVER)
#define CH_TX_STAGE CH_TX_SERVER_HELLO
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
    // The current traffic secrets, for KeyUpdate, and the resumption
    // master secret. Each holds as many bytes as the suite's hash,
    // tls_hash_len below, in an array sized for the longest hash the
    // build holds.
    uint8_t rd_secret[HKDF_HASH_MAX];
    uint8_t wr_secret[HKDF_HASH_MAX];
    uint8_t res_master[HKDF_HASH_MAX];
#ifdef CH_EXPORTER
    // exporter_master (RFC 9846 §7.5). It is derived beside the
    // application traffic secrets and lives as long as the session,
    // because ch_export is a call a connected caller makes and the wipe
    // at CONNECTED clears the handshake state rather than this. Every
    // path that kills a session wipes it with the rest.
    uint8_t exp_master[HKDF_HASH_MAX];
#endif
    ch_transcript transcript;
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
    // goes out encrypted. After the peer's close_notify only the write
    // direction is live (read_closed, below), and an alert is sealed
    // under that one. A TRANSPORT=quic build does not declare it,
    // because it sends no alert record at all: QUIC carries the failure
    // in a CONNECTION_CLOSE frame the caller writes (RFC 9001 §4.8),
    // and ch_quic_error_code reports the code that goes in it.
    uint8_t keys; // record protection live; alerts encrypt iff set
#endif
    // Which pin authenticated the server: 1 = cfg.server_pubkey, 2 =
    // cfg.server_pubkey2, 0 before a pinned handshake completes. Public
    // information — operators read it to watch key rotation progress.
    uint8_t pin_slot;
    // Set when a PSK authenticated the handshake, so the server sent no
    // Certificate and no CertificateVerify: the session resumed. 0 for a
    // full handshake, and before a ServerHello is accepted. Both roles
    // write it and give it that one meaning. A client writes it in
    // hsf_accept_server_hello: set when the ServerHello selected the
    // identity its hello offered, and clear when the hello offered no PSK
    // or a TRUST=webpki server declined the one it offered, which that
    // build answers with a full handshake in the same connection
    // (docs/decisions.md 55). A raw or ca client fails closed on a
    // declined PSK, so there it is set exactly when cfg.psk is. A server
    // role writes it when a ticket this server issued authenticated the
    // handshake, which then leaves sigalg 0 (srv_resume.h). Public, like
    // pin_slot: the caller reads it to tell a resumed session from a full
    // one, and the client's drivers read it to decide whether a
    // Certificate comes next.
    uint8_t psk_selected;
    // The NamedGroup of the key exchange that ran. hello_exchange
    // (handshake.c) writes it from the ServerHello: the code point
    // parse_key_share accepted — CH_GROUP_X25519 or
    // CH_GROUP_X25519MLKEM768 (cfg.h), one per raw or ca build, and
    // whichever the ServerHello selected under CH_KEX_TWO_GROUPS — and 0
    // before any ServerHello or when it carried no key_share. A server
    // role writes the group its own ServerHello selected, once the hello
    // it answers is settled: CH_GROUP_X25519MLKEM768 whenever the client
    // listed it, and CH_GROUP_X25519 otherwise (srv_kex.h). Public
    // information, like pin_slot: a caller reads it to see which exchange
    // protected the session, and a client's cfg.require_pq fails the
    // handshake when it is not the hybrid.
    uint16_t group;
#if defined(CH_SUITE_AES_GCM) && !defined(CH_ROLE_SERVER)
    // The cipher suite the ServerHello selected, which a client written
    // under -DCH_SUITE_AES_GCM writes beside group: ChaCha20, AES-128-GCM
    // or AES-256-GCM from a CH_CLIENT_AES_SUITES client, written as soon
    // as a HelloRetryRequest or the ServerHello names it. Public, like
    // group.
    // A build with a server role declares the field below and a client
    // in it writes that one.
    uint16_t suite;
#endif
#ifdef CH_ROLE_SERVER
    // What a ROLE=server build selected and must keep past the message that decided it.
    // A client needs none of these but suite, which a SUITE=aesgcm client writes too: its
    // session id is empty, and the rest describe the server's own choices. Every value
    // here is public: each one went out in the clear in the ServerHello or came in in the
    // clear in the ClientHello.
    //
    // session_id is the client's legacy_session_id, which the server echoes in
    // legacy_session_id_echo (RFC 9846 §4.2.3, rfc9846.txt:1365-1368) and which must
    // survive a HelloRetryRequest round trip (rfc9846.txt:1451), so it is copied rather
    // than pointed at. suite is the selected cipher suite and hash_len is the transcript
    // hash length that suite fixes (rfc9846.txt:4055-4056). sigalg is the scheme the
    // CertificateVerify carries. hrr_sent records that the one HelloRetryRequest this
    // flight allows has gone out. compat_ccs records that the client sent a non-empty
    // session id, so one dummy change_cipher_spec record is owed
    // (rfc9846.txt:6401-6403). sni_len is how many bytes of server_name the handshake
    // copied into cfg.sni_buf, and 0 when the client sent none or the name did not fit.
    // The server also writes psk_selected, which every build declares above.
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
#ifdef CH_TRUST_WEBPKI
    // webpki_ticket_config_hash of this session's hostname and anchors,
    // written when the session starts. handshake_post.c binds every
    // ticket the session receives to it, so the binding does not depend
    // on the caller's hostname and anchor bytes after ch_connect returns.
    uint8_t ticket_config_hash[SHA256_LEN];
    // The certificate type the server's EncryptedExtensions selected
    // (RFC 7250), CH_CERT_TYPE_X509 when it sent none: what the
    // Certificate message carries, a chain or one raw public key. Public,
    // like alpn_selected; the caller may read it once connected.
    uint8_t server_cert_type;
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
    // Set when the peer's close_notify arrived on a connected session.
    // RFC 9846 §6 makes that alert close one direction of the
    // connection, the sender's (rfc9846.txt:3767-3768), and §6.1 says it
    // has no effect on the sender's read side (rfc9846.txt:3857-3859).
    // So this session reads nothing more and still writes: ch_read
    // returns 0 without reading, the read key is wiped, and state stays
    // CH_ST_CONNECTED until ch_close. Public, like pin_slot. It sits in
    // the padding before send_epochs, so sizeof(ch_tls) did not change
    // when it was added. A TRANSPORT=quic build does not declare it:
    // QUIC carries no close_notify, and RFC 9001 §4.8 treats every TLS
    // alert as fatal (rfc9001.txt:888-893).
    uint8_t read_closed;
#endif
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
#ifdef CH_TRANSPORT_RECORD
    // The bytes of a post-handshake message that arrived in part when
    // ch_read returned CH_RECORD_AGAIN: they sit at the front of cfg.buf,
    // and the next ch_read continues the message with the next record
    // before it reads anything else (hspost_read). 0 when no message is
    // in part.
    size_t post_fill;
#endif
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
    // write: 1141 raw and ca classic, 2325 under KEX=pq, and 2648 under
    // TRUST=webpki, whose hello carries both groups' shares and the
    // certificate path. quic.c asserts CH_HELLO_MAX against this
    // constant, where both are visible.
    uint8_t tx[CH_TX_STAGE];
#else
    uint8_t tx[REC_HDR + CH_TX_STAGE];
#endif
} ch_tls;

// The hash length of the session's cipher suite (rfc9846.txt:4055-4056),
// the length of every secret above. A build that holds one hash answers
// SHA256_LEN. A -DCH_SUITE_AES_GCM build answers suite_hash_len of
// t->suite, which is 0 until the handshake has named a suite, so a caller
// reads it after the ServerHello, or after a HelloRetryRequest for a
// client. suite is public, like group.
static inline size_t tls_hash_len(const ch_tls *t) {
#ifdef CH_SUITE_AES_GCM
    return suite_hash_len(t->suite);
#else
    (void)t;
    return SHA256_LEN;
#endif
}

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
// ch_record_init both ask, and each checks the I/O callbacks itself.
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
// every read key (handshake_rx, handshake_hp_rx, all CH_QUIC_KEY_SETS
// slots of app_rx, and app_hp_rx), t.rd_secret, t.wr_secret,
// t.res_master, tx_len, t.pt_off and t.pt_len, and every read bit of
// levels_ready, so no later call opens a packet. It keeps the write keys
// of each level whose write bit is set, for the one CONNECTION_CLOSE
// ch_quic_seal_close seals there: initial_dcid and initial_dcid_len,
// which hold no key but derive the Initial one, handshake_tx and
// handshake_hp_tx, and app_tx and app_hp_tx. It wipes those of a level
// whose bit is clear, and ch_quic_seal_close wipes a level's right after
// its seal (docs/decisions.md 57). It wipes no rec_dir, because a
// TRANSPORT=quic build declares none. ch_quic_close wipes every field
// above, the write keys included, clears levels_ready and sets
// CH_ST_CLOSED.
//
// docs/quic.md, "The state that survives a return", states the whole
// table and the bound each field's proof harness assumes.
#endif

#endif
