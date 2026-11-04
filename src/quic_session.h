// The QUIC session under TRANSPORT=quic-nonblocking: ch_quic, the one struct whose fields
// outlive a call, and the rules each of its fields keeps between calls. quic.h includes this
// header and declares every call that takes a ch_quic; the struct sits here so quic.h holds
// the calls and this file holds the state they share. session.h declares the ch_tls that
// ch_quic embeds.
#ifndef CH_QUIC_SESSION_H
#define CH_QUIC_SESSION_H
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "handshake_record.h"
#include "quic_keys.h"
#include "session.h"

// What survives a return under TRANSPORT=quic-nonblocking.
//
// The tcp-blocking driver runs one handshake to completion inside ch_connect and
// keeps its working state on ch_handshake's own stack frame. The QUIC
// driver returns to the caller between handshake messages, so every
// value a later call reads lives in the session struct instead. That
// struct is ch_quic, which this header declares below: it holds one ch_tls, the
// handshake_state handshake_record.h declares, the step number, the
// levels, the staged length, the alert, the Key Phase bit, the packet
// protection key sets and the RFC 9001 §6.6 counters. No driver field
// is added to ch_tls; ch_quic embeds it.
//
// Six ch_tls fields carry the driver's state between calls, and each
// keeps the name session.h gives it:
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
//   tx               the one staged handshake message.
//   quic_negotiated_version
//                    the QUIC version every Handshake and 1-RTT key is
//                    derived under and every packet at those levels
//                    carries. Each init call writes the original
//                    version, cfg.quic_original_version, and one more
//                    write may follow: a client's ch_quic_switch_version
//                    or a server's cfg.srv.choose_version answer.
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
// TRANSPORT=quic-nonblocking build declares none. ch_quic_close wipes every field
// above, the write keys included, clears levels_ready and sets
// CH_ST_CLOSED. Neither touches the two versions, which are public
// values the caller read off the wire and hold no key.
//
// docs/quic.md, "The state that survives a return", states the whole
// table and the bound each field's proof harness assumes.

// The bit ch_quic.levels_ready holds for one direction at one encryption level. level is
// a CH_LEVEL_ value and direction is CH_KEY_READ or CH_KEY_WRITE (quic_cfg.h), so the six bits
// of the three levels sit in the low six bits of one byte. Both arguments are the
// caller's own public values, never a secret, so the shift is an ordinary index.
#define CH_QUIC_LEVEL_BIT(level, direction) ((uint8_t)(1U << ((level) * 2 + (direction))))

// One QUIC session. It holds everything that survives a return, because the driver returns to its
// caller between handshake messages: the ch_tls a TCP build holds alone, the handshake_state a
// tcp-blocking build keeps on ch_handshake's stack frame, the driver's own fields, and the packet
// protection keys of every encryption level. docs/quic.md, "The state that survives a return",
// states the bound each field's proof harness assumes. The caller declares one and passes its
// address to every call. It is not copyable: hs.t points at t, and every public entry rewrites that
// pointer to its own &q->t, so a copy cannot leave a dangling pointer inside a step.
//
// Two traffic secrets sit in t rather than here, and every 1-RTT derivation rests on which
// key set each names: t.wr_secret is the traffic secret of app_tx, and t.rd_secret that of
// app_rx[CH_QUIC_KEY_NEXT], not of app_rx[CH_QUIC_KEY_CURRENT]. The comment above states why,
// with what a build that kept the current phase's secret would get wrong.
typedef struct ch_quic {
    ch_tls t;
    // The flight handlers' working state, wiped at HSQ_STEP_COMPLETE, one round trip
    // earlier than the tcp-blocking driver wipes its frame, which is INV-17's rule that handshake
    // secrets die at CONNECTED.
    handshake_state hs;
    uint8_t step;     // HSQ_STEP_*, quic_step.h
    uint8_t rx_level; // the one level whose CRYPTO bytes cfg.buf holds
    uint8_t tx_level; // the level the staged message goes out at
    uint8_t alert;    // what ch_quic_alert reports after a failure
    uint8_t endpoint; // CH_QUIC_ENDPOINT_*, the side its init call gave it (quic.c's CH_QUIC_SELF)
    size_t tx_len;    // bytes staged in t.tx; 0 when nothing is owed
    // The Key Phase bit the current 1-RTT send set carries, 0 or 1 (RFC 9001 §6.1,
    // rfc9001.txt:1615-1616). ch_quic_key_phase reports it and ch_quic_key_update toggles it.
    uint8_t key_phase;
    // The QUIC transport error code a step or an entry wrote, and 0 when none did. Only quic_fail
    // and the steps that owe 0x0a write it, and ch_quic_error_code states the one rule that turns
    // this field, q->alert and q->t.state into the answer a caller puts in CONNECTION_CLOSE.
    uint64_t error_code;
    // Which encryption levels can protect or unprotect packets right now, one bit per level per
    // direction at CH_QUIC_LEVEL_BIT above. The packet calls and ch_quic_discard read it, and it is
    // the only answer to "installed and not discarded": a key set of all-zero bytes is a legitimate
    // derivation, so no call decides that question by comparing key bytes. ch_quic_initial_keys
    // sets both CH_LEVEL_INITIAL bits, and the step that fires cfg.on_level_ready for a later level
    // sets that level's bits in the same call, so the caller's view and this field agree.
    // ch_quic_discard clears both bits of one level and ch_quic_close clears every bit. A failure
    // clears every read bit and keeps the write bits, each of which then admits one
    // ch_quic_seal_close, which clears it. docs/quic.md's state table has its row.
    uint8_t levels_ready;
    // The Initial level: the Destination Connection ID RFC 9001 §5.2 derives every Initial
    // key from, and no key. quic_initial.c builds the key each packet needs on its own
    // stack, so none outlives a call, which is INV-26. Every long header carries these
    // bytes in the clear. ch_quic_initial_keys writes both, again after a Retry.
    uint8_t initial_dcid[CH_QUIC_DCID_MAX];
    uint8_t initial_dcid_len;
    // The Handshake level. The packet protection key and IV are one value per direction;
    // the header protection key is its own, because §5.4 keeps it for the whole
    // connection (rfc9001.txt:1172-1174).
    quic_keys handshake_rx, handshake_tx;
    quic_hp_key handshake_hp_rx, handshake_hp_tx;
    // The 1-RTT level: one send set, and three receive sets indexed by CH_QUIC_KEY_PREVIOUS,
    // CH_QUIC_KEY_CURRENT and CH_QUIC_KEY_NEXT (quic_keys.h) and by no computed index. §6.3 makes
    // the current and the next set a floor (rfc9001.txt:1711-1712); the previous set is this
    // design's choice, so a packet delayed across a key update still opens (§6.5). The header
    // protection keys are written once and never updated (§6.1, rfc9001.txt:1607).
    quic_keys app_tx;
    quic_keys app_rx[CH_QUIC_KEY_SETS];
    quic_hp_key app_hp_rx, app_hp_tx;
    // RFC 9001 §6.6's counts. open_failures counts received packets that failed authentication in
    // this connection, across every level and every key, because the limit is stated that way
    // (rfc9001.txt:1823-1827). initial_sealed counts packets sealed under the Initial keys, whose
    // AES-128-GCM pays a confidentiality limit (rfc9001.txt:1812-1813); a Retry does not reset it.
    // An AES-GCM suite's key sets count their own packets, in quic_keys.sealed.
    uint64_t open_failures;
    uint64_t initial_sealed;
} ch_quic;

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
#endif
