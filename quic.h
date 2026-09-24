// chapulin's public API under TRANSPORT=quic, beside tls.h: the same TLS 1.3 client, run
// over QUIC's CRYPTO frames and used to protect QUIC packets. RFC 9001 §4.1.3 and §4.1.4
// define the interface a TLS stack owes QUIC, and §5 defines the packet protection that
// interface feeds. This header covers both and stops there.
//
// It is not a QUIC client. chapulin owns every key and every packet's protection; the
// caller owns everything that is not cryptography, from packet numbers to loss recovery to
// streams. docs/quic.md, "What the mode does not do", lists the split in full. The object
// opens no socket and calls no I/O callback. Zero heap holds as it does over TCP: one
// ch_quic, one caller-supplied buffer, no allocation. Configuration and result codes live
// in cfg.h, the session struct under it in session.h, and ch_rand_bytes in rand.h. No call
// here polls for keys: RFC 9001 §4.1.4 says the availability of new keys is always a result
// of providing inputs to TLS (rfc9001.txt:530-531), so cfg.on_level_ready fires from inside
// ch_quic_crypto_in and the caller collects what a delivery produced.
//
// Result codes, in one sentence each. CH_OK means the call did what it says. CH_EINVAL
// means the caller called out of order, nothing changed, and the same call may run again
// later. CH_ECAP means two different things: from ch_quic_crypto_out and the two seal calls
// the caller's own buffer was short, nothing was consumed, and the same call may run again
// with a larger one; from ch_quic_crypto_in it is a peer message that could never fit
// cfg.buf_len, and it leaves the session dead like every other error from that call. cfg.h
// states CH_QUIC_DISCARD and CH_QUIC_AEAD_LIMIT, which ch_quic_open alone returns. Every
// other error means the session is now dead: ch_quic_alert names the TLS alert,
// ch_quic_error_code the transport error code the caller puts in CONNECTION_CLOSE, and
// ch_quic_seal_close seals that frame once at each level whose write keys the session had.
#ifndef CH_QUIC_H
#define CH_QUIC_H
#ifdef CH_TRANSPORT_QUIC

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "handshake_record.h"
#include "quic_gcm.h"
#include "quic_keys.h"
#include "quic_step.h"
#include "session.h"

// The bit ch_quic.levels_ready holds for one direction at one encryption level. level is
// a CH_LEVEL_ value and direction is CH_KEY_READ or CH_KEY_WRITE (cfg.h), so the six bits
// of the three levels sit in the low six bits of one byte. Both arguments are the
// caller's own public values, never a secret, so the shift is an ordinary index.
#define CH_QUIC_LEVEL_BIT(level, direction) ((uint8_t)(1U << ((level) * 2 + (direction))))

// One QUIC session. It holds everything that survives a return, because the driver returns
// to its caller between handshake messages: the ch_tls a TLS build holds alone, the
// handshake_state a TLS build keeps on ch_handshake's stack frame, the driver's own fields,
// and the packet protection keys of every encryption level. docs/quic.md, "The state that
// survives a return", states the bound each field's proof harness assumes. The caller
// declares one and passes its address to every call. It is not copyable: hs.t points at t,
// and every public entry rewrites that pointer to its own &q->t, so a copy cannot leave a
// dangling pointer inside a step.
//
// Two traffic secrets sit in t rather than here, and every 1-RTT derivation rests on which
// key set each names: t.wr_secret is the traffic secret of app_tx, and t.rd_secret that of
// app_rx[CH_QUIC_KEY_NEXT], not of app_rx[CH_QUIC_KEY_CURRENT]. session.h states why beside
// the two fields, with what a build that kept the current phase's secret would get wrong.
typedef struct ch_quic {
    ch_tls t;
    // The flight handlers' working state, wiped at HSQ_STEP_COMPLETE, one round trip
    // earlier than the TLS driver wipes its frame, which is INV-17's rule that handshake
    // secrets die at CONNECTED.
    handshake_state hs;
    uint8_t step;     // HSQ_STEP_*, quic_step.h
    uint8_t rx_level; // the one level whose CRYPTO bytes cfg.buf holds
    uint8_t tx_level; // the level the staged message goes out at
    uint8_t alert;    // what ch_quic_alert reports after a failure
    uint8_t endpoint; // CH_QUIC_ENDPOINT_*, the side its init call gave it (quic.c's CH_QUIC_SELF)
    size_t tx_len;    // bytes staged in t.tx; 0 when nothing is owed
    // The Key Phase bit the current 1-RTT send set carries, 0 or 1 (RFC 9001 §6.1,
    // rfc9001.txt:1615-1616). ch_quic_key_phase reports it and ch_quic_key_update toggles
    // it.
    uint8_t key_phase;
    // The QUIC transport error code a step or an entry wrote, and 0 when none did. Only
    // quic_fail and the steps that owe 0x0a write it, and ch_quic_error_code states the
    // one rule that turns this field, q->alert and q->t.state into the answer a caller
    // puts in CONNECTION_CLOSE.
    uint64_t error_code;
    // Which encryption levels can protect or unprotect packets right now, one bit per
    // level per direction at CH_QUIC_LEVEL_BIT above. The packet calls and
    // ch_quic_discard read it, and it is the only answer to "installed and not
    // discarded": a key set of all-zero bytes is a legitimate derivation, so no call
    // decides that question by comparing key bytes. ch_quic_initial_keys sets both
    // CH_LEVEL_INITIAL bits, and the step that fires cfg.on_level_ready for a later level
    // sets that level's bits in the same call, so the caller's view and this field agree.
    // ch_quic_discard clears both bits of one level and ch_quic_close clears every bit. A
    // failure clears every read bit and keeps the write bits, each of which then admits
    // one ch_quic_seal_close, which clears it. docs/quic.md's state table has its row.
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
    // The 1-RTT level: one send set, and three receive sets indexed by
    // CH_QUIC_KEY_PREVIOUS, CH_QUIC_KEY_CURRENT and CH_QUIC_KEY_NEXT (cfg.h) and by no
    // computed index. §6.3 makes the current and the next set a floor
    // (rfc9001.txt:1711-1712); the previous set is this design's choice, so a packet
    // delayed across a key update still opens (§6.5). The header protection keys are
    // written once and never updated (§6.1, rfc9001.txt:1607).
    quic_keys app_tx;
    quic_keys app_rx[CH_QUIC_KEY_SETS];
    quic_hp_key app_hp_rx, app_hp_tx;
    // RFC 9001 §6.6's two counts. open_failures counts received packets that failed
    // authentication in this connection, across every level and every key, because the
    // limit is stated that way (rfc9001.txt:1823-1827). initial_sealed counts packets
    // sealed under the Initial keys, the only keys here whose AEAD pays a confidentiality
    // limit (rfc9001.txt:1812-1813); a Retry does not reset it, so one count covers both key
    // sets.
    uint64_t open_failures;
    uint64_t initial_sealed;
} ch_quic;

// Validates the configuration, prepares the state machine and builds the ClientHello into
// the session's staging area. It sends nothing: the caller takes those bytes with
// ch_quic_crypto_out at CH_LEVEL_INITIAL.
//
// It zeroes q, copies cfg into q->t.cfg, and applies the checks ch_connect applies over
// TCP, minus cfg.send and cfg.recv, which have no meaning here. It keeps the ALPN
// configuration checks, and adds three rules of its own: cfg.transport_params is not NULL
// and its length is 1 to CH_TRANSPORT_PARAMS_MAX (§8.2, rfc9001.txt:1929-1936),
// cfg.on_level_ready is not NULL, and the ALPN offer names at least one protocol, because
// §8.1 makes ALPN mandatory for QUIC (rfc9001.txt:1891-1895).
//
// It keeps the buffer floor too, cfg.buf_len >= CH_MIN_RXBUF, which under this build is
// CH_QUIC_MIN_RXBUF and nothing else (cfg.h): a QUIC client sends no record_size_limit
// (RFC 9001 §4.1.3), so cfg.buf_len is the only bound a peer meets. Requires: q and cfg
// are not NULL, and cfg outlives the session, as over TCP, because q->t.cfg copies
// pointers and not the bytes named.
//
// Returns CH_OK, with one whole ClientHello staged, q->tx_len set, q->tx_level and
// q->rx_level CH_LEVEL_INITIAL, q->step HSQ_STEP_AWAIT_SERVER_HELLO and q->t.state
// CH_ST_START. Returns CH_EINVAL for any refusal above, leaving q zeroed but for
// q->t.state, which is CH_ST_FAILED, so no later call runs; nothing went out and no secret
// was drawn that a caller must wipe.
int ch_quic_init(ch_quic *q, const ch_cfg *cfg);

// Stores the Destination Connection ID that RFC 9001 §5.2 derives the Initial secrets
// from, beside its printed salt (rfc9001.txt:1051-1066), and marks both directions of the
// Initial level ready. Appendix A.1 is the vector for what the packet calls then derive.
//
// The caller calls it once before it sends its first Initial packet, and again after a
// Retry, because §5.2 changes the secrets then (rfc9001.txt:1092-1094): dcid is then the
// Source Connection ID the server sent, which RFC 9000 §17.2.5.2 makes the new Destination
// Connection ID. Replacing the connection ID is not a key update, and it does not reset
// q->initial_sealed, so one §6.6 count covers both key sets.
//
// Requires: q is initialized and its session is live; dcid points at dcid_len readable
// bytes, read only when dcid_len is above 0. A zero-length dcid is legal: §5.2 allows a
// zero-length Source Connection ID in a Retry (rfc9001.txt:1098-1100).
//
// Returns CH_OK, writes q->initial_dcid and q->initial_dcid_len, and sets both
// CH_LEVEL_INITIAL bits in q->levels_ready. It derives and stores no key: ch_quic_seal and
// ch_quic_open derive the one direction's key they need from these bytes at each packet,
// which is INV-26. A call after ch_quic_discard at that level sets the bits again, which is
// how a Retry reinstalls keys the caller had dropped.
//
// Returns CH_EINVAL and writes neither field when dcid_len is above CH_QUIC_DCID_MAX, RFC
// 9000 §17.2's cap on a version 1 connection ID, or when the session is dead. The check
// runs first, so a refusal leaves both fields as they were and the session live.
int ch_quic_initial_keys(ch_quic *q, const uint8_t *dcid, size_t dcid_len);

// Delivers the n bytes that CRYPTO frames carried at one encryption level and runs the
// state machine over them. This is the one call that advances the handshake and the one
// suspension point: it copies what fits into cfg.buf, runs one step per whole handshake
// message, and returns when the bytes run out.
//
// Requires: q is initialized; level is a CH_LEVEL_ value; p points at n readable bytes
// outside cfg.buf. Requires the caller contract cfg.h states: each level's bytes arrive
// once and in order, and bytes chapulin has consumed are never delivered again, because
// chapulin stores no CRYPTO stream offset and cannot tell a retransmission from new data.
// The callbacks this call fires must not call back into q.
//
// Returns CH_OK when it consumed all n bytes: either the driver needs more bytes at this
// level, or it finished the ones it got. The caller then checks ch_quic_crypto_out for a
// message it owes and ch_quic_state for completion. Returns CH_EINVAL, and consumes and
// changes nothing, when level is above CH_LEVEL_APPLICATION, when q->tx_len is not 0
// because the caller has not taken the staged message yet, or when level is above
// q->rx_level while no byte sits unconsumed. That last one is no peer error: §4.1.3 leaves
// bytes at a level whose keys are not installed for QUIC to hold (rfc9001.txt:488-490),
// and the caller may deliver them again once the keys arrive.
//
// Returns CH_EPROTO and leaves the session dead in four cases, and ch_quic_error_code
// reports 0x0a, PROTOCOL_VIOLATION, for the first three: a delivery at a level below
// q->rx_level, which extends data past what was already received at a level this client
// has left (rfc9001.txt:482-486); a delivery at a level above q->rx_level while bytes sit
// unconsumed at the lower one, §4.1.3's other rule (rfc9001.txt:491-493); a step that
// moved q->rx_level or staged a message and left a byte in cfg.buf, that same rule
// checked after the step; and a session already failed or closed, which returns without
// reading a byte. Every other error comes from the step — CH_EPROTO, CH_EAUTH or CH_ECAP —
// and leaves the session dead with its alert in ch_quic_alert. The CH_ECAP here is the
// peer's, not the caller's: hsr_peek_message answers it with ALERT_INTERNAL_ERROR for a
// message header naming a body that could never fit cfg.buf_len, which is a failure rather
// than a call to retry.
int ch_quic_crypto_in(ch_quic *q, uint8_t level, const uint8_t *p, size_t n);

// Hands out the one handshake message the client owes at that level, whole or not at all.
// The caller frames it into CRYPTO frames and keeps the bytes for retransmission, which
// RFC 9001 §4.9 leaves to QUIC. Refusing a partial drain keeps an offset out of the saved
// state: no field says how much of a message has gone out. Requires: q is initialized and
// live; level is a CH_LEVEL_ value; out points at cap writable bytes; out_len is not NULL.
//
// Returns CH_OK and writes 0 to *out_len when nothing is owed at that level, which is
// every level while q->tx_len is 0. Returns CH_OK and writes the whole message and its
// length when level is q->tx_level, and then clears q->tx_len, so the next call at that
// level answers 0. When the bytes handed out are the client Finished, q->t.state becomes
// CH_ST_CONNECTED in that same call, the moment §4.1.1 names: this stack has sent its
// Finished and verified the peer's.
//
// Returns CH_ECAP, consumes nothing and leaves *out_len alone when cap is shorter than the
// staged message. That short buffer is the caller's, not the peer's, so the session stays
// live and the caller calls again with a larger one. Returns CH_EINVAL and changes nothing
// when level is above CH_LEVEL_APPLICATION or the session is dead.
int ch_quic_crypto_out(ch_quic *q, uint8_t level, uint8_t *out, size_t cap, size_t *out_len);

// Protects one packet and writes it whole into out: the nonce from the packet protection
// IV and the packet number, the unprotected header as the associated data (RFC 9001 §5.3,
// rfc9001.txt:1135-1143), then the header protection mask over byte 0 and the pn_len
// packet number bytes (§5.4, rfc9001.txt:1188-1211). Packet protection runs before header
// protection, the order §5.3 states (rfc9001.txt:1129-1132). It modifies neither hdr nor
// pt: it copies the hdr_len header bytes into out, seals pt after them, writes the 16-byte
// tag, and masks the copy in out. hdr carries the packet number field the caller encoded,
// so hdr_len counts those bytes, pn_len says how many of the last ones they are, and pn is
// that same number. At CH_LEVEL_APPLICATION the caller has already written byte 0's Key
// Phase bit from ch_quic_key_phase, and this call only masks that byte.
//
// Requires: q is initialized and live; CH_QUIC_LEVEL_BIT(level, CH_KEY_WRITE) is set in
// q->levels_ready; hdr points at hdr_len readable bytes, pt at pt_len readable bytes, out
// at cap writable bytes overlapping neither; pn is below 2^62, the range RFC 9000 §17.1
// gives the field; out_len is not NULL.
//
// Returns CH_OK, writes hdr_len + pt_len + 16 bytes into out and that same count into
// *out_len. Returns CH_ECAP and writes nothing, leaving *out_len alone, when cap is below
// that sum.
//
// Returns CH_EINVAL and writes nothing when the session is dead, when level is above
// CH_LEVEL_APPLICATION, when that send bit is clear in q->levels_ready because the level's
// keys were never installed or were discarded, when pn_len is 0 or above 4, when hdr_len
// is below pn_len, or when pn_len + pt_len is below 4. That last refusal is §5.4.2's rule
// that the encoded packet number and the protected payload run at least 4 bytes past the
// sample (rfc9001.txt:1283-1286), which keeps the 16-byte sample inside out; writing the
// padding is the caller's, because the caller frames the packet. The boundary test is that
// pn_len + pt_len == 4 seals and 3 refuses.
//
// RFC 9001 §9.5 makes pn and pn_len secret bytes here (rfc9001.txt:2114-2116). The length
// refusals above are the only reads of pn_len that decide a branch, they run before any
// byte is sealed, and they reveal only a length the caller passed; quic_packet.h states
// what the steps that produce bytes owe.
//
// At CH_LEVEL_INITIAL the call counts what it seals in q->initial_sealed and refuses the
// 2^23rd packet, §6.6's confidentiality limit for AEAD_AES_128_GCM
// (rfc9001.txt:1800-1813), one packet stricter than the RFC.
//
// That refusal returns CH_EINVAL. docs/quic.md states the refusal, names no code, and
// makes CH_QUIC_DISCARD and CH_QUIC_AEAD_LIMIT ch_quic_open's alone, which leaves this
// one. It invites another call, which §6.6 answers by refusing that one too: the count
// only rises, so every later seal at this level returns CH_EINVAL and no packet goes out
// under those keys.
int ch_quic_seal(ch_quic *q, uint8_t level, uint64_t pn, size_t pn_len, const uint8_t *hdr,
                 size_t hdr_len, const uint8_t *pt, size_t pt_len, uint8_t *out, size_t cap,
                 size_t *out_len);

// The largest packet ch_quic_seal_close seals, header and tag included: RFC 9000 §14's
// smallest maximum datagram size, which every QUIC path carries (rfc9000.txt:4598-4599).
#define CH_QUIC_CLOSE_MAX 1200

// Seals the one CONNECTION_CLOSE packet a failed session sends at one level (RFC 9001
// §4.8), then wipes that level's write keys (docs/decisions.md 57). It takes ch_quic_seal's
// arguments, requirements and argument refusals. pt is one CONNECTION_CLOSE frame of type
// 0x1c and nothing else: chapulin builds no frame and cannot check one without parsing
// QUIC frames, which the caller owns. A client whose Initial datagram must be at least 1200
// bytes pads the datagram after this packet, as RFC 9000 §14.1 allows
// (rfc9000.txt:4645-4647). Requires: q->t.state is CH_ST_FAILED and
// CH_QUIC_LEVEL_BIT(level, CH_KEY_WRITE) is set, which a failure leaves at each level
// whose write keys were installed and not discarded.
//
// Returns CH_OK, writes the packet and *out_len as ch_quic_seal does, wipes that level's
// write keys and clears its write bit, so a second call at that level returns CH_EINVAL.
// Returns CH_ECAP when cap is short, and CH_EINVAL when the session has not failed, when
// that bit is clear, when hdr_len + pt_len + 16 is above CH_QUIC_CLOSE_MAX, or for a
// refusal ch_quic_seal lists; both change nothing, so the keys stay for a later call.
int ch_quic_seal_close(ch_quic *q, uint8_t level, uint64_t pn, size_t pn_len, const uint8_t *hdr,
                       size_t hdr_len, const uint8_t *pt, size_t pt_len, uint8_t *out, size_t cap,
                       size_t *out_len);

// Removes header protection, recovers the packet number and removes packet protection from
// one packet, in place in pkt. The three run in one call because RFC 9001 §9.5 requires
// them applied together without timing and other side channels (rfc9001.txt:2110-2112),
// which is also why the recovered packet number is an output: the caller has no other
// source for it, and recovering it outside would put that step outside the function §9.5
// names.
//
// At CH_LEVEL_APPLICATION it selects the receive key set by §6.5's rule rather than by the
// Key Phase bit alone, because the previous and the next phase carry the same bit value
// (rfc9001.txt:1735-1737): the bit picks the phase, and when it differs from the current
// phase's bit the recovered packet number decides (rfc9001.txt:1739-1743) — below
// current_phase_lowest_pn the previous keys open the packet, at or above it the next keys
// do. That keeps §5.5's MUST against opening a higher-numbered packet under the previous
// keys (rfc9001.txt:1365-1369).
//
// Requires: q is initialized and live; CH_QUIC_LEVEL_BIT(level, CH_KEY_READ) is set in
// q->levels_ready; pkt points at pkt_len readable and writable bytes holding one whole
// packet the caller owns and has already separated from the rest of the datagram; pn_off
// is the offset of the packet number field, which the caller read from the header it
// framed, and is at most pkt_len; largest_pn is the largest packet number the caller has
// successfully processed in that packet number space, or 0 before the first (RFC 9000
// Appendix A.3, rfc9000.txt:8350-8351); current_phase_lowest_pn is the lowest it has
// processed under the current key phase and is read at CH_LEVEL_APPLICATION alone;
// key_set, pn and pt_len are not NULL.
//
// Returns CH_OK. The unprotected header then sits at the front of pkt, the plaintext
// follows at pn_off + pn_len, *pt_len is that plaintext's length in bytes, *pn is the
// recovered packet number, and *key_set is the set that opened the packet:
// CH_QUIC_KEY_PREVIOUS, CH_QUIC_KEY_CURRENT or CH_QUIC_KEY_NEXT, and CH_QUIC_KEY_CURRENT at
// every level but CH_LEVEL_APPLICATION. The caller reads byte 0 of pkt for the reserved
// bits, the Key Phase bit and the packet number length, feeds *pn to the next call's
// largest_pn, and, on CH_QUIC_KEY_NEXT, calls ch_quic_key_update before it seals the
// acknowledgment, which §6.2 makes mandatory (rfc9001.txt:1654-1656).
//
// Returns CH_QUIC_DISCARD, writes none of the three outputs and leaves the session live in
// two cases, which differ in what they count. A packet shorter than pn_off + 4 + 16 cannot
// hold a complete sample, so §5.4.2 discards it before it is read
// (rfc9001.txt:1280-1281); it never reaches the AEAD, so no field of q changes at all,
// q->open_failures included, because §6.6 counts received packets that fail authentication
// (rfc9001.txt:1823-1827). A packet whose tag does not match is that authentication
// failure, which §5.5 says does not necessarily indicate a protocol error or an attack
// (rfc9001.txt:1373-1376): it raises q->open_failures and changes nothing else.
//
// Neither case installs a key set or derives one, so a packet that appears to trigger a
// key update and then fails to authenticate changes nothing at all, which is §5.5's second
// MUST (rfc9001.txt:1369-1371); §6.3 gives the reason, that such packets are easy to forge
// (rfc9001.txt:1706-1707). The bytes of a packet that reached the AEAD are unspecified
// after a discard, because the call works in place.
//
// Returns CH_QUIC_AEAD_LIMIT from the call that carries q->open_failures past §6.6's
// integrity limit of 2^36 invalid packets (rfc9001.txt:1823-1831). The session is then
// dead and no later call processes a packet; the caller sends CONNECTION_CLOSE with
// AEAD_LIMIT_REACHED.
//
// Returns CH_EINVAL and changes nothing when the session is dead, when level is above
// CH_LEVEL_APPLICATION, when that receive bit is clear in q->levels_ready because the
// level's keys were never installed or were discarded, or when level is
// CH_LEVEL_APPLICATION while q->t.state is below CH_ST_CONNECTED. That last refusal is
// §5.7, which forbids a client from processing a 1-RTT packet before the TLS handshake is
// complete even when it already holds the keys (rfc9001.txt:1484-1486): the caller buffers
// the packet and delivers it again once ch_quic_state reports CH_ST_CONNECTED.
int ch_quic_open(ch_quic *q, uint8_t level, uint8_t *pkt, size_t pkt_len, size_t pn_off,
                 uint64_t largest_pn, uint64_t current_phase_lowest_pn, uint8_t *key_set,
                 uint64_t *pn, size_t *pt_len);

// Recomputes RFC 9001 §5.8's Retry Integrity Tag over the Retry pseudo-packet the caller
// built and compares it with ct_memeq against the tag the packet carried, under the key
// and the nonce §5.8 prints (rfc9001.txt:1499-1502). Appendix A.4 is the vector.
//
// It is a predicate: it reads no session field and writes none, so it answers a verdict
// and not a ch_err code. Its return type is uint8_t for that reason, and not the int every
// other entry here returns: a caller cannot compare a uint8_t against a ch_err without the
// compiler saying so, and a caller that tested it against CH_OK would otherwise accept
// exactly the forged Retry packets RFC 9000 §17.2.5.2 makes it discard. A 0 fails nothing
// by itself. §17.2.5.2 makes discarding the Retry the caller's step
// (rfc9000.txt:5407-5411), as are that section's other three rules, which read fields
// chapulin does not parse.
//
// Requires: q is initialized; pseudo points at n readable bytes and is the pseudo-packet
// §5.8 defines, which the caller builds; tag points at GCM_TAG readable bytes. The caller
// checks the pseudo-packet's shape, because a wrong one produces a 0 and no diagnosis. q
// is unread, because §5.8 prints the key and the nonce; docs/quic.md gives the call q.
//
// Returns 1 for a matching tag and 0 otherwise, in a time that depends on n alone.
uint8_t ch_quic_retry_ok(const ch_quic *q, const uint8_t *pseudo, size_t n,
                         const uint8_t tag[GCM_TAG]);

// Runs RFC 9001 §6's packet-level key update on the 1-RTT keys. It advances the send
// secret with the "quic ku" label (§6.1, rfc9001.txt:1605-1613), rewrites the send packet
// protection key and IV from it, and toggles q->key_phase, the bit the caller must set in
// byte 0 of every 1-RTT header it seals from then on (rfc9001.txt:1615-1616). On the
// receive side it moves the current set to CH_QUIC_KEY_PREVIOUS and holds it, promotes
// CH_QUIC_KEY_NEXT to CH_QUIC_KEY_CURRENT, and derives a new next set.
//
// That is two quic_keys_update calls and no other derivation, under the invariant the
// ch_quic comment above states: quic_keys_update(q->t.wr_secret, &q->app_tx) for the send
// side, and, after the two moves, quic_keys_update(q->t.rd_secret,
// &q->app_rx[CH_QUIC_KEY_NEXT]), which leaves t.rd_secret naming the new next set again.
// The HSQ_STEP_AWAIT_FINISHED step runs that same receive call once (quic_step.h),
// which makes the invariant true from the first 1-RTT packet on. The moves copy key sets
// and derive nothing.
//
// It derives the next set here rather than while opening a packet, because §6.3 makes
// deriving a set during an open a timing signal an attacker reads (rfc9001.txt:1692-1696).
// It leaves both 1-RTT header protection keys alone (§5.4, rfc9001.txt:1172-1174; §6.1,
// rfc9001.txt:1607), and it drops no set, because §6.1 makes an endpoint retain its old
// keys until a packet under the new keys opens (rfc9001.txt:1637-1638);
// ch_quic_drop_previous_keys wipes that one.
//
// Requires: q is initialized and q->t.state is CH_ST_CONNECTED. The caller initiates
// under §6.1's two MUST NOTs, not before the handshake is confirmed and not before a
// packet under the current keys was acknowledged (rfc9001.txt:1618-1621), and responds
// under §6.2 when ch_quic_open reports CH_QUIC_KEY_NEXT, where this call is mandatory
// before the acknowledgment is sealed. chapulin holds neither the acknowledgments nor the
// HANDSHAKE_DONE frame, so it checks neither.
//
// Returns CH_OK, with the send set, the three receive sets and q->key_phase updated.
// Returns CH_EINVAL and changes nothing, leaving every key set and q->key_phase as they
// were, when the session is dead or q->t.state is below CH_ST_CONNECTED, because there is
// then no 1-RTT set to advance.
int ch_quic_key_update(ch_quic *q);

// Reports q->key_phase, the Key Phase bit the current 1-RTT send set carries, which the
// caller writes into byte 0 of every short header before it seals it. chapulin holds the
// send key and the bit that names it, so the two cannot disagree (RFC 9001 §6.1,
// rfc9001.txt:1615-1616). Requires: q is initialized. Returns 0 or 1, and 0 before the
// 1-RTT keys exist. It cannot fail and changes nothing.
uint8_t ch_quic_key_phase(const ch_quic *q);

// Wipes the previous 1-RTT receive key set, after which a packet from the old key phase is
// a discard rather than an open. The caller calls it when its own PTO-based timer ends the
// retention period RFC 9001 §6.5 leaves to the endpoint: the keys are here and the timer
// is there. Requires: q is initialized. It is idempotent, and a call before any key update
// wipes a set that is already zero. Returns nothing: a wipe has no failure to report.
void ch_quic_drop_previous_keys(ch_quic *q);

// Wipes that encryption level's key sets in both directions, and its header protection
// keys with them. RFC 9001 §4.9.1 makes a client discard Initial keys when it first sends
// a Handshake packet (rfc9001.txt:942-946) and §4.9.2 makes it discard Handshake keys
// when the handshake is confirmed (rfc9001.txt:953-954). Both events are the caller's to
// see, because chapulin sends no packet and reads no frame.
//
// It clears both of that level's bits in q->levels_ready, which the packet calls read, so
// every packet call at that level then returns CH_EINVAL and changes nothing, the code
// that leaves the session live: a packet under discarded keys is one the caller drops, not
// a peer error. The same bits answer for keys never installed. CRYPTO bytes at a level
// this client has left are the other rule: ch_quic_crypto_in fails the session with
// CH_EPROTO and reports 0x0a (§4.1.3, rfc9001.txt:482-486).
//
// Requires: q is initialized. Discarding a level twice is harmless, and so is discarding
// one whose keys were never installed. Returns CH_OK once that level's keys are zero and
// both its bits in q->levels_ready are clear, and CH_EINVAL, wiping nothing and clearing
// no bit, when level is above CH_LEVEL_APPLICATION.
int ch_quic_discard(ch_quic *q, uint8_t level);

// Reports q->t.state: CH_ST_START, CH_ST_CONNECTED, CH_ST_CLOSED or CH_ST_FAILED
// (session.h). CH_ST_CONNECTED is the handshake complete in the sense of RFC 9001 §4.1.1
// — this stack has sent its Finished and verified the peer's — and it is never reported
// while the Finished is still staged, because ch_quic_crypto_out raises it in the call
// that hands those bytes out. It reports complete, never confirmed: §4.1.2 makes the
// client's confirmation the receipt of a HANDSHAKE_DONE frame (rfc9001.txt:417-418), which
// chapulin never sees. Requires: q is initialized. It cannot fail and changes nothing.
uint8_t ch_quic_state(const ch_quic *q);

// Reports the TLS alert description behind the failure that killed the session (RFC 9846
// §6): unexpected_message, decode_error, no_application_protocol and the rest, as
// handshake_message.h spells them. ch_quic_error_code is what the caller puts on the wire;
// this call names the alert behind it, for a log or a test. Requires: q is initialized.
// Returns 0 while no failure has happened, which is close_notify and never a failure's
// description here. It cannot fail and changes nothing.
uint8_t ch_quic_alert(const ch_quic *q);

// Reports the QUIC transport error code the caller sends in CONNECTION_CLOSE (RFC 9001
// §4.8), as a uint64_t because that field is a variable-length integer (RFC 9000 §19.19,
// rfc9000.txt:6670-6671), though every value this mode produces fits in 16 bits.
//
// One rule answers, in this order, and nothing else does: 0, QUIC's NO_ERROR, when
// q->t.state is not CH_ST_FAILED; q->error_code verbatim when it is not 0; and
// 0x0100 + q->alert otherwise. So a live session and a session the caller closed both
// report 0, and no call fabricates a code for a session that never failed. A caller that
// wants to say why a failed session died reads this before ch_quic_close, which sets
// CH_ST_CLOSED over CH_ST_FAILED.
//
// q->error_code holds 0x0a, PROTOCOL_VIOLATION, for the four refusals RFC 9001 makes a
// connection error of that type, and nothing else writes it: the two §4.1.3 level rules
// ch_quic_crypto_in states, a post-handshake CertificateRequest (§4.4,
// rfc9001.txt:735-738), and a NewSessionTicket whose early_data names any
// max_early_data_size but 0xffffffff (§4.6.1, rfc9001.txt:808-809). Every other failure
// takes the 0x0100 + q->alert branch, which is how §4.8 carries a TLS alert, a KeyUpdate
// included: it reports 0x010a (§6, rfc9001.txt:1566-1568).
//
// Requires: q is initialized. It cannot fail and changes nothing.
uint64_t ch_quic_error_code(const ch_quic *q);

// Ends the session: it wipes every secret a ch_quic_discard has not wiped yet — the
// handshake state, the traffic secrets, every packet protection key set and every header
// protection key — clears every bit of q->levels_ready, and sets q->t.state to
// CH_ST_CLOSED, after which every call above returns CH_EINVAL or CH_EPROTO and no call
// protects a packet. It sends nothing and builds nothing: QUIC carries no TLS alert record
// and the CONNECTION_CLOSE frame is the caller's (RFC 9001 §4.8), so a caller that wants
// to say why reads ch_quic_error_code and calls ch_quic_seal_close first.
//
// Requires: q is initialized. It is idempotent. On a failed session it wipes the write
// keys the failure kept, whether or not ch_quic_seal_close used them. Returns nothing.
void ch_quic_close(ch_quic *q);

#endif // CH_TRANSPORT_QUIC
#endif
