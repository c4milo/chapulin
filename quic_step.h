// The QUIC driver's step table: the step numbers ch_quic.step stores
// and the one function that runs a step. RFC 9001 §4.1.3 takes the
// unprotected content of TLS handshake records as the content of CRYPTO
// frames (rfc9001.txt:462-464), so this client no longer drives a
// socket and cannot block on one. The driver returns to its caller
// between handshake messages, and the step number is what it resumes
// from.
//
// One whole handshake message per step. A step runs only when a whole
// message already sits in cfg.buf, it consumes that one message, and
// nothing inside it waits. So a step needs no resume point of its own,
// and the saved state is a step number rather than a program counter.
//
// This file holds no protocol logic. handshake_flight.[ch] holds the
// handlers both transports compile, handshake_auth.[ch] the server
// authentication flight, and handshake_post.[ch] the messages that
// arrive after the handshake. The step functions are static in
// handshake_step.c, where each one calls those handlers; hsq_advance is
// the only entry point, so the driver's harness can stub it and a step
// harness can reach the static functions by #include.
//
// Only a TRANSPORT=quic build compiles it. docs/quic.md, "Suspending
// the driver", states the design and the state each step leaves behind.
#ifndef CH_QUIC_STEP_H
#define CH_QUIC_STEP_H
#ifdef CH_TRANSPORT_QUIC

#include "cfg.h"

// quic.h completes this type. The declaration is repeated here rather
// than included so the dependency keeps pointing down: quic.[ch] sits
// above this pair in the chain CLAUDE.md states, handshake_step.c
// includes quic.h, and quic.h includes this file for the step numbers.
// C11 allows a typedef name to be declared twice for the same type.
typedef struct ch_quic ch_quic;

// The step numbers. Each names the handshake message the driver waits
// for, and they mirror the client states spec/Spec/Handshake.lean's
// State inductive carries, constructor for constructor: start,
// retried, gotSH, awaitCert, awaitCV, awaitFin and connected. The
// mirror is what lets one oracle judge both transports.
//
// They are uint8_t values rather than an enum, the style CH_ST_START
// and its neighbours already use (session.h), and ch_quic.step stores
// one. The values are consecutive from 0 and HSQ_STEP_COMPLETE is the
// largest, which is the fact hsq_advance's default arm rests on.
#define HSQ_STEP_AWAIT_SERVER_HELLO 0
#define HSQ_STEP_AWAIT_RETRY_HELLO 1
#define HSQ_STEP_AWAIT_ENCRYPTED_EXTENSIONS 2
#define HSQ_STEP_AWAIT_CERTIFICATE 3
#define HSQ_STEP_AWAIT_CERTIFICATE_VERIFY 4
#define HSQ_STEP_AWAIT_FINISHED 5
#define HSQ_STEP_COMPLETE 6

// Runs the one step q->step names, over the one whole handshake
// message that starts at q->t.cfg.buf + q->t.pt_off. It is the only
// switch in the mode: it dispatches and does nothing else, so every
// path into a handler runs through a step number a step wrote.
//
// Requires: q is not NULL; q->hs.t is &q->t, which every public entry
// rewrites before it calls here; q->t.state is CH_ST_START or
// CH_ST_CONNECTED, so a dead session never reaches a step. Both values
// reach HSQ_STEP_COMPLETE: ch_quic_crypto_out raises q->t.state when it
// hands the client Finished out, so a NewSessionTicket that arrives
// before the caller has drained that message runs this step with
// q->t.state still CH_ST_START. And
// hsr_peek_message has answered CH_OK for the unread bytes, which is
// what makes the message whole. The caller checks all of it. A step
// that reads no message is not in the table: hsq_advance is called once
// per whole message and never speculatively.
//
// Returns CH_OK when the step ran. On CH_OK the step may have raised
// q->step, moved q->rx_level, written one message into q->t.tx and set
// q->tx_len and q->tx_level, installed the key sets of one named
// encryption level and set that level's two bits in q->levels_ready,
// fired cfg.on_level_ready twice for that level and
// cfg.on_transport_params once, and wiped q->hs at HSQ_STEP_COMPLETE.
// It always consumes the message: q->t.pt_off advances past it.
//
// It never raises q->t.state. ch_quic_crypto_out does that in the call
// that hands the client Finished out (quic.h), which is the moment RFC
// 9001 §4.1.1 names: the stack has sent its Finished and verified the
// peer's. A step that raised it would report the handshake complete
// while those bytes were still staged, and a caller may install and use
// 1-RTT keys on that report.
//
// It installs no 1-RTT receive key set beyond the two the
// HSQ_STEP_AWAIT_FINISHED step derives, and it never touches
// q->open_failures, q->initial_sealed or q->key_phase, which belong to
// the packet calls.
//
// What the HSQ_STEP_AWAIT_FINISHED step derives, and the invariant it
// leaves true. It writes app_tx from q->t.wr_secret, writes
// app_rx[CH_QUIC_KEY_CURRENT] from q->t.rd_secret, and then runs one
// quic_keys_update(q->t.rd_secret, &q->app_rx[CH_QUIC_KEY_NEXT]), which
// advances that secret once with the "quic ku" label and writes the
// next set from it. So the next set exists before any packet arrives
// under it, and q->t.rd_secret afterwards names the next set rather
// than the current one, which is the invariant session.h states and
// ch_quic_key_update depends on. app_rx[CH_QUIC_KEY_PREVIOUS] stays
// zero until the first ch_quic_key_update.
//
// Returns CH_EPROTO, CH_EAUTH, CH_ECAP or CH_EINVAL from the handler
// the step ran, with the alert in q->hs.alert and, for the four
// refusals RFC 9001 makes a connection error of type PROTOCOL_VIOLATION
// (§4.1.3, §4.4, §4.6.1), the transport error code in q->error_code.
// It does not wipe the session and does not set CH_ST_FAILED: the
// caller turns any error into quic_fail, which copies the alert out,
// wipes every secret and marks the session dead. So an error leaves
// q->step and q->rx_level wherever the failed step left them, and no
// later call reads either.
//
// Returns CH_EPROTO with ALERT_UNEXPECTED_MESSAGE from the default arm
// for any step value above HSQ_STEP_COMPLETE. That arm is what a
// one-byte corruption of q->step meets: it kills the session instead of
// running a handler or reaching ch_assert_fail, because the step number
// is data a fault can reach and CH_ASSERT is for programmer error
// alone. A step value inside the table always has a handler, so the
// default arm answers nothing else.
int hsq_advance(ch_quic *q);

#endif // CH_TRANSPORT_QUIC
#endif
