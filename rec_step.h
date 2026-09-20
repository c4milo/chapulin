// The record-mode driver's step table: the step numbers ch_rec.step
// stores and the one function that runs a step.
//
// It is quic_step.h's table for the other transport, and the steps are
// the same seven because the handshake is the same handshake: the
// handlers in handshake_flight.[ch] and handshake_auth.[ch] decide what
// each message says, and this file decides only which one runs next.
// What differs from the QUIC table is where the keys land — rec_dir over
// records, packet protection over QUIC — and that a record has no
// encryption level to track.
//
// One whole handshake message per step. A step runs only when a whole
// message already sits in cfg.buf, it consumes that one message, and
// nothing inside it waits. So a step needs no resume point of its own,
// and the saved state is a step number rather than a program counter.
//
// Only a TRANSPORT=record build compiles it.
#ifndef CH_REC_STEP_H
#define CH_REC_STEP_H
#ifdef CH_TRANSPORT_RECORD

#include "cfg.h"

// rec.h completes this type. The declaration is repeated here rather
// than included so the dependency keeps pointing down, the way
// quic_step.h repeats ch_quic. C11 allows a typedef name to be declared
// twice for the same type.
typedef struct ch_rec ch_rec;

// The step numbers, mirroring quic_step.h's constructor for constructor
// so one Lean oracle judges every transport. Consecutive from 0, with
// HSR_STEP_COMPLETE largest, which is what hsr_advance's default arm
// rests on.
#define HSR_STEP_AWAIT_SERVER_HELLO 0
#define HSR_STEP_AWAIT_RETRY_HELLO 1
#define HSR_STEP_AWAIT_ENCRYPTED_EXTENSIONS 2
#define HSR_STEP_AWAIT_CERTIFICATE 3
#define HSR_STEP_AWAIT_CERTIFICATE_VERIFY 4
#define HSR_STEP_AWAIT_FINISHED 5
#define HSR_STEP_COMPLETE 6

// Runs the one step r->step names, over the one whole handshake message
// that starts at r->t.cfg.buf + r->t.pt_off. It is the only switch in
// the mode: it dispatches and does nothing else, so every path into a
// handler runs through a step number a step wrote.
//
// Requires: r is not NULL and r->hs.t is &r->t, which every public entry
// writes before it calls.
int hsr_advance(ch_rec *r);

// Stages one handshake message as a plaintext record, the shape a
// ClientHello goes out in. The message is already at t->tx + REC_HDR,
// where the builder wrote it. ch_rec_init stages the first hello and a
// HelloRetryRequest step stages the second.
void rec_stage_plain(ch_rec *r, size_t n);

#endif // CH_TRANSPORT_RECORD
#endif
