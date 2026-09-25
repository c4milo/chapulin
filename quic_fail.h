// The one way a QUIC session dies, shared by both drivers.
//
// INV-17 says every failure path wipes every secret the session holds,
// with one exception: each level's write keys, kept for the one
// CONNECTION_CLOSE packet ch_quic_seal_close seals there (docs/decisions.md
// 57). That claim is checkable only if there is one list to check, so the
// list lives here and quic.c and srv_quic.c both call it rather than each
// keeping a copy that drifts from the other.
#ifndef CH_QUIC_FAIL_H
#define CH_QUIC_FAIL_H
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

#include <stdint.h>

#include "quic.h"

// Wipes every secret, the write keys of every level included, and clears
// every bit of q->levels_ready and the two fields that say how many bytes
// are staged and unread. session.h lists the same names beside the
// invariant they serve. ch_quic_close calls it.
void quic_wipe(ch_quic *q);

// Wipes the write keys of one level and clears that level's write bit in
// q->levels_ready. At CH_LEVEL_INITIAL the keys are the stored
// Destination Connection ID the seal derives them from, which the read
// direction shares, so it runs only once the read bit is clear already:
// on a failed or closing session. ch_quic_seal_close calls it right after
// its one seal at that level. Requires: level is a CH_LEVEL_ value.
void quic_wipe_write_keys(ch_quic *q, uint8_t level);

// What tlsi_fail is on the TCP transports, minus the alert record, which
// QUIC has no way to carry: the alert goes to q->alert for ch_quic_alert
// to report and the session is dead. It wipes every secret but the write
// keys of each level whose write bit is set, and clears every read bit, so
// the write bits left in q->levels_ready name the levels where the caller
// may seal one CONNECTION_CLOSE. It leaves q->error_code alone, so a caller
// that wrote a code before it called still reports that code. Returns rc,
// so a caller can tail-call it.
int quic_fail(ch_quic *q, int rc);

// The RFC 9001 section 4.1.3 refusals that kill the session, in one place
// because both write PROTOCOL_VIOLATION (rfc9001.txt:482-486,
// rfc9001.txt:491-493).
int quic_fail_level(ch_quic *q);

// Writes the error that unread bytes at a level this endpoint leaves owe,
// and returns CH_EPROTO without failing the session: a driver passes it
// to quic_fail, and a step returns it for its driver to pass on. RFC 9001
// section 4.1.3 makes those bytes PROTOCOL_VIOLATION (rfc9001.txt:491-493),
// but section 6 makes a KeyUpdate 0x010a wherever it arrives
// (rfc9001.txt:1565-1568), so when the first unread message is a
// KeyUpdate it writes only the unexpected_message alert, which
// ch_quic_error_code reports as 0x010a.
int quic_refuse_unread(ch_quic *q);

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
#endif
