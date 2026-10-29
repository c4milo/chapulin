// Record-granular I/O over the caller's callbacks. Reads assemble exactly
// one TLS record into the caller's buffer; writes push a fully built
// record out. No protection logic here — record.[ch] owns that.
#ifndef CH_IO_H
#define CH_IO_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "session.h"

int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n);

// Reads one record (header + body) through t->cfg.recv into buf, which
// holds cap bytes. Returns CH_OK with the outer type and total length,
// CH_EIO on transport failure, CH_EPROTO on a malformed length and CH_ECAP
// when the record does not fit cap. Two results also write *alert:
//
// - A body longer than rec_body_max allows writes ALERT_RECORD_OVERFLOW
//   and returns CH_EPROTO (record.h).
// - A record longer than all of cfg.buf returns CH_ECAP and writes
//   ALERT_RECORD_OVERFLOW once t->limit_sent is set, because this side's
//   record_size_limit sized that buffer and the record is over it (RFC
//   8449 §4). Before then the record is legal and this side cannot hold
//   it, so it writes ALERT_INTERNAL_ERROR.
//
// Every other result leaves *alert as the caller set it. A record that
// fits cfg.buf but not cap, behind a message in part, is one of those.
int io_read_record(const ch_tls *t, uint8_t *buf, size_t cap, uint8_t *outer, size_t *record_len,
                   uint8_t *alert);

#endif
