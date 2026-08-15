// Record-granular I/O over the caller's callbacks. Reads assemble exactly
// one TLS record into the caller's buffer; writes push a fully built
// record out. No protection logic here — record.[ch] owns that.
#ifndef CH_IO_H
#define CH_IO_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"

int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n);

// Reads one record (header + body) into buf. Returns CH_OK with the outer
// type and total length, CH_EIO on transport failure, CH_EPROTO on a
// malformed length, CH_ECAP if the record exceeds cap.
int io_read_record(const ch_cfg *cfg, uint8_t *buf, size_t cap, uint8_t *outer, size_t *reclen);

#endif
