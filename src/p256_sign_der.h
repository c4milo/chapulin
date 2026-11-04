// The DER ECDSA-Sig-Value writer of p256_sign.c, which alone includes this header: a signature's
// SEQUENCE of two INTEGERs, r and s (RFC 5480 section 2.2.3, X.690). write_if_checked calls it
// only for a pair that passed both checks, which goes on the wire, so its branches on the
// leading bytes of r and s read public bytes (docs/decisions.md 155). Its functions are static,
// and proof/p256_sign_harness.c proves them through p256_sign.c.
#ifndef CH_P256_SIGN_DER_H
#define CH_P256_SIGN_DER_H

#include <stddef.h>
#include <stdint.h>

#include "buf.h"
#include "p256_sign.h"

// One DER INTEGER holding a 32-byte big-endian scalar, minimal-length
// per X.690 §8.3: leading zero bytes are dropped, and one zero byte is
// written back when the top bit of the first content byte is set. The
// value is r or s of a pair that passed both checks (write_if_checked),
// which goes on the wire, so reading its bytes here leaks nothing that
// the signature does not already carry.
static void write_integer(wbuf *w, const uint8_t value[P256_SCALAR_LEN]) {
    size_t lead = 0;
    while (lead < P256_SCALAR_LEN - 1 && value[lead] == 0) {
        lead++;
    }
    size_t content_len = P256_SCALAR_LEN - lead;
    int pad = (value[lead] & 0x80) != 0;
    wb_u8(w, 0x02);
    wb_u8(w, (uint8_t)(content_len + (size_t)pad));
    if (pad) {
        wb_u8(w, 0x00);
    }
    wb_bytes(w, value + lead, content_len);
}

// SEQUENCE { INTEGER r, INTEGER s }. The body is at most 70 bytes, so
// its length always fits the short form and no definite-long header is
// written. Returns 1 when the whole structure fit in cap.
static int write_signature(uint8_t *sig, size_t cap, size_t *sig_len,
                           const uint8_t r[P256_SCALAR_LEN], const uint8_t s[P256_SCALAR_LEN]) {
    uint8_t body[P256_SIG_MAX];
    wbuf inner;
    wbuf outer;

    wb_init(&inner, body, sizeof body);
    write_integer(&inner, r);
    write_integer(&inner, s);
    if (inner.err) {
        return 0;
    }
    wb_init(&outer, sig, cap);
    wb_u8(&outer, 0x30);
    wb_u8(&outer, (uint8_t)inner.len);
    wb_bytes(&outer, body, inner.len);
    if (outer.err) {
        return 0;
    }
    *sig_len = outer.len;
    return 1;
}

#endif
