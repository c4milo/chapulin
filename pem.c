// RFC 7468 armor and RFC 4648 base64, decode side. Contract in pem.h.
//
// The decoder keeps no line model. The body loop skips CR and LF
// wherever they appear and rejects every other byte outside the
// alphabet, so there is no line buffer to size and no line length to
// overflow. That is the whole answer to arbitrary wrapping without a
// heap.
#include "pem.h"

#include "buf.h"
#include "cfg.h"
#include "ch_assert.h"
#include "ct.h"

// The RFC 7468 section 2 boundaries, written as bytes. A string
// literal carries a terminating NUL that is not part of the boundary,
// and sizeof would count it: the BEGIN line is 27 characters, not 28.
static const uint8_t begin_line[] = {
    '-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N', ' ', 'C', 'E', 'R',
    'T', 'I', 'F', 'I', 'C', 'A', 'T', 'E', '-', '-', '-', '-', '-',
};
static const uint8_t end_line[] = {
    '-', '-', '-', '-', '-', 'E', 'N', 'D', ' ', 'C', 'E', 'R', 'T',
    'I', 'F', 'I', 'C', 'A', 'T', 'E', '-', '-', '-', '-', '-',
};

#define BASE64_INVALID 64

// The RFC 4648 section 4 alphabet, as five ranges. A 256-byte lookup
// table would cost more flash than the compares and buys nothing: the
// bytes here are public, so there is no timing property to protect.
static uint8_t base64_value(uint8_t c) {
    if (c >= 'A' && c <= 'Z') {
        return (uint8_t)(c - 'A');
    }
    if (c >= 'a' && c <= 'z') {
        return (uint8_t)(c - 'a' + 26);
    }
    if (c >= '0' && c <= '9') {
        return (uint8_t)(c - '0' + 52);
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return BASE64_INVALID;
}

// Literal compare against a boundary. These bytes are public;
// ct_memeq is INV-16's designated comparator either way.
static int match_bytes(rbuf *r, const uint8_t *want, size_t n) {
    const uint8_t *got = rb_bytes(r, n);
    if (got == NULL) {
        return 0;
    }
    return ct_memeq(got, want, n) != 0;
}

// One line terminator: LF, or CR then LF. A lone CR ends no line.
static int read_eol(rbuf *r) {
    uint8_t c = rb_u8(r);
    if (r->err) {
        return 0;
    }
    if (c == '\r') {
        c = rb_u8(r);
        if (r->err) {
            return 0;
        }
    }
    return c == '\n';
}

typedef struct {
    uint32_t acc;   // the bits not yet emitted, in the low nbits
    uint32_t nbits; // 0, 2, 4 or 6
    uint32_t pos;   // body characters so far, mod 4
    uint32_t npad;  // pad characters in this quantum, 0 to 2
    uint32_t seen;  // 1 after the first alphabet character is read
} base64_state;

// A pad character is legal only where it completes the final quantum:
// at group position 2 or 3, and at most two of them. RFC 4648 section
// 3.5 admits a final quantum of 8 or 16 bits and nothing else.
//
// The counters are the character position mod 4 and a 0..2 pad count,
// not running totals: nothing here needs a total, and CBMC pays for
// every bit of loop-carried state at every unwinding.
//
// The position test is redundant and stays anyway. body_ok already
// demands pos == 0, and no run of pads reachable through the relaxed
// rule ends there -- checked by enumerating every body of length 0..10
// over {A, Q, =}, 88573 of them, with no verdict differing. It stays
// because this is where a reader looks for RFC 4648 section 3.5, and
// because rejecting at the pad names the rule that was broken.
static int pad_ok(const base64_state *s) {
    return s->npad < 2 && (s->pos == 2 || s->pos == 3);
}

// One body character, already known not to be a boundary or a
// terminator. Returns 1 when it is accepted.
static int base64_step(base64_state *s, wbuf *w, uint8_t c) {
    if (c == '=') {
        if (!pad_ok(s)) {
            return 0;
        }
        s->npad++;
        s->pos = (s->pos + 1) & 3U;
        return 1;
    }
    uint8_t v = base64_value(c);
    if (v == BASE64_INVALID || s->npad != 0) {
        return 0; // outside the alphabet, or an alphabet character after a pad
    }
    s->acc = (s->acc << 6) | v;
    s->nbits += 6;
    s->pos = (s->pos + 1) & 3U;
    s->seen = 1;
    if (s->nbits >= 8) {
        s->nbits -= 8;
        wb_u8(w, (uint8_t)((s->acc >> s->nbits) & 0xFFU));
    }
    return 1;
}

// At the END boundary: the characters must close their last group, the
// body must have held something, and the bits the padding stands for
// must be zero. Rejecting non-zero unused bits detects corruption; it
// is not the canonicality argument x509_der.c makes, because nothing
// hashes this text.
static int body_ok(const wbuf *w, const base64_state *s) {
    if (!s->seen || s->pos != 0) {
        return 0;
    }
    uint32_t unused = s->acc & ((1U << s->nbits) - 1U);
    return unused == 0 && !w->err;
}

// The base64 body, from the byte after the BEGIN line's terminator up
// to the dash that opens the END line. Consumes that dash.
static int decode_body(rbuf *r, wbuf *w) {
    base64_state s = {0, 0, 0, 0, 0};
    while (rb_left(r) != 0) {
        uint8_t c = rb_u8(r);
        if (c == '-') {
            return body_ok(w, &s);
        }
        if (c == '\r' || c == '\n') {
            continue;
        }
        if (!base64_step(&s, w, c)) {
            return 0;
        }
    }
    return 0; // the input ended before the END line
}

// After the END line, only line terminators. A second block is a
// rejection rather than something to ignore; pem.h says why.
static int read_tail(rbuf *r) {
    while (rb_left(r) != 0) {
        uint8_t c = rb_u8(r);
        if (c != '\r' && c != '\n') {
            return 0;
        }
    }
    // Redundant and kept: rb_left returns 0 once err is set and no read
    // above can set it, so this is always true today. It states the
    // contract the caller relies on rather than an inference about the
    // loop, the same reason pad_ok keeps its position test.
    return r->err == 0;
}

int pem_decode_certificate(const uint8_t *pem, size_t pem_len, uint8_t der[CH_X509_MAX],
                           size_t *der_len) {
    CH_ASSERT(der != NULL && der_len != NULL);
    CH_ASSERT(pem != NULL || pem_len == 0);
    *der_len = 0;
    if (pem_len > CH_PEM_MAX) {
        return CH_EINVAL;
    }
    rbuf r;
    rb_init(&r, pem, pem_len);
    wbuf w;
    wb_init(&w, der, CH_X509_MAX);

    if (!match_bytes(&r, begin_line, sizeof begin_line) || !read_eol(&r)) {
        return CH_EINVAL;
    }
    if (!decode_body(&r, &w)) {
        return CH_EINVAL;
    }
    // decode_body consumed the END line's first dash, so match what
    // follows it. rbuf has no peek, and adding one would re-prove the
    // module every other module depends on.
    if (!match_bytes(&r, end_line + 1, sizeof end_line - 1)) {
        return CH_EINVAL;
    }
    if (!read_tail(&r)) {
        return CH_EINVAL;
    }
    *der_len = w.len;
    return CH_OK;
}
