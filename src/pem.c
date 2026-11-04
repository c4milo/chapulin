// RFC 7468 armor and RFC 4648 base64, decode side. Contract in pem.h.
//
// The decoder keeps no line model. The body loop skips CR and LF
// wherever they appear and rejects every other byte outside the
// alphabet, so there is no line buffer to size and no line length to
// overflow. That is the whole answer to arbitrary wrapping without a
// heap.
#include "pem.h"

#include "base64.h"
#include "buf.h"
#include "cfg.h"
#include "ch_assert.h"
#include "ct.h"

// The RFC 7468 section 2 boundaries, written as bytes: "-----BEGIN ",
// the label, "-----", and the same with "END". A string literal ends in
// a NUL that is not part of the boundary, and sizeof would count it. The
// CERTIFICATE BEGIN line is 27 characters, not 28.
static const uint8_t begin_prefix[] = {'-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N', ' '};
static const uint8_t end_prefix[] = {'-', '-', '-', '-', '-', 'E', 'N', 'D', ' '};
static const uint8_t boundary_dashes[] = {'-', '-', '-', '-', '-'};

// The four labels: RFC 7468 section 5 and section 10, RFC 5915 section
// 4, and the label OpenSSL writes above an EC PRIVATE KEY block.
static const uint8_t label_certificate[] = {'C', 'E', 'R', 'T', 'I', 'F', 'I', 'C', 'A', 'T', 'E'};
static const uint8_t label_private_key[] = {'P', 'R', 'I', 'V', 'A', 'T', 'E', ' ', 'K', 'E', 'Y'};
static const uint8_t label_ec_private_key[] = {'E', 'C', ' ', 'P', 'R', 'I', 'V',
                                               'A', 'T', 'E', ' ', 'K', 'E', 'Y'};
static const uint8_t label_ec_parameters[] = {'E', 'C', ' ', 'P', 'A', 'R', 'A',
                                              'M', 'E', 'T', 'E', 'R', 'S'};

typedef struct {
    const uint8_t *bytes;
    size_t len;
} label_bytes;

// Indexed by the PEM_LABEL_ values pem.h defines.
static const label_bytes labels[PEM_LABEL_COUNT] = {
    {label_certificate,    sizeof label_certificate   },
    {label_private_key,    sizeof label_private_key   },
    {label_ec_private_key, sizeof label_ec_private_key},
    {label_ec_parameters,  sizeof label_ec_parameters },
};

// Literal compare against a boundary. These bytes are public;
// ct_memeq is INV-16's designated comparator either way.
static int match_bytes(rbuf *r, const uint8_t *want, size_t n) {
    const uint8_t *got = rb_bytes(r, n);
    if (got == NULL) {
        return 0;
    }
    return ct_memeq(got, want, n) != 0;
}

// One boundary line from its prefix on: the prefix, the label, five
// dashes.
static int match_line(rbuf *r, const uint8_t *prefix, size_t prefix_len, uint8_t label) {
    return match_bytes(r, prefix, prefix_len) &&
           match_bytes(r, labels[label].bytes, labels[label].len) &&
           match_bytes(r, boundary_dashes, sizeof boundary_dashes);
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

// One body character's class (base64.h), already known not to be
// BASE64_DASH, BASE64_CR or BASE64_LF. Returns 1 when it is accepted.
// Every test here is against a class above 63, so it answers the same for
// every alphabet character.
static int base64_step(base64_state *s, wbuf *w, uint8_t v) {
    if (v == BASE64_PAD) {
        if (!pad_ok(s)) {
            return 0;
        }
        s->npad++;
        s->pos = (s->pos + 1) & 3U;
        return 1;
    }
    if (v >= BASE64_PAD || s->npad != 0) {
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

// The base64 body loop. Returns 1 at the dash that opens the END line.
// It has then consumed that dash and judged nothing yet. Returns 0 for a
// rejected character or an input that ends first. It reads each byte
// through base64_class, and it branches on the class alone, never on the
// byte. So no branch here or in base64_step tells one alphabet character
// from another (base64.h; .semgrep/invariants.yml, inv-16-pem-body-class).
static int body_loop(rbuf *r, wbuf *w, base64_state *s) {
    while (rb_left(r) != 0) {
        uint8_t v = base64_class(rb_u8(r));
        if (v == BASE64_DASH) {
            return 1;
        }
        if (v == BASE64_CR || v == BASE64_LF) {
            continue;
        }
        if (!base64_step(s, w, v)) {
            return 0;
        }
    }
    return 0; // the input ended before the END line
}

// The base64 body, from the byte after the BEGIN line's terminator up
// to the dash that opens the END line. Consumes that dash. acc holds the
// last 32 bits that the body decoded. In a key file they can be bits of
// the private scalar, so the call wipes the state on both paths.
static int decode_body(rbuf *r, wbuf *w) {
    base64_state s = {0, 0, 0, 0, 0};
    int ok = body_loop(r, w, &s) && body_ok(w, &s);
    ct_wipe(&s, sizeof s);
    return ok;
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

int pem_read_block(rbuf *r, uint8_t label, wbuf *der) {
    CH_ASSERT(r != NULL && der != NULL && label < PEM_LABEL_COUNT);
    if (!match_line(r, begin_prefix, sizeof begin_prefix, label) || !read_eol(r)) {
        return 0;
    }
    if (!decode_body(r, der)) {
        return 0;
    }
    // decode_body consumed the END line's first dash, so match what
    // follows it. rbuf has no peek. A peek would change the module that
    // every other module depends on, and its proof.
    return match_line(r, end_prefix + 1, sizeof end_prefix - 1, label);
}

int pem_begins_boundary(const rbuf *r) {
    CH_ASSERT(r != NULL);
    rbuf peek = *r;
    return match_bytes(&peek, begin_prefix, sizeof begin_prefix);
}

int pem_decode_one(const uint8_t *pem, size_t pem_len, uint8_t label, wbuf *der) {
    CH_ASSERT(pem != NULL || pem_len == 0);
    rbuf r;
    rb_init(&r, pem, pem_len);
    return pem_read_block(&r, label, der) && read_tail(&r);
}

int pem_decode_certificate(const uint8_t *pem, size_t pem_len, uint8_t der[CH_X509_MAX],
                           size_t *der_len) {
    CH_ASSERT(der != NULL && der_len != NULL);
    CH_ASSERT(pem != NULL || pem_len == 0);
    *der_len = 0;
    if (pem_len > CH_PEM_MAX) {
        return CH_EINVAL;
    }
    wbuf w;
    wb_init(&w, der, CH_X509_MAX);
    if (!pem_decode_one(pem, pem_len, PEM_LABEL_CERTIFICATE, &w)) {
        return CH_EINVAL;
    }
    *der_len = w.len;
    return CH_OK;
}
