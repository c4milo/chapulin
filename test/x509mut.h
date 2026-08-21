// DER carving for the certificate strictness suite: lenient readers
// that locate fields inside a known-good certificate, and a splice
// that replaces one byte range while re-encoding every enclosing
// length bottom-up, so mutants need no hand-patched offsets and the
// cases survive vector regeneration. Test-side only — the strict
// decoder under test shares nothing with these helpers. Any splice
// that misses a TLV boundary is a test bug and aborts.
#ifndef CH_CERTMUT_H
#define CH_CERTMUT_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "x509.h"

// A test bug (a bad carve or splice), never a finding.
static noreturn void mut_die(const char *what) {
    (void)fprintf(stderr, "test bug: %s\n", what);
    abort();
}

typedef struct {
    size_t header_len;
    size_t content_len;
} tlv_shape;

// The largest certificate any caller mutates (RSA-3072 material),
// plus header-growth slack — independent of CH_X509_MAX.
#define X509MUT_CAP (CH_X509_DEFAULT_MAX_RSA + 8)

// One CertificateEntry: u24 length, the certificate, an empty u16
// per-entry extension block. Every suite frames entries through this.
static size_t put_entry(uint8_t *out, const uint8_t *cert, size_t n) {
    out[0] = (uint8_t)(n >> 16);
    out[1] = (uint8_t)(n >> 8);
    out[2] = (uint8_t)n;
    memcpy(out + 3, cert, n);
    out[3 + n] = 0;
    out[4 + n] = 0;
    return n + 5;
}

static void tlv_read(const uint8_t *p, size_t avail, tlv_shape *s) {
    if (avail < 2) {
        mut_die("TLV header past the end");
    }
    size_t header_len = 2;
    size_t content_len = p[1];
    if (content_len == 0x81) {
        if (avail < 3) {
            mut_die("long-form length past the end");
        }
        content_len = p[2];
        header_len = 3;
    } else if (content_len == 0x82) {
        if (avail < 4) {
            mut_die("long-form length past the end");
        }
        content_len = ((size_t)p[2] << 8) | p[3];
        header_len = 4;
    } else if (content_len > 0x82) {
        mut_die("length form out of scope");
    }
    if (header_len + content_len > avail) {
        mut_die("TLV overruns its container");
    }
    s->header_len = header_len;
    s->content_len = content_len;
}

// Total encoded size of the TLV at off.
static size_t tlv_total(const uint8_t *cert, size_t cert_len, size_t off) {
    tlv_shape s;
    tlv_read(cert + off, cert_len - off, &s);
    return s.header_len + s.content_len;
}

// Absolute offset of the index-th child TLV inside the container at
// off. A BIT STRING's unused-bits octet is not a child.
static size_t nth_child(const uint8_t *cert, size_t cert_len, size_t off, size_t index) {
    tlv_shape s;
    tlv_read(cert + off, cert_len - off, &s);
    size_t pos = off + s.header_len + (cert[off] == 0x03 ? 1U : 0U);
    size_t end = off + s.header_len + s.content_len;
    while (index-- > 0) {
        pos += tlv_total(cert, cert_len, pos);
    }
    if (pos >= end) {
        mut_die("child index past the container");
    }
    return pos;
}

// TBSCertificate field by position: 0 version, 1 serial, 2 sigalg,
// 3 issuer, 4 validity, 5 subject, 6 spki, 7 extensions.
static size_t tbs_field(const uint8_t *cert, size_t cert_len, size_t index) {
    return nth_child(cert, cert_len, nth_child(cert, cert_len, 0, 0), index);
}

// Absolute offset of the extension whose extnID content matches oid3.
static size_t find_ext(const uint8_t *cert, size_t cert_len, const uint8_t oid3[3]) {
    size_t list = nth_child(cert, cert_len, tbs_field(cert, cert_len, 7), 0);
    tlv_shape s;
    tlv_read(cert + list, cert_len - list, &s);
    size_t pos = list + s.header_len;
    size_t end = pos + s.content_len;
    while (pos < end) {
        size_t oid = nth_child(cert, cert_len, pos, 0);
        tlv_shape o;
        tlv_read(cert + oid, cert_len - oid, &o);
        if (o.content_len == 3 && memcmp(cert + oid + o.header_len, oid3, 3) == 0) {
            return pos;
        }
        pos += tlv_total(cert, cert_len, pos);
    }
    mut_die("extension not found");
}

// First child of the extension at off carrying the given tag.
static size_t ext_child(const uint8_t *cert, size_t cert_len, size_t off, uint8_t tag) {
    tlv_shape s;
    tlv_read(cert + off, cert_len - off, &s);
    size_t pos = off + s.header_len;
    size_t end = pos + s.content_len;
    while (pos < end) {
        if (cert[pos] == tag) {
            return pos;
        }
        pos += tlv_total(cert, cert_len, pos);
    }
    mut_die("extension child not found");
}

static size_t first_ext(const uint8_t *cert, size_t cert_len) {
    return nth_child(cert, cert_len, nth_child(cert, cert_len, tbs_field(cert, cert_len, 7), 0), 0);
}

static size_t ext_count(const uint8_t *cert, size_t cert_len) {
    size_t list = nth_child(cert, cert_len, tbs_field(cert, cert_len, 7), 0);
    tlv_shape s;
    tlv_read(cert + list, cert_len - list, &s);
    size_t pos = list + s.header_len;
    size_t end = pos + s.content_len;
    size_t count = 0;
    while (pos < end) {
        count++;
        pos += tlv_total(cert, cert_len, pos);
    }
    return count;
}

// Header emission delegates to the proved encoder: a shared-encoder
// fault would surface as spurious rejects in accept cases, never as
// a silent pass, so the kit's independence argument stays with the
// lenient READERS above.
static size_t put_header(uint8_t *out, uint8_t tag, size_t len) {
    return x509_emit_header(tag, len, out);
}

// One level of the splice path: a container's offset and the bounds
// of the child run it sits in.
typedef struct {
    size_t node[16];
    size_t node_lo[16];
    size_t node_hi[16];
    size_t depth;
} splice_path;

// Descends from the whole certificate to the container whose own
// child run holds [target_off, target_off + target_len), recording
// each level. Leaves the innermost run's bounds in *lo and *hi.
static void splice_descend(const uint8_t *cert, size_t target_off, size_t target_len,
                           splice_path *p, size_t *lo, size_t *hi) {
    for (int descended = 1; descended;) {
        descended = 0;
        for (size_t pos = *lo; pos < *hi;) {
            tlv_shape s;
            tlv_read(cert + pos, *hi - pos, &s);
            size_t skip = cert[pos] == 0x03 ? 1U : 0U; // unused-bits octet
            size_t content_lo = pos + s.header_len + skip;
            size_t content_hi = pos + s.header_len + s.content_len;
            if (target_off >= content_lo && target_off < content_hi &&
                target_off + target_len <= content_hi) {
                if (p->depth == sizeof p->node / sizeof p->node[0]) {
                    mut_die("splice path deeper than any certificate");
                }
                p->node[p->depth] = pos;
                p->node_lo[p->depth] = *lo;
                p->node_hi[p->depth] = *hi;
                p->depth++;
                *lo = content_lo;
                *hi = content_hi;
                descended = 1;
                break;
            }
            pos += s.header_len + s.content_len;
        }
    }
}

// The splice must start and end on child-TLV boundaries of [lo, hi).
static void splice_check(const uint8_t *cert, size_t cert_len, size_t lo, size_t hi,
                         size_t target_off, size_t target_len) {
    int start_ok = 0;
    int end_ok = 0;
    for (size_t pos = lo;; pos += tlv_total(cert, cert_len, pos)) {
        start_ok |= pos == target_off;
        end_ok |= pos == target_off + target_len;
        if (pos >= hi) {
            break;
        }
    }
    if (!start_ok || !end_ok) {
        mut_die("splice not at a TLV boundary");
    }
}

// Rebuilds the whole certificate with [target_off, target_off +
// target_len) replaced by repl, re-encoding the length of every
// container on the path down to the splice; a nested header that
// changes size propagates upward because each level is rebuilt from
// the finished level below it. target_len == 0 inserts repl before the
// child TLV at target_off. The splice must start and end on child-TLV
// boundaries of one container; anything else is a test bug and aborts.
// Returns the rebuilt length.
static size_t splice(uint8_t *out, const uint8_t *cert, size_t cert_len, size_t target_off,
                     size_t target_len, const uint8_t *repl, size_t repl_len) {
    if (target_off > cert_len || target_len > cert_len - target_off) {
        mut_die("splice outside the certificate");
    }
    splice_path p = {.depth = 0};
    size_t lo = 0;
    size_t hi = cert_len;
    splice_descend(cert, target_off, target_len, &p, &lo, &hi);
    splice_check(cert, cert_len, lo, hi, target_off, target_len);

    // Splice the innermost run, then wrap it back upward level by
    // level: original bytes before the container's child, the new
    // header, the rebuilt content, original bytes after.
    // Kit-level capacity, not the build's cap: the differential
    // mutates RSA-sized material even in the ECDSA build.
    uint8_t buf_a[X509MUT_CAP];
    uint8_t buf_b[X509MUT_CAP];
    uint8_t *cur = buf_a;
    uint8_t *next = buf_b;
    // Growth guard: the rebuilt image is the original minus the
    // target plus the replacement, and each enclosing header can
    // grow by at most two bytes when its length crosses a form
    // boundary. Anything bigger is a test bug, not a vector.
    if (cert_len - target_len + repl_len + 2 * p.depth > sizeof buf_a) {
        mut_die("mutant outgrows the splice buffers");
    }
    size_t w = target_off - lo;
    memcpy(cur, cert + lo, w);
    if (repl_len > 0) {
        memcpy(cur + w, repl, repl_len);
        w += repl_len;
    }
    memcpy(cur + w, cert + target_off + target_len, hi - (target_off + target_len));
    w += hi - (target_off + target_len);
    while (p.depth-- > 0) {
        size_t pos = p.node[p.depth];
        tlv_shape s;
        tlv_read(cert + pos, p.node_hi[p.depth] - pos, &s);
        size_t skip = cert[pos] == 0x03 ? 1U : 0U;
        size_t tlv_end = pos + s.header_len + s.content_len;
        size_t next_w = pos - p.node_lo[p.depth];
        memcpy(next, cert + p.node_lo[p.depth], next_w);
        next_w += put_header(next + next_w, cert[pos], w + skip);
        if (skip) {
            next[next_w++] = cert[pos + s.header_len];
        }
        memcpy(next + next_w, cur, w);
        next_w += w;
        memcpy(next + next_w, cert + tlv_end, p.node_hi[p.depth] - tlv_end);
        next_w += p.node_hi[p.depth] - tlv_end;
        uint8_t *swap = cur;
        cur = next;
        next = swap;
        w = next_w;
    }
    memcpy(out, cur, w);
    return w;
}

// Inserts one unknown non-critical extension (extnID 2.5.29.<arc>,
// empty-SEQUENCE value) before the first extension.
static size_t insert_unknown(uint8_t *out, const uint8_t *cert, size_t n, uint8_t arc) {
    uint8_t e[11] = {0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, arc, 0x04, 0x02, 0x30, 0x00};
    return splice(out, cert, n, first_ext(cert, n), 0, e, sizeof e);
}

// Inserts one unknown non-critical extension whose whole TLV is
// exactly total bytes, its value padded with unread filler.
static size_t insert_big(uint8_t *out, const uint8_t *cert, size_t n, size_t total) {
    uint8_t e[260];
    size_t content = total - 3; // 3: the 30 81 xx header
    size_t filler = content - 8;
    memcpy(e, (const uint8_t[]){0x30, 0x81, 0x00, 0x06, 0x03, 0x55, 0x1d, 0x09, 0x04, 0x81, 0x00},
           11);
    e[2] = (uint8_t)content;
    e[10] = (uint8_t)filler;
    memset(e + 11, 0x5a, filler);
    return splice(out, cert, n, first_ext(cert, n), 0, e, total);
}

#endif
