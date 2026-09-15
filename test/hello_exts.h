// Reads a captured ClientHello back for the hello-bytes tests: the
// extension list, one extension's data, and the signature_algorithms
// list. Test-only, and it trusts nothing: every read goes through rbuf,
// so a malformed capture answers "absent" instead of reading past the
// bytes the client sent. Included by test/session_cfg_tests.h and
// test/webpki_session_test.c after buf.h and handshake_message.h.
#ifndef CH_TEST_HELLO_EXTS_H
#define CH_TEST_HELLO_EXTS_H

#include <stddef.h>
#include <stdint.h>

// Positions r at the first extension of a ClientHello handshake message
// (header included). Returns 0 when the message is not one.
static int hello_exts_open(rbuf *r, const uint8_t *msg, size_t n) {
    rb_init(r, msg, n);
    if (rb_u8(r) != HS_CLIENT_HELLO || rb_u24(r) != n - 4) {
        return 0;
    }
    (void)rb_bytes(r, 2 + 32);    // legacy_version, random
    (void)rb_bytes(r, rb_u8(r));  // legacy_session_id
    (void)rb_bytes(r, rb_u16(r)); // cipher_suites
    (void)rb_bytes(r, rb_u8(r));  // legacy_compression_methods
    return rb_u16(r) == rb_left(r) && !r->err;
}

// The type of the first extension, or -1 when the hello has none.
static long hello_first_ext(const uint8_t *msg, size_t n) {
    rbuf r;
    if (!hello_exts_open(&r, msg, n) || rb_left(&r) < 4) {
        return -1;
    }
    return rb_u16(&r);
}

// The data of the extension of this type, with its length in *len, or
// NULL when the hello does not carry it.
static const uint8_t *hello_ext(const uint8_t *msg, size_t n, uint16_t type, size_t *len) {
    rbuf r;
    if (!hello_exts_open(&r, msg, n)) {
        return NULL;
    }
    while (rb_left(&r) > 0 && !r.err) {
        uint16_t ext = rb_u16(&r);
        size_t ext_len = rb_u16(&r);
        const uint8_t *data = rb_bytes(&r, ext_len);
        if (data != NULL && ext == type) {
            *len = ext_len;
            return data;
        }
    }
    return NULL;
}

// The signature_algorithms list as up to cap code points in out; returns
// how many the extension lists, or -1 when the hello carries none or its
// framing is off.
static int hello_sigalgs(const uint8_t *msg, size_t n, uint16_t *out, int cap) {
    size_t len = 0;
    const uint8_t *data = hello_ext(msg, n, EXT_SIGNATURE_ALGORITHMS, &len);
    if (data == NULL) {
        return -1;
    }
    rbuf r;
    rb_init(&r, data, len);
    size_t list_len = rb_u16(&r);
    if (list_len != rb_left(&r) || list_len % 2 != 0) {
        return -1;
    }
    int count = 0;
    while (rb_left(&r) > 0) {
        uint16_t scheme = rb_u16(&r);
        if (count < cap) {
            out[count] = scheme;
        }
        count++;
    }
    return count;
}

#endif
