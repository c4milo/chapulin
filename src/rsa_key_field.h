// An RSA public key in RFC 3110 section 2's form: a one-byte exponent
// length, or a zero byte and a two-byte one, then the exponent, then the
// modulus, which runs to the end of the field. A DNSKEY carries its RSA
// key in this form (dnssec.h), and ch_jws_verify takes an RS256 key in it
// (jws.h). Each caller applies its own bounds to what the reader returns.
#ifndef CH_RSA_KEY_FIELD_H
#define CH_RSA_KEY_FIELD_H

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

// The longest exponent the reader takes, in bytes: the 8 bytes that e
// below holds.
#define RSA_KEY_FIELD_EXPONENT_MAX 8

typedef struct {
    uint64_t e;
    const uint8_t *n;
    size_t n_len;
} rsa_key_field;

// Reads key into k. Returns 1, or 0 for a field it refuses: an exponent
// of 0 bytes, or longer than RSA_KEY_FIELD_EXPONENT_MAX, or that begins
// with a zero byte; a modulus of 0 bytes or that begins with a zero byte.
// The key is public, so the branches read it.
static inline int rsa_key_field_read(const uint8_t *key, size_t key_len, rsa_key_field *k) {
    rbuf rb;
    rb_init(&rb, key, key_len);
    size_t e_len = rb_u8(&rb);
    if (e_len == 0) {
        e_len = rb_u16(&rb);
    }
    const uint8_t *e = rb_bytes(&rb, e_len);
    if (rb.err || e_len == 0 || e_len > RSA_KEY_FIELD_EXPONENT_MAX || e[0] == 0) {
        return 0;
    }
    k->e = 0;
    for (size_t i = 0; i < e_len; i++) {
        k->e = (k->e << 8) | e[i];
    }
    // The modulus runs to the end of the field, so the reader ends empty
    // (INV-25).
    k->n_len = rb_left(&rb);
    k->n = rb_bytes(&rb, k->n_len);
    return !rb.err && rb_left(&rb) == 0 && k->n_len != 0 && k->n[0] != 0;
}

#endif
