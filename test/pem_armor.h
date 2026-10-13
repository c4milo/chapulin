// RFC 7468 armouring, shared by the unit tests and the differential
// rows so both wrap certificates the same way. Test-side only: the
// decoder under test shares nothing with it.
#ifndef CH_PEM_ARMOR_H
#define CH_PEM_ARMOR_H

#include <stdint.h>
#include <string.h>

#include "pem.h"

static const char pem_armor_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Every width the cap budgets for, plus 0 meaning one unbroken line.
// The odd ones matter most: they break a line inside a base64 quantum,
// which is what pem.h claims to accept and what a multiple of four
// never exercises. Nothing below 4 appears, because CH_PEM_MAX budgets
// two terminator bytes per four characters and a narrower wrap can
// exceed the cap.
static const size_t pem_armor_widths[] = {4, 5, 6, 7, 8, 16, 32, 48, 60, 64, 70, 71, 72, 76, 0};

// One base64 quantum from src[i..i+2], padding what is not there.
static void pem_armor_quantum(const uint8_t *src, size_t n, size_t i, uint8_t q[4]) {
    uint32_t v = (uint32_t)src[i] << 16;
    size_t have = 1;
    if (i + 1 < n) {
        v |= (uint32_t)src[i + 1] << 8;
        have = 2;
    }
    if (i + 2 < n) {
        v |= src[i + 2];
        have = 3;
    }
    q[0] = (uint8_t)pem_armor_alphabet[(v >> 18) & 63];
    q[1] = (uint8_t)pem_armor_alphabet[(v >> 12) & 63];
    q[2] = have > 1 ? (uint8_t)pem_armor_alphabet[(v >> 6) & 63] : (uint8_t)'=';
    q[3] = have > 2 ? (uint8_t)pem_armor_alphabet[v & 63] : (uint8_t)'=';
}

// Base64 for src, unwrapped. Returns the character count.
static size_t pem_armor_encode(const uint8_t *src, size_t n, uint8_t *dst) {
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint8_t q[4];
        pem_armor_quantum(src, n, i, q);
        for (size_t k = 0; k < 4; k++) {
            dst[o++] = q[k];
        }
    }
    return o;
}

// One boundary line, "-----BEGIN " or "-----END ", the label and five
// dashes, at dst. Returns its length.
static size_t pem_armor_boundary(const char *prefix, const char *label, uint8_t *dst) {
    size_t o = 0;
    const char *parts[3] = {prefix, label, "-----"};
    for (size_t p = 0; p < 3; p++) {
        size_t n = strlen(parts[p]);
        (void)memcpy(dst + o, parts[p], n);
        o += n;
    }
    return o;
}

// Body characters between the two boundaries of label, wrapped at width
// (0 for one line). Takes the text as given, so a test can supply a body
// that is not valid base64.
static size_t pem_wrap_label(const char *label, const uint8_t *body, size_t n, size_t width,
                             const char *eol, uint8_t *dst) {
    size_t eol_len = strlen(eol);
    size_t col = 0;
    size_t o = pem_armor_boundary("-----BEGIN ", label, dst);
    (void)memcpy(dst + o, eol, eol_len);
    o += eol_len;
    for (size_t i = 0; i < n; i++) {
        dst[o++] = body[i];
        if (width != 0 && ++col == width) {
            (void)memcpy(dst + o, eol, eol_len);
            o += eol_len;
            col = 0;
        }
    }
    if (col != 0 || width == 0) {
        (void)memcpy(dst + o, eol, eol_len);
        o += eol_len;
    }
    o += pem_armor_boundary("-----END ", label, dst + o);
    (void)memcpy(dst + o, eol, eol_len);
    return o + eol_len;
}

// The same for a CERTIFICATE block. It and pem_armor_label are inline. So
// a file that includes this header and calls neither compiles under
// -Wunused-function.
static inline size_t pem_wrap_text(const uint8_t *body, size_t n, size_t width, const char *eol,
                                   uint8_t *dst) {
    return pem_wrap_label("CERTIFICATE", body, n, width, eol, dst);
}

// The largest DER a test armours: past the chain room of 12,288 bytes
// that the tests give (test/pem_files_test.c). One certificate may fill
// that room, or be a byte over it.
#define PEM_ARMOR_DER_MAX 12800
// The body room pem_armor_label needs: the larger of CH_X509_MAX's body
// and PEM_ARMOR_DER_MAX's.
#define PEM_ARMOR_DER_BODY_MAX (4 * ((PEM_ARMOR_DER_MAX + 2) / 3))
#define PEM_ARMOR_BODY_MAX                                                                         \
    (CH_PEM_BODY_MAX > PEM_ARMOR_DER_BODY_MAX ? CH_PEM_BODY_MAX : PEM_ARMOR_DER_BODY_MAX)

// src as one block of label in dst. Returns 0 when src is longer than the
// body room holds, and a test then sees a block that did not decode.
static inline size_t pem_armor_label(const char *label, const uint8_t *src, size_t n, size_t width,
                                     const char *eol, uint8_t *dst) {
    static uint8_t body[PEM_ARMOR_BODY_MAX];
    if (n > sizeof body / 4 * 3) {
        return 0;
    }
    size_t body_len = pem_armor_encode(src, n, body);
    return pem_wrap_label(label, body, body_len, width, eol, dst);
}

// src as one CERTIFICATE block in dst.
static size_t pem_armor(const uint8_t *src, size_t n, size_t width, const char *eol, uint8_t *dst) {
    return pem_armor_label("CERTIFICATE", src, n, width, eol, dst);
}

#endif
