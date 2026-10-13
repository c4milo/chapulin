// The PEM arm of the differential oracle. It holds four things against
// spec/lean/Spec/PemBlocks.lean and spec/lean/Spec/PemFiles.lean:
//  - pem.c's one block of each label;
//  - pem_blocks.c's runs under both text rules;
//  - x509_pem.c's DER readers;
//  - pem_files.c's three calls.
// The spec modules are written from RFC 7468, RFC 5280, RFC 5915 and RFC
// 5958, and never from these files. Every row asserts that the C and the
// spec reach the same verdict, and on acceptance the same bytes.
//
// Its own main, as test/diff_p256_wide_test.c is: the three calls exist
// only in an object with a server role and TRUST=webpki, and bin/diff
// compiles neither. The Makefile builds it as a ROLE=both TRUST=webpki
// device object's sources.
//
// The rows build texts and DER from random parts. Then they break them
// one rule at a time and at random. A break changes a byte, cuts the
// text, inserts a byte, or puts text or a second block around a block. Each limit of the three
// calls runs at its last admitted value and one past it. The limits are
// the caller's DER room and entries for a chain and a bundle, a chain's
// 255 certificates, and the key file's text cap. The key rows draw a
// scalar, take its point from p256_ecdh_keygen, and put that point in a
// leaf that the spec's own P-256 reads. So an accepted key is the spec's
// pubKey? of the scalar on both sides. Some key files carry an EC
// PARAMETERS block, whole or broken.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"

#include "diff_driver.h"

#include "p256_ecdh.h"
#include "pem.h"
#include "pem_armor.h"
#include "pem_blocks.h"
#include "pem_files.h"
#include "pem_files_der.h"
#include "widemul.h"
#include "x509_pem.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// The largest text a row builds: a chain of thirteen certificates of up
// to 6,200 bytes each. A mutation may double it, up to this size.
#define TEXT_MAX (160 * 1024)
// The largest DER room a row gives, which every text above fits.
#define ROOM_MAX (64 * 1024)
// Room for the largest request: the largest text, as hex, and the words
// before it.
#define CMD_MAX (2 * TEXT_MAX + 128)
static char cmd[CMD_MAX];
// Room for the largest reply this file builds: the DER of a full room as
// hex, and the separators.
#define WANT_MAX (2 * ROOM_MAX + 2048)
static char want[WANT_MAX];
static uint8_t text[TEXT_MAX];
static uint8_t room[ROOM_MAX];
// Rows whose answer is an acceptance, so a run that only ever refused
// shows as such.
static long accepted;

// One comparison of cmd against want. It counts the acceptances.
static void compare(void) {
    if (strncmp(want, "ok", 2) == 0) {
        accepted++;
    }
    expect(cmd, want);
}

// The request's hex argument at the end of cmd, after head.
static void request(const char *head, const uint8_t *p, size_t n) {
    int at = snprintf(cmd, sizeof cmd, "%s ", head);
    if (n == 0) {
        cmd[at] = '-';
        cmd[at + 1] = '\0';
        return;
    }
    (void)hex_encode(cmd + at, p, n);
}

// "ok " and each of count byte strings as hex, joined by commas, or "-"
// for none.
static void reply_list(const uint8_t *const parts[], const size_t lens[], size_t count) {
    size_t at = 3;
    memcpy(want, "ok ", 3);
    if (count == 0) {
        want[at++] = '-';
    }
    for (size_t i = 0; i < count; i++) {
        if (i != 0) {
            want[at++] = ',';
        }
        if (at + 2 * lens[i] + 2 >= WANT_MAX) {
            die("a reply outgrew the want buffer");
        }
        at += hex_encode(want + at, parts[i], lens[i]);
    }
    want[at] = '\0';
}

static const char *const label_names[PEM_LABEL_COUNT] = {"certificate", "private_key",
                                                         "ec_private_key", "ec_parameters"};
static const char *const label_texts[PEM_LABEL_COUNT] = {"CERTIFICATE", "PRIVATE KEY",
                                                         "EC PRIVATE KEY", "EC PARAMETERS"};

// One pemone row: pem_decode_one under a text cap and a room of der_max.
static void row_one(uint8_t label, const uint8_t *pem, size_t n, size_t text_max, size_t der_max) {
    int ok = 0;
    wbuf w;
    wb_init(&w, room, der_max);
    if (n <= text_max) {
        ok = pem_decode_one(pem, n, label, &w);
    }
    if (ok) {
        const uint8_t *parts[1] = {room};
        size_t lens[1] = {w.len};
        reply_list(parts, lens, 1);
    } else {
        (void)snprintf(want, sizeof want, "ERR pemone reject");
    }
    char head[96];
    (void)snprintf(head, sizeof head, "pemone %s %zu %zu", label_names[label], text_max, der_max);
    request(head, pem, n);
    compare();
}

// A random edit of n bytes at p, in place, whose result is returned.
static size_t mutate(uint8_t *p, size_t n, size_t cap) {
    switch (rng_below(5)) {
    case 0:
        if (n != 0) {
            p[rng_below(n)] = (uint8_t)(rng_next() >> 56);
        }
        return n;
    case 1:
        return rng_below(n + 1);
    case 2: {
        if (n + 1 > cap) {
            return n;
        }
        size_t at = rng_below(n + 1);
        memmove(p + at + 1, p + at, n - at);
        p[at] = (uint8_t)"\r\n-=A #"[rng_below(7)];
        return n + 1;
    }
    case 3:
        if (n + 5 > cap) {
            return n;
        }
        memmove(p + 5, p, n);
        memcpy(p, "note\n", 5);
        return n + 5;
    default:
        if (2 * n > cap) {
            return n;
        }
        memcpy(p + n, p, n);
        return 2 * n;
    }
}

static const char *const eols[] = {"\n", "\r\n"};

static void diff_one(void) {
    static uint8_t der[400];
    for (int i = 0; i < 300; i++) {
        uint8_t label = (uint8_t)rng_below(PEM_LABEL_COUNT);
        size_t der_len = 1 + rng_below(sizeof der);
        rng_fill(der, der_len);
        size_t width =
            pem_armor_widths[rng_below(sizeof pem_armor_widths / sizeof *pem_armor_widths)];
        size_t n =
            pem_armor_label(label_texts[label], der, der_len, width, eols[rng_below(2)], text);
        // The caps at the input's own size, one under it, and roomy.
        row_one(label, text, n, n, der_len);
        row_one(label, text, n, n - 1, der_len);
        row_one(label, text, n, n, der_len - 1);
        row_one(label, text, n, sizeof text, sizeof room);
        n = mutate(text, n, sizeof text);
        row_one(label, text, n, sizeof text, sizeof room);
    }
}

// Text between and around blocks, each piece a rule tests. Some pieces
// hold a BEGIN line of another label, or a broken one. Either refuses a
// bundle. Some hold "-----BEGIN" in a comment. With a space after it, it
// refuses a bundle. Without the space it is text (pem_blocks.h). Two
// pieces hold a block whose first line differs inside the 11 bytes of
// "-----BEGIN ". A bundle skips that block as text.
static const char *const gaps[] = {
    "",
    "\n",
    "\r\n",
    "\n\n",
    "\r",
    "\n\r",
    "# a comment\n",
    "Root\n====\n",
    " ",
    "\nnote",
    "\r\r\n",
    "-----END CERTIFICATE-----\n",
    "\n\n\n",
    "x\n",
    "\n-----BEGIN PRIVATE KEY-----\nAAAA\n",
    "\xef\xbb\xbf",
    "\t",
    "-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n",
    "\n-----BEGIN X509 CERTIFICATE-----\n",
    "-----BEGIN CERTIFICATE----\n",
    "# blocks open with -----BEGIN \n",
    "# blocks open with -----BEGIN\n",
    "# -----BEGIN-----\n",
    "-----begin CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    "-----BEGIN\tCERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"};

// One pemcerts row over the text at p. It calls pem_blocks_next until the
// text ends or a rule breaks, into a room of room_max bytes. It refuses a
// run of no block, as both of its callers refuse it.
static void row_certs(uint8_t rule, size_t room_max, const uint8_t *p, size_t n) {
    static const uint8_t *parts[TEXT_MAX / 32];
    static size_t lens[TEXT_MAX / 32];
    wbuf w;
    wb_init(&w, room, room_max);
    pem_blocks blocks;
    pem_blocks_init(&blocks, p, n, rule);
    size_t count = 0;
    int next = PEM_BLOCKS_READ;
    while (next == PEM_BLOCKS_READ) {
        const uint8_t *block = NULL;
        size_t block_len = 0;
        next = pem_blocks_next(&blocks, &w, &block, &block_len);
        if (next == PEM_BLOCKS_READ) {
            if (count == sizeof parts / sizeof *parts) {
                die("a run outgrew the parts array");
            }
            parts[count] = block;
            lens[count] = block_len;
            count++;
        }
    }
    if (next == PEM_BLOCKS_END && count != 0) {
        reply_list(parts, lens, count);
    } else {
        (void)snprintf(want, sizeof want, "ERR pemcerts reject");
    }
    char head[96];
    (void)snprintf(head, sizeof head, "pemcerts %s %zu",
                   rule == PEM_TEXT_SKIPPED ? "skipped" : "refused", room_max);
    request(head, p, n);
    compare();
}

// A room for a row: one every text here fits, or a small one a few blocks
// of random DER fill.
static size_t draw_room(void) {
    return rng_below(2) == 0 ? ROOM_MAX : 1 + rng_below(600);
}

// The largest DER blocks_text writes in one block.
#define BLOCK_DER_MOST 4096

// count blocks of random DER, each up to der_most bytes, with a random
// gap before each and after the last. Returns the text's length.
static size_t blocks_text(size_t count, size_t der_most) {
    static uint8_t der[BLOCK_DER_MOST];
    static uint8_t block[2 * BLOCK_DER_MOST];
    size_t n = 0;
    for (size_t i = 0; i <= count; i++) {
        const char *gap = gaps[rng_below(sizeof gaps / sizeof *gaps)];
        if (i == 0 && rng_below(2) == 0) {
            gap = "";
        }
        memcpy(text + n, gap, strlen(gap));
        n += strlen(gap);
        if (i == count) {
            break;
        }
        size_t der_len = 1 + rng_below(der_most);
        rng_fill(der, der_len);
        size_t width =
            pem_armor_widths[rng_below(sizeof pem_armor_widths / sizeof *pem_armor_widths)];
        size_t b = pem_armor(der, der_len, width, eols[rng_below(2)], block);
        // pem_armor ends each block with a terminator; drop it at random,
        // so the gap after the END line is all that follows it.
        if (rng_below(2) == 0) {
            b -= 1;
            if (block[b - 1] == '\r') {
                b -= 1;
            }
        }
        memcpy(text + n, block, b);
        n += b;
    }
    return n;
}

static void diff_certs(void) {
    for (int i = 0; i < 400; i++) {
        size_t count = rng_below(14);
        size_t n = blocks_text(count, 200);
        uint8_t rule = rng_below(2) ? PEM_TEXT_SKIPPED : PEM_TEXT_REFUSED;
        size_t room_max = draw_room();
        row_certs(rule, room_max, text, n);
        row_certs(rule == PEM_TEXT_SKIPPED ? PEM_TEXT_REFUSED : PEM_TEXT_SKIPPED, room_max, text,
                  n);
        n = mutate(text, n, sizeof text);
        row_certs(rule, room_max, text, n);
    }
    // A block of 4,096 bytes of DER in a room of that size and in one byte
    // less. Two blocks that fill a room of 600 bytes, and one byte less.
    static uint8_t der[BLOCK_DER_MOST];
    rng_fill(der, sizeof der);
    for (size_t short_by = 0; short_by < 2; short_by++) {
        size_t n = pem_armor(der, BLOCK_DER_MOST, 64, "\n", text);
        row_certs(PEM_TEXT_REFUSED, BLOCK_DER_MOST - short_by, text, n);
        row_certs(PEM_TEXT_SKIPPED, BLOCK_DER_MOST - short_by, text, n);
        n = pem_armor(der, 400, 64, "\n", text);
        n += pem_armor(der, 200, 64, "\n", text + n);
        row_certs(PEM_TEXT_REFUSED, 600 - short_by, text, n);
        row_certs(PEM_TEXT_SKIPPED, 600 - short_by, text, n);
    }
}

// A random point: what the readers carry is bytes, and the spec's
// readers judge no point.
static void draw_point(uint8_t point[64]) {
    rng_fill(point, 64);
}

// One pemsubjectkey row.
static void row_subject_key(const uint8_t *cert, size_t n) {
    const uint8_t *name = NULL;
    const uint8_t *spki = NULL;
    size_t name_len = 0;
    size_t spki_len = 0;
    if (x509_pem_read_subject_key(cert, n, &name, &name_len, &spki, &spki_len)) {
        (void)snprintf(want, sizeof want, "ok ");
        size_t at = 3 + hex_encode(want + 3, name, name_len);
        want[at++] = ' ';
        (void)hex_encode(want + at, spki, spki_len);
    } else {
        (void)snprintf(want, sizeof want, "ERR pemsubjectkey reject");
    }
    request("pemsubjectkey", cert, n);
    compare();
}

static void diff_subject_key(void) {
    static uint8_t cert[4096];
    for (int i = 0; i < 300; i++) {
        uint8_t point[64];
        draw_point(point);
        pfd_cert_shape shape = {(int)rng_below(2), (int)rng_below(2), rng_below(3) * rng_below(300),
                                (int)(rng_below(8) == 0)};
        size_t n = pfd_cert(cert, sizeof cert, point, shape);
        row_subject_key(cert, n);
        n = mutate(cert, n, sizeof cert);
        row_subject_key(cert, n);
    }
}

// One pemkeyder row.
static void row_key_der(int pkcs8, const uint8_t *der, size_t n) {
    uint8_t scalar[32];
    const uint8_t *point = NULL;
    int ok = pkcs8 ? x509_pem_read_pkcs8(der, n, scalar, &point)
                   : x509_pem_read_sec1(der, n, scalar, &point);
    if (ok) {
        (void)snprintf(want, sizeof want, "ok ");
        size_t at = 3 + hex_encode(want + 3, scalar, 32);
        want[at++] = ' ';
        if (point == NULL) {
            want[at++] = '-';
            want[at] = '\0';
        } else {
            (void)hex_encode(want + at, point, 64);
        }
    } else {
        (void)snprintf(want, sizeof want, "ERR pemkeyder reject");
    }
    request(pkcs8 ? "pemkeyder pkcs8" : "pemkeyder sec1", der, n);
    compare();
}

static pfd_key_shape draw_key_shape(void) {
    pfd_key_shape shape = {(int)rng_below(2), (int)rng_below(2), 32, 0, 0};
    switch (rng_below(8)) {
    case 0:
        shape.scalar_len = 31 + (int)rng_below(3);
        break;
    case 1:
        shape.attributes = 1;
        break;
    case 2:
        shape.pkcs8_version = 1;
        break;
    default:
        break;
    }
    return shape;
}

static void diff_key_der(void) {
    uint8_t der[CH_PEM_KEY_DER_MAX + 64];
    for (int i = 0; i < 300; i++) {
        uint8_t scalar[32];
        uint8_t point[64];
        rng_fill(scalar, sizeof scalar);
        draw_point(point);
        pfd_key_shape shape = draw_key_shape();
        size_t n = pfd_pkcs8(der, sizeof der, scalar, point, shape);
        row_key_der(1, der, n);
        row_key_der(0, der, n);
        n = mutate(der, n, sizeof der);
        row_key_der(1, der, n);
        n = pfd_ec_private_key(der, sizeof der, scalar, point, shape);
        row_key_der(0, der, n);
        row_key_der(1, der, n);
        n = mutate(der, n, sizeof der);
        row_key_der(0, der, n);
    }
}

#include "diff_pem_files_calls.h"

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff pem files: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    spawn_spec(path);
    expect("selftest", "ok");
    diff_one();
    diff_certs();
    diff_subject_key();
    diff_key_der();
    diff_calls();
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff pem files: %ld comparisons, %ld of them acceptances, C == spec\n",
                 comparisons, accepted);
    return 0;
}
