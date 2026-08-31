// PEM differential section: random certificates armoured at random line
// widths, and random mutations of them. Every row asserts that pem.c
// and the Lean spec reach the same verdict, and on acceptance return
// the same bytes. spec/Spec/Pem.lean is written from RFC 7468 and RFC
// 4648 and never from pem.c, so agreement is evidence rather than a
// restatement.
//
// These rows are the only coverage of long input. proof/pem_harness.c
// is exhaustive but stops at CH_PROOF_PEM_LEN, while the decoder
// accepts up to CH_PEM_MAX; the accept rows below run that whole range.
// Included by test/diff_test.c after diff_driver.h.
#ifndef CH_DIFFPEM_H
#define CH_DIFFPEM_H

#include "pem.h"
#include "pem_armor.h"

// One row: run both sides on the same bytes and compare. The C answer
// becomes the expected string, so a divergence prints both.
static void dpem_row(const uint8_t *pem, size_t pem_len) {
    static uint8_t der[CH_X509_MAX];
    size_t der_len = 0;
    int rc = pem_decode_certificate(pem, pem_len, der, &der_len);

    static char want[2 * CH_X509_MAX + 8];
    if (rc == CH_OK) {
        (void)memcpy(want, "ok ", 3);
        (void)hex_encode(want + 3, der, der_len);
    } else {
        (void)snprintf(want, sizeof want, "ERR pem reject");
    }
    static char cmd[2 * (CH_PEM_MAX + 64) + 32];
    int head = snprintf(cmd, sizeof cmd, "pemdecode %d ", (int)CH_X509_MAX);
    (void)hex_encode(cmd + head, pem, pem_len);
    expect(cmd, want);
}

// Rule-targeted near misses. Random mutation breaks a block in several
// ways at once, so both sides reject on whichever rule fires first and
// the row discriminates nothing. These bodies are valid except for one
// rule each, wrapped at a random width after a random number of valid
// quantums, so the position and length stay randomized while the
// violation stays exact.
static const char *const dpem_near[] = {
    "",         // an empty body
    "A===",     // three pads: the C rejects the first pad at group
                // position 1, the spec rejects npad > 2 -- same verdict,
                // different rule, which is what the row checks
    "QR==",     // the bits the padding stands for are not zero
    "QUJ=",     // the same, with one pad
    "QQ=",      // the quantum does not close
    "QQQ",      // likewise, with no pad
    "QQQQQ",    // nor does this
    "=QQQ",     // a pad at group position 0
    "Q=QQ",     // a pad inside a quantum
    "QQ==QQQQ", // an alphabet character after a pad
    "QQ==A",    // the same, unterminated
    "QQ--",     // base64url is a different alphabet
    "QQ__",
};

static void dpem_near_rows(uint8_t *pem, uint8_t *body) {
    for (size_t which = 0; which < sizeof dpem_near / sizeof *dpem_near; which++) {
        for (int rep = 0; rep < 3; rep++) {
            // A random run of whole valid quantums in front, so the
            // violation lands at a different offset every time. One
            // repetition always uses none, or the empty-body row would
            // carry a body and stop testing the rule it is here for.
            size_t quantums = (rep == 0) ? 0 : rng_below(12);
            size_t n = 0;
            for (size_t q = 0; q < quantums * 4; q++) {
                body[n++] = (uint8_t)pem_armor_alphabet[rng_below(64)];
            }
            size_t tail_len = strlen(dpem_near[which]);
            (void)memcpy(body + n, dpem_near[which], tail_len);
            n += tail_len;
            size_t width =
                pem_armor_widths[rng_below(sizeof pem_armor_widths / sizeof *pem_armor_widths)];
            const char *eol = rng_below(2) != 0 ? "\r\n" : "\n";
            dpem_row(pem, pem_wrap_text(body, n, width, eol, pem));
        }
    }
}

// The boundary rules, which no body mutation reaches: the BEGIN line's
// own terminator, content after the END line, and the byte cap.
static void dpem_boundary_rows(uint8_t *pem, const uint8_t *der, size_t der_n) {
    size_t base = pem_armor(der, der_n, 64, "\n", pem);
    static uint8_t v[CH_PEM_MAX + 64];

    // A bare CR, and CR CR LF, where the BEGIN terminator belongs.
    (void)memcpy(v, pem, base);
    v[27] = '\r';
    dpem_row(v, base);
    (void)memcpy(v, pem, 27);
    v[27] = '\r';
    v[28] = '\r';
    v[29] = '\n';
    (void)memcpy(v + 30, pem + 28, base - 28);
    dpem_row(v, base + 2);

    // Terminators after END are fine; one other byte is not.
    (void)memcpy(v, pem, base);
    v[base] = '\n';
    v[base + 1] = '\r';
    v[base + 2] = '\n';
    dpem_row(v, base + 3);
    v[base + 2] = 'x';
    dpem_row(v, base + 3);

    // Exactly at the cap, and one byte past it. No other row reaches
    // this: an armoured certificate always fits, by construction.
    if (base < CH_PEM_MAX) {
        (void)memcpy(v, pem, base);
        (void)memset(v + base, '\n', CH_PEM_MAX + 1 - base);
        dpem_row(v, CH_PEM_MAX);
        dpem_row(v, CH_PEM_MAX + 1);
    }
}

// An offset in [28, base - 56]: past the BEGIN line's 28 bytes, and
// short enough that a 4-byte run ends before the END line's 26. A run
// landing inside a boundary would test the boundary match, not the
// body's terminator handling the splice row is for. The floor covers
// the smallest armoured certificates, whose bodies are shorter than
// the margin.
static size_t dpem_body_offset(size_t base) {
    return 28 + rng_below(base > 83 ? base - 83 : 1);
}

// Random mutations of a valid block. The certificate stays small so
// a second block and an insertion still fit under the cap: the point
// is the grammar, and the cap has its own rows elsewhere.
static void dpem_mutation_rows(uint8_t *pem, uint8_t *mut, uint8_t *der) {
    for (int i = 0; i < 400; i++) {
        size_t n = 1 + rng_below(48);
        rng_fill(der, n);
        size_t width =
            pem_armor_widths[rng_below(sizeof pem_armor_widths / sizeof *pem_armor_widths)];
        size_t base = pem_armor(der, n, width, rng_below(2) != 0 ? "\r\n" : "\n", pem);
        (void)memcpy(mut, pem, base);
        size_t len = base;
        switch (rng_below(7)) {
        case 0: // one byte becomes any other byte
            mut[rng_below(base)] = (uint8_t)(rng_next() >> 56);
            break;
        case 1: // truncated anywhere
            len = rng_below(base);
            break;
        case 2: { // one byte inserted anywhere
            size_t at = rng_below(base);
            (void)memmove(mut + at + 1, mut + at, base - at);
            mut[at] = (uint8_t)(rng_next() >> 56);
            len = base + 1;
            break;
        }
        case 3: // a second block
            (void)memcpy(mut + base, pem, base);
            len = base * 2;
            break;
        case 6: { // a pad character spliced into the body, which is the
                  // only way to reach "alphabet character after a pad":
                  // no single-byte edit of a valid block produces it.
            size_t at = 28 + rng_below(base > 34 ? base - 34 : 1);
            (void)memmove(mut + at + 1, mut + at, base - at);
            mut[at] = (uint8_t)'=';
            len = base + 1;
            break;
        }
        case 4: { // explanatory text before the boundary
            (void)memmove(mut + 5, mut, base);
            (void)memcpy(mut, "note\n", 5);
            len = base + 5;
            break;
        }
        default: { // a run of terminators spliced into the body
            size_t at = dpem_body_offset(base);
            size_t run = 1 + rng_below(4);
            (void)memmove(mut + at + run, mut + at, base - at);
            for (size_t k = 0; k < run; k++) {
                mut[at + k] = (rng_below(2) != 0) ? (uint8_t)'\r' : (uint8_t)'\n';
            }
            len = base + run;
            break;
        }
        }
        dpem_row(mut, len);
    }
}

static void diff_pem(void) {
    static uint8_t der[CH_X509_MAX];
    static uint8_t pem[CH_PEM_MAX + 64];
    static uint8_t mut[CH_PEM_MAX + 64];

    // Accept rows across the whole length range. Any DER up to
    // CH_X509_MAX armours inside CH_PEM_MAX at every admitted width --
    // that is what the cap is sized for -- so no row is skipped.
    for (int i = 0; i < 120; i++) {
        size_t n = 1 + rng_below(CH_X509_MAX);
        rng_fill(der, n);
        size_t width =
            pem_armor_widths[rng_below(sizeof pem_armor_widths / sizeof *pem_armor_widths)];
        size_t len = pem_armor(der, n, width, rng_below(2) != 0 ? "\r\n" : "\n", pem);
        dpem_row(pem, len);
    }

    dpem_mutation_rows(pem, mut, der);

    dpem_near_rows(pem, mut);
    for (int i = 0; i < 8; i++) {
        size_t n = 1 + rng_below(64);
        rng_fill(der, n);
        dpem_boundary_rows(pem, der, n);
    }
}

#endif
