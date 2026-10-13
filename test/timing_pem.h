// bin/timing's pem_body row. test/timing_test.c alone includes it,
// after it declares sink and includes rand.h. The row sits in a header of
// its own, so that file stays under the 500 lines lint-size holds.
#ifndef CH_TEST_TIMING_PEM_H
#define CH_TEST_TIMING_PEM_H

#include "buf.h"
#include "pem.h"

// pem_read_block over a PRIVATE KEY block, the reader that a key file's
// body goes through. The row times a body of 'A' alone against bodies of
// random alphabet characters. pem.c branches on a byte's class and never
// on the byte (base64.h). clang wrote a branch on the byte for '+' in
// pem.c's first body loop. Such a branch shows here as a difference in
// the mean. About one character in 64 of a random body takes the other
// path, and none of the fixed body does (docs/decisions.md 131).
#define PEM_BODY_LEN 1024
static const uint8_t pem_begin[] = "-----BEGIN PRIVATE KEY-----\n";
static const uint8_t pem_end[] = "\n-----END PRIVATE KEY-----";
static uint8_t pem_text[sizeof pem_begin - 1 + PEM_BODY_LEN + sizeof pem_end - 1];
static uint8_t pem_der[PEM_BODY_LEN];

static void pem_prep(int class_id) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint8_t *body = pem_text + sizeof pem_begin - 1;
    memcpy(pem_text, pem_begin, sizeof pem_begin - 1);
    ch_rand_bytes(body, PEM_BODY_LEN);
    for (size_t i = 0; i < PEM_BODY_LEN; i++) {
        body[i] = class_id == 0 ? (uint8_t)'A' : (uint8_t)alphabet[body[i] & 63U];
    }
    memcpy(body + PEM_BODY_LEN, pem_end, sizeof pem_end - 1);
}

static void pem_run(void) {
    rbuf r;
    wbuf w;
    rb_init(&r, pem_text, sizeof pem_text);
    wb_init(&w, pem_der, sizeof pem_der);
    sink ^= (uint32_t)pem_read_block(&r, PEM_LABEL_PRIVATE_KEY, &w);
    sink ^= pem_der[w.len - 1];
}

#endif
