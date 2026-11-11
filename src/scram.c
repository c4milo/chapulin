// The parts of SCRAM-SHA-256 under scram.h's names. scram.h states each
// contract. This file forwards each call to the code that does the work:
// sha256.c, hkdf.c's HMAC, pbkdf2.c, ct.c and base64_codec.c.
// ch_tls_server_end_point is x509_end_point.c's, because it reads a
// certificate (INV-5). Outside a SCRAM build this file holds nothing,
// and scram.h's includes keep the unit from being empty.
#include "scram.h"

#ifdef CH_SCRAM

#include "base64_codec.h"
#include "ct.h"
#include "hkdf.h"
#include "pbkdf2.h"
#include "sha256.h"

_Static_assert(CH_SHA256_LEN == SHA256_LEN, "scram.h states SHA-256's digest length");

// What an empty input points at in the calls below that copy from their
// inputs: memcpy's pointers must be valid even for a length of 0 (C11
// 7.24.1), and scram.h permits NULL there.
static const uint8_t nothing[1] = {0};

void ch_sha256(const uint8_t *p, size_t n, uint8_t out[CH_SHA256_LEN]) {
    sha256 s;
    sha256_init(&s);
    if (n != 0) {
        sha256_update(&s, p, n);
    }
    sha256_final(&s, out);
    // The input may be a secret, such as SCRAM's ClientKey, and the state
    // holds its last block.
    ct_wipe(&s, sizeof s);
}

void ch_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                    uint8_t out[CH_SHA256_LEN]) {
    hmac_sha256(key_len != 0 ? key : nothing, key_len, msg_len != 0 ? msg : nothing, msg_len, out);
}

int ch_pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len, const uint8_t *salt,
                          size_t salt_len, uint32_t iteration_count, uint8_t *out,
                          size_t out_len) {
    return pbkdf2_hmac_sha256(password, password_len, salt, salt_len, iteration_count, out,
                              out_len);
}

int ch_ct_compare(const uint8_t *a, const uint8_t *b, size_t n) {
    // The caller branches on the answer, so it is public once computed.
    return ct_memeq_public(a, b, n) != 0 ? CH_OK : CH_EAUTH;
}

int ch_base64_encode(const uint8_t *in, size_t in_len, uint8_t *text, size_t text_cap,
                     size_t *text_len) {
    return base64_encode(in, in_len, text, text_cap, text_len);
}

int ch_base64_decode(const uint8_t *text, size_t text_len, uint8_t *out, size_t out_cap,
                     size_t *out_len) {
    return base64_decode(text, text_len, out, out_cap, out_len);
}

#endif // CH_SCRAM
