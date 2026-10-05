// HMAC, HKDF and the key schedule at SHA-384's hash length in the copies
// a host object runs on the CPU's hash instructions, against hkdf.c and
// keysched.c: test/sha2_equiv_copies.h's cases for the hash of
// TLS_AES_256_GCM_SHA384. On arm64 a copy's SHA-384 calls run on
// sha512_hw.c (hash_hw.h), so each case here runs one call under its own
// name and under its copy's, and the two must write the same bytes.
//
// Included by test/sha2_equiv_sha512.h only, on arm64.
#ifndef CH_SHA2_EQUIV_COPIES384_H
#define CH_SHA2_EQUIV_COPIES384_H

// What one case hands the calls: a key that is shorter than SHA-512's
// block, a block, or longer, which HMAC hashes first, a message, two
// secrets of one hash length and an output length.
#define COPY384_KEY_MAX ((size_t)300)
// Where a call that writes two or three secrets writes its second and its
// third.
#define COPY384_SECOND ((size_t)SHA384_LEN)
#define COPY384_THIRD ((size_t)(2 * SHA384_LEN))
typedef struct {
    uint8_t key[COPY384_KEY_MAX];
    size_t key_len;
    uint8_t text[COPY_MESSAGE_MAX];
    size_t text_len;
    uint8_t secret[SHA384_LEN];
    uint8_t transcript[SHA384_LEN];
    size_t out_len;
} copy384_case;

static void copy384_case_fill(copy384_case *c) {
    c->key_len = (size_t)(rng_next() % (COPY384_KEY_MAX + 1));
    rng_fill(c->key, c->key_len);
    c->text_len = (size_t)(rng_next() % (COPY_MESSAGE_MAX + 1));
    rng_fill(c->text, c->text_len);
    rng_fill(c->secret, sizeof c->secret);
    rng_fill(c->transcript, sizeof c->transcript);
    c->out_len = 1 + (size_t)(rng_next() % COPY_OUTPUT_MAX);
}

static void compare_hmac_hkdf384(const copy384_case *c) {
    uint8_t portable[COPY_OUTPUT_MAX];
    uint8_t copy[COPY_OUTPUT_MAX];
    hmac(SHA384_LEN, c->key, c->key_len, c->text, c->text_len, portable);
    hmac_hw(SHA384_LEN, c->key, c->key_len, c->text, c->text_len, copy);
    copies_agree("hmac_hw differs at SHA-384", portable, copy, SHA384_LEN);
    hkdf_extract(SHA384_LEN, c->key, c->key_len, c->text, c->text_len, portable);
    hkdf_extract_hw(SHA384_LEN, c->key, c->key_len, c->text, c->text_len, copy);
    copies_agree("hkdf_extract_hw differs at SHA-384", portable, copy, SHA384_LEN);
    size_t info_len = c->text_len % (HKDF_INFO_MAX + 1);
    hkdf_expand(SHA384_LEN, c->secret, c->text, info_len, portable, c->out_len);
    hkdf_expand_hw(SHA384_LEN, c->secret, c->text, info_len, copy, c->out_len);
    copies_agree("hkdf_expand_hw differs at SHA-384", portable, copy, c->out_len);
    hkdf_expand_label(SHA384_LEN, c->secret, "c hs traffic", c->transcript, SHA384_LEN, portable,
                      c->out_len);
    hkdf_expand_label_hw(SHA384_LEN, c->secret, "c hs traffic", c->transcript, SHA384_LEN, copy,
                         c->out_len);
    copies_agree("hkdf_expand_label_hw differs at SHA-384", portable, copy, c->out_len);
}

// The two calls that write three secrets, which sit one after another in
// each array.
static void compare_schedule_secrets384(const copy384_case *c) {
    uint8_t portable[3 * SHA384_LEN];
    uint8_t copy[3 * SHA384_LEN];
    ks_handshake(SHA384_LEN, c->secret, c->key, c->key_len, c->transcript, portable,
                 portable + COPY384_SECOND, portable + COPY384_THIRD);
    ks_handshake_hw(SHA384_LEN, c->secret, c->key, c->key_len, c->transcript, copy,
                    copy + COPY384_SECOND, copy + COPY384_THIRD);
    copies_agree("ks_handshake_hw differs at SHA-384", portable, copy, sizeof portable);
    ks_master(SHA384_LEN, c->secret, c->transcript, portable, portable + COPY384_SECOND,
              portable + COPY384_THIRD);
    ks_master_hw(SHA384_LEN, c->secret, c->transcript, copy, copy + COPY384_SECOND,
                 copy + COPY384_THIRD);
    copies_agree("ks_master_hw differs at SHA-384", portable, copy, sizeof portable);
}

static void compare_schedule384(const copy384_case *c) {
    uint8_t portable[COPY_OUTPUT_MAX];
    uint8_t copy[COPY_OUTPUT_MAX];
    int resumption = (int)(c->out_len & 1U);
    ks_early(SHA384_LEN, c->key, c->key_len, resumption, portable, portable + COPY384_SECOND);
    ks_early_hw(SHA384_LEN, c->key, c->key_len, resumption, copy, copy + COPY384_SECOND);
    copies_agree("ks_early_hw differs at SHA-384", portable, copy, COPY384_THIRD);
    ks_verify_data(SHA384_LEN, c->secret, c->transcript, portable);
    ks_verify_data_hw(SHA384_LEN, c->secret, c->transcript, copy);
    copies_agree("ks_verify_data_hw differs at SHA-384", portable, copy, SHA384_LEN);
    ks_res_master(SHA384_LEN, c->secret, c->transcript, portable);
    ks_res_master_hw(SHA384_LEN, c->secret, c->transcript, copy);
    copies_agree("ks_res_master_hw differs at SHA-384", portable, copy, SHA384_LEN);
    size_t nonce_len = c->key_len % (SHA384_LEN + 1);
    ks_res_psk(SHA384_LEN, c->secret, c->key, nonce_len, portable);
    ks_res_psk_hw(SHA384_LEN, c->secret, c->key, nonce_len, copy);
    copies_agree("ks_res_psk_hw differs at SHA-384", portable, copy, SHA384_LEN);
#ifdef CH_EXPORTER
    ks_exp_master(SHA384_LEN, c->secret, c->transcript, portable);
    ks_exp_master_hw(SHA384_LEN, c->secret, c->transcript, copy);
    copies_agree("ks_exp_master_hw differs at SHA-384", portable, copy, SHA384_LEN);
    ks_exporter(SHA384_LEN, c->secret, "EXPORTER-test", c->text, c->text_len, portable, c->out_len);
    ks_exporter_hw(SHA384_LEN, c->secret, "EXPORTER-test", c->text, c->text_len, copy, c->out_len);
    copies_agree("ks_exporter_hw differs at SHA-384", portable, copy, c->out_len);
#endif
}

static void run_copies384(void) {
    static copy384_case c;
    for (unsigned long i = 0; i < COPY_CASES && failures == 0; i++) {
        copy384_case_fill(&c);
        compare_hmac_hkdf384(&c);
        compare_schedule_secrets384(&c);
        compare_schedule384(&c);
    }
}

#endif
