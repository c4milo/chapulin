// HMAC, HKDF and the key schedule in the copies a host object runs on the
// CPU's hash instructions, hkdf_hw.c and keysched_hw.c, against hkdf.c and
// keysched.c (hash_hw.h, docs/decisions.md 93). A copy is its file's source
// text compiled once more with its SHA-256 calls on sha256_hw.c, so the two
// must write the same bytes for the same inputs. Each case here runs one
// call under its own name and under its copy's, on random keys, messages
// and lengths, at SHA-256's hash length.
//
// Included by test/sha2_equiv_test.c only, which declares the generator,
// report and the counts this file uses.
#ifndef CH_SHA2_EQUIV_COPIES_H
#define CH_SHA2_EQUIV_COPIES_H

#define COPY_CASES 2000
#define COPY_KEY_MAX ((size_t)200)
#define COPY_MESSAGE_MAX ((size_t)300)
#define COPY_OUTPUT_MAX ((size_t)200)
// Where a call that writes two or three secrets writes its second and its
// third.
#define COPY_SECOND ((size_t)SHA256_LEN)
#define COPY_THIRD ((size_t)(2 * SHA256_LEN))

// What one case hands the calls: a key that is shorter than a block, a
// block, or longer, which HMAC hashes first, a message, two secrets of one
// hash length and an output length.
typedef struct {
    uint8_t key[COPY_KEY_MAX];
    size_t key_len;
    uint8_t text[COPY_MESSAGE_MAX];
    size_t text_len;
    uint8_t secret[SHA256_LEN];
    uint8_t transcript[SHA256_LEN];
    size_t out_len;
} copy_case;

static void copy_case_fill(copy_case *c) {
    c->key_len = (size_t)(rng_next() % (COPY_KEY_MAX + 1));
    rng_fill(c->key, c->key_len);
    c->text_len = (size_t)(rng_next() % (COPY_MESSAGE_MAX + 1));
    rng_fill(c->text, c->text_len);
    rng_fill(c->secret, sizeof c->secret);
    rng_fill(c->transcript, sizeof c->transcript);
    c->out_len = 1 + (size_t)(rng_next() % COPY_OUTPUT_MAX);
}

// Counts one comparison, and reports it when the two outputs differ.
static void copies_agree(const char *call, const uint8_t *portable, const uint8_t *copy, size_t n) {
    compared++;
    if (memcmp(portable, copy, n) != 0) {
        report("copies", call, n, 0, 0, PATHS_ALL);
    }
}

static void compare_hmac(const copy_case *c) {
    uint8_t portable[SHA256_LEN];
    uint8_t copy[SHA256_LEN];
    hmac_sha256(c->key, c->key_len, c->text, c->text_len, portable);
    hmac_sha256_hw(c->key, c->key_len, c->text, c->text_len, copy);
    copies_agree("hmac_sha256_hw differs", portable, copy, SHA256_LEN);
    hmac(SHA256_LEN, c->key, c->key_len, c->text, c->text_len, portable);
    hmac_hw(SHA256_LEN, c->key, c->key_len, c->text, c->text_len, copy);
    copies_agree("hmac_hw differs", portable, copy, SHA256_LEN);
}

static void compare_hkdf(const copy_case *c) {
    uint8_t portable[COPY_OUTPUT_MAX];
    uint8_t copy[COPY_OUTPUT_MAX];
    hkdf_extract(SHA256_LEN, c->key, c->key_len, c->text, c->text_len, portable);
    hkdf_extract_hw(SHA256_LEN, c->key, c->key_len, c->text, c->text_len, copy);
    copies_agree("hkdf_extract_hw differs", portable, copy, SHA256_LEN);
    hkdf_extract(SHA256_LEN, NULL, 0, c->text, c->text_len, portable);
    hkdf_extract_hw(SHA256_LEN, NULL, 0, c->text, c->text_len, copy);
    copies_agree("hkdf_extract_hw differs with no salt", portable, copy, SHA256_LEN);
    size_t info_len = c->text_len % (HKDF_INFO_MAX + 1);
    hkdf_expand(SHA256_LEN, c->secret, c->text, info_len, portable, c->out_len);
    hkdf_expand_hw(SHA256_LEN, c->secret, c->text, info_len, copy, c->out_len);
    copies_agree("hkdf_expand_hw differs", portable, copy, c->out_len);
    hkdf_expand_label(SHA256_LEN, c->secret, "c hs traffic", c->transcript, SHA256_LEN, portable,
                      c->out_len);
    hkdf_expand_label_hw(SHA256_LEN, c->secret, "c hs traffic", c->transcript, SHA256_LEN, copy,
                         c->out_len);
    copies_agree("hkdf_expand_label_hw differs", portable, copy, c->out_len);
}

// The two calls that write three secrets, which sit one after another in
// each array.
static void compare_schedule_secrets(const copy_case *c) {
    uint8_t portable[3 * SHA256_LEN];
    uint8_t copy[3 * SHA256_LEN];
    ks_handshake(SHA256_LEN, c->secret, c->key, c->key_len, c->transcript, portable,
                 portable + COPY_SECOND, portable + COPY_THIRD);
    ks_handshake_hw(SHA256_LEN, c->secret, c->key, c->key_len, c->transcript, copy,
                    copy + COPY_SECOND, copy + COPY_THIRD);
    copies_agree("ks_handshake_hw differs", portable, copy, sizeof portable);
    ks_master(SHA256_LEN, c->secret, c->transcript, portable, portable + COPY_SECOND,
              portable + COPY_THIRD);
    ks_master_hw(SHA256_LEN, c->secret, c->transcript, copy, copy + COPY_SECOND, copy + COPY_THIRD);
    copies_agree("ks_master_hw differs", portable, copy, sizeof portable);
}

static void compare_schedule(const copy_case *c) {
    uint8_t portable[2 * SHA256_LEN];
    uint8_t copy[2 * SHA256_LEN];
    int resumption = (int)(c->out_len & 1U);
    ks_early(SHA256_LEN, c->key, c->key_len, resumption, portable, portable + COPY_SECOND);
    ks_early_hw(SHA256_LEN, c->key, c->key_len, resumption, copy, copy + COPY_SECOND);
    copies_agree("ks_early_hw differs", portable, copy, sizeof portable);
    ks_verify_data(SHA256_LEN, c->secret, c->transcript, portable);
    ks_verify_data_hw(SHA256_LEN, c->secret, c->transcript, copy);
    copies_agree("ks_verify_data_hw differs", portable, copy, SHA256_LEN);
    ks_res_master(SHA256_LEN, c->secret, c->transcript, portable);
    ks_res_master_hw(SHA256_LEN, c->secret, c->transcript, copy);
    copies_agree("ks_res_master_hw differs", portable, copy, SHA256_LEN);
    size_t nonce_len = c->key_len % (SHA256_LEN + 1);
    ks_res_psk(SHA256_LEN, c->secret, c->key, nonce_len, portable);
    ks_res_psk_hw(SHA256_LEN, c->secret, c->key, nonce_len, copy);
    copies_agree("ks_res_psk_hw differs", portable, copy, SHA256_LEN);
}

#ifdef CH_EXPORTER
static void compare_exporter(const copy_case *c) {
    uint8_t portable[COPY_OUTPUT_MAX];
    uint8_t copy[COPY_OUTPUT_MAX];
    ks_exp_master(SHA256_LEN, c->secret, c->transcript, portable);
    ks_exp_master_hw(SHA256_LEN, c->secret, c->transcript, copy);
    copies_agree("ks_exp_master_hw differs", portable, copy, SHA256_LEN);
    ks_exporter(SHA256_LEN, c->secret, "EXPORTER-test", c->text, c->text_len, portable, c->out_len);
    ks_exporter_hw(SHA256_LEN, c->secret, "EXPORTER-test", c->text, c->text_len, copy, c->out_len);
    copies_agree("ks_exporter_hw differs", portable, copy, c->out_len);
}
#endif

static void run_copies(void) {
    static copy_case c;
    for (unsigned long i = 0; i < COPY_CASES && failures == 0; i++) {
        copy_case_fill(&c);
        compare_hmac(&c);
        compare_hkdf(&c);
        compare_schedule_secrets(&c);
        compare_schedule(&c);
#ifdef CH_EXPORTER
        compare_exporter(&c);
#endif
    }
}

#endif
