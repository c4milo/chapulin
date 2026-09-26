// Proves: in a -DCH_SUITE_AES_GCM build, rec_dir_init_suite and
// rec_dir_update are memory safe over each of the three suites and a
// secret as long as that suite's hash, and they derive at the suite's
// hash and key length: every hkdf_expand_label call runs at
// suite_hash_len(suite), the "key" derive writes suite_key_len(suite)
// bytes, and the direction keeps its suite across a KeyUpdate. Then one
// record of up to 16 bytes seals and one opens, which proves the
// dispatch to the AEAD the suite names: AES-GCM for the two AES suites
// and ChaCha20-Poly1305 for the third, each with a key of the right
// length.
//
// Layered proof, as proof/record_harness.c is: hkdf, the ChaCha20 AEAD
// and the AES-GCM traffic entries are contract stubs. The AES entries run
// on the instructions in a suite build, which CBMC cannot read, so their
// contracts are what the stubs assert; bin/aes_suite_test and the
// Wycheproof AES-GCM suites test the cipher itself. record_harness.c
// proves the record framing, rec_seal and rec_open over hostile bytes, in
// the one-suite build; the framing is the same code in this one.
#include "harness.h"

#include <string.h>

#include "aead.h"
#include "aes_traffic_key.h"
#include "gcm.h"
#include "hkdf.h"
#include "suite.h"

#if !defined(CH_SUITE_AES_GCM)
#error "record_suite proves the suite build; its launch line must pass -DCH_SUITE_AES_GCM"
#endif

// What main expects the stubs to see for the suite it chose.
static size_t expected_hash_len;
static size_t expected_key_len;
static int aes_ran;
static int chacha_ran;

void hkdf_expand_label(size_t hash_len, const uint8_t *secret, const char *label,
                       const uint8_t *ctx, size_t ctx_len, uint8_t *out, size_t out_len) {
    __CPROVER_assert(hash_len == expected_hash_len, "label: the suite's hash");
    __CPROVER_assert(__CPROVER_r_ok(secret, hash_len), "label: secret readable");
    __CPROVER_assert(ctx_len == 0, "label: record labels take no context");
    (void)ctx;
    __CPROVER_assert(__CPROVER_w_ok(out, out_len), "label: output writable");
    if (strcmp(label, "key") == 0) {
        __CPROVER_assert(out_len == expected_key_len, "label: the suite's key length");
    }
    fill_nondet(out, out_len);
}

void aes_traffic_key_init(aes_traffic_key *k, const uint8_t *key, size_t key_len) {
    __CPROVER_assert(key_len == expected_key_len, "aes: the suite's key length");
    __CPROVER_assert(__CPROVER_r_ok(key, key_len), "aes: key readable");
    __CPROVER_assert(__CPROVER_w_ok(k, sizeof *k), "aes: schedule writable");
    k->key.rounds = nondet_u8();
    for (size_t i = 0; i < sizeof k->key.round_keys; i++) {
        k->key.round_keys[i] = nondet_u8();
    }
}

void gcm_traffic_seal(const aes_traffic_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                      size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                      uint8_t tag[GCM_TAG]) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "gcm seal: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AES_IV), "gcm seal: nonce readable");
    __CPROVER_assert(__CPROVER_r_ok(aad, aad_len), "gcm seal: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "gcm seal: pt readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(ct, n), "gcm seal: ct writable");
    __CPROVER_assert(__CPROVER_w_ok(tag, GCM_TAG), "gcm seal: tag writable");
    aes_ran = 1;
    fill_nondet(ct, n);
    fill_nondet(tag, GCM_TAG);
}

int gcm_traffic_open(const aes_traffic_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                     size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[GCM_TAG],
                     uint8_t *pt) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "gcm open: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AES_IV), "gcm open: nonce readable");
    __CPROVER_assert(__CPROVER_r_ok(aad, aad_len), "gcm open: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(ct, n), "gcm open: ct readable");
    __CPROVER_assert(__CPROVER_r_ok(tag, GCM_TAG), "gcm open: tag readable");
    aes_ran = 1;
    if (nondet_u8() & 1) {
        __CPROVER_assert(n == 0 || __CPROVER_w_ok(pt, n), "gcm open: pt writable");
        fill_nondet(pt, n);
        return 1;
    }
    return 0;
}

void aead_seal(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
               size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[AEAD_TAG]) {
    __CPROVER_assert(__CPROVER_r_ok(key, AEAD_KEY), "seal: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AEAD_NONCE), "seal: nonce readable");
    __CPROVER_assert(__CPROVER_r_ok(aad, aad_len), "seal: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "seal: pt readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(ct, n), "seal: ct writable");
    __CPROVER_assert(__CPROVER_w_ok(tag, AEAD_TAG), "seal: tag writable");
    chacha_ran = 1;
    fill_nondet(ct, n);
    fill_nondet(tag, AEAD_TAG);
}

int aead_open(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
              size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[AEAD_TAG],
              uint8_t *pt) {
    __CPROVER_assert(__CPROVER_r_ok(key, AEAD_KEY), "open: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AEAD_NONCE), "open: nonce readable");
    __CPROVER_assert(__CPROVER_r_ok(aad, aad_len), "open: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(ct, n), "open: ct readable");
    __CPROVER_assert(__CPROVER_r_ok(tag, AEAD_TAG), "open: tag readable");
    chacha_ran = 1;
    if (nondet_u8() & 1) {
        __CPROVER_assert(n == 0 || __CPROVER_w_ok(pt, n), "open: pt writable");
        fill_nondet(pt, n);
        return 1;
    }
    return 0;
}

#include "record.c"

#define RECORD_SUITE_PT_MAX 16

int main(void) {
    uint16_t suite = SUITE_CHACHA20_POLY1305_SHA256;
    uint8_t pick = nondet_u8();
    __CPROVER_assume(pick < 3);
    if (pick == 1) {
        suite = SUITE_AES_128_GCM_SHA256;
    }
    if (pick == 2) {
        suite = SUITE_AES_256_GCM_SHA384;
    }
    expected_hash_len = suite_hash_len(suite);
    expected_key_len = suite_key_len(suite);
    int aes_suite = suite != SUITE_CHACHA20_POLY1305_SHA256;

    uint8_t secret[HKDF_HASH_MAX];
    fill_nondet(secret, sizeof secret);
    rec_dir d;
    rec_dir_init_suite(&d, secret, suite);
    __CPROVER_assert(d.suite == suite, "init: the direction records its suite");
    __CPROVER_assert(d.seq == 0, "init: the sequence starts at 0");
    rec_dir_update(secret, &d);
    __CPROVER_assert(d.suite == suite, "update: KeyUpdate keeps the suite");

    uint8_t pt[RECORD_SUITE_PT_MAX];
    uint8_t out[REC_OVERHEAD + RECORD_SUITE_PT_MAX];
    fill_nondet(pt, sizeof pt);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof pt);
    size_t out_len = 0;
    aes_ran = 0;
    chacha_ran = 0;
    if (rec_seal(&d, REC_APPDATA, pt, n, out, sizeof out, &out_len) == 0) {
        __CPROVER_assert(aes_ran == aes_suite && chacha_ran == !aes_suite,
                         "seal: the AEAD the suite names");
    }

    uint8_t rec[REC_OVERHEAD + RECORD_SUITE_PT_MAX];
    fill_nondet(rec, sizeof rec);
    size_t rec_len = nondet_size_t();
    __CPROVER_assume(rec_len <= sizeof rec);
    uint8_t got[RECORD_SUITE_PT_MAX + 1];
    size_t got_len = 0;
    uint8_t type = 0;
    aes_ran = 0;
    chacha_ran = 0;
    (void)rec_open(&d, rec, rec_len, got, sizeof got, &got_len, &type);
    __CPROVER_assert(!aes_ran || aes_suite, "open: AES-GCM runs only under an AES suite");
    __CPROVER_assert(!chacha_ran || !aes_suite, "open: ChaCha20 runs only under ChaCha20");
    return 0;
}
