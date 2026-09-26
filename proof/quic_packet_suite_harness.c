// Proves: in a -DCH_SUITE_AES_GCM QUIC build, quic_hp_mask,
// quic_packet_seal and quic_packet_open_handshake run the cipher the key
// set's suite names and stay inside their buffers, over each of the
// three suites: header protection is AES-ECB under a key of
// suite_key_len(suite) bytes for the two AES suites and ChaCha20 for the
// third (RFC 9001 §5.4.3, §5.4.4), packet protection is AES-GCM or
// ChaCha20-Poly1305 by the same rule (§5.3), and quic_packet_seal
// refuses the packet that would reach §6.6's AES-GCM confidentiality
// limit and counts the ones it seals, and counts nothing under ChaCha20.
//
// Every cipher is a contract stub below, because the AES entries run on
// the instructions in a suite build and CBMC cannot read them; the stubs
// assert the key length and record which cipher ran.
// proof/quic_packet_harness.c proves the framing over hostile packets in
// the one-suite build, and test/quic_suite_test.c checks whole packets
// under both AES suites against an independent computation.
#include "harness.h"

#include "aead.h"
#include "aes_traffic_key.h"
#include "chacha20.h"
#include "gcm.h"
#include "suite.h"

#if !defined(CH_SUITE_AES_GCM) || !defined(CH_TRANSPORT_QUIC_NONBLOCKING)
#error                                                                                             \
    "quic_packet_suite proves the QUIC suite build: -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_SUITE_AES_GCM"
#endif

uint64_t nondet_u64(void);

static size_t expected_key_len;
static int aes_ran;
static int chacha_ran;

void aes_traffic_key_init(aes_traffic_key *k, const uint8_t *key, size_t key_len) {
    __CPROVER_assert(key_len == expected_key_len, "aes: the suite's key length");
    __CPROVER_assert(__CPROVER_r_ok(key, key_len), "aes: key readable");
    __CPROVER_assert(__CPROVER_w_ok(k, sizeof *k), "aes: schedule writable");
    k->key.rounds = nondet_u8();
    for (size_t i = 0; i < sizeof k->key.round_keys; i++) {
        k->key.round_keys[i] = nondet_u8();
    }
}

void aes_traffic_encrypt_block(const aes_traffic_key *k, const uint8_t in[AES_BLOCK],
                               uint8_t out[AES_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "aes block: key readable");
    __CPROVER_assert(__CPROVER_r_ok(in, AES_BLOCK), "aes block: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, AES_BLOCK), "aes block: output writable");
    aes_ran = 1;
    fill_nondet(out, AES_BLOCK);
}

void gcm_traffic_seal(const aes_traffic_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                      size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                      uint8_t tag[GCM_TAG]) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "gcm seal: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AES_IV), "gcm seal: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len), "gcm seal: aad readable");
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
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len), "gcm open: aad readable");
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

void chacha20_block(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    uint32_t counter, uint8_t out[CHACHA20_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(key, CHACHA20_KEY), "chacha20_block: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, CHACHA20_NONCE), "chacha20_block: nonce readable");
    __CPROVER_assert(__CPROVER_w_ok(out, CHACHA20_BLOCK), "chacha20_block: output writable");
    (void)counter;
    chacha_ran = 1;
    fill_nondet(out, CHACHA20_BLOCK);
}

void aead_seal(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
               size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[AEAD_TAG]) {
    __CPROVER_assert(__CPROVER_r_ok(key, AEAD_KEY), "aead_seal: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AEAD_NONCE), "aead_seal: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len), "aead_seal: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "aead_seal: plaintext readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(ct, n), "aead_seal: ciphertext writable");
    __CPROVER_assert(__CPROVER_w_ok(tag, AEAD_TAG), "aead_seal: tag writable");
    chacha_ran = 1;
    fill_nondet(ct, n);
    fill_nondet(tag, AEAD_TAG);
}

int aead_open(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
              size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[AEAD_TAG],
              uint8_t *pt) {
    __CPROVER_assert(__CPROVER_r_ok(key, AEAD_KEY), "aead_open: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AEAD_NONCE), "aead_open: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len), "aead_open: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(ct, n), "aead_open: ciphertext readable");
    __CPROVER_assert(__CPROVER_r_ok(tag, AEAD_TAG), "aead_open: tag readable");
    chacha_ran = 1;
    if (nondet_u8() & 1) {
        __CPROVER_assert(n == 0 || __CPROVER_w_ok(pt, n), "aead_open: plaintext writable");
        fill_nondet(pt, n);
        return 1;
    }
    return 0;
}

#include "quic_packet.c"

#define PKT_MAX 40
#define HDR_MAX 8
#define PT_MAX 8

static uint16_t nondet_suite(void) {
    uint8_t pick = nondet_u8();
    __CPROVER_assume(pick < 3);
    if (pick == 1) {
        return SUITE_AES_128_GCM_SHA256;
    }
    if (pick == 2) {
        return SUITE_AES_256_GCM_SHA384;
    }
    return SUITE_CHACHA20_POLY1305_SHA256;
}

static void fill_keys(quic_keys *k, uint16_t suite) {
    fill_nondet(k->key, sizeof k->key);
    fill_nondet(k->iv, sizeof k->iv);
    k->suite = suite;
    k->sealed = nondet_u64();
}

static void fill_hp(quic_hp_key *h, uint16_t suite) {
    fill_nondet(h->key, sizeof h->key);
    h->suite = suite;
}

int main(void) {
    uint16_t suite = nondet_suite();
    int aes = suite != SUITE_CHACHA20_POLY1305_SHA256;
    expected_key_len = suite_key_len(suite);

    quic_hp_key h;
    fill_hp(&h, suite);
    uint8_t sample[QUIC_HP_SAMPLE_LEN];
    uint8_t mask[QUIC_HP_MASK_LEN];
    fill_nondet(sample, sizeof sample);
    aes_ran = 0;
    chacha_ran = 0;
    quic_hp_mask(&h, sample, mask);
    __CPROVER_assert(aes_ran == aes && chacha_ran == !aes, "mask: the suite's cipher");

    // The seal over symbolic lengths and a symbolic count.
    quic_keys k;
    fill_keys(&k, suite);
    uint64_t sealed_before = k.sealed;
    uint8_t hdr[HDR_MAX];
    uint8_t pt[PT_MAX];
    uint8_t out[PKT_MAX];
    size_t out_len = 0;
    size_t hdr_len = nondet_size_t();
    size_t pt_len = nondet_size_t();
    size_t pn_len = nondet_size_t();
    size_t cap = nondet_size_t();
    __CPROVER_assume(hdr_len <= HDR_MAX && pt_len <= PT_MAX && cap <= PKT_MAX);
    __CPROVER_assume(pn_len <= QUIC_PN_MAX_LEN + 1);
    fill_nondet(hdr, sizeof hdr);
    fill_nondet(pt, sizeof pt);
    aes_ran = 0;
    chacha_ran = 0;
    int rc = quic_packet_seal(&k, &h, nondet_u8(), nondet_u64(), pn_len, hdr, hdr_len, pt, pt_len,
                              out, cap, &out_len);
    if (rc == CH_OK) {
        __CPROVER_assert(aes_ran == aes && chacha_ran == !aes, "seal: the suite's ciphers");
        __CPROVER_assert(k.sealed == (aes ? sealed_before + 1 : sealed_before),
                         "seal: AES-GCM counts the packet, ChaCha20 does not");
        __CPROVER_assert(!aes || sealed_before < QUIC_CONFIDENTIALITY_LIMIT - 1,
                         "seal: no AES-GCM packet reaches the limit");
    } else {
        __CPROVER_assert(k.sealed == sealed_before, "seal: a refusal counts nothing");
    }

    // The Handshake open over a symbolic packet.
    fill_keys(&k, suite);
    fill_hp(&h, suite);
    uint8_t pkt[PKT_MAX];
    fill_nondet(pkt, sizeof pkt);
    size_t pkt_len = nondet_size_t();
    size_t pn_off = nondet_size_t();
    __CPROVER_assume(pkt_len <= PKT_MAX && pn_off <= pkt_len);
    uint64_t pn = 0;
    size_t opened = 0;
    aes_ran = 0;
    chacha_ran = 0;
    rc = quic_packet_open_handshake(&k, &h, pkt, pkt_len, pn_off, nondet_u64(), &pn, &opened);
    __CPROVER_assert(!aes_ran || aes, "open: AES runs only under an AES suite");
    __CPROVER_assert(!chacha_ran || !aes, "open: ChaCha20 runs only under ChaCha20");
    if (rc == CH_OK) {
        __CPROVER_assert(pn_off + opened <= pkt_len, "open: the plaintext is in the packet");
    }
    return 0;
}
