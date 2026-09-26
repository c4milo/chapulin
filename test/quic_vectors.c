// The TRANSPORT=quic-nonblocking mode against its published vectors: FIPS 197 for the
// AES-128 and AES-256 forward ciphers, NIST SP 800-38D for
// AEAD_AES_128_GCM, AEAD_AES_256_GCM and GHASH, and RFC 9001 Appendix A
// for the Initial keys, the header protection masks, the client and
// server Initial packets and the Retry integrity tag. The Makefile builds
// it with -DCH_AES_256_TEST, so the AES-256 rows run on both AES values
// below. Its own
// binary because bin/unit includes tls.h and calls rec_seal, which a
// -DCH_TRANSPORT_QUIC_NONBLOCKING build does not compile; bin/sha3_test and
// bin/mlkem_test have the same shape for a mode's own sources.
// docs/quic.md, "Verification owed", names this file and the binary it
// builds.
//
// FIPS 197's vectors fix the key, and INV-26 makes the two constructors
// in aes.h the only public way to write an aes_public_key, so a
// vector whose key the standard chose reaches the cipher through
// aes_block.h's two entries instead. Those take plain bytes and are
// not static, so this file links aes.c and the AES implementation
// the build picked rather than compiling either in. aes_public_key.h gives
// aes_public_key a body here, which INV-26 admits in a test and the
// Semgrep rule excludes `test` for.
//
// bin/quic_test runs AES=soft, bin/quic_test_hw runs the same vectors on
// AES=hw, and bin/quic_test_extern runs them on AES=extern, whose
// ch_aes_block is test/aes_extern_hook.c, so every standard below is
// answered by all three implementations.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_block.h"
#include "aes_public_key.h"
#include "ch_assert.h"
#include "quic_initial.h"
#include "quic_keys.h"
#include "quic_packet.h"
#include "quic_retry.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// Hex helpers in the shape test/unit_test.c uses, so a vector below reads
// as the standard prints it rather than as a byte array someone
// re-encoded by hand. test/gcm_tests.h is their only caller.
static uint8_t nibble(char c) {
    if (c >= '0' && c <= '9') {
        return (uint8_t)(c - '0');
    }
    return (uint8_t)(c - 'a' + 10);
}

static size_t unhex(const char *hex, uint8_t *out) {
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    }
    return n;
}

static int eq_hex(const uint8_t *got, const char *hex) {
    uint8_t want[64];
    size_t n = unhex(hex, want);
    return memcmp(got, want, n) == 0;
}

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

// RFC 9001 Appendix A's Destination Connection ID, 0x8394c8f03e515708
// (rfc9001.txt:2323-2325). Every key below is derived from it.
static const uint8_t APPENDIX_DCID[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

// The GCM vectors, in their own header because the RFC 9001 Appendix A.2
// packet is long. They read APPENDIX_DCID, unhex, eq_hex and CHECK above,
// and aes_expand_round_keys from aes_block.h.
#include "gcm_tests.h"

// The packet protection and header protection vectors, in their own
// header for the same reason: RFC 9001 Appendix A.2's and A.3's headers
// are long. They read unhex, eq_hex and CHECK above.
#include "quic_initial_tests.h"
#include "quic_packet_tests.h"

// FIPS 197's own example values for AES-128. Appendix B works one
// encryption through every round; Appendix C.1 is the full block vector
// for Nk = 4. The key expansion is checked by both, because a wrong
// schedule gives a wrong block.
static void test_fips197_blocks(void) {
    static const uint8_t appendix_b_key[AES_128_KEY] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                                        0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                                        0x09, 0xcf, 0x4f, 0x3c};
    static const uint8_t appendix_b_in[AES_BLOCK] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a,
                                                     0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2,
                                                     0xe0, 0x37, 0x07, 0x34};
    static const uint8_t appendix_b_out[AES_BLOCK] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc,
                                                      0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97,
                                                      0x19, 0x6a, 0x0b, 0x32};
    static const uint8_t appendix_c_key[AES_128_KEY] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                                        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                                        0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t appendix_c_in[AES_BLOCK] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                                     0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                                     0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t appendix_c_out[AES_BLOCK] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b,
                                                      0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
                                                      0x70, 0xb4, 0xc5, 0x5a};
    aes_key_schedule schedule;
    uint8_t out[AES_BLOCK];

    aes_expand_round_keys(appendix_b_key, schedule.round_keys);
    // FIPS 197 §5.2: the key itself is the first round key.
    CHECK(memcmp(schedule.round_keys, appendix_b_key, AES_128_KEY) == 0);
    aes_cipher_block(schedule.round_keys, appendix_b_in, out);
    CHECK(memcmp(out, appendix_b_out, sizeof out) == 0);

    aes_expand_round_keys(appendix_c_key, schedule.round_keys);
    aes_cipher_block(schedule.round_keys, appendix_c_in, out);
    CHECK(memcmp(out, appendix_c_out, sizeof out) == 0);

    // The headers allow in == out, so the same vector must come back
    // when the caller passes one buffer twice.
    uint8_t both[AES_BLOCK];
    memcpy(both, appendix_c_in, sizeof both);
    aes_cipher_block(schedule.round_keys, both, both);
    CHECK(memcmp(both, appendix_c_out, sizeof both) == 0);
}

#ifdef CH_AES_256
// FIPS 197's AES-256 values, for TLS_AES_256_GCM_SHA384's cipher.
// Appendix A.3 expands the 256-bit example key: its first two round keys
// are the key, w[8] is the first word the expansion computes, and w[56]
// to w[59] are the last round key, which only a schedule that ran every
// step of Nk = 8 reaches. Appendix C.3 is the full block vector.
static void test_fips197_aes256(void) {
    static const char appendix_a3_key[] =
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    static const char appendix_c3_key[] =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    uint8_t key[AES_256_KEY];
    uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK];
    uint8_t out[AES_BLOCK];

    CHECK(unhex(appendix_a3_key, key) == sizeof key);
    aes_expand_round_keys_256(key, round_keys);
    CHECK(memcmp(round_keys, key, AES_256_KEY) == 0);
#ifndef CH_AES_EXTERN
    // AES=extern runs no expansion, so these two words exist only under
    // the other two values; test_extern_layout below checks what
    // aes_extern.c writes instead.
    CHECK(eq_hex(round_keys + AES_256_KEY, "9ba35411"));
    CHECK(eq_hex(round_keys + (size_t)AES_256_ROUNDS * AES_BLOCK,
                 "fe4890d1e6188d0b046df344706c631e"));
#endif

    uint8_t in[AES_BLOCK];
    CHECK(unhex(appendix_c3_key, key) == sizeof key);
    CHECK(unhex("00112233445566778899aabbccddeeff", in) == sizeof in);
    aes_expand_round_keys_256(key, round_keys);
    aes_cipher_block_256(round_keys, in, out);
    CHECK(eq_hex(out, "8ea2b7ca516745bfeafc49904b496089"));
    // in == out, as for AES-128 above.
    aes_cipher_block_256(round_keys, in, in);
    CHECK(eq_hex(in, "8ea2b7ca516745bfeafc49904b496089"));
}
#endif

#ifdef CH_AES_EXTERN
// What aes_extern.c's two expansions write, at the exact bound
// aes_block.h states: the key in the first bytes, zeros up to the last
// round key's last byte, and nothing past it. Each buffer is one byte
// longer than the schedule and starts filled with a marker, so the byte
// after the bound must keep it. The 32 key bytes are all checked, so an
// AES-256 expansion that stored 16 of them fails here as well as in the
// FIPS 197 block above.
static int bytes_are(const uint8_t *p, size_t n, uint8_t value) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != value) {
            return 0;
        }
    }
    return 1;
}

static void test_extern_layout(void) {
    enum { MARK = 0xa5, SCHEDULE_128 = AES_ROUND_KEYS * AES_BLOCK };
    uint8_t key[AES_256_KEY];
    for (size_t i = 0; i < sizeof key; i++) {
        key[i] = (uint8_t)(0x10U + i);
    }

    uint8_t round_keys[SCHEDULE_128 + 1];
    memset(round_keys, MARK, sizeof round_keys);
    aes_expand_round_keys(key, round_keys);
    CHECK(memcmp(round_keys, key, AES_128_KEY) == 0);
    CHECK(bytes_are(round_keys + AES_128_KEY, SCHEDULE_128 - AES_128_KEY, 0));
    CHECK(round_keys[SCHEDULE_128] == MARK);

#ifdef CH_AES_256
    enum { SCHEDULE_256 = AES_256_ROUND_KEYS * AES_BLOCK };
    uint8_t round_keys_256[SCHEDULE_256 + 1];
    memset(round_keys_256, MARK, sizeof round_keys_256);
    aes_expand_round_keys_256(key, round_keys_256);
    CHECK(memcmp(round_keys_256, key, AES_256_KEY) == 0);
    CHECK(bytes_are(round_keys_256 + AES_256_KEY, SCHEDULE_256 - AES_256_KEY, 0));
    CHECK(round_keys_256[SCHEDULE_256] == MARK);
#endif
}
#endif

// RFC 9001 Appendix A.1: the client and server Initial keys for the
// Destination Connection ID above (rfc9001.txt:2352-2377). The first 16
// bytes of a schedule are the key that built it, so comparing them
// checks the derivation and the expansion at once.
//
// aes_public_key_initial takes the endpoint whose secret to derive, not
// a direction. Which endpoint each of a caller's two directions needs is
// quic_initial.c's, and test_initial_endpoint_reads checks that.
static void test_appendix_a1_keys(void) {
    static const uint8_t client_key[AES_128_KEY] = {0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
                                                    0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d};
    static const uint8_t client_iv[AES_IV] = {0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3,
                                              0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c};
    static const uint8_t client_hp[AES_128_KEY] = {0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
                                                   0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2};
    static const uint8_t server_key[AES_128_KEY] = {0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c,
                                                    0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37};
    static const uint8_t server_iv[AES_IV] = {0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90,
                                              0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e};
    static const uint8_t server_hp[AES_128_KEY] = {0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76,
                                                   0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14};
    aes_public_key k;

    CHECK(aes_public_key_initial(&k, APPENDIX_DCID, sizeof APPENDIX_DCID,
                                 CH_QUIC_ENDPOINT_CLIENT) == CH_OK);
    CHECK(memcmp(k.key.round_keys, client_key, sizeof client_key) == 0);
    CHECK(memcmp(k.iv, client_iv, sizeof client_iv) == 0);
    CHECK(memcmp(k.hp.round_keys, client_hp, sizeof client_hp) == 0);

    CHECK(aes_public_key_initial(&k, APPENDIX_DCID, sizeof APPENDIX_DCID,
                                 CH_QUIC_ENDPOINT_SERVER) == CH_OK);
    CHECK(memcmp(k.key.round_keys, server_key, sizeof server_key) == 0);
    CHECK(memcmp(k.iv, server_iv, sizeof server_iv) == 0);
    CHECK(memcmp(k.hp.round_keys, server_hp, sizeof server_hp) == 0);
}

// RFC 9001 §5.4.3's mask, against the samples Appendix A.2 and A.3 print
// (rfc9001.txt:2407-2411, rfc9001.txt:2471-2473). The RFC states the
// first five bytes; aes_encrypt_block_hp writes all sixteen and its
// caller reads five.
static void test_appendix_header_masks(void) {
    static const uint8_t client_sample[AES_BLOCK] = {0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68,
                                                     0x9f, 0xb8, 0xec, 0x11, 0xd2, 0x42,
                                                     0xb1, 0x23, 0xdc, 0x9b};
    static const uint8_t client_mask[5] = {0x43, 0x7b, 0x9a, 0xec, 0x36};
    static const uint8_t server_sample[AES_BLOCK] = {0x2c, 0xd0, 0x99, 0x1c, 0xd2, 0x5b,
                                                     0x0a, 0xac, 0x40, 0x6a, 0x58, 0x16,
                                                     0xb6, 0x39, 0x41, 0x00};
    static const uint8_t server_mask[5] = {0x2e, 0xc0, 0xd8, 0x35, 0x6a};
    aes_public_key k;
    uint8_t mask[AES_BLOCK];

    CHECK(aes_public_key_initial(&k, APPENDIX_DCID, sizeof APPENDIX_DCID,
                                 CH_QUIC_ENDPOINT_CLIENT) == CH_OK);
    aes_encrypt_block_hp(&k, client_sample, mask);
    CHECK(memcmp(mask, client_mask, sizeof client_mask) == 0);

    CHECK(aes_public_key_initial(&k, APPENDIX_DCID, sizeof APPENDIX_DCID,
                                 CH_QUIC_ENDPOINT_SERVER) == CH_OK);
    aes_encrypt_block_hp(&k, server_sample, mask);
    CHECK(memcmp(mask, server_mask, sizeof server_mask) == 0);

    // sample == out is allowed, and the RFC's answer must not change.
    uint8_t both[AES_BLOCK];
    memcpy(both, server_sample, sizeof both);
    aes_encrypt_block_hp(&k, both, both);
    CHECK(memcmp(both, server_mask, sizeof server_mask) == 0);
}

// RFC 9001 §5.8's printed key (rfc9001.txt:1499-1500), and the two
// fields aes_public_key_retry leaves zero because §5.8 prints the nonce
// and a Retry packet carries no header protection.
static void test_retry_key(void) {
    static const uint8_t retry_key[AES_128_KEY] = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
                                                   0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e};
    static const aes_key_schedule zero_schedule;
    static const uint8_t zero_iv[AES_IV] = {0};
    aes_public_key k;
    memset(&k, 0xa5, sizeof k);

    aes_public_key_retry(&k);
    CHECK(memcmp(k.key.round_keys, retry_key, sizeof retry_key) == 0);
    CHECK(memcmp(k.iv, zero_iv, sizeof zero_iv) == 0);
    CHECK(memcmp(&k.hp, &zero_schedule, sizeof zero_schedule) == 0);
}

// RFC 9001 Appendix A.4 (rfc9001.txt:2490-2498) through the two calls
// quic_retry.h declares. test_appendix_a4_retry above builds the key,
// the nonce and the empty plaintext itself and drives gcm_seal and
// gcm_open; quic_retry_tag and quic_retry_ok hold all three, so this
// checks what a server sends and what a client gets rather than what a
// caller could assemble.
static void test_retry_call(void) {
    uint8_t pseudo[1 + sizeof APPENDIX_DCID + sizeof A4_RETRY_PACKET];
    size_t pseudo_len = 0;
    pseudo[pseudo_len++] = (uint8_t)sizeof APPENDIX_DCID;
    memcpy(&pseudo[pseudo_len], APPENDIX_DCID, sizeof APPENDIX_DCID);
    pseudo_len += sizeof APPENDIX_DCID;
    size_t retry_body = sizeof A4_RETRY_PACKET - GCM_TAG;
    memcpy(&pseudo[pseudo_len], A4_RETRY_PACKET, retry_body);
    pseudo_len += retry_body;
    const uint8_t *want_tag = &A4_RETRY_PACKET[retry_body];

    // The server's half of §5.8: the tag minted over that pseudo-packet,
    // against the bytes Appendix A.4 prints (rfc9001.txt:2497-2498), and
    // then through the check a client runs on it. Minting and checking
    // are one gcm_seal in quic_retry.c, and this is what holds them to
    // the RFC's answer rather than to each other.
    uint8_t minted[GCM_TAG];
    quic_retry_tag(pseudo, pseudo_len, minted);
    CHECK(memcmp(minted, want_tag, sizeof minted) == 0);
    CHECK(quic_retry_ok(pseudo, pseudo_len, minted) == 1);

    CHECK(quic_retry_ok(pseudo, pseudo_len, want_tag) == 1);

    // The two ways a forged Retry packet differs from this one, and RFC
    // 9000 §17.2.5.2 makes the client discard both: a changed
    // pseudo-packet byte and a changed tag byte.
    pseudo[0] = (uint8_t)(pseudo[0] ^ 1);
    CHECK(quic_retry_ok(pseudo, pseudo_len, want_tag) == 0);
    pseudo[0] = (uint8_t)(pseudo[0] ^ 1);

    uint8_t wrong_tag[GCM_TAG];
    memcpy(wrong_tag, want_tag, sizeof wrong_tag);
    wrong_tag[GCM_TAG - 1] = (uint8_t)(wrong_tag[GCM_TAG - 1] ^ 1);
    CHECK(quic_retry_ok(pseudo, pseudo_len, wrong_tag) == 0);

    // The Original Destination Connection ID is what ties the tag to the
    // Initial packet this Retry answers, so a client that kept the wrong
    // one gets a 0 (rfc9001.txt:1531-1544).
    pseudo[1] = (uint8_t)(pseudo[1] ^ 1);
    CHECK(quic_retry_ok(pseudo, pseudo_len, want_tag) == 0);
}

// The bound aes_public_key_initial states, both sides of it, and the
// endpoint check beside it. RFC 9000 §17.2 caps a connection ID at 20
// bytes and RFC 9001 §5.2 admits a zero-length one, so both ends of the
// admitted range derive keys and the first value past the top does not.
static void test_dcid_bounds(void) {
    uint8_t dcid[CH_QUIC_DCID_MAX + 1];
    memset(dcid, 0x5a, sizeof dcid);
    aes_public_key k;
    aes_public_key before;

    CHECK(aes_public_key_initial(&k, dcid, CH_QUIC_DCID_MAX, CH_QUIC_ENDPOINT_CLIENT) == CH_OK);
    memcpy(&before, &k, sizeof before);
    CHECK(aes_public_key_initial(&k, dcid, CH_QUIC_DCID_MAX + 1, CH_QUIC_ENDPOINT_CLIENT) ==
          CH_EINVAL);
    CHECK(memcmp(&k, &before, sizeof before) == 0);

    // A zero-length Destination Connection ID is the other end of the
    // range, and the salt alone keys the extract there.
    CHECK(aes_public_key_initial(&k, NULL, 0, CH_QUIC_ENDPOINT_CLIENT) == CH_OK);
    CHECK(memcmp(&k, &before, sizeof before) != 0);

    // CH_QUIC_ENDPOINT_CLIENT and CH_QUIC_ENDPOINT_SERVER are the only endpoints;
    // the first value past them refuses and writes nothing.
    memcpy(&before, &k, sizeof before);
    CHECK(aes_public_key_initial(&k, dcid, 8, CH_QUIC_ENDPOINT_SERVER + 1) == CH_EINVAL);
    CHECK(memcmp(&k, &before, sizeof before) == 0);

    // The two endpoints derive different keys from one connection ID,
    // which is what the two labels of §5.2 are for.
    aes_public_key client_side;
    aes_public_key server_side;
    CHECK(aes_public_key_initial(&client_side, dcid, 8, CH_QUIC_ENDPOINT_CLIENT) == CH_OK);
    CHECK(aes_public_key_initial(&server_side, dcid, 8, CH_QUIC_ENDPOINT_SERVER) == CH_OK);
    CHECK(memcmp(&client_side, &server_side, sizeof client_side) != 0);
}

// RFC 9001 Appendix A.5 (rfc9001.txt:2591-2610): the four values a
// server derives from one application write secret under the
// TLS_CHACHA20_POLY1305_SHA256 suite, which is the suite this client
// offers at every level above Initial. The RFC prints the secret and
// all four outputs, so this checks quic_keys.c's three calls end to
// end rather than against each other.
static void test_appendix_a5_keys(void) {
    static const uint8_t secret_in[SHA256_LEN] = {0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e,
                                                  0xbe, 0x69, 0x42, 0x27, 0x48, 0xad, 0x00, 0xa1,
                                                  0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60,
                                                  0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b};
    static const uint8_t want_key[AEAD_KEY] = {0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1,
                                               0xb2, 0x18, 0x20, 0x94, 0xf6, 0x9c, 0xaa, 0x2e,
                                               0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88, 0x96, 0x0a,
                                               0x7a, 0x98, 0x49, 0x79, 0xfb, 0x23, 0xe1, 0xc8};
    static const uint8_t want_iv[AEAD_NONCE] = {0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd,
                                                0xd0, 0xe4, 0x4a, 0x41, 0xc1, 0x44};
    static const uint8_t want_hp[CHACHA20_KEY] = {0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2,
                                                  0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc, 0x8f, 0x1b,
                                                  0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0,
                                                  0xef, 0xcb, 0x07, 0x6b, 0x0a, 0xb7, 0xa7, 0xa4};
    static const uint8_t want_ku[SHA256_LEN] = {0x12, 0x23, 0x50, 0x47, 0x55, 0x03, 0x6d, 0x55,
                                                0x63, 0x42, 0xee, 0x93, 0x61, 0xd2, 0x53, 0x42,
                                                0x1a, 0x82, 0x6c, 0x9e, 0xcd, 0xf3, 0xc7, 0x14,
                                                0x86, 0x84, 0xb3, 0x6b, 0x71, 0x48, 0x81, 0xf9};
    uint8_t secret[SHA256_LEN];
    quic_keys k;
    quic_hp_key h;

    memcpy(secret, secret_in, sizeof secret);
    quic_keys_init(&k, secret);
    CHECK(memcmp(k.key, want_key, sizeof want_key) == 0);
    CHECK(memcmp(k.iv, want_iv, sizeof want_iv) == 0);

    quic_hp_key_init(&h, secret);
    CHECK(memcmp(h.key, want_hp, sizeof want_hp) == 0);

    // The update writes the new secret back over its argument and
    // re-derives the key set from it, so both are checked: the secret
    // against the RFC's ku, and the key set against a fresh derivation
    // from that ku. A build that re-derived from the old secret would
    // pass the first check and fail the second.
    quic_keys_update(secret, &k);
    CHECK(memcmp(secret, want_ku, sizeof want_ku) == 0);
    quic_keys expect;
    quic_keys_init(&expect, want_ku);
    CHECK(memcmp(k.key, expect.key, sizeof expect.key) == 0);
    CHECK(memcmp(k.iv, expect.iv, sizeof expect.iv) == 0);

    // §6.1 does not update the header protection key, so the value the
    // connection started with is still the one to use.
    CHECK(memcmp(h.key, want_hp, sizeof want_hp) == 0);
}

// RFC 9001 Appendix A.2's client Initial packet through
// quic_initial_seal, and the refusals quic_initial.h documents.
//
// What these three sections read, and what they leave alone.
// quic_initial_seal runs three steps: the §5.2 derivation, the §5.3
// seal and the §5.4 mask. The mask reaches the packet through
// quic_packet.c's quic_header_protect, which is still a stub that
// writes nothing, so the header bytes in out are the unprotected ones
// this call copied rather than the protected header the RFC prints, and
// nothing below reads them. The payload and the tag are what the seal
// section compares, and header protection changes neither: §5.4.1 masks
// byte 0 and the packet number field alone. The lane that implements
// quic_packet.c adds the protected header, the A.3 packet and the round
// trip here.

int main(void) {
    test_fips197_blocks();
#ifdef CH_AES_256
    test_fips197_aes256();
#endif
#ifdef CH_AES_EXTERN
    test_extern_layout();
#endif
    test_appendix_a1_keys();
    test_appendix_a5_keys();
    test_appendix_header_masks();
    test_retry_key();
    test_dcid_bounds();
    test_sp800_38d_cases();
    test_ghash_against_tags();
    test_ghash_empty();
    test_appendix_a2_initial();
    test_appendix_a4_retry();
    test_retry_call();
    test_block_boundaries();
    test_in_place();
    test_appendix_a2_seal();
    test_initial_seal_refusals();
    test_initial_open_refusals();
    test_appendix_a3_seal();
    test_initial_endpoint_reads();
    test_initial_endpoint_refusals();
    test_appendix_a5_packet();
    test_appendix_header_protection();
    test_header_protection_edges();
    test_pn_read();
    test_pn_decode();
    test_key_set_rule();
    test_seal_refusals();
    test_open_discards();
    test_handshake_open();
    test_aead_limits();
    if (failures == 0) {
        (void)printf("quic vectors: FIPS 197, SP 800-38D and RFC 9001 Appendix A agree\n");
    }
    return failures != 0;
}
