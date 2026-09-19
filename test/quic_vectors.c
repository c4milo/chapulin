// The TRANSPORT=quic mode against its published vectors: FIPS 197 for the
// AES-128 forward cipher, NIST SP 800-38D for AEAD_AES_128_GCM and GHASH,
// and RFC 9001 Appendix A for the Initial keys, the header protection
// masks, the client Initial packet and the Retry integrity tag. Its own
// binary because bin/unit includes tls.h and calls rec_seal, which a
// -DCH_TRANSPORT_QUIC build does not compile; bin/sha3_test and
// bin/mlkem_test have the same shape for a mode's own sources.
// docs/quic.md, "Verification owed", names this file and the binary it
// builds.
//
// It compiles quic_aes.c rather than linking it. FIPS 197's vectors fix
// the key, INV-26 makes the two constructors the only public way to write
// an aes_public_key, and neither constructor takes a key the caller chose.
// So the block cipher and the key schedule are reached the way
// test/softmul_test.c reaches softmul.c: the source is compiled in.
// bin/quic_test therefore does not link quic_aes.c a second time. It does
// link quic_gcm.c, whose three entries are not static and take the key
// type that quic_aes.c builds.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "quic_aes.c"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// Hex helpers in the shape test/unit_test.c uses, so a vector below reads
// as the standard prints it rather than as a byte array someone
// re-encoded by hand. test/quic_gcm_tests.h is their only caller.
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
// and expand_key from the quic_aes.c included with them.
#include "quic_gcm_tests.h"

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

    expand_key(appendix_b_key, &schedule);
    // FIPS 197 §5.2: the key itself is the first round key.
    CHECK(memcmp(schedule.round_keys, appendix_b_key, AES_128_KEY) == 0);
    cipher(&schedule, appendix_b_in, out);
    CHECK(memcmp(out, appendix_b_out, sizeof out) == 0);

    expand_key(appendix_c_key, &schedule);
    cipher(&schedule, appendix_c_in, out);
    CHECK(memcmp(out, appendix_c_out, sizeof out) == 0);

    // The headers allow in == out, so the same vector must come back
    // when the caller passes one buffer twice.
    uint8_t both[AES_BLOCK];
    memcpy(both, appendix_c_in, sizeof both);
    cipher(&schedule, both, both);
    CHECK(memcmp(both, appendix_c_out, sizeof both) == 0);
}

// RFC 9001 Appendix A.1: the client and server Initial keys for the
// Destination Connection ID above (rfc9001.txt:2355-2377). The first 16
// bytes of a schedule are the key that built it, so comparing them
// checks the derivation and the expansion at once.
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

    CHECK(aes_public_key_initial(&k, APPENDIX_DCID, sizeof APPENDIX_DCID, CH_KEY_WRITE) == CH_OK);
    CHECK(memcmp(k.key.round_keys, client_key, sizeof client_key) == 0);
    CHECK(memcmp(k.iv, client_iv, sizeof client_iv) == 0);
    CHECK(memcmp(k.hp.round_keys, client_hp, sizeof client_hp) == 0);

    CHECK(aes_public_key_initial(&k, APPENDIX_DCID, sizeof APPENDIX_DCID, CH_KEY_READ) == CH_OK);
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

    CHECK(aes_public_key_initial(&k, APPENDIX_DCID, sizeof APPENDIX_DCID, CH_KEY_WRITE) == CH_OK);
    aes_encrypt_block_hp(&k, client_sample, mask);
    CHECK(memcmp(mask, client_mask, sizeof client_mask) == 0);

    CHECK(aes_public_key_initial(&k, APPENDIX_DCID, sizeof APPENDIX_DCID, CH_KEY_READ) == CH_OK);
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
    static const aes_key_schedule zero_schedule = {{0}};
    static const uint8_t zero_iv[AES_IV] = {0};
    aes_public_key k;
    memset(&k, 0xa5, sizeof k);

    aes_public_key_retry(&k);
    CHECK(memcmp(k.key.round_keys, retry_key, sizeof retry_key) == 0);
    CHECK(memcmp(k.iv, zero_iv, sizeof zero_iv) == 0);
    CHECK(memcmp(&k.hp, &zero_schedule, sizeof zero_schedule) == 0);
}

// The bound aes_public_key_initial states, both sides of it, and the
// direction check beside it. RFC 9000 §17.2 caps a connection ID at 20
// bytes and RFC 9001 §5.2 admits a zero-length one, so both ends of the
// admitted range derive keys and the first value past the top does not.
static void test_dcid_bounds(void) {
    uint8_t dcid[CH_QUIC_DCID_MAX + 1];
    memset(dcid, 0x5a, sizeof dcid);
    aes_public_key k;
    aes_public_key before;

    CHECK(aes_public_key_initial(&k, dcid, CH_QUIC_DCID_MAX, CH_KEY_WRITE) == CH_OK);
    memcpy(&before, &k, sizeof before);
    CHECK(aes_public_key_initial(&k, dcid, CH_QUIC_DCID_MAX + 1, CH_KEY_WRITE) == CH_EINVAL);
    CHECK(memcmp(&k, &before, sizeof before) == 0);

    // A zero-length Destination Connection ID is the other end of the
    // range, and the salt alone keys the extract there.
    CHECK(aes_public_key_initial(&k, NULL, 0, CH_KEY_WRITE) == CH_OK);
    CHECK(memcmp(&k, &before, sizeof before) != 0);

    // CH_KEY_READ and CH_KEY_WRITE are the only directions; the first
    // value past them refuses and writes nothing.
    memcpy(&before, &k, sizeof before);
    CHECK(aes_public_key_initial(&k, dcid, 8, CH_KEY_WRITE + 1) == CH_EINVAL);
    CHECK(memcmp(&k, &before, sizeof before) == 0);

    // The two directions derive different keys from one connection ID,
    // which is what the two labels of §5.2 are for.
    aes_public_key read_side;
    aes_public_key write_side;
    CHECK(aes_public_key_initial(&read_side, dcid, 8, CH_KEY_READ) == CH_OK);
    CHECK(aes_public_key_initial(&write_side, dcid, 8, CH_KEY_WRITE) == CH_OK);
    CHECK(memcmp(&read_side, &write_side, sizeof read_side) != 0);
}

int main(void) {
    test_fips197_blocks();
    test_appendix_a1_keys();
    test_appendix_header_masks();
    test_retry_key();
    test_dcid_bounds();
    test_sp800_38d_cases();
    test_ghash_against_tags();
    test_ghash_empty();
    test_appendix_a2_initial();
    test_appendix_a4_retry();
    test_block_boundaries();
    test_in_place();
    if (failures == 0) {
        (void)printf("quic vectors: FIPS 197, SP 800-38D and RFC 9001 Appendix A agree\n");
    }
    return failures != 0;
}
