// A QUIC host object's two ciphers in one binary (docs/decisions.md 81
// and 89). A QUIC host object runs a public key on the AES instructions or
// on quic_aes_soft.c's table, as the CH_CPU_CONSTANT_TIME_AES bit of its
// caller's ch_cfg.cpu says, and runs every traffic key on the
// instructions. This binary checks both, with the bit and without it:
//
//   - RFC 9001 Appendix A and RFC 9369 Appendix A: the keys, the client
//     and server Initial packets, every byte, and the Retry tag, of QUIC
//     version 1 and version 2.
//   - AES-128-GCM and AES-256-GCM under traffic keys, against the SP
//     800-38D vectors bin/quic_test_hw checks the instructions against,
//     and the header protection block against FIPS 197.
//   - What each key schedule records beside its cipher: the description
//     of the CPU its constructor was given, which gcm.c reads to pick the
//     VAES kernels on x86-64 (aes_schedule.h). An Initial key records the
//     session's value, a Retry key and a new traffic key 0, and
//     aes_traffic_key_cpu the value it is given.
//   - Which cipher ran. test/aes_runtime_soft.c and test/aes_runtime_hw.c
//     count every call into the table, the AES instructions and the
//     carry-less multiply (test/aes_runtime_count.h). Without the bit no
//     call goes to the instructions or the carry-less multiply; with it
//     the table runs no Initial key; and it runs no traffic key either
//     way. A Retry key runs on the table either way.
//
// Its one argument picks what it runs, "present" for the bit set or
// "absent" for the bit clear, and with none it runs both.
// test/aes-runtime-qemu.sh runs "absent" on an x86-64 CPU model without
// AES-NI and PCLMULQDQ, where either instruction traps, and "present"
// there to show that it does.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_block.h"
#include "aes_public_key.h"
#include "aes_runtime_count.h"
#include "aes_traffic_key.h"
#include "ch_assert.h"
#include "gcm.h"
#include "quic_initial.h"
#include "quic_retry.h"
#include "quic_v1_vectors.h"
#include "quic_v2_vectors.h"

#ifndef CH_AES_TWO_CIPHERS
#error                                                                                             \
    "bin/aes_runtime_test is a QUIC host object: -DCH_CPU_RUNTIME -DCH_TRANSPORT_QUIC_NONBLOCKING"
#endif

// The two values a caller states: the AES instructions stated, and the
// probe's bit alone.
#define RUNTIME_PRESENT (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES)
#define RUNTIME_ABSENT CH_CPU_PROBED

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

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

// RFC 9001 Appendix A's Destination Connection ID (rfc9001.txt:2324-2325),
// which RFC 9369 Appendix A uses too (rfc9369.txt:408-409).
static const uint8_t APPENDIX_DCID[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

// The Initial packets' shapes, which both appendices share: A.2's 22-byte
// header with a four-byte packet number 2 over a 1162-byte payload, and
// A.3's 20-byte header with a two-byte packet number 1 over 99 bytes.
#define A2_HDR 22
#define A2_PN_LEN 4
#define A2_PAYLOAD 1162
#define A2_PACKET (A2_HDR + A2_PAYLOAD + GCM_TAG)
#define A3_HDR 20
#define A3_PN_LEN 2
#define A3_PAYLOAD 99
#define A3_PACKET (A3_HDR + A3_PAYLOAD + GCM_TAG)
// A.4's Retry packet: 20 bytes and the 16-byte tag after them.
#define A4_RETRY 36

// One version's Appendix A, from test/quic_v1_vectors.h or
// test/quic_v2_vectors.h. The plaintexts are the same in both appendices.
typedef struct {
    uint32_t version;
    const char *client_key;
    const char *client_iv;
    const char *client_hp;
    const char *server_key;
    const char *server_iv;
    const char *server_hp;
    const char *a2_header;
    const char *a2_packet;
    const char *a3_header;
    const char *a3_packet;
    const char *a4_retry;
} appendix;

static const appendix APPENDICES[2] = {
    {CH_QUIC_VERSION_1, V1_CLIENT_KEY, V1_CLIENT_IV, V1_CLIENT_HP, V1_SERVER_KEY, V1_SERVER_IV,
     V1_SERVER_HP, V1_A2_HEADER, V1_A2_PACKET, V1_A3_HEADER, V1_A3_PACKET, V1_A4_RETRY_PACKET},
    {CH_QUIC_VERSION_2, V2_CLIENT_KEY, V2_CLIENT_IV, V2_CLIENT_HP, V2_SERVER_KEY, V2_SERVER_IV,
     V2_SERVER_HP, V2_A2_HEADER, V2_A2_PACKET, V2_A3_HEADER, V2_A3_PACKET, V2_A4_RETRY_PACKET},
};

static void reset_counts(void) {
    aes_runtime_table_calls = 0;
    aes_runtime_instruction_calls = 0;
    aes_runtime_clmul_calls = 0;
}

// Which cipher ran for the calls since the last reset: the instructions
// and the carry-less multiply alone when cpu holds the AES bit, and the
// table alone when it does not.
static void check_ran_on(uint32_t cpu) {
    if ((cpu & CH_CPU_CONSTANT_TIME_AES) != 0) {
        CHECK(aes_runtime_table_calls == 0);
        CHECK(aes_runtime_instruction_calls > 0 && aes_runtime_clmul_calls > 0);
        return;
    }
    CHECK(aes_runtime_instruction_calls == 0 && aes_runtime_clmul_calls == 0);
    CHECK(aes_runtime_table_calls > 0);
}

// A.1: both endpoints' three values, and the cipher and the description of
// the CPU each schedule records. A value without the AES bit takes the
// table, the cipher every CPU runs. The key starts from bytes that are
// neither, so a field the constructor left alone fails a check.
static void check_keys(uint32_t cpu, const appendix *a) {
    uint8_t recorded = (cpu & CH_CPU_CONSTANT_TIME_AES) != 0 ? AES_ON_INSTRUCTIONS : AES_ON_TABLE;
    aes_public_key k;
    memset(&k, 0xff, sizeof k);
    CHECK(aes_public_key_initial(&k, cpu, a->version, APPENDIX_DCID, sizeof APPENDIX_DCID,
                                 CH_QUIC_ENDPOINT_CLIENT) == CH_OK);
    CHECK(eq_hex(k.key.round_keys, a->client_key) && eq_hex(k.iv, a->client_iv) &&
          eq_hex(k.hp.round_keys, a->client_hp));
    CHECK(k.key.instructions == recorded && k.hp.instructions == recorded);
    CHECK(k.key.cpu == (uint8_t)cpu && k.hp.cpu == (uint8_t)cpu);
    memset(&k, 0xff, sizeof k);
    CHECK(aes_public_key_initial(&k, cpu, a->version, APPENDIX_DCID, sizeof APPENDIX_DCID,
                                 CH_QUIC_ENDPOINT_SERVER) == CH_OK);
    CHECK(eq_hex(k.key.round_keys, a->server_key) && eq_hex(k.iv, a->server_iv) &&
          eq_hex(k.hp.round_keys, a->server_hp));
    CHECK(k.key.instructions == recorded && k.hp.instructions == recorded);
    CHECK(k.key.cpu == (uint8_t)cpu && k.hp.cpu == (uint8_t)cpu);
}

// A.2: the client's Initial packet sealed by the client entry, all 1200
// bytes, and opened by the server's.
static void check_client_initial(uint32_t cpu, const appendix *a) {
    static uint8_t pt[A2_PAYLOAD];
    static uint8_t want[A2_PACKET];
    static uint8_t out[A2_PACKET];
    uint8_t hdr[A2_HDR];
    size_t out_len = 0;
    memset(pt, 0, sizeof pt);
    CHECK(unhex(V2_A2_CRYPTO_FRAME, pt) < sizeof pt);
    CHECK(unhex(a->a2_header, hdr) == sizeof hdr);
    CHECK(unhex(a->a2_packet, want) == sizeof want);
    CHECK(quic_initial_seal(cpu, CH_QUIC_ENDPOINT_CLIENT, a->version, APPENDIX_DCID,
                            sizeof APPENDIX_DCID, 2, A2_PN_LEN, hdr, sizeof hdr, pt, sizeof pt, out,
                            sizeof out, &out_len) == CH_OK);
    CHECK(out_len == sizeof want && memcmp(out, want, sizeof want) == 0);
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(quic_initial_open(cpu, CH_QUIC_ENDPOINT_SERVER, a->version, APPENDIX_DCID,
                            sizeof APPENDIX_DCID, out, out_len, A2_HDR - A2_PN_LEN, 0, &pn,
                            &pt_len) == CH_OK);
    CHECK(pn == 2 && pt_len == A2_PAYLOAD && memcmp(&out[A2_HDR], pt, A2_PAYLOAD) == 0);
}

// A.3: the server's Initial packet sealed by the server entry, every
// byte, and opened by the client's.
static void check_server_initial(uint32_t cpu, const appendix *a) {
    static uint8_t pt[A3_PAYLOAD];
    static uint8_t want[A3_PACKET];
    static uint8_t out[A3_PACKET];
    uint8_t hdr[A3_HDR];
    size_t out_len = 0;
    CHECK(unhex(V2_A3_PAYLOAD, pt) == sizeof pt);
    CHECK(unhex(a->a3_header, hdr) == sizeof hdr);
    CHECK(unhex(a->a3_packet, want) == sizeof want);
    CHECK(quic_initial_seal(cpu, CH_QUIC_ENDPOINT_SERVER, a->version, APPENDIX_DCID,
                            sizeof APPENDIX_DCID, 1, A3_PN_LEN, hdr, sizeof hdr, pt, sizeof pt, out,
                            sizeof out, &out_len) == CH_OK);
    CHECK(out_len == sizeof want && memcmp(out, want, sizeof want) == 0);
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(quic_initial_open(cpu, CH_QUIC_ENDPOINT_CLIENT, a->version, APPENDIX_DCID,
                            sizeof APPENDIX_DCID, out, out_len, A3_HDR - A3_PN_LEN, 0, &pn,
                            &pt_len) == CH_OK);
    CHECK(pn == 1 && pt_len == A3_PAYLOAD && memcmp(&out[A3_HDR], pt, A3_PAYLOAD) == 0);
}

// A.4: the tag both Retry calls compute over the Retry pseudo-packet, the
// original Destination Connection ID with its length byte and then the
// Retry packet without its tag (RFC 9001 §5.8). It takes no ch_cfg.cpu:
// the Retry key runs on the table in every session of a QUIC host object
// (aes.h).
static void check_retry(const appendix *a) {
    uint8_t packet[A4_RETRY];
    uint8_t pseudo[1 + sizeof APPENDIX_DCID + A4_RETRY - GCM_TAG];
    uint8_t tag[GCM_TAG];
    CHECK(unhex(a->a4_retry, packet) == sizeof packet);
    pseudo[0] = (uint8_t)sizeof APPENDIX_DCID;
    memcpy(&pseudo[1], APPENDIX_DCID, sizeof APPENDIX_DCID);
    memcpy(&pseudo[1 + sizeof APPENDIX_DCID], packet, A4_RETRY - GCM_TAG);
    reset_counts();
    CHECK(quic_retry_tag(a->version, pseudo, sizeof pseudo, tag) == CH_OK);
    CHECK(memcmp(tag, &packet[A4_RETRY - GCM_TAG], GCM_TAG) == 0);
    CHECK(quic_retry_ok(a->version, pseudo, sizeof pseudo, &packet[A4_RETRY - GCM_TAG]) == 1);
    check_ran_on(RUNTIME_ABSENT);
    // The key those two calls build: on the table, with a description of
    // the CPU that names no kernel.
    aes_public_key k;
    memset(&k, 0xff, sizeof k);
    aes_public_key_retry(&k, a->version);
    CHECK(k.key.instructions == AES_ON_TABLE && k.key.cpu == 0);
}

// Both appendices under one ch_cfg.cpu, and what ran for them.
static void check_public_keys(uint32_t cpu) {
    for (size_t i = 0; i < sizeof APPENDICES / sizeof APPENDICES[0]; i++) {
        reset_counts();
        check_keys(cpu, &APPENDICES[i]);
        check_client_initial(cpu, &APPENDICES[i]);
        check_server_initial(cpu, &APPENDICES[i]);
        check_ran_on(cpu);
        check_retry(&APPENDICES[i]);
    }
    // The constructor reads the AES bit for the cipher, and hands the value
    // to HKDF, whose entry reads the SHA-256 bit (docs/decisions.md 93): a
    // value with that bit derives the keys on instructions this CPU may
    // lack. Every other bit is the init calls' to judge. So 0, which the
    // init calls refuse, and every bit but the AES one and the three hash
    // bits run the table.
    static const uint32_t without_aes[2] = {
        0, ~(uint32_t)(CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_SHA256 |
                       CH_CPU_CONSTANT_TIME_SHA512 | CH_CPU_CONSTANT_TIME_SHA3)};
    for (size_t i = 0; i < 2; i++) {
        aes_public_key k;
        reset_counts();
        CHECK(aes_public_key_initial(&k, without_aes[i], CH_QUIC_VERSION_1, APPENDIX_DCID,
                                     sizeof APPENDIX_DCID, CH_QUIC_ENDPOINT_CLIENT) == CH_OK);
        CHECK(eq_hex(k.key.round_keys, V1_CLIENT_KEY) && k.key.instructions == AES_ON_TABLE);
        CHECK(k.key.cpu == (uint8_t)without_aes[i]);
        CHECK(aes_runtime_instruction_calls == 0 && aes_runtime_table_calls > 0);
    }
}

// One traffic AEAD case: SP 800-38D's case 4 for AES-128-GCM and case 16
// for AES-256-GCM, the fourth shape of each key size (the cases
// test/gcm_tests.h holds for bin/quic_test_hw), sealed and opened under an
// aes_traffic_key.
typedef struct {
    const char *key;
    const char *iv;
    const char *aad;
    const char *pt;
    const char *ct;
    const char *tag;
} traffic_case;

static const traffic_case TRAFFIC_CASES[2] = {
    {"feffe9928665731c6d6a8f9467308308",                                 "cafebabefacedbaddecaf888",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449"
     "a6b525b16aedf5aa0de657ba637b39",                           "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac8"
     "4aa051ba30b396a0aac973d58e091",                                                      "5bc94fbc3221a5db94fae95ae7121a47"},
    {"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662", "76fc6ece0f4e1768cddf8853bb2d551b"},
};

static void check_traffic_case(const traffic_case *c) {
    uint8_t key[AES_256_KEY];
    uint8_t iv[AES_IV];
    uint8_t aad[32];
    uint8_t pt[64];
    uint8_t ct[64];
    uint8_t tag[GCM_TAG];
    uint8_t opened[64];
    size_t key_len = unhex(c->key, key);
    CHECK(unhex(c->iv, iv) == sizeof iv);
    size_t aad_len = unhex(c->aad, aad);
    size_t n = unhex(c->pt, pt);
    aes_traffic_key k;
    memset(&k, 0xff, sizeof k);
    aes_traffic_key_init(&k, key, key_len);
    CHECK(k.key.instructions == AES_ON_INSTRUCTIONS && k.key.cpu == 0);
    gcm_traffic_seal(&k, iv, aad, aad_len, pt, n, ct, tag);
    CHECK(eq_hex(ct, c->ct) && eq_hex(tag, c->tag));
    CHECK(gcm_traffic_open(&k, iv, aad, aad_len, ct, n, tag, opened) == 1);
    CHECK(memcmp(opened, pt, n) == 0);
    // The description a record or a packet gives the key afterwards, and
    // the same bytes under it.
    aes_traffic_key_cpu(&k, RUNTIME_PRESENT);
    CHECK(k.key.cpu == RUNTIME_PRESENT && k.key.instructions == AES_ON_INSTRUCTIONS);
    gcm_traffic_seal(&k, iv, aad, aad_len, pt, n, ct, tag);
    CHECK(eq_hex(ct, c->ct) && eq_hex(tag, c->tag));
}

// FIPS 197 Appendix C.1 and C.3, the forward cipher under a 128-bit and a
// 256-bit key, through the header protection entry a traffic key takes.
static void check_traffic_block(const char *key_hex, const char *ct_hex) {
    uint8_t key[AES_256_KEY];
    uint8_t in[AES_BLOCK];
    uint8_t out[AES_BLOCK];
    size_t key_len = unhex(key_hex, key);
    CHECK(unhex("00112233445566778899aabbccddeeff", in) == sizeof in);
    aes_traffic_key k;
    aes_traffic_key_init(&k, key, key_len);
    aes_traffic_encrypt_block(&k, in, out);
    CHECK(eq_hex(out, ct_hex));
}

// Every traffic key runs on the instructions and never on the table.
static void check_traffic_keys(void) {
    reset_counts();
    check_traffic_case(&TRAFFIC_CASES[0]);
    check_traffic_case(&TRAFFIC_CASES[1]);
    check_traffic_block("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a");
    check_traffic_block("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                        "8ea2b7ca516745bfeafc49904b496089");
    check_ran_on(RUNTIME_PRESENT);
}

int main(int argc, char **argv) {
    const char *which = argc > 1 ? argv[1] : "both";
    int present = strcmp(which, "absent") != 0;
    int absent = strcmp(which, "present") != 0;
    CHECK(present || absent);
    if (present) {
        check_public_keys(RUNTIME_PRESENT);
        check_traffic_keys();
    }
    if (absent) {
        check_public_keys(RUNTIME_ABSENT);
    }
    if (failures == 0) {
        const char *which_bits = "without CH_CPU_CONSTANT_TIME_AES";
        if (present) {
            which_bits = absent ? "with CH_CPU_CONSTANT_TIME_AES and without it"
                                : "with CH_CPU_CONSTANT_TIME_AES";
        }
        (void)printf("aes_runtime: RFC 9001 and RFC 9369 Appendix A %s, each on the cipher the bit"
                     " names%s\n",
                     which_bits, present ? ", and the traffic keys on the instructions alone" : "");
    }
    return failures != 0;
}
