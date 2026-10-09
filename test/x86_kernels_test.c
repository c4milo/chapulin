// bin/x86_kernels_test: which calls an x86-64 host object sends to its
// kernels under each ch_cfg.cpu value (docs/decisions.md 89 and 90).
// chacha20.c's use_avx2 picks chacha20_avx2.c's ChaCha20 where the value
// holds CH_CPU_AVX2, mlkem.h's entries pick mlkem_avx2.c's copy of ML-KEM
// where it holds the same bit (docs/decisions.md 107), widemul.h's
// widemul_poly1305_avx2 picks poly1305_avx2.c's Poly1305 where it holds
// that bit and CH_CPU_CONSTANT_TIME_MULTIPLY both (docs/decisions.md 110),
// gcm_vaes.h's gcm_use_vaes picks gcm_vaes.c's three entries where it
// holds CH_CPU_VAES and CH_CPU_CONSTANT_TIME_AES both, and rsa_mont.c's
// use_ifma picks rsa_ifma.c's RSA public operation where it holds
// CH_CPU_AVX512_IFMA. The kernels compute the bytes the
// paths beside them compute, so no vector can tell which ran:
// test/x86_kernels_count.c and test/rsa_ifma_count.c count the calls
// instead, and run each on the entry it stands beside, so this binary runs
// on every x86-64 CPU.
//
// Every row runs under each of the 32 values the five bits from 0x02 to
// 0x10 and 0x100 make beside CH_CPU_PROBED, and under 0, which a wiped
// record direction holds. Those five are the AES bit, the multiply bit and
// the three that name a kernel; a hash bit picks no path a row here takes.
// Under each, a call must run a kernel exactly when the value names it,
// and must give the same bytes back:
//
//   - chacha20_xor_cpu, and aead_seal_cpu and aead_open_cpu, which pass
//     the value on to the keystream and to Poly1305's update of the
//     ciphertext. chacha20_xor, aead_seal and aead_open take no value and
//     run no kernel.
//   - a record under each of the three suites, sealed and opened: the
//     direction's cpu picks the AVX2 keystream and the AVX2 Poly1305 under
//     ChaCha20 and the VAES kernels under AES-GCM.
//   - a QUIC 1-RTT packet under each suite, and a Handshake packet, sealed
//     and opened, with the value the packet calls take first.
//   - a QUIC Initial packet, whose key the table runs without the AES bit,
//     so it runs the VAES kernels under both bits alone.
//   - an AES traffic key: aes_traffic_key_init names no kernel, and
//     aes_traffic_key_cpu names what its value does.
//   - ML-KEM's three session calls, mlkem_keygen_dk_cpu,
//     mlkem_encaps_derand_cpu and mlkem_decaps_cpu.
//   - the two RSA verifiers' entries that take a value, and rsa_vp1_cpu,
//     which runs the kernel for each of two moduli it takes and rsa_vp1
//     for each of three it does not (test/x86_kernels_rsa.h).
//   - an RSA-PSS signature through widemul.h's entry, which runs
//     rsa_ifma_sign.c's exponentiations, the check on rsa_ifma.c and the
//     two wipes after each where the value holds CH_CPU_AVX512_IFMA and
//     CH_CPU_CONSTANT_TIME_MULTIPLY (test/x86_kernels_rsa.h).
//
// What the kernels compute is held elsewhere: bin/chacha20_equiv_test,
// bin/poly1305_equiv_test and bin/aes_equiv_test call them against the
// portable code, and
// bin/unit_host, bin/quic_test_hw, bin/ghash_equiv_test and the host
// Wycheproof test run the published vectors on them where the CPU has their
// instructions.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aead.h"
#include "aes_traffic_key.h"
#include "ch_assert.h"
#include "chacha20.h"
#include "gcm.h"
#include "mlkem.h"
#include "quic_initial.h"
#include "quic_keys.h"
#include "quic_packet.h"
#include "record.h"
#include "suite.h"
#include "widemul.h"
#include "x86_kernels_count.h"

#if !defined(CH_CPU_RUNTIME) || !defined(CH_SUITE_AES_GCM) ||                                      \
    !defined(CH_TRANSPORT_QUIC_NONBLOCKING)
#error                                                                                             \
    "bin/x86_kernels_test is a host object with the suite: -DCH_CPU_RUNTIME -DCH_SUITE_AES_GCM -DCH_TRANSPORT_QUIC_NONBLOCKING"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#ifdef __x86_64__

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

#include "x86_kernels_rsa.h"

// The payload every row seals: four passes of AES-GCM's eight blocks, one
// whole block more and 7 bytes, so each kernel has whole passes, a whole
// block and a partial block to take or leave. The four passes are one
// pass of ChaCha20's eight blocks, and the 528 bytes of whole blocks are
// past the 512 a Poly1305 update needs before it hands its four whole
// groups of eight blocks to the AVX2 kernel (POLY1305_AVX2_MIN).
#define PAYLOAD ((size_t)(4 * 128 + 16 + 7))

static uint8_t payload[PAYLOAD];

static void fill(uint8_t *p, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(seed + 7 * i);
    }
}

// What a value names, written here apart from the library's predicates so
// that a wrong predicate fails a row: the AVX2 kernel under CH_CPU_AVX2,
// the AVX2 Poly1305 under CH_CPU_AVX2 and CH_CPU_CONSTANT_TIME_MULTIPLY
// both, and the VAES kernels under CH_CPU_VAES and
// CH_CPU_CONSTANT_TIME_AES both.
static unsigned long names_avx2(uint32_t cpu) {
    return (cpu & CH_CPU_AVX2) != 0 ? 1 : 0;
}

static unsigned long names_poly1305_avx2(uint32_t cpu) {
    return (cpu & CH_CPU_AVX2) != 0 && (cpu & CH_CPU_CONSTANT_TIME_MULTIPLY) != 0 ? 1 : 0;
}

static unsigned long names_vaes(uint32_t cpu) {
    return (cpu & CH_CPU_VAES) != 0 && (cpu & CH_CPU_CONSTANT_TIME_AES) != 0 ? 1 : 0;
}

static void reset_calls(void) {
    x86_avx2_calls = 0;
    x86_poly1305_avx2_calls = 0;
    x86_vaes_seal_calls = 0;
    x86_vaes_open_calls = 0;
    x86_vaes_counter_calls = 0;
}

// Whether the calls since the last reset are these, and resets them.
static int calls_are(unsigned long avx2, unsigned long poly1305, unsigned long seal,
                     unsigned long open, unsigned long counter) {
    int same = x86_avx2_calls == avx2 && x86_poly1305_avx2_calls == poly1305 &&
               x86_vaes_seal_calls == seal && x86_vaes_open_calls == open &&
               x86_vaes_counter_calls == counter;
    if (!same) {
        (void)fprintf(stderr,
                      "calls: AVX2 %lu, AVX2 Poly1305 %lu, VAES seal %lu, open %lu, counter %lu; "
                      "want %lu, %lu, %lu, %lu, %lu\n",
                      x86_avx2_calls, x86_poly1305_avx2_calls, x86_vaes_seal_calls,
                      x86_vaes_open_calls, x86_vaes_counter_calls, avx2, poly1305, seal, open,
                      counter);
    }
    reset_calls();
    return same;
}

// One AES-GCM seal hands its whole passes to the one-pass seal and the
// whole blocks after them to counter mode, once each, and an open the
// same with the one-pass open (gcm.c). A ChaCha20-Poly1305 seal or open
// runs the keystream once and hands the ciphertext's whole groups to the
// Poly1305 kernel once.
static int sealed_on(uint16_t suite, uint32_t cpu) {
    if (suite_runs_aes_gcm(suite)) {
        return calls_are(0, 0, names_vaes(cpu), 0, names_vaes(cpu));
    }
    return calls_are(names_avx2(cpu), names_poly1305_avx2(cpu), 0, 0, 0);
}

static int opened_on(uint16_t suite, uint32_t cpu) {
    if (suite_runs_aes_gcm(suite)) {
        return calls_are(0, 0, 0, names_vaes(cpu), names_vaes(cpu));
    }
    return calls_are(names_avx2(cpu), names_poly1305_avx2(cpu), 0, 0, 0);
}

// The keystream and the AEAD. The entries that take no description run
// the 128-bit path, and the entries that take one give the same bytes.
static void check_chacha20(uint32_t cpu) {
    uint8_t key[AEAD_KEY];
    uint8_t nonce[AEAD_NONCE];
    uint8_t aad[13];
    uint8_t want[PAYLOAD];
    uint8_t got[PAYLOAD];
    uint8_t want_tag[AEAD_TAG];
    uint8_t got_tag[AEAD_TAG];
    fill(key, sizeof key, 0x11);
    fill(nonce, sizeof nonce, 0x22);
    fill(aad, sizeof aad, 0x33);

    chacha20_xor(key, nonce, 1, payload, want, PAYLOAD);
    CHECK(calls_are(0, 0, 0, 0, 0));
    chacha20_xor_cpu(cpu, key, nonce, 1, payload, got, PAYLOAD);
    CHECK(calls_are(names_avx2(cpu), 0, 0, 0, 0));
    CHECK(memcmp(got, want, PAYLOAD) == 0);

    aead_seal(widemul_of_cpu(cpu), key, nonce, aad, sizeof aad, payload, PAYLOAD, want, want_tag);
    CHECK(calls_are(0, 0, 0, 0, 0));
    aead_seal_cpu(cpu, key, nonce, aad, sizeof aad, payload, PAYLOAD, got, got_tag);
    CHECK(calls_are(names_avx2(cpu), names_poly1305_avx2(cpu), 0, 0, 0));
    CHECK(memcmp(got, want, PAYLOAD) == 0 && memcmp(got_tag, want_tag, AEAD_TAG) == 0);

    uint8_t back[PAYLOAD];
    CHECK(aead_open(widemul_of_cpu(cpu), key, nonce, aad, sizeof aad, want, PAYLOAD, want_tag,
                    back) == 1);
    CHECK(calls_are(0, 0, 0, 0, 0));
    CHECK(memcmp(back, payload, PAYLOAD) == 0);
    memset(back, 0, sizeof back);
    CHECK(aead_open_cpu(cpu, key, nonce, aad, sizeof aad, got, PAYLOAD, got_tag, back) == 1);
    CHECK(calls_are(names_avx2(cpu), names_poly1305_avx2(cpu), 0, 0, 0));
    CHECK(memcmp(back, payload, PAYLOAD) == 0);
    // A wrong tag runs no keystream: the open computes the tag and
    // compares it before it decrypts.
    got_tag[0] ^= 1;
    CHECK(aead_open_cpu(cpu, key, nonce, aad, sizeof aad, got, PAYLOAD, got_tag, back) == 0);
    CHECK(calls_are(0, names_poly1305_avx2(cpu), 0, 0, 0));
}

// One record under suite, sealed by a direction whose cpu is the value
// and opened by another, as a session's two ends hold them.
static void check_record(uint16_t suite, uint32_t cpu) {
    uint8_t secret[HKDF_HASH_MAX];
    uint8_t rec[PAYLOAD + REC_OVERHEAD];
    uint8_t back[PAYLOAD + REC_OVERHEAD];
    fill(secret, sizeof secret, 0x44);
    rec_dir wr;
    rec_dir rd;
    memset(&wr, 0, sizeof wr);
    memset(&rd, 0, sizeof rd);
    rec_dir_init_suite(&wr, secret, suite);
    rec_dir_init_suite(&rd, secret, suite);
    // Keying a direction leaves its cpu as it was: 0, which names no
    // kernel, until the session writes its value (record.h).
    CHECK(wr.cpu == 0 && rd.cpu == 0);
    wr.cpu = cpu;
    rd.cpu = cpu;
    reset_calls();

    size_t n = 0;
    CHECK(rec_seal(&wr, REC_APPDATA, payload, PAYLOAD, rec, sizeof rec, &n) == 0);
    // A record's plaintext is the payload and its content type byte.
    CHECK(sealed_on(suite, cpu));
    size_t pt_len = 0;
    uint8_t type = 0;
    CHECK(rec_open(&rd, rec, n, back, sizeof back, &pt_len, &type) == 0);
    CHECK(opened_on(suite, cpu));
    CHECK(type == REC_APPDATA && pt_len == PAYLOAD && memcmp(back, payload, PAYLOAD) == 0);

    // KeyUpdate rekeys a direction and leaves its cpu.
    uint8_t next[HKDF_HASH_MAX];
    memcpy(next, secret, sizeof next);
    rec_dir_update(next, &wr);
    CHECK(wr.cpu == cpu);
}

// A short header with an empty connection ID and a two-byte packet number,
// 5, and a version 1 long header of the Handshake type with two empty
// connection IDs, the Length of what follows it and the same packet
// number. chapulin reads no header field but the packet number.
static const uint8_t short_hdr[3] = {0x41, 0x00, 0x05};
static const uint8_t handshake_hdr[11] = {0xe1, 0x00, 0x00, 0x00, 0x01, 0x00,
                                          0x00, 0x41, 0x29, 0x00, 0x05};

// One 1-RTT packet and one Handshake packet under suite, each sealed and
// opened with the value the packet calls take first.
static void check_packets(uint16_t suite, uint32_t cpu) {
    uint8_t secret[HKDF_HASH_MAX];
    fill(secret, sizeof secret, 0x55);
    quic_keys k;
    quic_hp_key h;
    quic_keys_init_suite(cpu, &k, CH_QUIC_VERSION_1, secret, suite);
    quic_hp_key_init_suite(cpu, &h, CH_QUIC_VERSION_1, secret, suite);
    uint8_t pkt[sizeof handshake_hdr + PAYLOAD + AEAD_TAG];
    size_t pkt_len = 0;
    reset_calls();

    CHECK(quic_packet_seal(cpu, &k, &h, CH_LEVEL_APPLICATION, 5, 2, short_hdr, sizeof short_hdr,
                           payload, PAYLOAD, pkt, sizeof pkt, &pkt_len) == CH_OK);
    CHECK(sealed_on(suite, cpu));
    quic_keys sets[CH_QUIC_KEY_SETS];
    memset(sets, 0, sizeof sets);
    sets[CH_QUIC_KEY_CURRENT] = k;
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(quic_packet_open_application(cpu, sets, &h, 0, pkt, pkt_len, 1, 0, 0, &key_set, &pn,
                                       &pt_len) == CH_OK);
    CHECK(opened_on(suite, cpu));
    CHECK(pn == 5 && pt_len == PAYLOAD && memcmp(pkt + sizeof short_hdr, payload, PAYLOAD) == 0);

    CHECK(quic_packet_seal(cpu, &k, &h, CH_LEVEL_HANDSHAKE, 5, 2, handshake_hdr,
                           sizeof handshake_hdr, payload, PAYLOAD, pkt, sizeof pkt,
                           &pkt_len) == CH_OK);
    CHECK(sealed_on(suite, cpu));
    CHECK(quic_packet_open_handshake(cpu, &k, &h, pkt, pkt_len, sizeof handshake_hdr - 2, 0, &pn,
                                     &pt_len) == CH_OK);
    CHECK(opened_on(suite, cpu));
    CHECK(pn == 5 && pt_len == PAYLOAD &&
          memcmp(pkt + sizeof handshake_hdr, payload, PAYLOAD) == 0);
}

// One Initial packet a client seals and a server opens. Its AES-128-GCM
// key is public, and the value picks its cipher: the table without the AES
// bit, which runs no instruction and so no kernel, and the instructions
// with it, on the VAES kernels where the value names them.
static void check_initial(uint32_t cpu) {
    static const uint8_t dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    static const uint8_t hdr[20] = {0xc1, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0,
                                    0x3e, 0x51, 0x57, 0x08, 0x00, 0x00, 0x41, 0x29, 0x00, 0x07};
    uint8_t pkt[sizeof hdr + PAYLOAD + GCM_TAG];
    size_t pkt_len = 0;
    reset_calls();
    CHECK(quic_initial_seal(cpu, CH_QUIC_ENDPOINT_CLIENT, CH_QUIC_VERSION_1, dcid, sizeof dcid, 7,
                            2, hdr, sizeof hdr, payload, PAYLOAD, pkt, sizeof pkt,
                            &pkt_len) == CH_OK);
    CHECK(sealed_on(SUITE_AES_128_GCM_SHA256, cpu));
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(quic_initial_open(cpu, CH_QUIC_ENDPOINT_SERVER, CH_QUIC_VERSION_1, dcid, sizeof dcid, pkt,
                            pkt_len, sizeof hdr - 2, 0, &pn, &pt_len) == CH_OK);
    CHECK(opened_on(SUITE_AES_128_GCM_SHA256, cpu));
    CHECK(pn == 7 && pt_len == PAYLOAD && memcmp(pkt + sizeof hdr, payload, PAYLOAD) == 0);
}

// A traffic key of key_len bytes. aes_traffic_key_init records no
// description of the CPU, whatever the storage held, so the key runs no
// kernel, and aes_traffic_key_cpu records the value, which picks.
static void check_traffic_key(size_t key_len, uint32_t cpu) {
    uint8_t key[AES_256_KEY];
    uint8_t iv[AES_IV];
    uint8_t aad[5];
    uint8_t ct[PAYLOAD];
    uint8_t tag[GCM_TAG];
    uint8_t back[PAYLOAD];
    fill(key, sizeof key, 0x66);
    fill(iv, sizeof iv, 0x77);
    fill(aad, sizeof aad, 0x88);
    uint16_t suite = key_len == AES_256_KEY ? SUITE_AES_256_GCM_SHA384 : SUITE_AES_128_GCM_SHA256;
    aes_traffic_key k;
    memset(&k, 0xff, sizeof k);
    aes_traffic_key_init(&k, key, key_len);
    CHECK(k.key.cpu == 0);
    reset_calls();
    gcm_traffic_seal(&k, iv, aad, sizeof aad, payload, PAYLOAD, ct, tag);
    CHECK(sealed_on(suite, 0));
    CHECK(gcm_traffic_open(&k, iv, aad, sizeof aad, ct, PAYLOAD, tag, back) == 1);
    CHECK(opened_on(suite, 0));

    aes_traffic_key_cpu(&k, cpu);
    CHECK(k.key.cpu == (uint8_t)cpu);
    uint8_t ct_cpu[PAYLOAD];
    uint8_t tag_cpu[GCM_TAG];
    gcm_traffic_seal(&k, iv, aad, sizeof aad, payload, PAYLOAD, ct_cpu, tag_cpu);
    CHECK(sealed_on(suite, cpu));
    CHECK(memcmp(ct_cpu, ct, PAYLOAD) == 0 && memcmp(tag_cpu, tag, GCM_TAG) == 0);
    CHECK(gcm_traffic_open(&k, iv, aad, sizeof aad, ct_cpu, PAYLOAD, tag_cpu, back) == 1);
    CHECK(opened_on(suite, cpu));
    CHECK(memcmp(back, payload, PAYLOAD) == 0);
}

// Whether the calls into ML-KEM's copy since the last look are these, and
// resets them.
static int mlkem_calls_are(unsigned long keygen, unsigned long encaps, unsigned long decaps) {
    int same = x86_mlkem_keygen_calls == keygen && x86_mlkem_encaps_calls == encaps &&
               x86_mlkem_decaps_calls == decaps;
    if (!same) {
        (void)fprintf(stderr,
                      "calls: ML-KEM's copy, key generation %lu, encapsulation %lu, decapsulation "
                      "%lu; want %lu, %lu, %lu\n",
                      x86_mlkem_keygen_calls, x86_mlkem_encaps_calls, x86_mlkem_decaps_calls,
                      keygen, encaps, decaps);
    }
    x86_mlkem_keygen_calls = 0;
    x86_mlkem_encaps_calls = 0;
    x86_mlkem_decaps_calls = 0;
    return same;
}

// ML-KEM's three session calls: each runs mlkem_avx2.c's copy where the
// value holds CH_CPU_AVX2 and the call it is named for everywhere else, and
// gives that call's bytes. The encapsulation key sits at dk + 1152, as
// mlkem.h says.
static void check_mlkem(uint32_t cpu) {
    uint8_t d[32];
    uint8_t z[32];
    uint8_t m[32];
    fill(d, sizeof d, 0x55);
    fill(z, sizeof z, 0x66);
    fill(m, sizeof m, 0x77);
    static uint8_t dk[MLKEM_DK_LEN];
    static uint8_t dk_cpu[MLKEM_DK_LEN];
    mlkem_keygen_dk(dk, d, z);
    mlkem_keygen_dk_cpu(cpu, dk_cpu, d, z);
    CHECK(mlkem_calls_are(names_avx2(cpu), 0, 0));
    CHECK(memcmp(dk_cpu, dk, sizeof dk) == 0);

    const uint8_t *ek = dk + 1152;
    uint8_t widemul = widemul_of_cpu(cpu);
    uint8_t ct[MLKEM_CT_LEN];
    uint8_t ct_cpu[MLKEM_CT_LEN];
    uint8_t ss[MLKEM_SS_LEN];
    uint8_t ss_cpu[MLKEM_SS_LEN];
    CHECK(mlkem_encaps_derand(widemul, ct, ss, ek, m) == 0);
    CHECK(mlkem_encaps_derand_cpu(cpu, widemul, ct_cpu, ss_cpu, ek, m) == 0);
    CHECK(mlkem_calls_are(0, names_avx2(cpu), 0));
    CHECK(memcmp(ct_cpu, ct, sizeof ct) == 0 && memcmp(ss_cpu, ss, sizeof ss) == 0);

    uint8_t back[MLKEM_SS_LEN];
    mlkem_decaps_cpu(cpu, widemul, back, ct, dk);
    CHECK(mlkem_calls_are(0, 0, names_avx2(cpu)));
    CHECK(memcmp(back, ss, sizeof back) == 0);
}

static void check_value(uint32_t cpu) {
    static const uint16_t suites[] = {SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_128_GCM_SHA256,
                                      SUITE_AES_256_GCM_SHA384};
    int failures_before = failures;
    check_chacha20(cpu);
    for (size_t i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        check_record(suites[i], cpu);
        check_packets(suites[i], cpu);
    }
    check_initial(cpu);
    check_traffic_key(AES_128_KEY, cpu);
    check_traffic_key(AES_256_KEY, cpu);
    check_mlkem(cpu);
    check_rsa_verifiers(cpu);
    check_rsa_moduli(cpu);
    check_rsa_signer(cpu);
    if (failures != failures_before) {
        (void)fprintf(stderr, "x86 kernels: the checks above ran under ch_cfg.cpu 0x%x\n",
                      (unsigned)cpu);
    }
}

int main(void) {
    fill(payload, sizeof payload, 0x99);
    // The five bits are 0x02 to 0x10 and 0x100, so the 32 values are the
    // probe's bit with each of 0 to 15 shifted up one, and each of those
    // with CH_CPU_AVX512_IFMA.
    for (uint32_t bits = 0; bits < 32; bits++) {
        uint32_t ifma = (bits & 16U) != 0 ? CH_CPU_AVX512_IFMA : 0U;
        check_value(CH_CPU_PROBED | ((bits & 15U) << 1) | ifma);
    }
    check_value(0);
    if (failures == 0) {
        (void)printf(
            "x86 kernels: under each of 33 ch_cfg.cpu values, the ChaCha20 keystream and "
            "ML-KEM's matrix ran on the AVX2 kernels where CH_CPU_AVX2 was set, Poly1305 "
            "where CH_CPU_AVX2 and CH_CPU_CONSTANT_TIME_MULTIPLY were, AES-GCM on the VAES "
            "kernels where CH_CPU_VAES and CH_CPU_CONSTANT_TIME_AES were, RSA's public "
            "operation on the IFMA kernel where CH_CPU_AVX512_IFMA was, RSA signing's "
            "exponentiations and check on the IFMA kernels, each followed by both wipes, where "
            "CH_CPU_AVX512_IFMA and CH_CPU_CONSTANT_TIME_MULTIPLY were, and none of them "
            "anywhere else\n");
    }
    return failures != 0;
}

#else

// The Makefile builds this binary for x86-64 alone. On any other target
// the file holds this main, so a tool that reads it there reads a whole
// program.
int main(void) {
    (void)printf("x86 kernels: an x86-64 host object holds the kernels; nothing to count here\n");
    return 0;
}

#endif // __x86_64__
