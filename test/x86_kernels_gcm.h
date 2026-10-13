// bin/x86_kernels_test's rows of the two AES-GCM keys a session holds outside its record
// directions and packet keys: a QUIC Initial key and an AES traffic key on its own.
// test/x86_kernels_test.c alone includes this file, on x86-64, after it defines CHECK, PAYLOAD,
// payload, fill, reset_calls, sealed_on and opened_on, which these rows run.
//
// sealed_on and opened_on read which kernel a call ran: the 512-bit kernel, whose four
// functions test/x86_kernels_count.c stands in for and counts, beside gcm_avx512.c's two real
// entries, each of which must call avx512_wipe_registers once after the kernel, or the VAES
// kernels, or neither (docs/decisions.md 90 and 130).
#ifndef CH_TEST_X86_KERNELS_GCM_H
#define CH_TEST_X86_KERNELS_GCM_H

#include <string.h>

#include "aes_traffic_key.h"
#include "gcm.h"
#include "quic_initial.h"
#include "suite.h"

// One Initial packet a client seals and a server opens. Its AES-128-GCM
// key is public, and the value picks its cipher: the table without the AES
// bit, which runs no instruction and so no kernel, and the instructions
// with it, on the 512-bit kernel or the VAES kernels where the value names
// them: the key is public, so the 512-bit kernel takes it as gcm_vaes.c
// does (docs/decisions.md 130).
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
    CHECK(k.key.cpu == 0 && k.key.cpu_high == 0);
    reset_calls();
    gcm_traffic_seal(&k, iv, aad, sizeof aad, payload, PAYLOAD, ct, tag);
    CHECK(sealed_on(suite, 0));
    CHECK(gcm_traffic_open(&k, iv, aad, sizeof aad, ct, PAYLOAD, tag, back) == 1);
    CHECK(opened_on(suite, 0));

    aes_traffic_key_cpu(&k, cpu);
    CHECK(k.key.cpu == (uint8_t)cpu && k.key.cpu_high == (uint8_t)(cpu >> 8));
    uint8_t ct_cpu[PAYLOAD];
    uint8_t tag_cpu[GCM_TAG];
    gcm_traffic_seal(&k, iv, aad, sizeof aad, payload, PAYLOAD, ct_cpu, tag_cpu);
    CHECK(sealed_on(suite, cpu));
    CHECK(memcmp(ct_cpu, ct, PAYLOAD) == 0 && memcmp(tag_cpu, tag, GCM_TAG) == 0);
    CHECK(gcm_traffic_open(&k, iv, aad, sizeof aad, ct_cpu, PAYLOAD, tag_cpu, back) == 1);
    CHECK(opened_on(suite, cpu));
    CHECK(memcmp(back, payload, PAYLOAD) == 0);
}

#endif
