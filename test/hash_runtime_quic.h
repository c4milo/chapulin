// The rows of bin/hash_runtime_test that a QUIC object alone holds: a
// level's keys and their update under each suite, and an Initial packet
// (test/hash_runtime_test.c). That file includes this one after the
// names its rows read: input, pseudorandom_key, output, row_suite and
// CHECK.
#ifndef CH_TEST_HASH_RUNTIME_QUIC_H
#define CH_TEST_HASH_RUNTIME_QUIC_H
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

#include "quic_initial.h"
#include "quic_keys.h"

// One level's packet protection keys and header protection key under
// row_suite, and the key update.
static void row_quic_keys(uint32_t cpu) {
    uint8_t traffic_secret[HKDF_HASH_MAX];
    memcpy(traffic_secret, pseudorandom_key, sizeof traffic_secret);
    quic_keys k;
    quic_hp_key h;
    memset(&k, 0, sizeof k);
    memset(&h, 0, sizeof h);
    quic_keys_init_suite(cpu, &k, CH_QUIC_VERSION_1, traffic_secret, row_suite);
    quic_hp_key_init_suite(cpu, &h, CH_QUIC_VERSION_1, traffic_secret, row_suite);
    memcpy(output, k.key, sizeof k.key);
    memcpy(output + sizeof k.key, k.iv, sizeof k.iv);
    memcpy(output + 64, h.key, sizeof h.key);
    quic_keys_update(cpu, traffic_secret, &k, CH_QUIC_VERSION_1);
    memcpy(output + 128, k.key, sizeof k.key);
    memcpy(output + 128 + sizeof k.key, k.iv, sizeof k.iv);
    memcpy(output + 192, traffic_secret, sizeof traffic_secret);
}

// One Initial packet a client seals, whose keys RFC 9001 §5.2 derives with
// HKDF over SHA-256 whatever suite the session runs. The seal then runs
// AES-128-GCM: on the AES instructions under the value's AES bit, and on
// the 256-bit kernels under its VAES bit as well. A CPU without those
// faults on them, so the row clears the three bits that pick an AES or
// ChaCha20 path, and the packet is sealed on the table and the portable
// multiply, which every CPU runs. The value keeps every bit a hash call
// reads.
static void row_quic_initial(uint32_t cpu) {
    static const uint8_t dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    static const uint8_t hdr[20] = {0xc1, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0,
                                    0x3e, 0x51, 0x57, 0x08, 0x00, 0x00, 0x40, 0x42, 0x00, 0x07};
    uint32_t no_cipher_bits =
        cpu & ~(uint32_t)(CH_CPU_CONSTANT_TIME_AES | CH_CPU_AVX2 | CH_CPU_VAES);
    size_t pkt_len = 0;
    CHECK(quic_initial_seal(no_cipher_bits, CH_QUIC_ENDPOINT_CLIENT, CH_QUIC_VERSION_1, dcid,
                            sizeof dcid, 7, 2, hdr, sizeof hdr, input, 48, output, sizeof output,
                            &pkt_len) == CH_OK);
}

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
#endif
