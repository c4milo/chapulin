// Differential rows for quic_aes.c: the AES-128 forward cipher against
// FIPS 197 as spec/lean/Spec/Aes.lean states it, and the RFC 9001 §5.2
// Initial keys against the same file's derivation. The C ships a
// 256-byte S-box table and the spec computes the S-box from the field
// definition, so every row that agrees is the table checked against what
// FIPS 197 says the table is.
//
// Included by test/diff_quic_test.c only, which is the driver a
// -DCH_TRANSPORT_QUIC build can compile.
#ifndef CH_DIFF_AES_H
#define CH_DIFF_AES_H

// The block cipher takes a key the caller chose, and INV-26 keeps the
// two constructors the only public way to write an aes_public_key, so
// this file reaches the cipher through quic_aes_block.h's two entries,
// which take plain bytes. quic_aes_key.h gives aes_public_key a body for
// the derivation rows below.
#include "quic_aes_block.h"
#include "quic_aes_key.h"

// FIPS 197 fixes the key and the block at 128 bits, so the only domain
// to sample is their contents.
static void diff_aes128(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t key[AES_128_KEY];
        uint8_t block[AES_BLOCK];
        rng_fill(key, sizeof key);
        rng_fill(block, sizeof block);

        aes_key_schedule schedule;
        aes_expand_round_keys(key, schedule.round_keys);
        uint8_t out[AES_BLOCK];
        aes_cipher_block(schedule.round_keys, block, out);

        char key_hex[2 * AES_128_KEY + 1];
        (void)hex_encode(key_hex, key, sizeof key);
        char block_hex[2 * AES_BLOCK + 1];
        (void)hex_encode(block_hex, block, sizeof block);
        char want[2 * AES_BLOCK + 1];
        (void)hex_encode(want, out, sizeof out);
        char cmd[128];
        (void)snprintf(cmd, sizeof cmd, "aes128 %s %s", key_hex, block_hex);
        expect(cmd, want);
    }
}

// Every Destination Connection ID length RFC 9001 §5.2 admits, from zero
// to CH_QUIC_DCID_MAX, for both endpoints. The domain stops at the cap on
// purpose: one byte past it the C refuses and the spec answers ERR, so
// the two agree about the refusal and not about a key. test_dcid_bounds
// in test/quic_vectors.c holds that boundary.
static void diff_quic_initial_keys(void) {
    for (size_t dcid_len = 0; dcid_len <= CH_QUIC_DCID_MAX; dcid_len++) {
        for (int client = 0; client < 2; client++) {
            uint8_t dcid[CH_QUIC_DCID_MAX];
            rng_fill(dcid, dcid_len);
            aes_public_key k;
            uint8_t endpoint = client ? CH_QUIC_ENDPOINT_CLIENT : CH_QUIC_ENDPOINT_SERVER;
            if (aes_public_key_initial(&k, dcid, dcid_len, endpoint) != CH_OK) {
                (void)fprintf(stderr, "diff: aes_public_key_initial refused %zu bytes\n", dcid_len);
                exit(1);
            }

            char dcid_hex[2 * CH_QUIC_DCID_MAX + 1];
            (void)hex_encode(dcid_hex, dcid, dcid_len);
            char key_hex[2 * AES_128_KEY + 1];
            (void)hex_encode(key_hex, k.key.round_keys, AES_128_KEY);
            char iv_hex[2 * AES_IV + 1];
            (void)hex_encode(iv_hex, k.iv, sizeof k.iv);
            char hp_hex[2 * AES_128_KEY + 1];
            (void)hex_encode(hp_hex, k.hp.round_keys, AES_128_KEY);
            char want[3 * (2 * AES_128_KEY + 1) + 1];
            (void)snprintf(want, sizeof want, "%s %s %s", key_hex, iv_hex, hp_hex);
            char cmd[128];
            (void)snprintf(cmd, sizeof cmd, "quic_initial_keys %s %s", dcid_hex,
                           client ? "client" : "server");
            expect(cmd, want);
        }
    }
}

#endif
