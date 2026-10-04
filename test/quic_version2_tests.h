// RFC 9369 Appendix A, the version 2 twins of the RFC 9001 Appendix A rows
// in test/quic_vectors.c and the headers it includes: the Initial keys
// and the labels that derive them (A.1), the client and the server
// Initial packets (A.2, A.3), the Retry integrity tag (A.4), and the
// ChaCha20-Poly1305 short header packet with its key update secret (A.5).
// Every value comes from test/quic_v2_vectors.h, which copies it from
// docs/rfcs/rfc9369.txt. test/quic_vectors.c includes this header after
// the others, and it reads their helpers and lengths: unhex, eq_hex,
// CHECK and APPENDIX_DCID, A4_RETRY_PACKET, the A.2 and A.3 lengths, and
// A5_PN. Version 2 packets have the shapes of version 1's, so those
// lengths serve both.
#ifndef CH_QUIC_VERSION2_TESTS_H
#define CH_QUIC_VERSION2_TESTS_H

#include "hkdf.h"
#include "quic_v2_vectors.h"
#include "quic_version.h"
#include "test_cpu.h"

// A.1's derivation one step at a time, with the salt of RFC 9369 §3.3.1:
// the initial secret, each endpoint's secret, and each key, where every
// HKDF-Expand-Label call is also run as HKDF-Expand over the HkdfLabel
// A.1 prints, so the printed label bytes are checked against the labels
// quic_version.h holds for version 2 (rfc9369.txt:414-464).
static void v2_expand_both(const uint8_t *secret, const char *label, const char *info_hex,
                           const char *want_hex, size_t len) {
    uint8_t info[32];
    uint8_t by_label[SHA256_LEN];
    uint8_t by_info[SHA256_LEN];
    size_t info_len = unhex(info_hex, info);
    hkdf_expand_label(SHA256_LEN, secret, label, NULL, 0, by_label, len);
    hkdf_expand(SHA256_LEN, secret, info, info_len, by_info, len);
    CHECK(memcmp(by_label, by_info, len) == 0);
    CHECK(eq_hex(by_label, want_hex));
}

static void test_v2_a1_steps(void) {
    uint8_t salt[20];
    uint8_t initial_secret[SHA256_LEN];
    uint8_t client_secret[SHA256_LEN];
    uint8_t server_secret[SHA256_LEN];
    quic_labels labels = quic_version_labels(CH_QUIC_VERSION_2);
    CHECK(unhex(V2_INITIAL_SALT, salt) == sizeof salt);
    hkdf_extract(SHA256_LEN, salt, sizeof salt, APPENDIX_DCID, sizeof APPENDIX_DCID,
                 initial_secret);
    CHECK(eq_hex(initial_secret, V2_INITIAL_SECRET));
    v2_expand_both(initial_secret, "client in", V2_LABEL_CLIENT_IN, V2_CLIENT_INITIAL_SECRET,
                   SHA256_LEN);
    v2_expand_both(initial_secret, "server in", V2_LABEL_SERVER_IN, V2_SERVER_INITIAL_SECRET,
                   SHA256_LEN);
    CHECK(unhex(V2_CLIENT_INITIAL_SECRET, client_secret) == sizeof client_secret);
    CHECK(unhex(V2_SERVER_INITIAL_SECRET, server_secret) == sizeof server_secret);
    v2_expand_both(client_secret, labels.key, V2_LABEL_KEY, V2_CLIENT_KEY, AES_128_KEY);
    v2_expand_both(client_secret, labels.iv, V2_LABEL_IV, V2_CLIENT_IV, AES_IV);
    v2_expand_both(client_secret, labels.hp, V2_LABEL_HP, V2_CLIENT_HP, AES_128_KEY);
    v2_expand_both(server_secret, labels.key, V2_LABEL_KEY, V2_SERVER_KEY, AES_128_KEY);
    v2_expand_both(server_secret, labels.iv, V2_LABEL_IV, V2_SERVER_IV, AES_IV);
    v2_expand_both(server_secret, labels.hp, V2_LABEL_HP, V2_SERVER_HP, AES_128_KEY);
}

// A.1's six keys from the constructor, which holds the salt in aes.c
// (rfc9369.txt:441-464). The first 16 bytes of a schedule are the key
// that built it, as in test_appendix_a1_keys.
static void test_v2_a1_keys(void) {
    aes_public_key k;
    CHECK(aes_public_key_initial(&k, CH_QUIC_VERSION_2, APPENDIX_DCID, sizeof APPENDIX_DCID,
                                 CH_QUIC_ENDPOINT_CLIENT) == CH_OK);
    CHECK(eq_hex(k.key.round_keys, V2_CLIENT_KEY));
    CHECK(eq_hex(k.iv, V2_CLIENT_IV));
    CHECK(eq_hex(k.hp.round_keys, V2_CLIENT_HP));
    CHECK(aes_public_key_initial(&k, CH_QUIC_VERSION_2, APPENDIX_DCID, sizeof APPENDIX_DCID,
                                 CH_QUIC_ENDPOINT_SERVER) == CH_OK);
    CHECK(eq_hex(k.key.round_keys, V2_SERVER_KEY));
    CHECK(eq_hex(k.iv, V2_SERVER_IV));
    CHECK(eq_hex(k.hp.round_keys, V2_SERVER_HP));
}

// The masks A.2 and A.3 print, from the samples they print
// (rfc9369.txt:492-495, rfc9369.txt:562-563).
static void test_v2_header_masks(void) {
    aes_public_key k;
    uint8_t sample[AES_BLOCK];
    uint8_t mask[AES_BLOCK];
    CHECK(aes_public_key_initial(&k, CH_QUIC_VERSION_2, APPENDIX_DCID, sizeof APPENDIX_DCID,
                                 CH_QUIC_ENDPOINT_CLIENT) == CH_OK);
    CHECK(unhex(V2_A2_SAMPLE, sample) == sizeof sample);
    aes_encrypt_block_hp(&k, sample, mask);
    CHECK(eq_hex(mask, V2_A2_MASK));
    CHECK(aes_public_key_initial(&k, CH_QUIC_VERSION_2, APPENDIX_DCID, sizeof APPENDIX_DCID,
                                 CH_QUIC_ENDPOINT_SERVER) == CH_OK);
    CHECK(unhex(V2_A3_SAMPLE, sample) == sizeof sample);
    aes_encrypt_block_hp(&k, sample, mask);
    CHECK(eq_hex(mask, V2_A3_MASK));
}

// A.2's client Initial packet, all 1200 bytes, sealed by the client entry
// and opened by the server's (rfc9369.txt:466-542). Version 1's keys
// derive from the same connection ID and do not open it.
static void test_v2_a2_packet(void) {
    static uint8_t pt[A2_PAYLOAD];
    static uint8_t want[A2_PACKET];
    static uint8_t out[A2_PACKET];
    static uint8_t again[A2_PACKET];
    uint8_t hdr[A2_HDR_LEN];
    size_t out_len = 0;
    memset(pt, 0, sizeof pt);
    CHECK(unhex(V2_A2_CRYPTO_FRAME, pt) == sizeof A2_CRYPTO_FRAME);
    CHECK(unhex(V2_A2_HEADER, hdr) == sizeof hdr);
    CHECK(unhex(V2_A2_PACKET, want) == sizeof want);
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_CLIENT, CH_QUIC_VERSION_2, APPENDIX_DCID,
                            sizeof APPENDIX_DCID, A2_PN, A2_PN_LEN, hdr, sizeof hdr, pt, sizeof pt,
                            out, sizeof out, &out_len) == CH_OK);
    CHECK(out_len == sizeof want && memcmp(out, want, sizeof want) == 0);
    CHECK(eq_hex(out, V2_A2_PROTECTED_HEADER));

    uint64_t pn = 0;
    size_t pt_len = 0;
    memcpy(again, out, sizeof again);
    CHECK(quic_initial_open(CH_QUIC_ENDPOINT_SERVER, CH_QUIC_VERSION_1, APPENDIX_DCID,
                            sizeof APPENDIX_DCID, again, sizeof again, A2_HDR_LEN - A2_PN_LEN, 0,
                            &pn, &pt_len) == CH_QUIC_DISCARD);
    CHECK(quic_initial_open(CH_QUIC_ENDPOINT_SERVER, CH_QUIC_VERSION_2, APPENDIX_DCID,
                            sizeof APPENDIX_DCID, out, out_len, A2_HDR_LEN - A2_PN_LEN, 0, &pn,
                            &pt_len) == CH_OK);
    CHECK(pn == A2_PN && pt_len == A2_PAYLOAD && memcmp(&out[A2_HDR_LEN], pt, A2_PAYLOAD) == 0);
    CHECK(eq_hex(out, V2_A2_HEADER));
}

// A.3's server Initial packet, every byte, sealed by the server entry and
// opened by the client's (rfc9369.txt:544-572).
static void test_v2_a3_packet(void) {
    static uint8_t pt[A3_PAYLOAD];
    static uint8_t want[A3_PACKET];
    static uint8_t out[A3_PACKET];
    uint8_t hdr[A3_HDR_LEN];
    size_t out_len = 0;
    CHECK(unhex(V2_A3_PAYLOAD, pt) == sizeof pt);
    CHECK(unhex(V2_A3_HEADER, hdr) == sizeof hdr);
    CHECK(unhex(V2_A3_PACKET, want) == sizeof want);
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_SERVER, CH_QUIC_VERSION_2, APPENDIX_DCID,
                            sizeof APPENDIX_DCID, A3_PN, A3_PN_LEN, hdr, sizeof hdr, pt, sizeof pt,
                            out, sizeof out, &out_len) == CH_OK);
    CHECK(out_len == sizeof want && memcmp(out, want, sizeof want) == 0);
    CHECK(eq_hex(out, V2_A3_PROTECTED_HEADER));

    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(quic_initial_open(CH_QUIC_ENDPOINT_CLIENT, CH_QUIC_VERSION_2, APPENDIX_DCID,
                            sizeof APPENDIX_DCID, out, out_len, A3_PN_OFF, 0, &pn,
                            &pt_len) == CH_OK);
    CHECK(pn == A3_PN && pt_len == A3_PAYLOAD && memcmp(&out[A3_HDR_LEN], pt, A3_PAYLOAD) == 0);
    CHECK(eq_hex(out, V2_A3_HEADER));
}

// A.4's Retry packet: version 2's key from the constructor, the tag both
// Retry calls compute over A.2's connection ID and the packet, and the
// refusal of each version's tag in the other (rfc9369.txt:574-582).
static void test_v2_a4_retry(void) {
    static const aes_key_schedule zero_schedule;
    static const uint8_t zero_iv[AES_IV] = {0};
    uint8_t packet[36];
    aes_public_key k;
    memset(&k, 0xa5, sizeof k);
    aes_public_key_retry(&k, CH_QUIC_VERSION_2);
    CHECK(eq_hex(k.key.round_keys, V2_RETRY_KEY));
    CHECK(memcmp(k.iv, zero_iv, sizeof zero_iv) == 0);
    CHECK(memcmp(&k.hp, &zero_schedule, sizeof zero_schedule) == 0);

    CHECK(unhex(V2_A4_RETRY_PACKET, packet) == sizeof packet);
    uint8_t pseudo[1 + sizeof APPENDIX_DCID + sizeof packet];
    size_t pseudo_len = 0;
    pseudo[pseudo_len++] = (uint8_t)sizeof APPENDIX_DCID;
    memcpy(&pseudo[pseudo_len], APPENDIX_DCID, sizeof APPENDIX_DCID);
    pseudo_len += sizeof APPENDIX_DCID;
    size_t retry_body = sizeof packet - GCM_TAG;
    memcpy(&pseudo[pseudo_len], packet, retry_body);
    pseudo_len += retry_body;
    const uint8_t *want_tag = &packet[retry_body];

    uint8_t minted[GCM_TAG];
    CHECK(quic_retry_tag(CH_QUIC_VERSION_2, pseudo, pseudo_len, minted) == CH_OK);
    CHECK(memcmp(minted, want_tag, sizeof minted) == 0);
    CHECK(quic_retry_ok(CH_QUIC_VERSION_2, pseudo, pseudo_len, want_tag) == 1);
    CHECK(quic_retry_ok(CH_QUIC_VERSION_1, pseudo, pseudo_len, want_tag) == 0);

    // RFC 9001 Appendix A.4's version 1 packet, checked as version 2.
    size_t v1_len = 0;
    pseudo[0] = (uint8_t)sizeof APPENDIX_DCID;
    v1_len = 1 + sizeof APPENDIX_DCID;
    memcpy(&pseudo[v1_len], A4_RETRY_PACKET, sizeof A4_RETRY_PACKET - GCM_TAG);
    v1_len += sizeof A4_RETRY_PACKET - GCM_TAG;
    const uint8_t *v1_tag = &A4_RETRY_PACKET[sizeof A4_RETRY_PACKET - GCM_TAG];
    CHECK(quic_retry_ok(CH_QUIC_VERSION_1, pseudo, v1_len, v1_tag) == 1);
    CHECK(quic_retry_ok(CH_QUIC_VERSION_2, pseudo, v1_len, v1_tag) == 0);
}

// A.5's four values from its application write secret, the key update
// secret among them (rfc9369.txt:589-612). The update writes the next
// secret over its argument and derives the next key set from it, and the
// header protection key stays, as in test_appendix_a5_keys.
static void test_v2_a5_keys(void) {
    uint8_t secret[SHA256_LEN];
    uint8_t next[SHA256_LEN];
    quic_keys k;
    quic_keys expect;
    quic_hp_key h;
    CHECK(unhex(V2_A5_SECRET, secret) == sizeof secret);
    quic_keys_init(&k, CH_QUIC_VERSION_2, secret);
    CHECK(eq_hex(k.key, V2_A5_KEY) && eq_hex(k.iv, V2_A5_IV));
    quic_hp_key_init(&h, CH_QUIC_VERSION_2, secret);
    CHECK(eq_hex(h.key, V2_A5_HP));
    quic_keys_update(secret, &k, CH_QUIC_VERSION_2);
    CHECK(eq_hex(secret, V2_A5_KU));
    CHECK(unhex(V2_A5_KU, next) == sizeof next);
    quic_keys_init(&expect, CH_QUIC_VERSION_2, next);
    CHECK(memcmp(k.key, expect.key, sizeof expect.key) == 0);
    CHECK(memcmp(k.iv, expect.iv, sizeof expect.iv) == 0);
    CHECK(eq_hex(h.key, V2_A5_HP));
}

// A.5's packet, sealed and opened, with the nonce, the ciphertext and the
// header protection it prints (rfc9369.txt:614-638).
static void test_v2_a5_packet(void) {
    uint8_t secret[SHA256_LEN];
    uint8_t hdr[4];
    uint8_t pt[1];
    uint8_t nonce[AEAD_NONCE];
    uint8_t mask[QUIC_HP_MASK_LEN];
    uint8_t out[32];
    size_t out_len = 0;
    quic_keys k;
    quic_hp_key h;
    CHECK(unhex(V2_A5_SECRET, secret) == sizeof secret);
    quic_keys_init(&k, CH_QUIC_VERSION_2, secret);
    quic_hp_key_init(&h, CH_QUIC_VERSION_2, secret);
    CHECK(unhex(V2_A5_HEADER, hdr) == sizeof hdr);
    CHECK(unhex(V2_A5_PLAINTEXT, pt) == sizeof pt);
    quic_nonce(k.iv, A5_PN, nonce);
    CHECK(eq_hex(nonce, V2_A5_NONCE));

    CHECK(quic_packet_seal(TEST_SESSION_CPU, &k, &h, CH_LEVEL_APPLICATION, A5_PN, A5_PN_LEN, hdr,
                           sizeof hdr, pt, sizeof pt, out, sizeof out, &out_len) == CH_OK);
    CHECK(out_len == 21 && eq_hex(out, V2_A5_PACKET));
    CHECK(eq_hex(&out[sizeof hdr], V2_A5_CIPHERTEXT));
    CHECK(eq_hex(&out[sizeof hdr + 1], V2_A5_SAMPLE));

    // The printed mask over the printed header, the §5.4.1 step alone.
    // quic_header_protect writes QUIC_PN_MAX_LEN bytes at the packet
    // number offset, so the buffer runs one byte past the header, and
    // that byte keeps its value.
    uint8_t protect[sizeof hdr + 1];
    memset(protect, 0xa5, sizeof protect);
    memcpy(protect, hdr, sizeof hdr);
    CHECK(unhex(V2_A5_MASK, mask) == sizeof mask);
    quic_header_protect(protect, 1, A5_PN_LEN, CH_LEVEL_APPLICATION, mask);
    CHECK(eq_hex(protect, V2_A5_PROTECTED_HEADER) && protect[sizeof hdr] == 0xa5);

    quic_keys sets[CH_QUIC_KEY_SETS];
    memset(sets, 0, sizeof sets);
    memcpy(&sets[CH_QUIC_KEY_CURRENT], &k, sizeof k);
    uint8_t key_set = 0xff;
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(quic_packet_open_application(TEST_SESSION_CPU, sets, &h, 0, out, out_len, 1, A5_PN - 1, 0,
                                       &key_set, &pn, &pt_len) == CH_OK);
    CHECK(key_set == CH_QUIC_KEY_CURRENT && pn == A5_PN && pt_len == 1);
    CHECK(eq_hex(out, V2_A5_HEADER) && out[sizeof hdr] == pt[0]);
}

static void test_rfc9369_appendix_a(void) {
    test_v2_a1_steps();
    test_v2_a1_keys();
    test_v2_header_masks();
    test_v2_a2_packet();
    test_v2_a3_packet();
    test_v2_a4_retry();
    test_v2_a5_keys();
    test_v2_a5_packet();
}

#endif
