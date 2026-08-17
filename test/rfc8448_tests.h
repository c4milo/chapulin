// RFC 8448 trace replay at the transcript level: third-party values for
// which messages enter the transcript hash and when each secret
// snapshots it, which single-primitive vectors cannot check. The traces
// protect records with AES-GCM, which chapulin excludes, so the replay
// stops at secrets and MACs and never seals a record. Included by
// test/unit.c only, after its CHECK macro and includes.
//
// RFC 8448 signs with an RSA-1024 key and rsa_pss_verify enforces a
// 2048-bit floor, so the CertificateVerify check runs one layer down:
// the real rsa_vp1 does the modexp (a 32-limb size no other test
// reaches) and a test-local PSS check validates the recovered message.
// The floor itself stays: the public API must refuse the RFC's key.
#ifndef CH_RFC8448_TESTS_H
#define CH_RFC8448_TESTS_H

#include "keysched.h"
#include "rfc8448_vectors.h"
#include "rsa.h"

// Transcript hash at this point in the handshake, without ending the
// running hash.
static void rfc8448_snapshot(const sha256 *t, uint8_t out[SHA256_LEN]) {
    sha256 c = *t;
    sha256_final(&c, out);
}

// MGF1-SHA256 (RFC 8017 B.2.1). Test-local: rsa.c keeps its own static.
static void rfc8448_mgf1(const uint8_t seed[SHA256_LEN], uint8_t *mask, size_t len) {
    uint32_t counter = 0;
    for (size_t off = 0; off < len; off += SHA256_LEN) {
        uint8_t counter_bytes[4] = {(uint8_t)(counter >> 24), (uint8_t)(counter >> 16),
                                    (uint8_t)(counter >> 8), (uint8_t)counter};
        uint8_t digest[SHA256_LEN];
        sha256 h;
        sha256_init(&h);
        sha256_update(&h, seed, SHA256_LEN);
        sha256_update(&h, counter_bytes, sizeof counter_bytes);
        sha256_final(&h, digest);
        size_t take = len - off < SHA256_LEN ? len - off : SHA256_LEN;
        memcpy(mask + off, digest, take);
        counter++;
    }
}

// EMSA-PSS-VERIFY (RFC 8017 9.1.2) at the trace's RSA-1024 geometry:
// emLen 128, emBits 1023, SHA-256, MGF1-SHA256, saltLen 32.
static int rfc8448_pss_ok(const uint8_t msg_hash[SHA256_LEN], const uint8_t em[128]) {
    enum { EMLEN = 128, DBLEN = EMLEN - SHA256_LEN - 1, PSLEN = DBLEN - SHA256_LEN - 1 };
    // Trailer byte, then the one leftmost bit 8*emLen - emBits leaves.
    if (em[EMLEN - 1] != 0xbc || (em[0] & 0x80)) {
        return 0;
    }
    const uint8_t *hh = em + DBLEN;
    uint8_t db[DBLEN];
    rfc8448_mgf1(hh, db, DBLEN);
    for (size_t i = 0; i < DBLEN; i++) {
        db[i] ^= em[i];
    }
    db[0] &= 0x7f;
    // DB = PS (zeros) || 0x01 || salt.
    for (size_t i = 0; i < PSLEN; i++) {
        if (db[i] != 0) {
            return 0;
        }
    }
    if (db[PSLEN] != 0x01) {
        return 0;
    }
    // H' = Hash(0x00 * 8 || msg_hash || salt).
    static const uint8_t zeros8[8] = {0};
    uint8_t h_prime[SHA256_LEN];
    sha256 h;
    sha256_init(&h);
    sha256_update(&h, zeros8, sizeof zeros8);
    sha256_update(&h, msg_hash, SHA256_LEN);
    sha256_update(&h, db + PSLEN + 1, SHA256_LEN);
    sha256_final(&h, h_prime);
    return memcmp(h_prime, hh, SHA256_LEN) == 0;
}

// Verifies the section 3 CertificateVerify over the CH..Certificate
// transcript hash. Content per RFC 9846 §4.5.2.
static void rfc8448_check_cv(const uint8_t transcript_hash[SHA256_LEN]) {
    // 0f | 000084 | 0804 (rsa_pss_rsae_sha256) | 0080 | 128-byte sig.
    CHECK(rfc8448_s3_cv[0] == 0x0f && rfc8448_s3_cv[3] == 0x84);
    CHECK(rfc8448_s3_cv[4] == 0x08 && rfc8448_s3_cv[5] == 0x04);
    CHECK(rfc8448_s3_cv[6] == 0x00 && rfc8448_s3_cv[7] == 0x80);
    const uint8_t *sig = rfc8448_s3_cv + 8;

    static const char ctx[] = "TLS 1.3, server CertificateVerify";
    uint8_t pad[64];
    memset(pad, 0x20, sizeof pad);
    uint8_t signed_hash[SHA256_LEN];
    sha256 h;
    sha256_init(&h);
    sha256_update(&h, pad, sizeof pad);
    sha256_update(&h, (const uint8_t *)ctx, sizeof ctx); // includes the 0x00
    sha256_update(&h, transcript_hash, SHA256_LEN);
    sha256_final(&h, signed_hash);

    // The 2048-bit floor must refuse the RFC's RSA-1024 key outright.
    CHECK(rsa_pss_verify(rfc8448_rsa_n, sizeof rfc8448_rsa_n, signed_hash, sig, 128) == 0);

    // One layer down: RSAVP1 at 32 limbs, then the local PSS check.
    CHECK(memcmp(sig, rfc8448_rsa_n, 128) < 0); // rsa_vp1 needs sig < n
    uint8_t em[128];
    rsa_vp1(rfc8448_rsa_n, sizeof rfc8448_rsa_n, sig, em);
    CHECK(rfc8448_pss_ok(signed_hash, em));
    em[100] ^= 1;
    CHECK(!rfc8448_pss_ok(signed_hash, em));
}

// Section 3: the full 1-RTT schedule, message by message.
static void test_rfc8448_1rtt(void) {
    // ECDHE: both key pairs, shared secret from both sides.
    uint8_t pub[X25519_LEN];
    uint8_t shared[X25519_LEN];
    x25519_base(pub, rfc8448_s3_client_priv);
    CHECK(memcmp(pub, rfc8448_s3_client_pub, X25519_LEN) == 0);
    x25519_base(pub, rfc8448_s3_server_priv);
    CHECK(memcmp(pub, rfc8448_s3_server_pub, X25519_LEN) == 0);
    CHECK(x25519(shared, rfc8448_s3_client_priv, rfc8448_s3_server_pub) == 1);
    CHECK(memcmp(shared, rfc8448_s3_ecdhe, X25519_LEN) == 0);
    CHECK(x25519(shared, rfc8448_s3_server_priv, rfc8448_s3_client_pub) == 1);
    CHECK(memcmp(shared, rfc8448_s3_ecdhe, X25519_LEN) == 0);

    // Early secret: no PSK, so the IKM is 32 zero bytes.
    uint8_t zeros[SHA256_LEN] = {0};
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    ks_early(zeros, sizeof zeros, 0, early, binder_key);
    CHECK(memcmp(early, rfc8448_s3_early_secret, SHA256_LEN) == 0);

    // CH..SH snapshot feeds the handshake traffic secrets.
    sha256 transcript;
    sha256_init(&transcript);
    sha256_update(&transcript, rfc8448_s3_client_hello, sizeof rfc8448_s3_client_hello);
    sha256_update(&transcript, rfc8448_s3_server_hello, sizeof rfc8448_s3_server_hello);
    uint8_t h[SHA256_LEN];
    rfc8448_snapshot(&transcript, h);
    CHECK(memcmp(h, rfc8448_s3_th_ch_sh, SHA256_LEN) == 0);
    uint8_t handshake_secret[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN];
    ks_handshake(early, shared, h, handshake_secret, c_hs, s_hs);
    CHECK(memcmp(handshake_secret, rfc8448_s3_hs_secret, SHA256_LEN) == 0);
    CHECK(memcmp(c_hs, rfc8448_s3_c_hs_traffic, SHA256_LEN) == 0);
    CHECK(memcmp(s_hs, rfc8448_s3_s_hs_traffic, SHA256_LEN) == 0);

    // CH..Certificate snapshot signs the CertificateVerify.
    sha256_update(&transcript, rfc8448_s3_ee, sizeof rfc8448_s3_ee);
    sha256_update(&transcript, rfc8448_s3_cert, sizeof rfc8448_s3_cert);
    rfc8448_snapshot(&transcript, h);
    rfc8448_check_cv(h);

    // CH..CertificateVerify snapshot is what the server Finished MACs.
    sha256_update(&transcript, rfc8448_s3_cv, sizeof rfc8448_s3_cv);
    rfc8448_snapshot(&transcript, h);
    uint8_t mac[SHA256_LEN];
    ks_verify_data(s_hs, h, mac);
    CHECK(memcmp(mac, rfc8448_s3_server_fin_mac, SHA256_LEN) == 0);
    CHECK(memcmp(rfc8448_s3_server_fin_msg + 4, mac, SHA256_LEN) == 0);

    // CH..server Finished snapshot: application secrets, exporter, and
    // the client Finished MAC all take this one.
    sha256_update(&transcript, rfc8448_s3_server_fin_msg, sizeof rfc8448_s3_server_fin_msg);
    rfc8448_snapshot(&transcript, h);
    CHECK(memcmp(h, rfc8448_s3_th_ch_sf, SHA256_LEN) == 0);
    uint8_t master[SHA256_LEN];
    uint8_t c_ap[SHA256_LEN];
    uint8_t s_ap[SHA256_LEN];
    ks_master(handshake_secret, h, master, c_ap, s_ap);
    CHECK(memcmp(master, rfc8448_s3_master_secret, SHA256_LEN) == 0);
    CHECK(memcmp(c_ap, rfc8448_s3_c_ap_traffic, SHA256_LEN) == 0);
    CHECK(memcmp(s_ap, rfc8448_s3_s_ap_traffic, SHA256_LEN) == 0);
    uint8_t exp[SHA256_LEN];
    hkdf_derive_secret(master, "exp master", h, exp);
    CHECK(memcmp(exp, rfc8448_s3_exp_master, SHA256_LEN) == 0);
    ks_verify_data(c_hs, h, mac);
    CHECK(memcmp(mac, rfc8448_s3_client_fin_mac, SHA256_LEN) == 0);
    CHECK(memcmp(rfc8448_s3_client_fin_msg + 4, mac, SHA256_LEN) == 0);

    // CH..client Finished snapshot closes the schedule; the ticket's
    // PSK comes from the resumption master and the ticket nonce.
    sha256_update(&transcript, rfc8448_s3_client_fin_msg, sizeof rfc8448_s3_client_fin_msg);
    rfc8448_snapshot(&transcript, h);
    CHECK(memcmp(h, rfc8448_s3_th_ch_cf, SHA256_LEN) == 0);
    uint8_t res[SHA256_LEN];
    ks_res_master(master, h, res);
    CHECK(memcmp(res, rfc8448_s3_res_master, SHA256_LEN) == 0);
    uint8_t psk[SHA256_LEN];
    ks_res_psk(res, rfc8448_s3_ticket_nonce, sizeof rfc8448_s3_ticket_nonce, psk);
    CHECK(memcmp(psk, rfc8448_s3_res_psk, SHA256_LEN) == 0);
}

// Section 4: the PSK binder chain over the section 3 ticket.
static void test_rfc8448_binder(void) {
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    ks_early(rfc8448_s3_res_psk, sizeof rfc8448_s3_res_psk, 1, early, binder_key);
    CHECK(memcmp(early, rfc8448_s4_early_secret, SHA256_LEN) == 0);
    CHECK(memcmp(binder_key, rfc8448_s4_binder_key, SHA256_LEN) == 0);
    // The binder MACs the ClientHello truncated before the binder list.
    uint8_t h[SHA256_LEN];
    sha256_of(rfc8448_s4_ch_prefix, sizeof rfc8448_s4_ch_prefix, h);
    CHECK(memcmp(h, rfc8448_s4_binder_hash, SHA256_LEN) == 0);
    uint8_t mac[SHA256_LEN];
    ks_verify_data(binder_key, h, mac);
    CHECK(memcmp(mac, rfc8448_s4_binder, SHA256_LEN) == 0);
}

// Section 5: the HelloRetryRequest transcript restart and the
// handshake secrets it feeds.
static void test_rfc8448_hrr(void) {
    // CH1 collapses to a synthetic message_hash message (RFC 9846
    // §4.1); the transcript restarts from it.
    uint8_t h1[SHA256_LEN];
    sha256_of(rfc8448_s5_ch1, sizeof rfc8448_s5_ch1, h1);
    static const uint8_t synth_hdr[4] = {0xfe, 0x00, 0x00, 0x20};
    sha256 transcript;
    sha256_init(&transcript);
    sha256_update(&transcript, synth_hdr, sizeof synth_hdr);
    sha256_update(&transcript, h1, SHA256_LEN);
    sha256_update(&transcript, rfc8448_s5_hrr, sizeof rfc8448_s5_hrr);
    sha256_update(&transcript, rfc8448_s5_ch2, sizeof rfc8448_s5_ch2);
    sha256_update(&transcript, rfc8448_s5_sh, sizeof rfc8448_s5_sh);
    uint8_t h[SHA256_LEN];
    sha256_final(&transcript, h);
    CHECK(memcmp(h, rfc8448_s5_th_ch_sh, SHA256_LEN) == 0);

    // The restarted transcript feeds the handshake secrets. The shared
    // secret is P-256 ECDH, which chapulin never computes; the trace
    // supplies it.
    uint8_t zeros[SHA256_LEN] = {0};
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    ks_early(zeros, sizeof zeros, 0, early, binder_key);
    uint8_t handshake_secret[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN];
    ks_handshake(early, rfc8448_s5_ecdhe, h, handshake_secret, c_hs, s_hs);
    CHECK(memcmp(c_hs, rfc8448_s5_c_hs_traffic, SHA256_LEN) == 0);
    CHECK(memcmp(s_hs, rfc8448_s5_s_hs_traffic, SHA256_LEN) == 0);
}

#endif
