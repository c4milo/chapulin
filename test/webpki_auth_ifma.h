// The AVX-512 IFMA rows of the TRUST=webpki CertificateVerify test:
// test/webpki_auth_test.c built as bin/webpki_auth_host, the webpki
// client's sources in a host object, on the Makefile's widemul_counted
// lists, which link test/rsa_ifma_count.c in place of rsa_ifma.c and which
// the binary says with -DTEST_WIDEMUL_COUNTED. Every other case of that
// file runs in the same binary with the client describing the CPU as
// TEST_CPU, which holds no CH_CPU_AVX512_IFMA. In any other build
// test_rsa_ifma_chain does nothing. Included by test/webpki_auth_test.c
// after test/webpki_auth_pins.h, whose auth_vector_named it reads.
//
// What the rows hold: rsa_mont.c's rsa_vp1_cpu sends RSA's public
// operation to rsa_ifma_public for a session whose ch_cfg.cpu holds
// CH_CPU_AVX512_IFMA (rsa.h), so each caller in the chain walk and in
// CertificateVerify must pass the session's value. The aws chain's leaf,
// intermediate and anchor keys are each RSA-2048, and its flight through
// hsa_server_auth makes three public operations: webpki.c's read_issuer
// verifies the leaf's signature under the intermediate's key,
// anchor_verifies verifies the intermediate's signature under the
// anchor's key, and handshake_auth.c verifies the CertificateVerify under
// the leaf's key. With the bit all three go to rsa_ifma_public, and
// without it none does. The r2 chain holds no RSA key, so its flight
// sends none under either.
//
// An arm64 object refuses CH_CPU_AVX512_IFMA at every init call, so no
// session there holds it, and its rsa_vp1_cpu sends nothing to a kernel:
// there the rows run without the bit alone and require no call.
#ifndef CH_TEST_WEBPKI_AUTH_IFMA_H
#define CH_TEST_WEBPKI_AUTH_IFMA_H
#ifdef TEST_WIDEMUL_COUNTED

#include "rsa_ifma_count.h"

// The bits each row's client takes beside TEST_CPU: none, and on x86-64
// CH_CPU_AVX512_IFMA.
#ifdef __x86_64__
static const uint32_t ifma_row_bits[] = {0, CH_CPU_AVX512_IFMA};
#else
static const uint32_t ifma_row_bits[] = {0};
#endif
#define IFMA_ROW_VALUES (sizeof ifma_row_bits / sizeof ifma_row_bits[0])

// The vector called name through hsa_server_auth from a session whose
// ch_cfg.cpu is TEST_CPU with bits, which must accept it. Returns the
// calls the flight made to rsa_ifma_public.
static unsigned long ifma_calls_of_flight(const char *name, uint32_t bits) {
    const webpki_auth_vector *v = auth_vector_named(name);
    const webpki_corpus_chain *row = chain_named(v->chain);
    if (row == NULL) {
        return 0;
    }
    ch_trust_anchor anchors[CH_WEBPKI_ANCHOR_MAX];
    ch_tls t;
    memset(&t, 0, sizeof t);
    row_cfg(row, anchors, &t.cfg);
    t.cfg.cpu = TEST_CPU | bits;
    handshake_state h;
    uint8_t verify_msg[VERIFY_MSG_MAX];
    size_t verify_len = 0;
    rsa_ifma_public_calls = 0;
    CHECK(run_flight(&t, &h, row->message, row->message_len, v->scheme, v->sig, v->sig_len,
                     verify_msg, &verify_len) == CH_OK);
    return rsa_ifma_public_calls;
}

static void test_rsa_ifma_chain(void) {
    for (size_t i = 0; i < IFMA_ROW_VALUES; i++) {
        unsigned long want = (ifma_row_bits[i] & CH_CPU_AVX512_IFMA) != 0 ? 3 : 0;
        CHECK(ifma_calls_of_flight("rsa_pss", ifma_row_bits[i]) == want);
        CHECK(ifma_calls_of_flight("p256_sha256", ifma_row_bits[i]) == 0);
    }
}

#else

static void test_rsa_ifma_chain(void) {
}

#endif // TEST_WIDEMUL_COUNTED
#endif
