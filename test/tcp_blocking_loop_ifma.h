// The AVX-512 IFMA rows of the blocking loop: test/tcp_blocking_loop_test.c
// built as bin/tcp_blocking_loop_host, a ROLE=both host object whose client
// half is the raw client, on the Makefile's widemul_counted lists, which
// link test/rsa_ifma_count.c in place of rsa_ifma.c,
// test/rsa_ifma_sign_count.c in place of rsa_ifma_sign.c and
// avx512_wipe.c, and test/aead_avx512_count.c in place of
// chacha20_avx512.c and poly1305_ifma.c's native copy, and which the
// binary says with -DTEST_WIDEMUL_COUNTED. So the rows run no AVX-512
// instruction, and pass on every x86-64 CPU.
// Every other case of that file runs in the same binary with both ends
// describing the CPU as TEST_CPU, which holds no CH_CPU_AVX512_IFMA.
//
// What the rows hold: rsa_mont.c's rsa_vp1_cpu sends RSA's public
// operation to rsa_ifma_public for a session whose ch_cfg.cpu holds
// CH_CPU_AVX512_IFMA (rsa.h), so each caller that holds a session must
// pass the session's value, and these rows count the calls each caller
// makes:
//
//   - the client's CertificateVerify, which handshake_auth.c verifies
//     under the pinned RSA-2048 key, once through ch_connect and once
//     through the client's handlers under ch_srv_accept: one call where
//     the client's value holds the bit and none where it does not,
//     whatever the server's value holds.
//   - ch_srv_check's check of the RSA identity, which srv_auth.c's
//     verify_digest makes: one call where the server's value holds the
//     bit and none where it does not.
//   - the server's RSA-PSS signature, its CertificateVerify in a handshake
//     and the one ch_srv_check makes: its exponentiations run on
//     rsa_ifma_sign.c, and its check of each signature sends one public
//     operation to rsa_ifma_public, where the server's value holds the bit
//     beside TEST_CPU's multiply bit (rsa_sign64.h, docs/decisions.md
//     120), and neither where it does not.
//   - the records each end seals and opens: chacha20.c's chacha20_xor_cpu
//     runs their keystream on chacha20_avx512.c's kernel for a session
//     whose value holds the bit (docs/decisions.md 121), so a handshake
//     makes at least one call where either end's value holds it and none
//     where neither does. No record here holds the 512 bytes of whole
//     blocks poly1305.c hands the AVX-512 IFMA Poly1305, so these rows
//     count no call to it; bin/x86_kernels_test counts that kernel's.
//
// An arm64 object refuses CH_CPU_AVX512_IFMA at every init call and
// ch_srv_check, and its rsa_vp1_cpu sends nothing to a kernel, so there
// the rows run without the bit alone and require no call.
#ifndef CH_TEST_TCP_BLOCKING_LOOP_IFMA_H
#define CH_TEST_TCP_BLOCKING_LOOP_IFMA_H
#ifdef TEST_WIDEMUL_COUNTED

#include "aead_avx512_count.h"
#include "rsa_ifma_count.h"
#include "rsa_ifma_sign_count.h"

// The bits each row's ends take beside TEST_CPU: none, and on x86-64
// CH_CPU_AVX512_IFMA.
#ifdef __x86_64__
static const uint32_t ifma_row_bits[] = {0, CH_CPU_AVX512_IFMA};
#else
static const uint32_t ifma_row_bits[] = {0};
#endif
#define IFMA_ROW_VALUES (sizeof ifma_row_bits / sizeof ifma_row_bits[0])

// The calls a row requires: one where the end's bits hold the IFMA bit.
static unsigned long ifma_row_calls(uint32_t bits) {
    return (bits & CH_CPU_AVX512_IFMA) != 0 ? 1 : 0;
}

static void reset_ifma_calls(void) {
    rsa_ifma_public_calls = 0;
    rsa_ifma_sign_pair_calls = 0;
    chacha20_avx512_calls = 0;
}

// Whether the calls since the last reset are a handshake's: the client's
// verification of the CertificateVerify under client_bits, the server's
// signature of it and the signature's check under server_bits, and the
// keystream of the records the two ends seal and open under each end's
// bits.
static int handshake_calls_are(uint32_t client_bits, uint32_t server_bits) {
    unsigned long verify = ifma_row_calls(client_bits);
    unsigned long sign = ifma_row_calls(server_bits);
    int keystream = ifma_row_calls(client_bits | server_bits) != 0;
    return rsa_ifma_public_calls == verify + sign && rsa_ifma_sign_pair_calls == sign &&
           (chacha20_avx512_calls > 0) == keystream;
}

static void test_rsa_ifma_callers(void) {
    for (size_t c = 0; c < IFMA_ROW_VALUES; c++) {
        for (size_t s = 0; s < IFMA_ROW_VALUES; s++) {
            blocking_client_cpu = TEST_CPU | ifma_row_bits[c];
            blocking_server_cpu = TEST_CPU | ifma_row_bits[s];
            reset_ifma_calls();
            client_reads_flight(0, 0);
            CHECK(handshake_calls_are(ifma_row_bits[c], ifma_row_bits[s]));
            reset_ifma_calls();
            server_reads_client(0, 0);
            CHECK(handshake_calls_are(ifma_row_bits[c], ifma_row_bits[s]));
        }
    }
    // ch_srv_check signs once, which runs the kernels and the signature's
    // check, and verifies that signature once.
    for (size_t s = 0; s < IFMA_ROW_VALUES; s++) {
        ch_cfg cfg;
        server_config(&cfg, read_to_server);
        cfg.cpu = TEST_CPU | ifma_row_bits[s];
        reset_ifma_calls();
        CHECK(ch_srv_check(&cfg) == CH_OK);
        CHECK(rsa_ifma_public_calls == 2 * ifma_row_calls(ifma_row_bits[s]));
        CHECK(rsa_ifma_sign_pair_calls == ifma_row_calls(ifma_row_bits[s]));
    }
    blocking_client_cpu = TEST_CPU;
    blocking_server_cpu = TEST_CPU;
}

#endif // TEST_WIDEMUL_COUNTED
#endif
