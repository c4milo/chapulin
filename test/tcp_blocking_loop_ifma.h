// The AVX-512 IFMA rows of the blocking loop: test/tcp_blocking_loop_test.c
// built as bin/tcp_blocking_loop_host, a ROLE=both host object whose client
// half is the raw client, on the Makefile's widemul_counted lists, which
// link test/rsa_ifma_count.c in place of rsa_ifma.c and which the binary
// says with -DTEST_WIDEMUL_COUNTED. Every other case of that file runs in
// the same binary with both ends describing the CPU as TEST_CPU, which
// holds no CH_CPU_AVX512_IFMA.
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
//
// An arm64 object refuses CH_CPU_AVX512_IFMA at every init call and
// ch_srv_check, and its rsa_vp1_cpu sends nothing to a kernel, so there
// the rows run without the bit alone and require no call.
#ifndef CH_TEST_TCP_BLOCKING_LOOP_IFMA_H
#define CH_TEST_TCP_BLOCKING_LOOP_IFMA_H
#ifdef TEST_WIDEMUL_COUNTED

#include "rsa_ifma_count.h"

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

static void test_rsa_ifma_callers(void) {
    for (size_t c = 0; c < IFMA_ROW_VALUES; c++) {
        for (size_t s = 0; s < IFMA_ROW_VALUES; s++) {
            blocking_client_cpu = TEST_CPU | ifma_row_bits[c];
            blocking_server_cpu = TEST_CPU | ifma_row_bits[s];
            rsa_ifma_public_calls = 0;
            client_reads_flight(0, 0);
            CHECK(rsa_ifma_public_calls == ifma_row_calls(ifma_row_bits[c]));
            rsa_ifma_public_calls = 0;
            server_reads_client(0, 0);
            CHECK(rsa_ifma_public_calls == ifma_row_calls(ifma_row_bits[c]));
        }
    }
    for (size_t s = 0; s < IFMA_ROW_VALUES; s++) {
        ch_cfg cfg;
        server_config(&cfg, read_to_server);
        cfg.cpu = TEST_CPU | ifma_row_bits[s];
        rsa_ifma_public_calls = 0;
        CHECK(ch_srv_check(&cfg) == CH_OK);
        CHECK(rsa_ifma_public_calls == ifma_row_calls(ifma_row_bits[s]));
    }
    blocking_client_cpu = TEST_CPU;
    blocking_server_cpu = TEST_CPU;
}

#endif // TEST_WIDEMUL_COUNTED
#endif
