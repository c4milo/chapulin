// SRV_CLIENT_HELLO_EXT_MAX on the QUIC server's HelloRetryRequest round,
// over the two ClientHellos ngtcp2's interop client sent colibri's server
// (test/srv_quic_retry_vectors.h). It uses CHECK from test/srv_quic_test.c
// and the helpers of test/srv_quic_retry_tests.h, and is included after
// both.
#ifndef CH_SRV_QUIC_RETRY_COUNT_TESTS_H
#define CH_SRV_QUIC_RETRY_COUNT_TESTS_H

// The first of the distinct unknown types that fill a hello out to a count:
// no type either recorded hello carries and none the parser recognizes.
#define RETRY_PAD_TYPE 0x1000
// How many extensions ngtcp2's recorded hellos carry. The second adds the
// cookie.
#define FIRST_EXT_COUNT 10
#define SECOND_EXT_COUNT 11

// Writes to out a copy of in with extra empty extensions of distinct
// unknown types after its last one. The filler's types are the same on
// every call, so a first and a second hello filled out by the same count
// carry the same covered set.
static void padded_hello(retry_msg *out, const retry_msg *in, size_t extra) {
    static uint8_t filler[RETRY_EXT_MAX][4];
    hello_parts parts;
    split_hello(in, &parts);
    CHECK(parts.count + extra <= RETRY_EXT_MAX);
    for (size_t i = 0; i < extra && parts.count < RETRY_EXT_MAX; i++) {
        filler[i][0] = (uint8_t)((RETRY_PAD_TYPE + i) >> 8);
        filler[i][1] = (uint8_t)(RETRY_PAD_TYPE + i);
        parts.ext[parts.count] = filler[i];
        parts.ext_len[parts.count] = sizeof filler[i];
        parts.count++;
    }
    join_hello(out, &parts);
}

// SRV_CLIENT_HELLO_EXT_MAX on the retry path (docs/decisions.md 59).
// ngtcp2's first hello carries ten extensions and its second eleven,
// because the second adds the cookie. Each case fills both out with the
// same unknown extensions, so the frozen digest matches and only the count
// can refuse. A first hello one under the bound draws a HelloRetryRequest,
// and its second, at the bound, draws the server's flight. A first hello
// at the bound draws one too, and its second, one past the bound, is
// refused with illegal_parameter. A first hello one past the bound is
// refused before any HelloRetryRequest.
static void test_retry_extension_count(void) {
    static ch_quic q;
    static retry_msg recorded1;
    static retry_msg recorded2;
    static retry_msg hello;
    from_hex(&recorded1, ngtcp2_hello1_hex);
    for (size_t extra = SRV_CLIENT_HELLO_EXT_MAX - SECOND_EXT_COUNT;
         extra <= SRV_CLIENT_HELLO_EXT_MAX - FIRST_EXT_COUNT; extra++) {
        retry_session(&q);
        padded_hello(&hello, &recorded1, extra);
        CHECK(ch_srv_quic_crypto_in(&q, CH_LEVEL_INITIAL, hello.bytes, hello.len) == CH_OK);
        size_t body_len = 0;
        const uint8_t *body = server_ext(retry_out.bytes[CH_LEVEL_INITIAL],
                                         retry_out.len[CH_LEVEL_INITIAL], EXT_COOKIE, &body_len);
        CHECK(body != NULL && body_len > 2 && body_len - 2 <= SRV_COOKIE_MAX);
        if (body == NULL || body_len <= 2 || body_len - 2 > SRV_COOKIE_MAX) {
            return;
        }
        recorded_second(&recorded2, body + 2, body_len - 2, NULL);
        padded_hello(&hello, &recorded2, extra);
        int rc = ch_srv_quic_crypto_in(&q, CH_LEVEL_INITIAL, hello.bytes, hello.len);
        if (SECOND_EXT_COUNT + extra <= SRV_CLIENT_HELLO_EXT_MAX) {
            CHECK(rc == CH_OK && retry_out.len[CH_LEVEL_HANDSHAKE] > 0);
        } else {
            CHECK(rc == CH_EPROTO && ch_quic_alert(&q) == ALERT_ILLEGAL_PARAMETER);
            CHECK(retry_out.len[CH_LEVEL_HANDSHAKE] == 0);
        }
    }
    retry_session(&q);
    padded_hello(&hello, &recorded1, SRV_CLIENT_HELLO_EXT_MAX + 1 - FIRST_EXT_COUNT);
    CHECK(ch_srv_quic_crypto_in(&q, CH_LEVEL_INITIAL, hello.bytes, hello.len) == CH_EPROTO);
    CHECK(ch_quic_alert(&q) == ALERT_ILLEGAL_PARAMETER);
    CHECK(retry_out.len[CH_LEVEL_INITIAL] == 0);
}

#endif
