// The count bound, SRV_CLIENT_HELLO_EXT_MAX, of the tcp-nonblocking
// server. Included by test/srv_tcp_nonblocking_test.c after its
// configuration, its record wrapper and its hello builder.
#ifndef CH_TEST_SRV_TCP_NONBLOCKING_EXTENSION_TESTS_H
#define CH_TEST_SRV_TCP_NONBLOCKING_EXTENSION_TESTS_H

// The count bound, SRV_CLIENT_HELLO_EXT_MAX, on the record path. This
// tree's own hello, filled out with empty extensions of distinct unknown
// types after its last one, draws the server's flight at the bound and
// illegal_parameter one past it (docs/decisions.md 59). The hello at the
// bound is larger than srv_buf, so the case gives the server a buffer of
// its own.
#define PAD_TYPE 0x1000
#define PADDED_CAP (CH_HELLO_MAX + 4 * SRV_CLIENT_HELLO_EXT_MAX)
static uint8_t padded_buf[PADDED_CAP + REC_HDR];

// Fills hello, a message of hello_len bytes in a buffer of PADDED_CAP,
// out to count extensions, and returns its new length.
static size_t pad_to(uint8_t *hello, size_t hello_len, size_t count) {
    rbuf r;
    rb_init(&r, hello + 4, hello_len - 4);
    rb_skip(&r, 2 + 32);
    rb_skip(&r, rb_u8(&r));
    rb_skip(&r, rb_u16(&r));
    rb_skip(&r, rb_u8(&r));
    size_t block_at = 4 + (hello_len - 4 - rb_left(&r));
    rb_skip(&r, 2);
    size_t have = 0;
    while (rb_left(&r) > 0 && !r.err) {
        (void)rb_u16(&r);
        rb_skip(&r, rb_u16(&r));
        have++;
    }
    CHECK(!r.err && have < count);
    wbuf w;
    wb_init(&w, hello + hello_len, PADDED_CAP - hello_len);
    for (size_t i = have; i < count; i++) {
        wb_u16(&w, (uint16_t)(PAD_TYPE + i));
        wb_u16(&w, 0);
    }
    CHECK(!w.err);
    size_t len = hello_len + w.len;
    size_t block_len = len - block_at - 2;
    hello[block_at] = (uint8_t)(block_len >> 8);
    hello[block_at + 1] = (uint8_t)block_len;
    hello[1] = (uint8_t)((len - 4) >> 16);
    hello[2] = (uint8_t)((len - 4) >> 8);
    hello[3] = (uint8_t)(len - 4);
    return len;
}

static void test_extension_count_bound(void) {
    for (size_t count = SRV_CLIENT_HELLO_EXT_MAX; count <= SRV_CLIENT_HELLO_EXT_MAX + 1; count++) {
        static uint8_t hello[PADDED_CAP];
        size_t hello_len = pad_to(hello, build_hello(hello, PADDED_CAP), count);
        static uint8_t rec[PADDED_CAP + REC_HDR];
        size_t rec_len = wrap(rec, hello, hello_len);

        ch_cfg cfg;
        server_config(&cfg);
        cfg.buf = padded_buf;
        cfg.buf_len = sizeof padded_buf;
        ch_tcp_priv r;
        memset(&seen, 0, sizeof seen);
        CHECK(server_init(&r, &cfg) == CH_OK);
        size_t consumed = 0;
        int rc = ch_srv_tcp_in(tcp_public(&r), rec, rec_len, &consumed);
        if (count <= SRV_CLIENT_HELLO_EXT_MAX) {
            CHECK(rc == CH_OK && seen.count >= 5);
        } else {
            // No ServerHello, and one record through the sink: the alert,
            // in the clear, because the server holds no key yet.
            CHECK(rc == CH_EPROTO && r.t.alert_sent == ALERT_ILLEGAL_PARAMETER);
            CHECK(seen.count == 1 && seen.type[0] == REC_ALERT && seen.len[0] == REC_HDR + 2);
        }
        ch_tcp_close(tcp_public(&r));
    }
}

#endif
