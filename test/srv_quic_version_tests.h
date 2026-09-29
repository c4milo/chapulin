// The QUIC version rules of docs/decisions.md 79 through a server's
// public calls: the original version ch_srv_quic_init takes and the
// negotiated version it starts, the version ch_srv_quic_retry_tag keys a
// Retry under, and, in a ROLE=both object, a switch the server session
// may not make. test/srv_quic_test.c includes it after seen, CHECK and
// the server configuration it builds, which it reads.
//
// This build derives version 1's keys alone, so every value below is one
// it refuses.
#ifndef CH_SRV_QUIC_VERSION_TESTS_H
#define CH_SRV_QUIC_VERSION_TESTS_H

// Versions this build derives no keys for: 0, the two values beside
// version 1, version 2, and a version RFC 9000 §15 reserves for
// exercising version negotiation.
static const uint32_t srv_underived[] = {0, CH_QUIC_VERSION_1 + 1, CH_QUIC_VERSION_2, 0x0a0a0a0aU};
#define SRV_UNDERIVED_COUNT (sizeof srv_underived / sizeof srv_underived[0])

// ch_srv_quic_init refuses an original version this build derives no keys
// for, 0 among them, sends nothing and leaves no negotiated version.
// Version 1 starts the session, negotiated as the original.
static void test_server_init_versions(const ch_cfg *base) {
    static ch_quic q;
    ch_cfg cfg = *base;
    for (size_t i = 0; i < SRV_UNDERIVED_COUNT; i++) {
        cfg.quic_original_version = srv_underived[i];
        memset(&seen, 0, sizeof seen);
        CHECK(ch_srv_quic_init(&q, &cfg) == CH_EINVAL && ch_quic_state(&q) == CH_ST_FAILED);
        CHECK(ch_quic_negotiated_version(&q) == 0 && seen.count == 0);
    }
    cfg.quic_original_version = CH_QUIC_VERSION_1;
    CHECK(ch_srv_quic_init(&q, &cfg) == CH_OK);
    CHECK(ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_1);
#ifdef CH_ROLE_BOTH
    // A ROLE=both object declares ch_quic_switch_version, and RFC 9369
    // section 4.1 gives the switch to a client alone.
    CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_1) == CH_EINVAL);
    CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_2) == CH_EINVAL);
    CHECK(ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_1);
#endif
    ch_quic_close(&q);
}

// ch_srv_quic_retry_tag refuses a version this build derives no keys for
// and writes no tag byte. In version 1 it writes the tag a client of that
// original version validates.
static void test_retry_tag_versions(const ch_cfg *base) {
    static ch_quic q;
    uint8_t pseudo[20];
    uint8_t tag[GCM_TAG];
    uint8_t poisoned[GCM_TAG];
    memset(pseudo, 0x3c, sizeof pseudo);
    memset(poisoned, 0xa5, sizeof poisoned);
    for (size_t i = 0; i < SRV_UNDERIVED_COUNT; i++) {
        memset(tag, 0xa5, sizeof tag);
        CHECK(ch_srv_quic_retry_tag(srv_underived[i], pseudo, sizeof pseudo, tag) == CH_EINVAL);
        CHECK(memcmp(tag, poisoned, sizeof tag) == 0);
    }
    CHECK(ch_srv_quic_retry_tag(CH_QUIC_VERSION_1, pseudo, sizeof pseudo, tag) == CH_OK);
    CHECK(ch_srv_quic_init(&q, base) == CH_OK);
    CHECK(ch_quic_retry_ok(&q, CH_QUIC_VERSION_1, pseudo, sizeof pseudo, tag) == 1);
    ch_quic_close(&q);
}

#endif
