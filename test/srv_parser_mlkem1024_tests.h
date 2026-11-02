// The ML-KEM-1024 share (draft-ietf-tls-mlkem, docs/decisions.md 179):
// the MLKEM_EK_LEN_1024-byte encapsulation key every server outside
// PROFILE=cnsa2 parses beside its other three groups. It continues
// test/srv_parser_tests.h, whose fixtures and golden hello it reads.
#ifndef CH_SRV_PARSER_MLKEM1024_TESTS_H
#define CH_SRV_PARSER_MLKEM1024_TESTS_H

#include "srv_parser_hello.h"
#include "srv_parser_tests.h"

// The golden hello with its supported_groups listing ML-KEM-1024 and
// then x25519, and the key_share given.
static size_t mlkem1024_hello(uint8_t *dst, const uint8_t *key_share, size_t n) {
    static const uint8_t groups[] = {0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x02, 0x02, 0x00, 0x1d};
    extension exts[GOLDEN_EXT_COUNT];
    for (size_t i = 0; i < GOLDEN_EXT_COUNT; i++) {
        exts[i] = golden_exts[i];
    }
    exts[AT_GROUPS] = (extension){groups, sizeof groups};
    exts[AT_KEY_SHARE] = (extension){key_share, n};
    return assemble(dst, hello_head, sizeof hello_head, exts, GOLDEN_EXT_COUNT);
}

// The exact length is taken, pointing into the message, and one byte
// either side is illegal_parameter, as for every other group.
static void test_mlkem1024_key_share(void) {
    uint8_t buf[HELLO_CAP];
    uint8_t ext[HELLO_CAP];
    size_t m = make_key_share(ext, CH_GROUP_MLKEM1024, MLKEM_EK_LEN_1024);
    size_t n = mlkem1024_hello(buf, ext, m);
    CHECK(parse(buf, n) == CH_OK);
    CHECK(parsed.groups == (SRV_GROUP_MLKEM1024 | SRV_GROUP_X25519));
    CHECK(parsed.shares == SRV_GROUP_MLKEM1024 && parsed.x25519_share == NULL);
    CHECK(inside(buf, n, parsed.mlkem_share, MLKEM_EK_LEN_1024));
    m = make_key_share(ext, CH_GROUP_MLKEM1024, MLKEM_EK_LEN_1024 - 1);
    n = mlkem1024_hello(buf, ext, m);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));
    m = make_key_share(ext, CH_GROUP_MLKEM1024, MLKEM_EK_LEN_1024 + 1);
    n = mlkem1024_hello(buf, ext, m);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));
    // An ML-KEM-1024 share when supported_groups does not list it (§4.3.8).
    m = make_key_share(ext, CH_GROUP_MLKEM1024, MLKEM_EK_LEN_1024);
    n = replaced(buf, AT_KEY_SHARE, ext, m);
    CHECK(refused(buf, n, ALERT_ILLEGAL_PARAMETER));
    // Listed with x25519 shared alone: the bit is in groups and not in
    // shares, the input srv_select answers with a retry.
    n = mlkem1024_hello(buf, ext_key_share, sizeof ext_key_share);
    CHECK(parse(buf, n) == CH_OK);
    CHECK(parsed.shares == SRV_GROUP_X25519 && parsed.mlkem_share == NULL);
}

#endif
