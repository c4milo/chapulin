// Proves: base64_class (base64.c) is RFC 4648 section 4's table on all
// 256 bytes, and is UB-free. It gives each of '=', CR, LF and '-' its own
// class, and every other byte BASE64_INVALID.
//
// The reference below is the alphabet as the RFC prints it, searched
// linearly. So the nine masked ranges have to agree with it on every
// byte:
//  - each of the 64 characters gives its index;
//  - the four bytes that pem.c tells apart give their classes;
//  - every other byte gives BASE64_INVALID.
// Concrete, so the search is 64 constant compares against one symbolic
// byte. The last assertion is the fact that pem.c's branches rest on:
// every class outside the alphabet is above 63.
// proof/pem_step_harness.c drives pem.c's per-character step over every
// class.
//
// It proves the same of base64url_class and RFC 4648 section 5's table,
// under CH_JWS: each of the 64 characters gives its index, and every
// other byte BASE64_INVALID, '+', '/', '=', CR and LF among them. And
// base64url_char is the table itself for every value below 64, so each
// function is the other's inverse there. base64_char is section 4's
// table the same way, and base64_class is its inverse on the 64 values.
// proof/base64_codec_harness.c drives jws.h's and scram.h's encoders and
// decoders over all four.
#include "harness.h"

#include "base64.h"

static uint32_t ref_base64_class(uint8_t c) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (uint32_t i = 0; i < 64; i++) {
        if ((uint8_t)table[i] == c) {
            return i;
        }
    }
    if (c == '=') {
        return BASE64_PAD;
    }
    if (c == '\r') {
        return BASE64_CR;
    }
    if (c == '\n') {
        return BASE64_LF;
    }
    if (c == '-') {
        return BASE64_DASH;
    }
    return BASE64_INVALID;
}

static const char url_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static uint32_t ref_base64url_class(uint8_t c) {
    for (uint32_t i = 0; i < 64; i++) {
        if ((uint8_t)url_table[i] == c) {
            return i;
        }
    }
    return BASE64_INVALID;
}

int main(void) {
    uint8_t c = nondet_u8();
    uint8_t got = base64_class(c);
    __CPROVER_assert(base64url_class(c) == ref_base64url_class(c),
                     "base64url_class is RFC 4648 section 5's table");
    uint8_t v = nondet_u8();
    __CPROVER_assume(v < 64);
    __CPROVER_assert(base64url_char(v) == (uint8_t)url_table[v],
                     "base64url_char is RFC 4648 section 5's table");
    __CPROVER_assert(base64url_class(base64url_char(v)) == v,
                     "base64url_class is base64url_char's inverse");
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    __CPROVER_assert(base64_char(v) == (uint8_t)table[v],
                     "base64_char is RFC 4648 section 4's table");
    __CPROVER_assert(base64_class(base64_char(v)) == v, "base64_class is base64_char's inverse");
    __CPROVER_assert(got == ref_base64_class(c),
                     "base64_class is RFC 4648 section 4's table and pem.c's four classes");
    __CPROVER_assert(BASE64_PAD > 63 && BASE64_CR > 63 && BASE64_LF > 63 && BASE64_DASH > 63 &&
                         BASE64_INVALID > 63,
                     "every class outside the alphabet is above 63");
    return 0;
}
