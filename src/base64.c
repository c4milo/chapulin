// The RFC 4648 section 4 alphabet in constant time. Contract in base64.h.
#include "base64.h"

// All ones when lo <= c <= hi, and zero otherwise. c is a byte widened to
// 32 bits. So a difference that goes below zero wraps past 2^31, and its
// top bit says so. The shift reads a sign, not a byte of c. The
// subtraction turns 0 into all ones and 1 into zero.
static uint32_t range_mask(uint32_t c, uint32_t lo, uint32_t hi) {
    uint32_t outside = ((c - lo) | (hi - c)) >> 31;
    return outside - 1U;
}

// A 256-byte lookup table would be a memory index on the character,
// which INV-16 forbids for a key's characters. The range compares as
// branches would be a branch on one. So each range gives a mask, and the
// class is the sum of each range's class under its mask. At most one
// mask is all ones, so the ORs never mix two ranges.
uint8_t base64_class(uint8_t c) {
    uint32_t x = c;
    uint32_t upper = range_mask(x, 'A', 'Z');
    uint32_t lower = range_mask(x, 'a', 'z');
    uint32_t digit = range_mask(x, '0', '9');
    uint32_t plus = range_mask(x, '+', '+');
    uint32_t slash = range_mask(x, '/', '/');
    uint32_t pad = range_mask(x, '=', '=');
    uint32_t cr = range_mask(x, '\r', '\r');
    uint32_t lf = range_mask(x, '\n', '\n');
    uint32_t dash = range_mask(x, '-', '-');
    uint32_t value = (upper & (x - 'A')) | (lower & (x - 'a' + 26U)) | (digit & (x - '0' + 52U)) |
                     (plus & 62U) | (slash & 63U);
    uint32_t other =
        (pad & BASE64_PAD) | (cr & BASE64_CR) | (lf & BASE64_LF) | (dash & BASE64_DASH);
    uint32_t known = upper | lower | digit | plus | slash | pad | cr | lf | dash;
    uint32_t invalid = ~known & BASE64_INVALID;
    return (uint8_t)(value | other | invalid);
}

#ifdef CH_JWS
// base64_class's sum with section 5's two characters. A byte outside the
// five ranges has no mask, so it gets BASE64_INVALID alone.
uint8_t base64url_class(uint8_t c) {
    uint32_t x = c;
    uint32_t upper = range_mask(x, 'A', 'Z');
    uint32_t lower = range_mask(x, 'a', 'z');
    uint32_t digit = range_mask(x, '0', '9');
    uint32_t minus = range_mask(x, '-', '-');
    uint32_t underscore = range_mask(x, '_', '_');
    uint32_t value = (upper & (x - 'A')) | (lower & (x - 'a' + 26U)) | (digit & (x - '0' + 52U)) |
                     (minus & 62U) | (underscore & 63U);
    uint32_t known = upper | lower | digit | minus | underscore;
    uint32_t invalid = ~known & BASE64_INVALID;
    return (uint8_t)(value | invalid);
}

// The same five ranges over the value. Exactly one mask is all ones for a
// v below 64, so the ORs never mix two ranges.
uint8_t base64url_char(uint8_t v) {
    uint32_t x = v;
    uint32_t upper = range_mask(x, 0, 25);
    uint32_t lower = range_mask(x, 26, 51);
    uint32_t digit = range_mask(x, 52, 61);
    uint32_t minus = range_mask(x, 62, 62);
    uint32_t underscore = range_mask(x, 63, 63);
    return (uint8_t)((upper & (x + 'A')) | (lower & (x - 26U + 'a')) | (digit & (x - 52U + '0')) |
                     (minus & '-') | (underscore & '_'));
}
#endif
