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
