// The RFC 4648 section 4 alphabet, read one character at a time in
// constant time. pem.c decodes every body through it. A PRIVATE KEY or
// EC PRIVATE KEY body is a private key in another form, so each
// character is a secret. No branch and no memory index here reads it
// (INV-16). It sits in a file of its own, so lint-wide-multiply can hold
// its count of conditional branches at zero under every compiler it
// measures. pem.c's parser branches would hide a count (docs/decisions.md
// 131).
//
// pem.c reads each body byte through base64_class alone, and it branches
// on the class, never on the byte. Every class that a body byte can have
// outside the alphabet is above 63. So each test that pem.c makes
// against one of them answers the same for all 64 alphabet characters.
// It does so whatever order of compares a compiler writes for it. A
// compare against the byte itself does not have that property. clang
// wrote pem.c's tests for '-', CR, LF and '=' as one split at 44. The
// split sent '+' (43) one way and the other 63 characters the other
// (docs/decisions.md 131).
#ifndef CH_BASE64_H
#define CH_BASE64_H

#include <stdint.h>

// The classes base64_class gives a byte outside the alphabet. Each is
// above 63, the largest value an alphabet character has.
#define BASE64_PAD 64     // '=', RFC 4648 section 3.2
#define BASE64_CR 65      // CR, which a body may hold between characters
#define BASE64_LF 66      // LF, the same
#define BASE64_DASH 67    // '-', the first byte of the END line
#define BASE64_INVALID 68 // every other byte

// The class of c. For an alphabet character it is the value in RFC 4648
// section 4's table:
//  - 'A' to 'Z' give 0 to 25, and 'a' to 'z' give 26 to 51;
//  - '0' to '9' give 52 to 61, '+' gives 62 and '/' gives 63.
// Every other byte gets one of the five classes above. The answer is a
// mask sum over nine ranges, computed the same way for every c.
uint8_t base64_class(uint8_t c);

#ifdef CH_JWS
// The class of c in RFC 4648 section 5's alphabet, base64url, which a
// JWS writes its parts in (RFC 7515 section 2). It is base64_class's
// table with '-' at 62 and '_' at 63. Every other byte gets
// BASE64_INVALID, '+', '/', '=', CR and LF among them, because a JWS part
// has no padding and no line break. The answer is a mask sum over five
// ranges, computed the same way for every c.
uint8_t base64url_class(uint8_t c);

// The character of the 6-bit value v in RFC 4648 section 5's alphabet,
// the inverse of base64url_class. Requires v below 64. The answer is a
// mask sum over five ranges, computed the same way for every v: a token's
// bytes may be secret, so no table is indexed by one (INV-16).
uint8_t base64url_char(uint8_t v);
#endif

#endif
