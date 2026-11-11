// RFC 4648 sections 4 and 5 in constant time. Contract in base64_codec.h,
// jws.h and scram.h. Outside a CH_JWS or CH_SCRAM build the file holds
// nothing, and the header's includes keep the unit from being empty.
//
// The two alphabets share every loop. Each loop takes which alphabet it
// runs as an argument, a public value that its caller fixes, and asks
// base64.c for a character or a class through one of the two functions
// below.
#include "base64_codec.h"

#include "base64.h"

#ifdef CH_BASE64_TEXT

#include "ct.h"
#include "result.h"

// The two alphabets: section 4's, with '+' and '/', and section 5's,
// with '-' and '_'.
#define STANDARD 0
#define URL 1

static uint8_t character_of(int alphabet, uint8_t value) {
    return alphabet == URL ? base64url_char(value) : base64_char(value);
}

static uint32_t class_of(int alphabet, uint8_t character) {
    return alphabet == URL ? base64url_class(character) : base64_class(character);
}

// The four characters of three bytes: 24 bits, 6 at a time, the first
// byte's top bits first (RFC 4648 section 4's figure).
static void encode_group(int alphabet, uint8_t text[4], const uint8_t in[3]) {
    uint32_t bits = ((uint32_t)in[0] << 16) | ((uint32_t)in[1] << 8) | in[2];
    text[0] = character_of(alphabet, (uint8_t)(bits >> 18));
    text[1] = character_of(alphabet, (uint8_t)((bits >> 12) & 63U));
    text[2] = character_of(alphabet, (uint8_t)((bits >> 6) & 63U));
    text[3] = character_of(alphabet, (uint8_t)(bits & 63U));
}

// Writes the text of in_len bytes with no padding, and returns its
// length. The caller has held the room to that length.
static size_t encode_text(int alphabet, const uint8_t *in, size_t in_len, uint8_t *text) {
    // Whole groups of 3 bytes, counted by subtraction. A division by 3
    // compiles to a widening multiply, which lint-wide-multiply counts in
    // this file.
    size_t read = 0;
    size_t written = 0;
    while (in_len - read >= 3) {
        encode_group(alphabet, text + written, in + read);
        read += 3;
        written += 4;
    }
    // The last 1 or 2 bytes fill a group with zero bits, and the text
    // keeps the 2 or 3 characters that hold a bit of them.
    size_t tail = in_len - read;
    if (tail != 0) {
        uint8_t last[3] = {in[read], 0, 0};
        if (tail == 2) {
            last[1] = in[read + 1];
        }
        uint8_t group[4];
        encode_group(alphabet, group, last);
        for (size_t i = 0; i < tail + 1; i++) {
            text[written + i] = group[i];
        }
        written += tail + 1;
        ct_wipe(last, sizeof last);
        ct_wipe(group, sizeof group);
    }
    return written;
}

// The bits of a class above 63, which no alphabet character has. The
// classes stay below 128, so the shift leaves 0 or 1.
static uint32_t refused(uint32_t character_class) {
    return character_class >> 6;
}

// Decodes text_len characters that carry no padding: whole groups of 4,
// and a last group of 2 or 3. jws.h's and scram.h's decoders state the
// contract, and each passes its alphabet.
static int decode_text(int alphabet, const uint8_t *text, size_t text_len, uint8_t *out,
                       size_t out_cap, size_t *out_len) {
    *out_len = 0;
    size_t groups = text_len / 4;
    size_t tail = text_len % 4;
    // One character holds 6 bits, less than a byte, so no text ends with
    // a group of one.
    if (tail == 1) {
        return CH_EINVAL;
    }
    // A last group of 2 characters holds 1 byte, and of 3 holds 2.
    size_t tail_bytes = tail == 0 ? 0 : tail - 1;
    size_t need = 3 * groups + tail_bytes;
    if (out_cap < need) {
        return CH_ECAP;
    }
    uint32_t bad = 0;
    for (size_t i = 0; i < groups; i++) {
        uint32_t a = class_of(alphabet, text[4 * i]);
        uint32_t b = class_of(alphabet, text[4 * i + 1]);
        uint32_t c = class_of(alphabet, text[4 * i + 2]);
        uint32_t d = class_of(alphabet, text[4 * i + 3]);
        bad |= refused(a) | refused(b) | refused(c) | refused(d);
        uint32_t bits = ((a & 63U) << 18) | ((b & 63U) << 12) | ((c & 63U) << 6) | (d & 63U);
        out[3 * i] = (uint8_t)(bits >> 16);
        out[3 * i + 1] = (uint8_t)(bits >> 8);
        out[3 * i + 2] = (uint8_t)bits;
    }
    if (tail != 0) {
        uint32_t a = class_of(alphabet, text[4 * groups]);
        uint32_t b = class_of(alphabet, text[4 * groups + 1]);
        // A group of 2 has no third character: the class of 'A', zero
        // bits, takes its place.
        uint32_t c = tail == 3 ? class_of(alphabet, text[4 * groups + 2]) : 0;
        bad |= refused(a) | refused(b) | refused(c);
        uint32_t bits = ((a & 63U) << 18) | ((b & 63U) << 12) | ((c & 63U) << 6);
        out[3 * groups] = (uint8_t)(bits >> 16);
        if (tail == 3) {
            out[3 * groups + 1] = (uint8_t)(bits >> 8);
        }
        // The bits the last group holds past its bytes are zero in
        // canonical text (section 3.5): 4 bits of a group of 2, and 2 of a
        // group of 3. Text that sets one would be a second spelling of
        // the same bytes.
        bad |= tail == 3 ? (bits & 0xffU) : (bits & 0xffffU);
    }
    // The one branch on the characters: whether the call refused any,
    // which its result code tells the caller.
    CT_DECLASSIFY(&bad, sizeof bad);
    if (bad != 0) {
        ct_wipe(out, need);
        return CH_EINVAL;
    }
    *out_len = need;
    return CH_OK;
}

#ifdef CH_JWS

#include "jws.h"

// Whether a room of text_cap characters holds the text of in_len bytes.
// The text is CH_BASE64URL_LEN(in_len) characters, the least whole number
// at or above 4 * in_len / 3, so the room holds it when 3 * text_cap is
// at least 4 * in_len. The compare divides by 3 nowhere, for the reason
// encode_text gives. The caller has held in_len to
// CH_BASE64URL_IN_LEN_MAX, so 4 * in_len does not wrap, and a text_cap
// whose triple would wrap is above every such product.
static int room_holds(size_t text_cap, size_t in_len) {
    return text_cap > SIZE_MAX / 3 || 3 * text_cap >= 4 * in_len;
}

int base64url_encode(const uint8_t *in, size_t in_len, uint8_t *text, size_t text_cap,
                     size_t *text_len) {
    if (in_len > CH_BASE64URL_IN_LEN_MAX || !room_holds(text_cap, in_len)) {
        return CH_ECAP;
    }
    // Section 3.2 permits text with no padding, and RFC 7515 section 2
    // requires it.
    *text_len = encode_text(URL, in, in_len, text);
    return CH_OK;
}

int base64url_decode(const uint8_t *text, size_t text_len, uint8_t *out, size_t out_cap,
                     size_t *out_len) {
    return decode_text(URL, text, text_len, out, out_cap, out_len);
}

#endif // CH_JWS

#ifdef CH_SCRAM

// Whether a room of text_cap characters holds the padded text of in_len
// bytes. The text is 4 characters for each 3 bytes or part of 3, so a
// room of text_cap characters holds text_cap / 4 groups, which take up
// to 3 * (text_cap / 4) bytes. The division by 4 is a shift, the product
// does not wrap, and nothing divides by 3.
static int padded_room_holds(size_t text_cap, size_t in_len) {
    return in_len <= 3 * (text_cap / 4);
}

int base64_encode(const uint8_t *in, size_t in_len, uint8_t *text, size_t text_cap,
                  size_t *text_len) {
    if (!padded_room_holds(text_cap, in_len)) {
        return CH_ECAP;
    }
    size_t written = encode_text(STANDARD, in, in_len, text);
    // '=' fills the last group to 4 characters (section 3.2).
    while (written % 4 != 0) {
        text[written] = '=';
        written++;
    }
    *text_len = written;
    return CH_OK;
}

// 1 when a equals b, and 0 when it does not, for values below 2^31. The
// difference is 0 only for equal values, and 0 less 1 wraps to all ones,
// whose top bit the shift keeps.
static uint32_t equal_bit(uint32_t a, uint32_t b) {
    return ((a ^ b) - 1U) >> 31;
}

int base64_decode(const uint8_t *text, size_t text_len, uint8_t *out, size_t out_cap,
                  size_t *out_len) {
    *out_len = 0;
    if (text_len % 4 != 0) {
        return CH_EINVAL;
    }
    if (text_len == 0) {
        return CH_OK;
    }
    // The count of '=' at the end, 0, 1 or 2, from the classes of the
    // last two characters. A '=' before a last character that is not one
    // counts as no padding: decode_text then meets it as a character
    // outside the alphabet and refuses the text, as it refuses a '='
    // anywhere before these two.
    uint32_t last_is_pad = equal_bit(base64_class(text[text_len - 1]), BASE64_PAD);
    uint32_t before_is_pad = equal_bit(base64_class(text[text_len - 2]), BASE64_PAD);
    size_t pads = last_is_pad + (last_is_pad & before_is_pad);
    // The count is the text's length less what it decodes to, which the
    // caller sees.
    CT_DECLASSIFY(&pads, sizeof pads);
    // What is left is unpadded text whose last group has 2 or 3
    // characters, or none.
    return decode_text(STANDARD, text, text_len - pads, out, out_cap, out_len);
}

#endif // CH_SCRAM

#endif // CH_BASE64_TEXT
