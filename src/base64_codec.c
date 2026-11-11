// RFC 4648 section 5 in constant time. Contract in base64_codec.h and
// jws.h. Outside a CH_JWS build the file holds nothing, and the header's
// includes keep the unit from being empty.
#include "base64_codec.h"

#ifdef CH_JWS

#include "base64.h"
#include "ct.h"
#include "jws.h"

// The four characters of three bytes: 24 bits, 6 at a time, the first
// byte's top bits first (RFC 4648 section 4's figure).
static void encode_group(uint8_t text[4], const uint8_t in[3]) {
    uint32_t bits = ((uint32_t)in[0] << 16) | ((uint32_t)in[1] << 8) | in[2];
    text[0] = base64url_char((uint8_t)(bits >> 18));
    text[1] = base64url_char((uint8_t)((bits >> 12) & 63U));
    text[2] = base64url_char((uint8_t)((bits >> 6) & 63U));
    text[3] = base64url_char((uint8_t)(bits & 63U));
}

// Whether a room of text_cap characters holds the text of in_len bytes.
// The text is CH_BASE64URL_LEN(in_len) characters, the least whole number
// at or above 4 * in_len / 3, so the room holds it when 3 * text_cap is
// at least 4 * in_len. The compare multiplies and divides nothing at run
// time: a division by 3 compiles to a widening multiply, which
// lint-wide-multiply counts in this file. The caller has held in_len to
// BASE64URL_IN_LEN_MAX, so 4 * in_len does not wrap, and a text_cap whose
// triple would wrap is above every such product.
static int room_holds(size_t text_cap, size_t in_len) {
    return text_cap > SIZE_MAX / 3 || 3 * text_cap >= 4 * in_len;
}

int base64url_encode(const uint8_t *in, size_t in_len, uint8_t *text, size_t text_cap,
                     size_t *text_len) {
    if (in_len > CH_BASE64URL_IN_LEN_MAX || !room_holds(text_cap, in_len)) {
        return CH_ECAP;
    }
    // Whole groups of 3 bytes, counted by subtraction for the reason
    // room_holds gives.
    size_t read = 0;
    size_t written = 0;
    while (in_len - read >= 3) {
        encode_group(text + written, in + read);
        read += 3;
        written += 4;
    }
    // The last 1 or 2 bytes fill a group with zero bits, and the text
    // keeps the 2 or 3 characters that hold a bit of them (section 3.2
    // permits text with no padding, and RFC 7515 section 2 requires it).
    size_t tail = in_len - read;
    if (tail != 0) {
        uint8_t last[3] = {in[read], 0, 0};
        if (tail == 2) {
            last[1] = in[read + 1];
        }
        uint8_t group[4];
        encode_group(group, last);
        for (size_t i = 0; i < tail + 1; i++) {
            text[written + i] = group[i];
        }
        written += tail + 1;
        ct_wipe(last, sizeof last);
        ct_wipe(group, sizeof group);
    }
    *text_len = written;
    return CH_OK;
}

// The bits of a class above 63, which no alphabet character has. The
// classes stay below 128, so the shift leaves 0 or 1.
static uint32_t refused(uint32_t character_class) {
    return character_class >> 6;
}

int base64url_decode(const uint8_t *text, size_t text_len, uint8_t *out, size_t out_cap,
                     size_t *out_len) {
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
        uint32_t a = base64url_class(text[4 * i]);
        uint32_t b = base64url_class(text[4 * i + 1]);
        uint32_t c = base64url_class(text[4 * i + 2]);
        uint32_t d = base64url_class(text[4 * i + 3]);
        bad |= refused(a) | refused(b) | refused(c) | refused(d);
        uint32_t bits = ((a & 63U) << 18) | ((b & 63U) << 12) | ((c & 63U) << 6) | (d & 63U);
        out[3 * i] = (uint8_t)(bits >> 16);
        out[3 * i + 1] = (uint8_t)(bits >> 8);
        out[3 * i + 2] = (uint8_t)bits;
    }
    if (tail != 0) {
        uint32_t a = base64url_class(text[4 * groups]);
        uint32_t b = base64url_class(text[4 * groups + 1]);
        // A group of 2 has no third character: the class of 'A', zero
        // bits, takes its place.
        uint32_t c = tail == 3 ? base64url_class(text[4 * groups + 2]) : 0;
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

#endif // CH_JWS
