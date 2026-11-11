// Proves: base64url_encode and base64url_decode (base64_codec.c) are
// memory safe and free of UB over any bytes, any text and any room of up
// to the harness's bounds. And that they keep what jws.h states:
// - the encoder answers CH_OK exactly when the room holds
//   CH_BASE64URL_LEN(in_len) characters, writes that many and reports
//   that length, and a refused call writes nothing;
// - the text it writes decodes to the same bytes;
// - the decoder refuses a text whose length has the remainder 1 by 4,
//   answers CH_ECAP exactly when the room is below the decoded length,
//   and then writes nothing;
// - text it accepts is canonical: the encoder writes the same characters
//   from the bytes it decoded, so no two texts decode to one value;
// - after each refusal *out_len is 0, and after CH_EINVAL the room holds
//   zeros where the decoded bytes would be.
// - room_holds, the encoder's test of the room, is the compare
//   text_cap >= CH_BASE64URL_LEN(in_len) for every in_len of up to
//   CH_BASE64URL_IN_LEN_MAX and every text_cap, with no wrap. The encoder
//   refuses a longer in_len before it reads a byte.
//
// It proves the same of base64_encode and base64_decode and what scram.h
// states, with section 4's alphabet and its padding:
// - the encoder answers CH_OK exactly when the room holds
//   CH_BASE64_LEN(in_len) characters, and its text decodes to the same
//   bytes;
// - the decoder refuses a text whose length is no multiple of 4, and
//   never answers CH_ECAP for a room of CH_BASE64_DECODED_LEN_MAX bytes;
// - text it accepts is canonical, '=' and all: the encoder writes the
//   same characters from the bytes it decoded;
// - a refusal reports no bytes, and leaves each byte of the room as it
//   was or zero;
// - padded_room_holds is the compare text_cap >= CH_BASE64_LEN(in_len)
//   for every in_len whose CH_BASE64_LEN does not wrap and every
//   text_cap.
//
// base64.c's four character functions are real, and the base64 harness
// proves them against RFC 4648's two tables. ct_wipe is
// proof/ct_wipe_stub.c's loop, under ct.h's contract.
//
// Bounds. BYTES_MAX is 7: two whole groups and a last group of 1 byte,
// so the lengths 0 to 7 cover a text that ends with a whole group, with a
// group of 2 characters and with a group of 3. TEXT_MAX is the 10
// characters those bytes take with no padding, and PADDED_TEXT_MAX the 12
// they take with it. The loops step a group at a time, and no step reads
// the count of groups before it.
#include "harness.h"

#include "base64_codec.c"
#include "scram.h"

#define BYTES_MAX 7
#define TEXT_MAX 10
#define PADDED_TEXT_MAX 12

static void encoder(void) {
    uint8_t in[BYTES_MAX];
    uint8_t text[TEXT_MAX];
    uint8_t before[TEXT_MAX];
    fill_nondet(in, sizeof in);
    fill_nondet(text, sizeof text);
    for (size_t i = 0; i < TEXT_MAX; i++) {
        before[i] = text[i];
    }
    size_t in_len = nondet_size_t();
    size_t text_cap = nondet_size_t();
    size_t text_len = nondet_size_t();
    size_t unset = text_len;
    __CPROVER_assume(in_len <= BYTES_MAX && text_cap <= TEXT_MAX);

    int rc = base64url_encode(in, in_len, text, text_cap, &text_len);

    size_t need = CH_BASE64URL_LEN(in_len);
    __CPROVER_assert(rc == (text_cap >= need ? CH_OK : CH_ECAP),
                     "CH_OK exactly when the room holds the text");
    if (rc != CH_OK) {
        __CPROVER_assert(text_len == unset, "a refused encode reports nothing");
        for (size_t i = 0; i < TEXT_MAX; i++) {
            __CPROVER_assert(text[i] == before[i], "a refused encode writes nothing");
        }
        return;
    }
    __CPROVER_assert(text_len == need, "the text is CH_BASE64URL_LEN(in_len) characters");
    for (size_t i = need; i < TEXT_MAX; i++) {
        __CPROVER_assert(text[i] == before[i], "no byte past the text is written");
    }
    uint8_t out[BYTES_MAX];
    size_t out_len = nondet_size_t();
    int back = base64url_decode(text, text_len, out, sizeof out, &out_len);
    __CPROVER_assert(back == CH_OK && out_len == in_len, "the text decodes to as many bytes");
    for (size_t i = 0; i < in_len; i++) {
        __CPROVER_assert(out[i] == in[i], "the text decodes to the same bytes");
    }
}

static void decoder(void) {
    uint8_t text[TEXT_MAX];
    uint8_t out[BYTES_MAX];
    uint8_t before[BYTES_MAX];
    fill_nondet(text, sizeof text);
    fill_nondet(out, sizeof out);
    for (size_t i = 0; i < BYTES_MAX; i++) {
        before[i] = out[i];
    }
    size_t text_len = nondet_size_t();
    size_t out_cap = nondet_size_t();
    size_t out_len = nondet_size_t();
    __CPROVER_assume(text_len <= TEXT_MAX && out_cap <= BYTES_MAX);

    int rc = base64url_decode(text, text_len, out, out_cap, &out_len);

    size_t need = CH_BASE64URL_DECODED_LEN_MAX(text_len);
    __CPROVER_assert(rc == CH_OK || rc == CH_ECAP || rc == CH_EINVAL, "one of its three codes");
    if (text_len % 4 == 1) {
        __CPROVER_assert(rc == CH_EINVAL, "a last group of 1 character is refused");
    } else {
        __CPROVER_assert((rc == CH_ECAP) == (out_cap < need),
                         "CH_ECAP exactly when the room is below the decoded length");
    }
    if (rc != CH_OK) {
        __CPROVER_assert(out_len == 0, "a refusal reports no bytes");
    }
    if (rc == CH_ECAP || text_len % 4 == 1) {
        for (size_t i = 0; i < BYTES_MAX; i++) {
            __CPROVER_assert(out[i] == before[i],
                             "a refusal before the text is read writes nothing");
        }
        return;
    }
    for (size_t i = need; i < BYTES_MAX; i++) {
        __CPROVER_assert(out[i] == before[i], "no byte past the decoded length is written");
    }
    if (rc == CH_EINVAL) {
        for (size_t i = 0; i < need; i++) {
            __CPROVER_assert(out[i] == 0, "a refused text leaves zeros");
        }
        return;
    }
    __CPROVER_assert(out_len == need, "the decoded length is CH_BASE64URL_DECODED_LEN_MAX");
    uint8_t again[TEXT_MAX];
    size_t again_len = nondet_size_t();
    int back = base64url_encode(out, out_len, again, sizeof again, &again_len);
    __CPROVER_assert(back == CH_OK && again_len == text_len,
                     "the bytes encode to as many characters");
    for (size_t i = 0; i < text_len; i++) {
        __CPROVER_assert(again[i] == text[i], "accepted text is the one text of its bytes");
    }
}

// The test of the room, over every length the encoder takes: no product
// wraps, and the answer is the compare jws.h states.
static void room(void) {
    size_t in_len = nondet_size_t();
    size_t text_cap = nondet_size_t();
    __CPROVER_assume(in_len <= CH_BASE64URL_IN_LEN_MAX);
    __CPROVER_assert(room_holds(text_cap, in_len) == (text_cap >= CH_BASE64URL_LEN(in_len)),
                     "room_holds is text_cap >= CH_BASE64URL_LEN(in_len)");
}

// A length above the bound is refused before a byte is read: the pointers
// are NULL, so a read or a write here fails the proof.
static void too_long(void) {
    size_t in_len = nondet_size_t();
    size_t text_cap = nondet_size_t();
    size_t text_len = 0;
    __CPROVER_assume(in_len > CH_BASE64URL_IN_LEN_MAX);
    __CPROVER_assert(base64url_encode(NULL, in_len, NULL, text_cap, &text_len) == CH_ECAP,
                     "a length above CH_BASE64URL_IN_LEN_MAX is refused");
}

static void padded_encoder(void) {
    uint8_t in[BYTES_MAX];
    uint8_t text[PADDED_TEXT_MAX];
    uint8_t before[PADDED_TEXT_MAX];
    fill_nondet(in, sizeof in);
    fill_nondet(text, sizeof text);
    for (size_t i = 0; i < PADDED_TEXT_MAX; i++) {
        before[i] = text[i];
    }
    size_t in_len = nondet_size_t();
    size_t text_cap = nondet_size_t();
    size_t text_len = nondet_size_t();
    size_t unset = text_len;
    __CPROVER_assume(in_len <= BYTES_MAX && text_cap <= PADDED_TEXT_MAX);

    int rc = base64_encode(in, in_len, text, text_cap, &text_len);

    size_t need = CH_BASE64_LEN(in_len);
    __CPROVER_assert(rc == (text_cap >= need ? CH_OK : CH_ECAP),
                     "CH_OK exactly when the room holds the padded text");
    if (rc != CH_OK) {
        __CPROVER_assert(text_len == unset, "a refused encode reports nothing");
        for (size_t i = 0; i < PADDED_TEXT_MAX; i++) {
            __CPROVER_assert(text[i] == before[i], "a refused encode writes nothing");
        }
        return;
    }
    __CPROVER_assert(text_len == need, "the text is CH_BASE64_LEN(in_len) characters");
    for (size_t i = need; i < PADDED_TEXT_MAX; i++) {
        __CPROVER_assert(text[i] == before[i], "no byte past the text is written");
    }
    uint8_t out[BYTES_MAX];
    size_t out_len = nondet_size_t();
    int back = base64_decode(text, text_len, out, sizeof out, &out_len);
    __CPROVER_assert(back == CH_OK && out_len == in_len, "the text decodes to as many bytes");
    for (size_t i = 0; i < in_len; i++) {
        __CPROVER_assert(out[i] == in[i], "the text decodes to the same bytes");
    }
}

static void padded_decoder(void) {
    uint8_t text[PADDED_TEXT_MAX];
    uint8_t out[BYTES_MAX + 2];
    uint8_t before[BYTES_MAX + 2];
    fill_nondet(text, sizeof text);
    fill_nondet(out, sizeof out);
    for (size_t i = 0; i < sizeof out; i++) {
        before[i] = out[i];
    }
    size_t text_len = nondet_size_t();
    size_t out_cap = nondet_size_t();
    size_t out_len = nondet_size_t();
    __CPROVER_assume(text_len <= PADDED_TEXT_MAX && out_cap <= sizeof out);

    int rc = base64_decode(text, text_len, out, out_cap, &out_len);

    __CPROVER_assert(rc == CH_OK || rc == CH_ECAP || rc == CH_EINVAL, "one of its three codes");
    if (text_len % 4 != 0) {
        __CPROVER_assert(rc == CH_EINVAL, "a length that is no multiple of 4 is refused");
    }
    if (out_cap >= CH_BASE64_DECODED_LEN_MAX(text_len)) {
        __CPROVER_assert(rc != CH_ECAP, "a room of CH_BASE64_DECODED_LEN_MAX bytes is enough");
    }
    if (rc != CH_OK) {
        __CPROVER_assert(out_len == 0, "a refusal reports no bytes");
        for (size_t i = 0; i < sizeof out; i++) {
            __CPROVER_assert(out[i] == before[i] || out[i] == 0,
                             "a refusal leaves each byte as it was or zero");
        }
        return;
    }
    __CPROVER_assert(out_len <= out_cap, "the bytes fit the room");
    for (size_t i = out_len; i < sizeof out; i++) {
        __CPROVER_assert(out[i] == before[i], "no byte past the decoded length is written");
    }
    uint8_t again[PADDED_TEXT_MAX];
    size_t again_len = nondet_size_t();
    int back = base64_encode(out, out_len, again, sizeof again, &again_len);
    __CPROVER_assert(back == CH_OK && again_len == text_len,
                     "the bytes encode to as many characters");
    for (size_t i = 0; i < text_len; i++) {
        __CPROVER_assert(again[i] == text[i], "accepted text is the one text of its bytes");
    }
}

// The padded encoder's test of the room, over every length whose text
// length a size_t counts: the answer is the compare scram.h states.
static void padded_room(void) {
    size_t in_len = nondet_size_t();
    size_t text_cap = nondet_size_t();
    __CPROVER_assume(in_len <= SIZE_MAX - 2 && (in_len + 2) / 3 <= SIZE_MAX / 4);
    __CPROVER_assert(padded_room_holds(text_cap, in_len) == (text_cap >= CH_BASE64_LEN(in_len)),
                     "padded_room_holds is text_cap >= CH_BASE64_LEN(in_len)");
}

int main(void) {
    uint8_t part = nondet_u8();
    if (part == 0) {
        encoder();
    } else if (part == 1) {
        decoder();
    } else if (part == 2) {
        room();
    } else if (part == 3) {
        too_long();
    } else if (part == 4) {
        padded_encoder();
    } else if (part == 5) {
        padded_decoder();
    } else {
        padded_room();
    }
    return 0;
}
