// ch_jws_verify, ch_base64url_encode and ch_base64url_decode
// (docs/decisions.md 221) against tokens OpenSSL signed and Python's
// base64 module wrote (test/gen_jws_vectors.py), against the examples RFC
// 7515 and RFC 8037 print (test/gen_jws_rfc_vectors.py), and at each edge
// jws.h states: every refusal of a key, each bound of an RS256 modulus, an
// algorithm the call does not take, a changed signature or input, and
// each kind of text the decoder refuses. The binary builds as a host
// object with CH_JWS at the 512-byte bound.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "ed25519_mixed_order_vectors.h"
#include "jws.h"
#include "jws_rfc_vectors.h"
#include "jws_vectors.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures;

static void expect(int got, int want, const char *what) {
    if (got != want) {
        printf("FAIL jws: %s: got %d, want %d\n", what, got, want);
        failures++;
    }
}

#define VECTOR_COUNT (sizeof jws_vectors / sizeof jws_vectors[0])

// The room for a token's parts: the longest token here holds a 513-byte
// signature.
#define ROOM 1024

static int verify(const jws_vector *v) {
    return ch_jws_verify(v->algorithm, v->key, v->key_len, (const uint8_t *)v->token,
                         v->input_len, v->sig, v->sig_len);
}

// The first vector of an algorithm.
static const jws_vector *first_of(uint8_t algorithm) {
    for (size_t i = 0; i < VECTOR_COUNT; i++) {
        if (jws_vectors[i].algorithm == algorithm) {
            return &jws_vectors[i];
        }
    }
    abort();
}

// One token verifies as a caller checks one: the signature part decodes
// to the signer's bytes, and the signature holds over the first two
// parts. A one-bit change to the signature or to the input fails. A key
// one byte outside the bounds is refused with a signature OpenSSL
// accepted.
static void token(const jws_vector *v) {
    {
        const uint8_t *text = (const uint8_t *)v->token + v->input_len + 1;
        size_t text_len = v->token_len - v->input_len - 1;
        uint8_t sig[ROOM];
        size_t sig_len = 0;
        expect(v->token[v->input_len], '.', "the signature part follows a '.'");
        expect(ch_base64url_decode(text, text_len, sig, sizeof sig, &sig_len), CH_OK,
               "a signature part decodes");
        expect(sig_len == v->sig_len && memcmp(sig, v->sig, sig_len) == 0, 1,
               "the decoded signature is OpenSSL's");
        if (!v->in_bounds) {
            expect(verify(v), CH_EINVAL, "a modulus outside the bounds is refused");
            return;
        }
        expect(ch_jws_verify(v->algorithm, v->key, v->key_len, (const uint8_t *)v->token,
                             v->input_len, sig, sig_len),
               CH_OK, "a token verifies");
        sig[sig_len - 1] ^= 1;
        expect(ch_jws_verify(v->algorithm, v->key, v->key_len, (const uint8_t *)v->token,
                             v->input_len, sig, sig_len),
               CH_EAUTH, "a changed signature fails");
        uint8_t input[ROOM];
        memcpy(input, v->token, v->input_len);
        input[v->input_len / 2] ^= 0x01;
        expect(ch_jws_verify(v->algorithm, v->key, v->key_len, input, v->input_len, v->sig,
                             v->sig_len),
               CH_EAUTH, "a changed input fails");
        expect(ch_jws_verify(v->algorithm, v->key, v->key_len, (const uint8_t *)v->token,
                             v->input_len - 1, v->sig, v->sig_len),
               CH_EAUTH, "a shorter input fails");
        expect(ch_jws_verify(v->algorithm, v->key, v->key_len, NULL, 0, v->sig, v->sig_len),
               CH_EAUTH, "an empty input fails under a token's signature");
    }
}

// OpenSSL's tokens, and then the examples of RFC 7515 appendix A.2 and
// A.3 and RFC 8037 appendix A.4, whose keys and signatures the RFCs
// print.
static void tokens(void) {
    for (size_t i = 0; i < VECTOR_COUNT; i++) {
        token(&jws_vectors[i]);
    }
    for (size_t i = 0; i < sizeof jws_rfc_vectors / sizeof jws_rfc_vectors[0]; i++) {
        token(&jws_rfc_vectors[i]);
    }
}

// A signature of the wrong length is the token's fault, and the key's
// algorithm decides the length.
static void signature_lengths(void) {
    for (size_t i = 0; i < VECTOR_COUNT; i++) {
        const jws_vector *v = &jws_vectors[i];
        if (!v->in_bounds) {
            continue;
        }
        uint8_t sig[ROOM] = {0};
        memcpy(sig, v->sig, v->sig_len);
        expect(ch_jws_verify(v->algorithm, v->key, v->key_len, (const uint8_t *)v->token,
                             v->input_len, sig, v->sig_len - 1),
               CH_EAUTH, "a signature one byte short fails");
        expect(ch_jws_verify(v->algorithm, v->key, v->key_len, (const uint8_t *)v->token,
                             v->input_len, sig, v->sig_len + 1),
               CH_EAUTH, "a signature one byte long fails");
        expect(ch_jws_verify(v->algorithm, v->key, v->key_len, (const uint8_t *)v->token,
                             v->input_len, sig, 0),
               CH_EAUTH, "an empty signature fails");
    }
}

// The algorithm is the caller's, and a key of one algorithm is no key of
// another (RFC 8725 section 3.1).
static void algorithms(void) {
    const jws_vector *rsa = first_of(CH_JWS_RS256);
    const jws_vector *ec = first_of(CH_JWS_ES256);
    const jws_vector *ed = first_of(CH_JWS_EDDSA);
    const uint8_t *input = (const uint8_t *)ec->token;
    expect(ch_jws_verify(0, ec->key, ec->key_len, input, ec->input_len, ec->sig, ec->sig_len),
           CH_EINVAL, "algorithm 0 is refused");
    expect(ch_jws_verify(4, ec->key, ec->key_len, input, ec->input_len, ec->sig, ec->sig_len),
           CH_EINVAL, "algorithm 4 is refused");
    expect(ch_jws_verify(255, ec->key, ec->key_len, input, ec->input_len, ec->sig, ec->sig_len),
           CH_EINVAL, "algorithm 255 is refused");
    expect(ch_jws_verify(CH_JWS_ES256, rsa->key, rsa->key_len, (const uint8_t *)rsa->token,
                         rsa->input_len, rsa->sig, rsa->sig_len),
           CH_EINVAL, "an RSA key under ES256 is refused");
    expect(ch_jws_verify(CH_JWS_EDDSA, ec->key, ec->key_len, input, ec->input_len, ec->sig,
                         ec->sig_len),
           CH_EINVAL, "a P-256 key under EdDSA is refused");
    expect(ch_jws_verify(CH_JWS_ES256, ed->key, ed->key_len, (const uint8_t *)ed->token,
                         ed->input_len, ed->sig, ed->sig_len),
           CH_EINVAL, "an Ed25519 key under ES256 is refused");
    expect(ch_jws_verify(CH_JWS_RS256, ec->key, ec->key_len, input, ec->input_len, ec->sig,
                         ec->sig_len),
           CH_EINVAL, "a P-256 key under RS256 is refused");
    expect(ch_jws_verify(CH_JWS_ES256, ec->key, ec->key_len - 1, input, ec->input_len, ec->sig,
                         ec->sig_len),
           CH_EINVAL, "a P-256 key one byte short is refused");
    expect(ch_jws_verify(CH_JWS_EDDSA, ed->key, ed->key_len + 1, (const uint8_t *)ed->token,
                         ed->input_len, ed->sig, ed->sig_len),
           CH_EINVAL, "an Ed25519 key one byte long is refused");
    expect(ch_jws_verify(CH_JWS_ES256, NULL, 0, input, ec->input_len, ec->sig, ec->sig_len),
           CH_EINVAL, "an empty key is refused");
}

// EdDSA under the keys of test/gen_ed25519_mixed_order_vectors.py. Each
// signature meets RFC 8032's equation under its key, so only the refusal
// of a key outside the subgroup of prime order stops it. Row 0's key is
// in the subgroup.
static void ed25519_key_orders(void) {
    for (size_t i = 0;
         i < sizeof ed25519_mixed_order_vectors / sizeof ed25519_mixed_order_vectors[0]; i++) {
        const ed25519_mixed_order_vector *m = &ed25519_mixed_order_vectors[i];
        int rc = ch_jws_verify(CH_JWS_EDDSA, m->key, 32, (const uint8_t *)m->msg, m->msg_len,
                               m->sig, 64);
        if (m->torsion_order == 1) {
            expect(rc, CH_OK, "an Ed25519 key in the prime-order subgroup verifies");
        } else {
            expect(rc, CH_EAUTH, "an Ed25519 key outside the prime-order subgroup is refused");
        }
    }
}

// An RS256 key field with the exponent bytes given and vector 0's
// 2048-bit modulus.
static size_t rsa_field(uint8_t *out, const uint8_t *e, size_t e_len) {
    const jws_vector *v = first_of(CH_JWS_RS256);
    size_t old_e_len = v->key[0];
    size_t n_len = v->key_len - 1 - old_e_len;
    out[0] = (uint8_t)e_len;
    memcpy(out + 1, e, e_len);
    memcpy(out + 1 + e_len, v->key + 1 + old_e_len, n_len);
    return 1 + e_len + n_len;
}

static int verify_under(const uint8_t *key, size_t key_len) {
    const jws_vector *v = first_of(CH_JWS_RS256);
    return ch_jws_verify(CH_JWS_RS256, key, key_len, (const uint8_t *)v->token, v->input_len,
                         v->sig, v->sig_len);
}

// Each RS256 key the call refuses, which jws.h lists. A key it admits
// with another exponent does not verify vector 0's signature, and the
// answer is then CH_EAUTH: the call read the key and ran the check.
static void refused_rsa_keys(void) {
    const jws_vector *v = first_of(CH_JWS_RS256);
    uint8_t key[ROOM];
    static const uint8_t even[] = {0x02};
    static const uint8_t one[] = {0x01};
    static const uint8_t leading_zero[] = {0x00, 0x03};
    static const uint8_t eight[] = {0x01, 0, 0, 0, 0, 0, 0, 0x01};
    static const uint8_t nine[] = {0x01, 0, 0, 0, 0, 0, 0, 0, 0x01};
    static const uint8_t five[] = {0x05};
    expect(verify_under(key, rsa_field(key, even, sizeof even)), CH_EINVAL, "an even exponent");
    expect(verify_under(key, rsa_field(key, one, sizeof one)), CH_EINVAL, "the exponent 1");
    expect(verify_under(key, rsa_field(key, leading_zero, sizeof leading_zero)), CH_EINVAL,
           "an exponent with a leading zero byte");
    expect(verify_under(key, rsa_field(key, nine, sizeof nine)), CH_EINVAL,
           "an exponent of 9 bytes");
    expect(verify_under(key, rsa_field(key, eight, sizeof eight)), CH_EAUTH,
           "an exponent of 8 bytes is read, and is not the signer's");
    expect(verify_under(key, rsa_field(key, five, sizeof five)), CH_EAUTH,
           "the exponent 5 is read, and is not the signer's");
    expect(verify_under(key, rsa_field(key, even, 0)), CH_EINVAL, "an exponent of 0 bytes");

    // The three-byte length form of RFC 3110 section 2 names the same key.
    size_t e_len = v->key[0];
    key[0] = 0;
    key[1] = 0;
    key[2] = (uint8_t)e_len;
    memcpy(key + 3, v->key + 1, v->key_len - 1);
    expect(verify_under(key, v->key_len + 2), CH_OK, "the two-byte exponent length is read");

    // The modulus: even, with a leading zero byte, and absent.
    memcpy(key, v->key, v->key_len);
    key[v->key_len - 1] &= 0xfe;
    expect(verify_under(key, v->key_len), CH_EINVAL, "an even modulus");
    memcpy(key, v->key, v->key_len);
    key[1 + e_len] = 0;
    expect(verify_under(key, v->key_len), CH_EINVAL, "a modulus with a leading zero byte");
    expect(verify_under(v->key, 1 + e_len), CH_EINVAL, "a key with no modulus");
    expect(verify_under(v->key, 1), CH_EINVAL, "a key that ends inside the exponent");
    expect(verify_under(v->key, 0), CH_EINVAL, "an empty key");

    // A signature at or above the modulus is no signature (RFC 8017
    // section 5.2.2): the modulus itself, as the signature.
    expect(ch_jws_verify(CH_JWS_RS256, v->key, v->key_len, (const uint8_t *)v->token,
                         v->input_len, v->key + 1 + e_len, v->sig_len),
           CH_EAUTH, "a signature equal to the modulus fails");
}

typedef struct {
    const char *bytes;
    const char *text;
} base64url_pair;

// RFC 4648 section 10's vectors, without the padding, as RFC 7515
// appendix C drops it, and three values that use both of section 5's
// characters.
static const base64url_pair pairs[] = {
    {"", ""},
    {"f", "Zg"},
    {"fo", "Zm8"},
    {"foo", "Zm9v"},
    {"foob", "Zm9vYg"},
    {"fooba", "Zm9vYmE"},
    {"foobar", "Zm9vYmFy"},
    {"\xfb\xff", "-_8"},
    {"\xfb\xef\xbe", "----"},
    {"\xff\xff\xff", "____"},
};

static void base64url_vectors(void) {
    for (size_t i = 0; i < sizeof pairs / sizeof pairs[0]; i++) {
        size_t n = strlen(pairs[i].bytes);
        size_t text_len = strlen(pairs[i].text);
        uint8_t text[16];
        uint8_t bytes[16];
        size_t got = 99;
        expect((int)CH_BASE64URL_LEN(n), (int)text_len, "CH_BASE64URL_LEN");
        expect((int)CH_BASE64URL_DECODED_LEN_MAX(text_len), (int)n,
               "CH_BASE64URL_DECODED_LEN_MAX");
        expect(ch_base64url_encode((const uint8_t *)pairs[i].bytes, n, text, sizeof text, &got),
               CH_OK, "a vector encodes");
        expect(got == text_len && memcmp(text, pairs[i].text, text_len) == 0, 1,
               "the text is the vector's");
        expect(ch_base64url_decode((const uint8_t *)pairs[i].text, text_len, bytes, sizeof bytes,
                                   &got),
               CH_OK, "a vector decodes");
        expect(got == n && memcmp(bytes, pairs[i].bytes, n) == 0, 1, "the bytes are the vector's");
        // The exact room holds the value, and a room one byte short does
        // not. The call writes nothing past what it reports.
        memset(text, 0x5a, sizeof text);
        expect(ch_base64url_encode((const uint8_t *)pairs[i].bytes, n, text, text_len, &got),
               CH_OK, "the exact room holds the text");
        expect(text[text_len], 0x5a, "the encoder writes no byte past the text");
        memset(bytes, 0x5a, sizeof bytes);
        expect(ch_base64url_decode((const uint8_t *)pairs[i].text, text_len, bytes, n, &got),
               CH_OK, "the exact room holds the bytes");
        expect(bytes[n], 0x5a, "the decoder writes no byte past the bytes");
        if (n != 0) {
            memset(text, 0x5a, sizeof text);
            expect(ch_base64url_encode((const uint8_t *)pairs[i].bytes, n, text, text_len - 1,
                                       &got),
                   CH_ECAP, "a text room one byte short is refused");
            expect(text[0], 0x5a, "a refused encode writes nothing");
            memset(bytes, 0x5a, sizeof bytes);
            got = 99;
            expect(ch_base64url_decode((const uint8_t *)pairs[i].text, text_len, bytes, n - 1,
                                       &got),
                   CH_ECAP, "a byte room one byte short is refused");
            expect(bytes[0] == 0x5a && got == 0, 1, "a refused decode writes nothing");
        }
    }
    // The encoder's bound on its input: one byte past it is refused
    // before a byte is read, whatever the room. At the bound a room one
    // character short is refused the same way. The pointers are NULL, so
    // a call that read or wrote would fault.
    size_t got = 99;
    expect(ch_base64url_encode(NULL, CH_BASE64URL_IN_LEN_MAX + 1, NULL, SIZE_MAX, &got), CH_ECAP,
           "an input one byte over the bound is refused");
    expect(ch_base64url_encode(NULL, CH_BASE64URL_IN_LEN_MAX, NULL,
                               CH_BASE64URL_LEN(CH_BASE64URL_IN_LEN_MAX) - 1, &got),
           CH_ECAP, "an input at the bound is refused by a room one character short");
    expect((int)got, 99, "a refused encode reports no length");
    expect(ch_base64url_encode(NULL, 0, NULL, 0, &got), CH_OK, "no bytes encode to no text");
    expect((int)got, 0, "and the length is 0");
    got = 99;
    expect(ch_base64url_decode(NULL, 0, NULL, 0, &got), CH_OK, "no text decodes to no bytes");
    expect((int)got, 0, "and the length is 0");
}

// Every byte value encodes to text that decodes to itself, at each of the
// three positions of a group, and the encoder's alphabet is the decoder's.
static void base64url_round_trip(void) {
    uint8_t bytes[259];
    for (size_t i = 0; i < sizeof bytes; i++) {
        bytes[i] = (uint8_t)(i * 7 + 3);
    }
    for (size_t n = 0; n <= sizeof bytes; n++) {
        uint8_t text[CH_BASE64URL_LEN(sizeof bytes)];
        uint8_t back[sizeof bytes];
        size_t text_len = 0;
        size_t back_len = 0;
        expect(ch_base64url_encode(bytes, n, text, sizeof text, &text_len), CH_OK, "encode");
        expect(text_len == CH_BASE64URL_LEN(n), 1, "the text is CH_BASE64URL_LEN long");
        expect(ch_base64url_decode(text, text_len, back, sizeof back, &back_len), CH_OK, "decode");
        expect(back_len == n && memcmp(back, bytes, n) == 0, 1, "the bytes come back");
    }
}

static int decodes(const char *text) {
    uint8_t out[16];
    size_t out_len = 99;
    memset(out, 0x5a, sizeof out);
    int rc = ch_base64url_decode((const uint8_t *)text, strlen(text), out, sizeof out, &out_len);
    if (rc != CH_OK) {
        // A refusal reports no bytes, and leaves zeros where it wrote.
        expect((int)out_len, 0, "a refused text reports no bytes");
        for (size_t i = 0; i < sizeof out; i++) {
            expect(out[i] == 0 || out[i] == 0x5a, 1, "a refused text leaves no decoded byte");
        }
    }
    return rc;
}

// Each kind of text jws.h says the decoder refuses, and beside each one
// the nearest text it takes.
static void base64url_refusals(void) {
    expect(decodes("Zg"), CH_OK, "\"Zg\" is canonical");
    expect(decodes("Zh"), CH_EINVAL, "a group of 2 with a low bit set");
    expect(decodes("Zm8"), CH_OK, "\"Zm8\" is canonical");
    expect(decodes("Zm9"), CH_EINVAL, "a group of 3 with a low bit set");
    expect(decodes("Z"), CH_EINVAL, "a text of 1 character");
    expect(decodes("Zm9vY"), CH_EINVAL, "a text of 5 characters");
    expect(decodes("Zg=="), CH_EINVAL, "padding");
    expect(decodes("Zm8="), CH_EINVAL, "one '='");
    expect(decodes("+_8"), CH_EINVAL, "'+', section 4's character");
    expect(decodes("-/8"), CH_EINVAL, "'/', section 4's character");
    expect(decodes("Zm9v\n"), CH_EINVAL, "a line feed");
    expect(decodes("Zm 9v"), CH_EINVAL, "a space");
    expect(decodes("Zm9v."), CH_EINVAL, "the '.' between a token's parts");
    // Every byte outside the alphabet is refused at each position of a
    // group, and every character of the alphabet is taken there.
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (unsigned c = 0; c < 256; c++) {
        int in_alphabet = c != 0 && strchr(alphabet, (int)c) != NULL;
        for (size_t at = 0; at < 4; at++) {
            uint8_t text[4] = {'A', 'A', 'A', 'A'};
            uint8_t out[3];
            size_t out_len = 0;
            text[at] = (uint8_t)c;
            expect(ch_base64url_decode(text, sizeof text, out, sizeof out, &out_len),
                   in_alphabet ? CH_OK : CH_EINVAL, "one byte value at one position of a group");
        }
    }
}

int main(void) {
    tokens();
    signature_lengths();
    algorithms();
    ed25519_key_orders();
    refused_rsa_keys();
    base64url_vectors();
    base64url_round_trip();
    base64url_refusals();
    if (failures != 0) {
        return 1;
    }
    printf("jws: %zu OpenSSL tokens, the RFC 7515 and RFC 8037 examples, RFC 4648's vectors, "
           "and every refusal jws.h states\n",
           VECTOR_COUNT);
    return 0;
}
