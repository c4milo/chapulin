// scram.h's calls (docs/decisions.md 222) against the vectors
// test/gen_scram_vectors.py reads out of RFC 4231, RFC 7914 and RFC 7677
// and checks with Python, against certificates OpenSSL minted, and at
// each edge scram.h states. The SCRAM-SHA-256 exchange of RFC 7677
// section 3 is computed here from the password with the calls alone, as
// a client and as a server compute it. The binary builds as a host
// object with CH_SCRAM.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "scram.h"
#include "scram_vectors.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures;

static void expect(int got, int want, const char *what) {
    if (got != want) {
        printf("FAIL scram: %s: got %d, want %d\n", what, got, want);
        failures++;
    }
}

#define COUNT(a) (sizeof(a) / sizeof(a)[0])

static void sha256_vectors_hold(void) {
    for (size_t i = 0; i < COUNT(sha256_vectors); i++) {
        uint8_t digest[CH_SHA256_LEN];
        ch_sha256(sha256_vectors[i].message, sha256_vectors[i].message_len, digest);
        expect(memcmp(digest, sha256_vectors[i].digest, sizeof digest), 0, "a SHA-256 vector");
    }
    uint8_t digest[CH_SHA256_LEN];
    ch_sha256(NULL, 0, digest);
    expect(memcmp(digest, sha256_vectors[0].digest, sizeof digest), 0,
           "SHA-256 of no bytes, from a NULL pointer");
}

static void hmac_vectors_hold(void) {
    for (size_t i = 0; i < COUNT(hmac_vectors); i++) {
        uint8_t tag[CH_SHA256_LEN];
        ch_hmac_sha256(hmac_vectors[i].key, hmac_vectors[i].key_len, hmac_vectors[i].data,
                       hmac_vectors[i].data_len, tag);
        expect(memcmp(tag, hmac_vectors[i].tag, hmac_vectors[i].tag_len), 0,
               "an HMAC-SHA-256 vector");
    }
    // The last row is the empty key and the empty message, which a caller
    // may pass as NULL.
    uint8_t tag[CH_SHA256_LEN];
    ch_hmac_sha256(NULL, 0, NULL, 0, tag);
    expect(memcmp(tag, hmac_vectors[COUNT(hmac_vectors) - 1].tag, sizeof tag), 0,
           "HMAC of an empty key and an empty message, from NULL pointers");
}

static void pbkdf2_vectors_hold(void) {
    for (size_t i = 0; i < COUNT(pbkdf2_vectors); i++) {
        uint8_t key[64];
        memset(key, 0x5a, sizeof key);
        expect(ch_pbkdf2_hmac_sha256(pbkdf2_vectors[i].password, pbkdf2_vectors[i].password_len,
                                     pbkdf2_vectors[i].salt, pbkdf2_vectors[i].salt_len,
                                     pbkdf2_vectors[i].iteration_count, key,
                                     pbkdf2_vectors[i].key_len),
               CH_OK, "a PBKDF2 vector runs");
        expect(memcmp(key, pbkdf2_vectors[i].key, pbkdf2_vectors[i].key_len), 0, "a PBKDF2 vector");
    }
    // A shorter output is the longer one's first bytes, at each length
    // around a block's end, and the call writes no byte past it.
    static const size_t lengths[] = {1, 31, 32, 33, 63, 64};
    for (size_t i = 0; i < COUNT(lengths); i++) {
        uint8_t key[65];
        memset(key, 0x5a, sizeof key);
        expect(ch_pbkdf2_hmac_sha256(pbkdf2_vectors[0].password, pbkdf2_vectors[0].password_len,
                                     pbkdf2_vectors[0].salt, pbkdf2_vectors[0].salt_len, 1, key,
                                     lengths[i]),
               CH_OK, "a shorter output runs");
        expect(memcmp(key, pbkdf2_vectors[0].key, lengths[i]), 0, "a shorter output is a prefix");
        expect(key[lengths[i]], 0x5a, "PBKDF2 writes no byte past its output");
    }
}

// The refusals, each with an output room it must leave as it was, and
// the bound on the output: the longest output runs, and one byte more is
// refused.
static void pbkdf2_bounds_hold(void) {
    uint8_t key[32];
    memset(key, 0x5a, sizeof key);
    const uint8_t *password = pbkdf2_vectors[0].password;
    size_t password_len = pbkdf2_vectors[0].password_len;
    const uint8_t *salt = pbkdf2_vectors[0].salt;
    size_t salt_len = pbkdf2_vectors[0].salt_len;
    expect(ch_pbkdf2_hmac_sha256(password, password_len, salt, salt_len, 0, key, sizeof key),
           CH_EINVAL, "an iteration count of 0 is refused");
    expect(ch_pbkdf2_hmac_sha256(password, password_len, salt, salt_len, 1, key, 0), CH_EINVAL,
           "an output of 0 bytes is refused");
    expect(ch_pbkdf2_hmac_sha256(password, password_len, salt, salt_len, 1, NULL,
                                 CH_PBKDF2_OUT_LEN_MAX + 1),
           CH_EINVAL, "an output one byte over the bound is refused");
    for (size_t i = 0; i < sizeof key; i++) {
        expect(key[i], 0x5a, "a refused call writes nothing");
    }
    expect(ch_pbkdf2_hmac_sha256(NULL, 0, NULL, 0, 1, key, sizeof key), CH_OK,
           "an empty password and an empty salt run, from NULL pointers");
    uint8_t *longest = malloc(CH_PBKDF2_OUT_LEN_MAX);
    if (longest == NULL) {
        abort();
    }
    expect(ch_pbkdf2_hmac_sha256(password, password_len, salt, salt_len, 1, longest,
                                 CH_PBKDF2_OUT_LEN_MAX),
           CH_OK, "the longest output runs");
    uint8_t digest[CH_SHA256_LEN];
    ch_sha256(longest, CH_PBKDF2_OUT_LEN_MAX, digest);
    expect(memcmp(digest, pbkdf2_longest_digest, sizeof digest), 0,
           "the longest output is Python's, to its last block");
    free(longest);
}

// RFC 5802 section 3, over RFC 7677 section 3's messages. The client
// computes its proof from the password. The server holds StoredKey and
// ServerKey alone, and checks the proof with them.
static void scram_exchange_holds(void) {
    uint8_t salt[32];
    size_t salt_len = 0;
    expect(ch_base64_decode((const uint8_t *)scram_salt, strlen(scram_salt), salt, sizeof salt,
                            &salt_len),
           CH_OK, "the salt decodes");
    uint8_t salted_password[CH_SHA256_LEN];
    expect(ch_pbkdf2_hmac_sha256((const uint8_t *)scram_password, strlen(scram_password), salt,
                                 salt_len, SCRAM_ITERATION_COUNT, salted_password,
                                 sizeof salted_password),
           CH_OK, "Hi() runs");
    uint8_t client_key[CH_SHA256_LEN];
    uint8_t stored_key[CH_SHA256_LEN];
    uint8_t server_key[CH_SHA256_LEN];
    ch_hmac_sha256(salted_password, sizeof salted_password, (const uint8_t *)"Client Key", 10,
                   client_key);
    ch_sha256(client_key, sizeof client_key, stored_key);
    ch_hmac_sha256(salted_password, sizeof salted_password, (const uint8_t *)"Server Key", 10,
                   server_key);

    char auth_message[512];
    int auth_len = snprintf(auth_message, sizeof auth_message, "%s,%s,%s", scram_client_first_bare,
                            scram_server_first, scram_client_final_without_proof);
    uint8_t client_signature[CH_SHA256_LEN];
    uint8_t proof[CH_SHA256_LEN];
    ch_hmac_sha256(stored_key, sizeof stored_key, (const uint8_t *)auth_message, (size_t)auth_len,
                   client_signature);
    for (size_t i = 0; i < sizeof proof; i++) {
        proof[i] = client_key[i] ^ client_signature[i];
    }
    uint8_t text[CH_BASE64_LEN(CH_SHA256_LEN)];
    size_t text_len = 0;
    expect(ch_base64_encode(proof, sizeof proof, text, sizeof text, &text_len), CH_OK,
           "the proof encodes");
    expect(text_len == strlen(scram_proof) && memcmp(text, scram_proof, text_len) == 0, 1,
           "the ClientProof is the RFC's");

    uint8_t server_signature[CH_SHA256_LEN];
    ch_hmac_sha256(server_key, sizeof server_key, (const uint8_t *)auth_message, (size_t)auth_len,
                   server_signature);
    expect(ch_base64_encode(server_signature, sizeof server_signature, text, sizeof text,
                            &text_len),
           CH_OK, "the signature encodes");
    expect(text_len == strlen(scram_signature) && memcmp(text, scram_signature, text_len) == 0, 1,
           "the ServerSignature is the RFC's");

    // The server's check: the proof it received gives a ClientKey whose
    // hash is the StoredKey it holds. A proof with one bit changed does
    // not.
    uint8_t received[CH_SHA256_LEN];
    size_t received_len = 0;
    expect(ch_base64_decode((const uint8_t *)scram_proof, strlen(scram_proof), received,
                            sizeof received, &received_len),
           CH_OK, "the received proof decodes");
    expect((int)received_len, CH_SHA256_LEN, "the proof is 32 bytes");
    for (int changed = 0; changed < 2; changed++) {
        uint8_t key[CH_SHA256_LEN];
        uint8_t hash[CH_SHA256_LEN];
        received[7] ^= (uint8_t)changed;
        for (size_t i = 0; i < sizeof key; i++) {
            key[i] = received[i] ^ client_signature[i];
        }
        ch_sha256(key, sizeof key, hash);
        expect(ch_ct_compare(hash, stored_key, sizeof hash), changed ? CH_EAUTH : CH_OK,
               changed ? "a changed proof fails" : "the server accepts the RFC's proof");
    }
}

static void compare_holds(void) {
    uint8_t a[67];
    uint8_t b[67];
    for (size_t i = 0; i < sizeof a; i++) {
        a[i] = (uint8_t)(i * 5 + 1);
    }
    memcpy(b, a, sizeof b);
    for (size_t n = 0; n <= sizeof a; n++) {
        expect(ch_ct_compare(a, b, n), CH_OK, "equal bytes compare equal");
    }
    // One bit of difference at each position, and at each bit of a byte.
    for (size_t at = 0; at < sizeof a; at++) {
        b[at] ^= (uint8_t)(1U << (at % 8));
        expect(ch_ct_compare(a, b, sizeof a), CH_EAUTH, "one changed bit compares different");
        expect(ch_ct_compare(a, b, at), CH_OK, "the bytes before the change compare equal");
        b[at] = a[at];
    }
    expect(ch_ct_compare(NULL, NULL, 0), CH_OK, "no bytes compare equal, from NULL pointers");
    expect(CH_OK, 0, "CH_OK is 0, so 0 means equal, as in memcmp");
}

typedef struct {
    const char *bytes;
    const char *text;
} base64_pair;

// RFC 4648 section 10's vectors, and three values that use both of
// section 4's last two characters.
static const base64_pair pairs[] = {
    {"", ""},
    {"f", "Zg=="},
    {"fo", "Zm8="},
    {"foo", "Zm9v"},
    {"foob", "Zm9vYg=="},
    {"fooba", "Zm9vYmE="},
    {"foobar", "Zm9vYmFy"},
    {"\xfb\xff", "+/8="},
    {"\xfb\xef\xbe", "++++"},
    {"\xff\xff\xff", "////"},
};

static void base64_vectors_hold(void) {
    for (size_t i = 0; i < COUNT(pairs); i++) {
        size_t n = strlen(pairs[i].bytes);
        size_t text_len = strlen(pairs[i].text);
        uint8_t text[16];
        uint8_t bytes[16];
        size_t got = 99;
        expect((int)CH_BASE64_LEN(n), (int)text_len, "CH_BASE64_LEN");
        expect(CH_BASE64_DECODED_LEN_MAX(text_len) >= n, 1, "CH_BASE64_DECODED_LEN_MAX");
        memset(text, 0x5a, sizeof text);
        expect(ch_base64_encode((const uint8_t *)pairs[i].bytes, n, text, text_len, &got), CH_OK,
               "a vector encodes into the exact room");
        expect(got == text_len && memcmp(text, pairs[i].text, text_len) == 0, 1,
               "the text is the vector's");
        expect(text[text_len], 0x5a, "the encoder writes no byte past the text");
        memset(bytes, 0x5a, sizeof bytes);
        expect(ch_base64_decode((const uint8_t *)pairs[i].text, text_len, bytes, n, &got), CH_OK,
               "a vector decodes into the exact room");
        expect(got == n && memcmp(bytes, pairs[i].bytes, n) == 0, 1, "the bytes are the vector's");
        expect(bytes[n], 0x5a, "the decoder writes no byte past the bytes");
        if (n != 0) {
            memset(text, 0x5a, sizeof text);
            got = 99;
            expect(ch_base64_encode((const uint8_t *)pairs[i].bytes, n, text, text_len - 1, &got),
                   CH_ECAP, "a text room one byte short is refused");
            expect(text[0] == 0x5a && got == 99, 1, "a refused encode writes nothing");
            memset(bytes, 0x5a, sizeof bytes);
            expect(ch_base64_decode((const uint8_t *)pairs[i].text, text_len, bytes, n - 1, &got),
                   CH_ECAP, "a byte room one byte short is refused");
            expect(bytes[0] == 0x5a && got == 0, 1, "a refused decode writes nothing");
        }
    }
    size_t got = 99;
    expect(ch_base64_encode(NULL, 0, NULL, 0, &got), CH_OK, "no bytes encode to no text");
    expect((int)got, 0, "and the length is 0");
    got = 99;
    expect(ch_base64_decode(NULL, 0, NULL, 0, &got), CH_OK, "no text decodes to no bytes");
    expect((int)got, 0, "and the length is 0");
}

// Every length from 0 to 259 bytes encodes to text that decodes to the
// same bytes, so each byte value passes at each position of a group.
static void base64_round_trip(void) {
    uint8_t bytes[259];
    for (size_t i = 0; i < sizeof bytes; i++) {
        bytes[i] = (uint8_t)(i * 7 + 3);
    }
    for (size_t n = 0; n <= sizeof bytes; n++) {
        uint8_t text[CH_BASE64_LEN(sizeof bytes)];
        uint8_t back[sizeof bytes];
        size_t text_len = 0;
        size_t back_len = 0;
        expect(ch_base64_encode(bytes, n, text, sizeof text, &text_len), CH_OK, "encode");
        expect(text_len == CH_BASE64_LEN(n), 1, "the text is CH_BASE64_LEN long");
        expect(ch_base64_decode(text, text_len, back, sizeof back, &back_len), CH_OK, "decode");
        expect(back_len == n && memcmp(back, bytes, n) == 0, 1, "the bytes come back");
    }
}

static int decodes(const char *text) {
    uint8_t out[16];
    size_t out_len = 99;
    memset(out, 0x5a, sizeof out);
    int rc = ch_base64_decode((const uint8_t *)text, strlen(text), out, sizeof out, &out_len);
    if (rc != CH_OK) {
        expect((int)out_len, 0, "a refused text reports no bytes");
        for (size_t i = 0; i < sizeof out; i++) {
            expect(out[i] == 0 || out[i] == 0x5a, 1, "a refused text leaves no decoded byte");
        }
    }
    return rc;
}

// Each kind of text scram.h says the decoder refuses, and beside each
// one the nearest text it takes.
static void base64_refusals_hold(void) {
    expect(decodes("Zg=="), CH_OK, "\"Zg==\" is canonical");
    expect(decodes("Zh=="), CH_EINVAL, "a group of 2 with a low bit set");
    expect(decodes("Zm8="), CH_OK, "\"Zm8=\" is canonical");
    expect(decodes("Zm9="), CH_EINVAL, "a group of 3 with a low bit set");
    expect(decodes("Zg"), CH_EINVAL, "a text with its padding left out");
    expect(decodes("Zm8"), CH_EINVAL, "a text of 3 characters");
    expect(decodes("Zg="), CH_EINVAL, "one '=' where two belong");
    expect(decodes("Z==="), CH_EINVAL, "three '='");
    expect(decodes("===="), CH_EINVAL, "four '='");
    expect(decodes("Zg=a"), CH_EINVAL, "'=' before the last character");
    expect(decodes("Zg==Zm8="), CH_EINVAL, "'=' in a group that is not the last");
    expect(decodes("=m9v"), CH_EINVAL, "'=' as a group's first character");
    expect(decodes("-_8="), CH_EINVAL, "section 5's two characters");
    expect(decodes("Zm9v\n\n\n\n"), CH_EINVAL, "line feeds");
    expect(decodes("Zm 9"), CH_EINVAL, "a space");
    // Every byte outside the alphabet is refused at each position of a
    // group, and every character of the alphabet is taken there.
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (unsigned c = 0; c < 256; c++) {
        int in_alphabet = c != 0 && strchr(alphabet, (int)c) != NULL;
        for (size_t at = 0; at < 4; at++) {
            uint8_t text[8] = {'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A'};
            uint8_t out[6];
            size_t out_len = 0;
            text[at] = (uint8_t)c;
            expect(ch_base64_decode(text, sizeof text, out, sizeof out, &out_len),
                   in_alphabet ? CH_OK : CH_EINVAL, "one byte value at one position of a group");
        }
    }
}

static int end_point(const uint8_t *cert, size_t cert_len, uint8_t out[64], size_t *out_len) {
    memset(out, 0x5a, CH_TLS_SERVER_END_POINT_LEN_MAX);
    *out_len = 99;
    int rc = ch_tls_server_end_point(cert, cert_len, out, out_len);
    if (rc != CH_OK) {
        expect(*out_len == 99 && out[0] == 0x5a && out[63] == 0x5a, 1, "a refusal writes nothing");
    }
    return rc;
}

// One certificate for each signature algorithm, and each way the bytes
// can fail to be one certificate.
static void end_point_vectors_hold(void) {
    uint8_t out[CH_TLS_SERVER_END_POINT_LEN_MAX];
    size_t out_len = 0;
    for (size_t i = 0; i < COUNT(end_point_vectors); i++) {
        const uint8_t *cert = end_point_vectors[i].cert;
        size_t cert_len = end_point_vectors[i].cert_len;
        if (end_point_vectors[i].end_point == NULL) {
            expect(end_point(cert, cert_len, out, &out_len), CH_EINVAL,
                   end_point_vectors[i].name);
            continue;
        }
        expect(end_point(cert, cert_len, out, &out_len), CH_OK, end_point_vectors[i].name);
        expect(out_len == end_point_vectors[i].end_point_len &&
                   memcmp(out, end_point_vectors[i].end_point, out_len) == 0,
               1, end_point_vectors[i].name);
        expect(out_len == 64 || out[out_len] == 0x5a, 1, "no byte past the value is written");
        expect(end_point(cert, cert_len - 1, out, &out_len), CH_EINVAL, "a certificate cut short");
        uint8_t copy[2048];
        memcpy(copy, cert, cert_len);
        copy[cert_len] = 0;
        expect(end_point(copy, cert_len + 1, out, &out_len), CH_EINVAL, "a byte after it");
        copy[0] = 0x31;
        expect(end_point(copy, cert_len, out, &out_len), CH_EINVAL, "a SET in the SEQUENCE's place");
    }
    expect(end_point(NULL, 0, out, &out_len), CH_EINVAL, "no bytes");
}

// The least bytes the call reads as a certificate: an empty
// TBSCertificate, a signatureAlgorithm whose content is the n bytes at
// algorithm, and an empty signature. The call judges no field, so these
// bytes test its rules for the algorithm's parameters one at a time.
static size_t bare_certificate(uint8_t *out, const uint8_t *algorithm, size_t n) {
    size_t at = 0;
    out[at++] = 0x30;
    out[at++] = (uint8_t)(2 + 2 + n + 3);
    out[at++] = 0x30; // tbsCertificate
    out[at++] = 0x00;
    out[at++] = 0x30; // signatureAlgorithm
    out[at++] = (uint8_t)n;
    memcpy(out + at, algorithm, n);
    at += n;
    out[at++] = 0x03; // signatureValue: a BIT STRING of no bits
    out[at++] = 0x01;
    out[at++] = 0x00;
    return at;
}

#define RSA_OID(n) 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, (n)
#define ECDSA_SHA256_OID 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
#define SHA2_OID(n) 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, (n)

// What the call answers for a bare certificate with this algorithm: its
// digest length, or 0 for a refusal. An accepted one must be the plain
// hash of the bytes.
static size_t answer(const uint8_t *algorithm, size_t n) {
    uint8_t cert[128];
    uint8_t out[CH_TLS_SERVER_END_POINT_LEN_MAX];
    size_t out_len = 0;
    size_t cert_len = bare_certificate(cert, algorithm, n);
    if (end_point(cert, cert_len, out, &out_len) != CH_OK) {
        return 0;
    }
    if (out_len == CH_SHA256_LEN) {
        uint8_t digest[CH_SHA256_LEN];
        ch_sha256(cert, cert_len, digest);
        expect(memcmp(out, digest, sizeof digest), 0, "a 32-byte value is the SHA-256 of the bytes");
    }
    return out_len;
}

#define ANSWER(...) answer((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))

static void end_point_parameters_hold(void) {
    // RSA: NULL parameters, and nothing else.
    expect((int)ANSWER(RSA_OID(0x0b), 0x05, 0x00), 32, "sha256WithRSAEncryption with NULL");
    expect((int)ANSWER(RSA_OID(0x0c), 0x05, 0x00), 48, "sha384WithRSAEncryption with NULL");
    expect((int)ANSWER(RSA_OID(0x0d), 0x05, 0x00), 64, "sha512WithRSAEncryption with NULL");
    expect((int)ANSWER(RSA_OID(0x0b)), 0, "sha256WithRSAEncryption with no parameters");
    expect((int)ANSWER(RSA_OID(0x0b), 0x05, 0x00, 0x05, 0x00), 0, "two NULLs");
    expect((int)ANSWER(RSA_OID(0x0e), 0x05, 0x00), 0, "sha224WithRSAEncryption");
    expect((int)ANSWER(RSA_OID(0x01), 0x05, 0x00), 0, "rsaEncryption, which names no hash");
    // ECDSA: no parameters.
    expect((int)ANSWER(ECDSA_SHA256_OID), 32, "ecdsa-with-SHA256");
    expect((int)ANSWER(ECDSA_SHA256_OID, 0x05, 0x00), 0, "ecdsa-with-SHA256 with NULL");
    // RSASSA-PSS: absent parameters and an empty SEQUENCE are every
    // default, so SHA-1, which takes SHA-256.
    expect((int)ANSWER(RSA_OID(0x0a)), 32, "RSASSA-PSS with no parameters");
    expect((int)ANSWER(RSA_OID(0x0a), 0x30, 0x00), 32, "RSASSA-PSS with empty parameters");
    // The hash field, with NULL parameters and with none.
    expect((int)ANSWER(RSA_OID(0x0a), 0x30, 0x0f, 0xa0, 0x0d, 0x30, 0x0b, SHA2_OID(0x02)), 48,
           "RSASSA-PSS with SHA-384 and no hash parameters");
    expect((int)ANSWER(RSA_OID(0x0a), 0x30, 0x11, 0xa0, 0x0f, 0x30, 0x0d, SHA2_OID(0x03), 0x05,
                       0x00),
           64, "RSASSA-PSS with SHA-512 and NULL hash parameters");
    expect((int)ANSWER(RSA_OID(0x0a), 0x30, 0x0f, 0xa0, 0x0d, 0x30, 0x0b, SHA2_OID(0x04)), 0,
           "RSASSA-PSS with SHA-224");
    // A salt length with no hash field keeps the default hash.
    expect((int)ANSWER(RSA_OID(0x0a), 0x30, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x20), 32,
           "RSASSA-PSS with a salt length alone");
    expect((int)ANSWER(RSA_OID(0x0a), 0x30, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x20, 0x00), 0,
           "a byte after the parameters");
    expect((int)ANSWER(RSA_OID(0x0a), 0x30, 0x06, 0xa2, 0x03, 0x02, 0x01, 0x20, 0x00), 0,
           "a byte after the last field");
    expect((int)ANSWER(RSA_OID(0x0a), 0x30, 0x10, 0xa0, 0x0e, 0x30, 0x0b, SHA2_OID(0x02), 0x00), 0,
           "a byte after the hash's AlgorithmIdentifier");
    // Two fields out of order: the salt length, then the hash.
    expect((int)ANSWER(RSA_OID(0x0a), 0x30, 0x14, 0xa2, 0x03, 0x02, 0x01, 0x20, 0xa0, 0x0d, 0x30,
                       0x0b, SHA2_OID(0x01)),
           0, "RSASSA-PSS fields out of order");
    // Other algorithms: Ed25519, 1.3.101.112, and an empty content.
    expect((int)ANSWER(0x06, 0x03, 0x2b, 0x65, 0x70), 0, "Ed25519");
    expect((int)answer(NULL, 0), 0, "an AlgorithmIdentifier with no OID");
}

int main(void) {
    sha256_vectors_hold();
    hmac_vectors_hold();
    pbkdf2_vectors_hold();
    pbkdf2_bounds_hold();
    scram_exchange_holds();
    compare_holds();
    base64_vectors_hold();
    base64_round_trip();
    base64_refusals_hold();
    end_point_vectors_hold();
    end_point_parameters_hold();
    if (failures != 0) {
        return 1;
    }
    printf("scram: RFC 4231's HMAC cases, RFC 7914's PBKDF2 vectors, RFC 7677's exchange, RFC "
           "4648's vectors, %zu certificates, and every refusal scram.h states\n",
           COUNT(end_point_vectors));
    return 0;
}
