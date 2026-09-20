// Published vectors for quic_gcm.c: NIST SP 800-38D's own AES-128 test
// cases for AEAD_AES_128_GCM and GHASH, and the two RFC 9001 Appendix A
// packets that use them — the client Initial packet of A.2 and the Retry
// integrity tag of A.4.
//
// Included by test/quic_vectors.c only, which is the vectors binary a
// -DCH_TRANSPORT_QUIC build compiles. It sits in its own header for the
// reason test/pem_tests.h and test/session_tests.h do: the arrays are
// long, and the main stays readable beside them. That main compiles
// quic_aes_block.h, so aes_expand_round_keys is in scope here and a test can build an
// aes_public_key over a key SP 800-38D chose. INV-26 bans that shape in
// a library source and admits it in a test, which is why the Semgrep
// rule excludes `test`.
#ifndef CH_QUIC_GCM_TESTS_H
#define CH_QUIC_GCM_TESTS_H

#include "quic_gcm.h"

// The longest plaintext below is A.2's 1162-byte packet payload, and
// every buffer in this file is sized from that one number.
#define GCM_TEST_MAX 1200

// SP 800-38D's AES-128 test cases, in the order the specification prints
// them. Every field is hex, the way the specification writes it, so a
// reader compares this table against the document rather than against a
// re-encoding of it. An empty string is an empty field: case 1 has no
// plaintext and no associated data, and case 2 has no associated data.
static const struct {
    const char *name;
    const char *key;
    const char *iv;
    const char *aad;
    const char *pt;
    const char *ct;
    const char *tag;
} SP800_38D_CASES[] = {
    {"case 1", "00000000000000000000000000000000", "000000000000000000000000", "", "", "",
     "58e2fccefa7e3061367f1d57a4e7455a"                                                                                                                       },
    {"case 2", "00000000000000000000000000000000", "000000000000000000000000", "",
     "00000000000000000000000000000000",                                               "0388dace60b6a392f328c2b971b2fe78",
     "ab6e47d42cec13bdf53a67b21257bddf"                                                                                                                       },
    {"case 3", "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449"
     "a6b525b16aedf5aa0de657ba637b391aafd255",                                         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac8"
     "4aa051ba30b396a0aac973d58e091473f5985",                                 "4d5c2af327cd64a62cf35abd2ba6fab4"},
    {"case 4", "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2",                                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449"
     "a6b525b16aedf5aa0de657ba637b39", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac8"
     "4aa051ba30b396a0aac973d58e091", "5bc94fbc3221a5db94fae95ae7121a47"},
};

// One aes_public_key over a key the caller chose. Only a test does this:
// the two constructors in quic_aes.h are the only public way to write
// this type, and neither takes a caller's key, so a vector whose key SP
// 800-38D fixed reaches the cipher through the key schedule directly.
static void gcm_test_key(aes_public_key *k, const char *key_hex) {
    uint8_t key[AES_128_KEY];
    CHECK(unhex(key_hex, key) == sizeof key);
    memset(k, 0, sizeof *k);
    aes_expand_round_keys(key, k->key.round_keys);
}

// Every SP 800-38D case, four questions each: the ciphertext and the tag
// gcm_seal writes, the plaintext gcm_open releases, and the refusal
// gcm_open answers with when one tag bit is wrong. The refusal arm also
// checks that no plaintext byte was written, which is the promise
// quic_gcm.h makes and the reason the tag is computed first.
static void test_sp800_38d_cases(void) {
    for (size_t i = 0; i < sizeof SP800_38D_CASES / sizeof SP800_38D_CASES[0]; i++) {
        uint8_t iv[AES_IV];
        uint8_t aad[GCM_TEST_MAX];
        uint8_t pt[GCM_TEST_MAX];
        uint8_t ct[GCM_TEST_MAX];
        uint8_t tag[GCM_TAG];
        aes_public_key k;
        gcm_test_key(&k, SP800_38D_CASES[i].key);
        CHECK(unhex(SP800_38D_CASES[i].iv, iv) == sizeof iv);
        size_t aad_len = unhex(SP800_38D_CASES[i].aad, aad);
        size_t n = unhex(SP800_38D_CASES[i].pt, pt);
        CHECK(unhex(SP800_38D_CASES[i].ct, ct) == n);
        CHECK(unhex(SP800_38D_CASES[i].tag, tag) == sizeof tag);

        uint8_t got_ct[GCM_TEST_MAX];
        uint8_t got_tag[GCM_TAG];
        gcm_seal(&k, iv, aad, aad_len, pt, n, got_ct, got_tag);
        CHECK(memcmp(got_ct, ct, n) == 0);
        CHECK(memcmp(got_tag, tag, sizeof tag) == 0);

        uint8_t got_pt[GCM_TEST_MAX];
        CHECK(gcm_open(&k, iv, aad, aad_len, ct, n, tag, got_pt) == 1);
        CHECK(memcmp(got_pt, pt, n) == 0);

        // One wrong tag bit, and the plaintext buffer stays as it was.
        uint8_t wrong_tag[GCM_TAG];
        memcpy(wrong_tag, tag, sizeof wrong_tag);
        wrong_tag[0] = (uint8_t)(wrong_tag[0] ^ 1);
        uint8_t untouched[GCM_TEST_MAX];
        memset(untouched, 0xa5, sizeof untouched);
        CHECK(gcm_open(&k, iv, aad, aad_len, ct, n, wrong_tag, untouched) == 0);
        for (size_t j = 0; j < n; j++) {
            CHECK(untouched[j] == 0xa5);
        }
    }
}

// GHASH on its own. SP 800-38D prints tags rather than GHASH outputs, so
// the check is the equation §7.1 step 6 states: the tag is GHASH over the
// associated data and the ciphertext, exclusive-ored with the forward
// cipher of the first counter block. Both sides of that equation are
// computed here from the specification's own numbers, so nothing below
// is a value this tree invented.
static void test_ghash_against_tags(void) {
    for (size_t i = 0; i < sizeof SP800_38D_CASES / sizeof SP800_38D_CASES[0]; i++) {
        uint8_t iv[AES_IV];
        uint8_t aad[GCM_TEST_MAX];
        uint8_t ct[GCM_TEST_MAX];
        uint8_t tag[GCM_TAG];
        aes_public_key k;
        gcm_test_key(&k, SP800_38D_CASES[i].key);
        CHECK(unhex(SP800_38D_CASES[i].iv, iv) == sizeof iv);
        size_t aad_len = unhex(SP800_38D_CASES[i].aad, aad);
        size_t n = unhex(SP800_38D_CASES[i].ct, ct);
        CHECK(unhex(SP800_38D_CASES[i].tag, tag) == sizeof tag);

        uint8_t hashed[AES_BLOCK];
        gcm_ghash(&k, aad, aad_len, ct, n, hashed);

        // SP 800-38D §7.1 step 2: a 96-bit IV gives the first counter
        // block as the IV followed by 31 zero bits and a one.
        uint8_t first_counter[AES_BLOCK];
        memcpy(first_counter, iv, sizeof iv);
        first_counter[12] = 0;
        first_counter[13] = 0;
        first_counter[14] = 0;
        first_counter[15] = 1;
        uint8_t mask[AES_BLOCK];
        aes_encrypt_block(&k, first_counter, mask);
        for (size_t j = 0; j < GCM_TAG; j++) {
            CHECK((uint8_t)(hashed[j] ^ mask[j]) == tag[j]);
        }
    }
}

// SP 800-38D §6.4 over nothing at all: with no associated data and no
// ciphertext, the only block GHASH hashes is the two zero lengths, and
// zero times the hash subkey is zero. Case 1's tag is therefore the
// forward cipher of the first counter block alone, which the loop above
// checks; this states the GHASH half of it directly.
static void test_ghash_empty(void) {
    static const uint8_t zero_block[AES_BLOCK] = {0};
    aes_public_key k;
    gcm_test_key(&k, SP800_38D_CASES[0].key);
    uint8_t hashed[AES_BLOCK];
    memset(hashed, 0xa5, sizeof hashed);
    gcm_ghash(&k, NULL, 0, NULL, 0, hashed);
    CHECK(memcmp(hashed, zero_block, sizeof hashed) == 0);
}

// RFC 9001 Appendix A.2, the client Initial packet
// (rfc9001.txt:2394-2402). The payload is this CRYPTO frame followed by
// PADDING frames to 1162 bytes, and a PADDING frame is a zero byte (RFC
// 9000 §19.1), so the test writes the frame and zeros the rest.
static const uint8_t A2_CRYPTO_FRAME[245] = {
    0x06, 0x00, 0x40, 0xf1, 0x01, 0x00, 0x00, 0xed, 0x03, 0x03, 0xeb, 0xf8, 0xfa, 0x56, 0xf1, 0x29,
    0x39, 0xb9, 0x58, 0x4a, 0x38, 0x96, 0x47, 0x2e, 0xc4, 0x0b, 0xb8, 0x63, 0xcf, 0xd3, 0xe8, 0x68,
    0x04, 0xfe, 0x3a, 0x47, 0xf0, 0x6a, 0x2b, 0x69, 0x48, 0x4c, 0x00, 0x00, 0x04, 0x13, 0x01, 0x13,
    0x02, 0x01, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a,
    0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x10, 0x00, 0x07, 0x00, 0x05,
    0x04, 0x61, 0x6c, 0x70, 0x6e, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33,
    0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x93, 0x70, 0xb2, 0xc9, 0xca, 0xa4, 0x7f, 0xba,
    0xba, 0xf4, 0x55, 0x9f, 0xed, 0xba, 0x75, 0x3d, 0xe1, 0x71, 0xfa, 0x71, 0xf5, 0x0f, 0x1c, 0xe1,
    0x5d, 0x43, 0xe9, 0x94, 0xec, 0x74, 0xd7, 0x48, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
    0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08,
    0x05, 0x08, 0x06, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00,
    0x39, 0x00, 0x32, 0x04, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x04, 0x80,
    0x00, 0xff, 0xff, 0x07, 0x04, 0x80, 0x00, 0xff, 0xff, 0x08, 0x01, 0x10, 0x01, 0x04, 0x80, 0x00,
    0x75, 0x30, 0x09, 0x01, 0x10, 0x0f, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x06,
    0x04, 0x80, 0x00, 0xff, 0xff,
};

// The A.2 payload length: 1162 bytes of frames (rfc9001.txt:2396).
#define A2_PAYLOAD 1162

// RFC 9001 Appendix A.2's client Initial packet, checked end to end
// against the packet the RFC prints.
//
// The associated data is the unprotected header the RFC states,
// `c300000001088394c8f03e5157080000449e00000002` — packet protection
// runs before header protection (RFC 9001 §5.4.1), so the AEAD sees the
// header with its packet number in the clear.
//
// The nonce is RFC 9001 §5.3's: the packet protection IV exclusive-ored
// with the packet number, which is 2 here, left-padded to the IV's
// length.
//
// Two values are compared, and between them they cover every ciphertext
// byte. The first is the RFC's tag. A tag is computed over the whole
// ciphertext, so a tag equal to the RFC's is a ciphertext equal to the
// RFC's; the check does not need the other 1162 bytes printed here. The
// second is the 16-byte sample the RFC names, which is the first
// ciphertext block, so a reader sees one value from the document
// compared directly rather than only the tag.
static void test_appendix_a2_initial(void) {
    aes_public_key k;
    CHECK(aes_public_key_initial(&k, APPENDIX_DCID, sizeof APPENDIX_DCID,
                                 CH_QUIC_ENDPOINT_CLIENT) == CH_OK);

    uint8_t aad[GCM_TEST_MAX];
    size_t aad_len = unhex("c300000001088394c8f03e5157080000449e00000002", aad);
    CHECK(aad_len == 22);

    // RFC 9001 §5.3: the packet number, left-padded to the IV's length,
    // exclusive-ored with the IV. Written byte by byte from the packet
    // number rather than as a constant, so no step assumes host
    // endianness.
    uint64_t packet_number = 2;
    uint8_t nonce[AES_IV];
    memcpy(nonce, k.iv, sizeof nonce);
    for (size_t i = 0; i < 8; i++) {
        nonce[AES_IV - 1 - i] =
            (uint8_t)(nonce[AES_IV - 1 - i] ^ (uint8_t)(packet_number >> (8 * i)));
    }

    uint8_t pt[A2_PAYLOAD];
    memset(pt, 0, sizeof pt);
    memcpy(pt, A2_CRYPTO_FRAME, sizeof A2_CRYPTO_FRAME);

    uint8_t ct[A2_PAYLOAD];
    uint8_t tag[GCM_TAG];
    gcm_seal(&k, nonce, aad, aad_len, pt, sizeof pt, ct, tag);
    CHECK(eq_hex(tag, "e221af44860018ab0856972e194cd934"));
    CHECK(eq_hex(ct, "d1b1c98dd7689fb8ec11d242b123dc9b"));

    // The same packet back. gcm_open must release exactly the payload
    // that went in, padding included.
    uint8_t got_pt[A2_PAYLOAD];
    CHECK(gcm_open(&k, nonce, aad, aad_len, ct, sizeof ct, tag, got_pt) == 1);
    CHECK(memcmp(got_pt, pt, sizeof pt) == 0);
}

// RFC 9001 Appendix A.4's Retry packet (rfc9001.txt:2497-2499), 36
// bytes: 20 bytes of Retry packet and the 16-byte Retry Integrity Tag
// after them.
static const uint8_t A4_RETRY_PACKET[36] = {
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
    0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
    0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
};

// RFC 9001 §5.8's printed nonce, 0x461599d35d632bf2239825bb
// (rfc9001.txt:1501-1502).
static const uint8_t RETRY_NONCE[AES_IV] = {0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
                                            0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};

// RFC 9001 §5.8: the Retry Integrity Tag is AEAD_AES_128_GCM over an
// empty plaintext, with the Retry Pseudo-Packet as associated data
// (rfc9001.txt:1490-1502). The pseudo-packet is the length of the
// original Destination Connection ID, that connection ID, and then the
// Retry packet up to but not including the tag.
//
// Appendix A.4 says the integrity check covers the client-chosen
// connection ID 0x8394c8f03e515708 while the packet itself does not
// carry it, which is exactly what the pseudo-packet is for.
static void test_appendix_a4_retry(void) {
    aes_public_key k;
    aes_public_key_retry(&k);

    // The pseudo-packet: one length byte, the original Destination
    // Connection ID, and the 20 Retry bytes before the tag.
    uint8_t pseudo[1 + sizeof APPENDIX_DCID + sizeof A4_RETRY_PACKET];
    size_t pseudo_len = 0;
    pseudo[pseudo_len++] = (uint8_t)sizeof APPENDIX_DCID;
    memcpy(&pseudo[pseudo_len], APPENDIX_DCID, sizeof APPENDIX_DCID);
    pseudo_len += sizeof APPENDIX_DCID;
    size_t retry_body = sizeof A4_RETRY_PACKET - GCM_TAG;
    memcpy(&pseudo[pseudo_len], A4_RETRY_PACKET, retry_body);
    pseudo_len += retry_body;

    // quic_gcm.h states the plaintext pointer for n readable bytes and
    // says nothing about a null one, so the empty plaintext of §5.8 gets
    // a real buffer rather than a pointer the contract does not cover.
    uint8_t empty[1] = {0};
    const uint8_t *want_tag = &A4_RETRY_PACKET[retry_body];
    uint8_t tag[GCM_TAG];
    gcm_seal(&k, RETRY_NONCE, pseudo, pseudo_len, empty, 0, empty, tag);
    CHECK(memcmp(tag, want_tag, sizeof tag) == 0);

    // The check a client performs on a Retry packet it receives: the
    // same tag, opened rather than sealed, over an empty ciphertext.
    CHECK(gcm_open(&k, RETRY_NONCE, pseudo, pseudo_len, empty, 0, want_tag, empty) == 1);

    // One wrong byte anywhere in the pseudo-packet, and the client
    // discards the packet (RFC 9000 §17.2.5.2).
    pseudo[0] = (uint8_t)(pseudo[0] ^ 1);
    CHECK(gcm_open(&k, RETRY_NONCE, pseudo, pseudo_len, empty, 0, want_tag, empty) == 0);
}

// The block boundary, both sides of it. SP 800-38D pads a last partial
// block with zeros, so the lengths either side of AES_BLOCK are where a
// wrong pad shows. Every length from 0 to two blocks and one byte goes
// through seal and open, and each one must come back.
static void test_block_boundaries(void) {
    aes_public_key k;
    gcm_test_key(&k, SP800_38D_CASES[2].key);
    uint8_t iv[AES_IV];
    CHECK(unhex(SP800_38D_CASES[2].iv, iv) == sizeof iv);

    uint8_t pt[2 * AES_BLOCK + 1];
    for (size_t i = 0; i < sizeof pt; i++) {
        pt[i] = (uint8_t)i;
    }
    for (size_t n = 0; n <= sizeof pt; n++) {
        for (size_t aad_len = 0; aad_len <= sizeof pt; aad_len++) {
            uint8_t ct[sizeof pt];
            uint8_t tag[GCM_TAG];
            gcm_seal(&k, iv, pt, aad_len, pt, n, ct, tag);
            uint8_t got[sizeof pt];
            CHECK(gcm_open(&k, iv, pt, aad_len, ct, n, tag, got) == 1);
            CHECK(memcmp(got, pt, n) == 0);
        }
    }
}

// The aliasing shapes quic_gcm.h admits: pt == ct on both calls, and pt
// below ct on open. A packet caller decrypts in place, so these are the
// shapes real code uses rather than shapes only a test produces.
static void test_in_place(void) {
    aes_public_key k;
    gcm_test_key(&k, SP800_38D_CASES[3].key);
    uint8_t iv[AES_IV];
    CHECK(unhex(SP800_38D_CASES[3].iv, iv) == sizeof iv);
    uint8_t aad[GCM_TEST_MAX];
    size_t aad_len = unhex(SP800_38D_CASES[3].aad, aad);
    uint8_t want_ct[GCM_TEST_MAX];
    size_t n = unhex(SP800_38D_CASES[3].ct, want_ct);
    uint8_t want_pt[GCM_TEST_MAX];
    CHECK(unhex(SP800_38D_CASES[3].pt, want_pt) == n);
    uint8_t want_tag[GCM_TAG];
    CHECK(unhex(SP800_38D_CASES[3].tag, want_tag) == sizeof want_tag);

    // Seal with one buffer.
    uint8_t both[GCM_TEST_MAX];
    memcpy(both, want_pt, n);
    uint8_t tag[GCM_TAG];
    gcm_seal(&k, iv, aad, aad_len, both, n, both, tag);
    CHECK(memcmp(both, want_ct, n) == 0);
    CHECK(memcmp(tag, want_tag, sizeof tag) == 0);

    // Open with one buffer, which turns it back.
    CHECK(gcm_open(&k, iv, aad, aad_len, both, n, tag, both) == 1);
    CHECK(memcmp(both, want_pt, n) == 0);

    // Open with the plaintext one byte below the ciphertext, the shape a
    // caller produces when it strips a header in place.
    uint8_t shifted[GCM_TEST_MAX];
    memcpy(&shifted[1], want_ct, n);
    CHECK(gcm_open(&k, iv, aad, aad_len, &shifted[1], n, want_tag, shifted) == 1);
    CHECK(memcmp(shifted, want_pt, n) == 0);
}

#endif
