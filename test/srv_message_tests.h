// srv_message.c against the message formats RFC 9846 §4 prints, in its own
// header for the reason test/quic_packet_tests.h is one: the vectors are long
// and test/srv_test.c holds the helpers they read. It uses CHECK, out and
// built from that file and is included after them.
//
// No standard prints a whole ServerHello, so every vector here is written out
// by hand from the field list of the section it names, with the inputs below.
// Writing them by hand is the point: a vector built by calling the same
// helpers the builder calls would drift with it.
#ifndef CH_SRV_MESSAGE_TESTS_H
#define CH_SRV_MESSAGE_TESTS_H

// The three inputs the hello vectors share. Each is a counting pattern, so a
// field written at the wrong offset shows as the wrong byte rather than as a
// byte that matches by luck.
static const uint8_t vec_random[SRV_RANDOM] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const uint8_t vec_session_id[SRV_SESSION_ID_MAX] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
static const uint8_t vec_share[X25519_LEN] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f};

// The four bytes a HelloRetryRequest vector carries as its cookie. Any bytes
// do: srv_build_hello_retry_request copies them and reads nothing in them.
static const uint8_t vec_cookie[4] = {0xde, 0xad, 0xbe, 0xef};

// The selection every vector is built under: the one suite this build offers,
// the one group it offers, and SHA-256's length.
static selection vec_selection(void) {
    selection sel;
    memset(&sel, 0, sizeof sel);
    sel.suite = SUITE_CHACHA20_POLY1305_SHA256;
    sel.hash_len = SHA256_LEN;
    sel.group = CH_GROUP_X25519;
    sel.sigalg = SIGALG_ECDSA_P256_SHA256;
    return sel;
}

// RFC 9846 §4.2.3: the handshake header, legacy_version, the 32 random bytes,
// legacy_session_id_echo, the cipher suite, legacy_compression_method, and an
// extension block of supported_versions (§4.3.1) and key_share (§4.3.8).
static const uint8_t want_server_hello[] = {
    0x02, 0x00, 0x00, 0x76,                         // ServerHello, 118 body bytes
    0x03, 0x03,                                     // legacy_version
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // random
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, //
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, //
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, //
    0x20,                                           // legacy_session_id_echo length
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, //
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, //
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, //
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, //
    0x13, 0x03,                                     // cipher_suite
    0x00,                                           // legacy_compression_method
    0x00, 0x2e,                                     // extensions, 46 bytes
    0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,             // supported_versions: TLS 1.3
    0x00, 0x33, 0x00, 0x24,                         // key_share, 36 bytes
    0x00, 0x1d, 0x00, 0x20,                         // group x25519, 32-byte key_exchange
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, //
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, //
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, //
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f};

// RFC 9846 §4.2.4: the ServerHello's format with srv_hrr_random in place of
// the random value, a key_share carrying the group alone, and the cookie
// extension of §4.3.2.
static const uint8_t want_hello_retry_request[] = {
    0x02, 0x00, 0x00, 0x5e,                         // ServerHello, 94 body bytes
    0x03, 0x03,                                     // legacy_version
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, // srv_hrr_random
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, //
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, //
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c, //
    0x20,                                           // legacy_session_id_echo length
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, //
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, //
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, //
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, //
    0x13, 0x03,                                     // cipher_suite
    0x00,                                           // legacy_compression_method
    0x00, 0x16,                                     // extensions, 22 bytes
    0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,             // supported_versions: TLS 1.3
    0x00, 0x33, 0x00, 0x02, 0x00, 0x1d,             // key_share: the group, no key
    0x00, 0x2c, 0x00, 0x06, 0x00, 0x04,             // cookie, 4 bytes of it
    0xde, 0xad, 0xbe, 0xef};

// RFC 9846 Appendix E.4's dummy record: content type 20,
// legacy_record_version 0x0303, a length of 1 and the byte 0x01.
static const uint8_t want_compat_ccs[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};

// RFC 9846 §4.4.1 with no extension at all, which is legal and is 6 bytes.
static const uint8_t want_encrypted_extensions_empty[] = {0x08, 0x00, 0x00, 0x02, 0x00, 0x00};

// The same message carrying all three extensions this server ever sends:
// record_size_limit (RFC 8449 §4) at 512, one ALPN protocol (RFC 7301
// §3.2) naming "h2", and a three-byte quic_transport_parameters body
// (RFC 9001 §8.2) at code point 0x39. The body's bytes are not a real
// encoding: §8.2 makes the content the QUIC version's, so the builder
// copies whatever it is given and this vector holds it to that.
static const uint8_t want_encrypted_extensions_full[] = {
    0x08, 0x00, 0x00, 0x18,             // EncryptedExtensions, 24 body bytes
    0x00, 0x16,                         // extensions, 22 bytes
    0x00, 0x1c, 0x00, 0x02, 0x02, 0x00, // record_size_limit 512
    0x00, 0x10, 0x00, 0x05,             // ALPN, 5 bytes
    0x00, 0x03, 0x02, 0x68, 0x32,       // one name of 2 bytes: "h2"
    0x00, 0x39, 0x00, 0x03,             // quic_transport_parameters, 3 bytes
    0xc0, 0xc1, 0xc2};                  // the caller's body, copied unread
static const uint8_t vec_transport_params[] = {0xc0, 0xc1, 0xc2};

static void test_server_hello(void) {
    selection sel = vec_selection();
    size_t n = srv_build_server_hello(out, sizeof out, &sel, vec_random, vec_session_id,
                                      sizeof vec_session_id, vec_share, sizeof vec_share);
    CHECK(built(n, want_server_hello, sizeof want_server_hello));

    // An empty legacy_session_id is the other end of §4.2.3's echo rule: the
    // length byte goes to 0 and the message loses exactly those 32 bytes.
    n = srv_build_server_hello(out, sizeof out, &sel, vec_random, vec_session_id, 0, vec_share,
                               sizeof vec_share);
    CHECK(n == sizeof want_server_hello - SRV_SESSION_ID_MAX);
    CHECK(out[38] == 0);
}

static void test_hello_retry_request(void) {
    selection sel = vec_selection();
    size_t n = srv_build_hello_retry_request(out, sizeof out, &sel, vec_session_id,
                                             sizeof vec_session_id, vec_cookie, sizeof vec_cookie);
    CHECK(built(n, want_hello_retry_request, sizeof want_hello_retry_request));

    // The retry differs from the ServerHello in the random value and nowhere
    // else in the head, which is what §4.2.4 means by the same format.
    CHECK(memcmp(out + 6, srv_hrr_random, SRV_RANDOM) == 0);
}

static void test_compat_ccs(void) {
    size_t n = srv_build_compat_ccs(out, sizeof out);
    CHECK(built(n, want_compat_ccs, sizeof want_compat_ccs));
    CHECK(n == SRV_CCS_RECORD_LEN);
}

static void test_encrypted_extensions(void) {
    size_t n = srv_build_encrypted_extensions(out, sizeof out, 0, NULL, NULL, 0);
    CHECK(built(n, want_encrypted_extensions_empty, sizeof want_encrypted_extensions_empty));

    static const uint8_t h2[] = {0x68, 0x32};
    ch_alpn_protocol selected = {h2, sizeof h2};
    n = srv_build_encrypted_extensions(out, sizeof out, 512, &selected, vec_transport_params,
                                       sizeof vec_transport_params);
    CHECK(built(n, want_encrypted_extensions_full, sizeof want_encrypted_extensions_full));

    // Each extension is independent of the others: a limit of 0 drops only
    // record_size_limit, a NULL selection drops only ALPN, and a NULL body
    // drops only quic_transport_parameters.
    n = srv_build_encrypted_extensions(out, sizeof out, 0, &selected, NULL, 0);
    CHECK(n == sizeof want_encrypted_extensions_empty + 9);
    n = srv_build_encrypted_extensions(out, sizeof out, 512, NULL, NULL, 0);
    CHECK(n == sizeof want_encrypted_extensions_empty + 6);
    n = srv_build_encrypted_extensions(out, sizeof out, 0, NULL, vec_transport_params,
                                       sizeof vec_transport_params);
    CHECK(n == sizeof want_encrypted_extensions_empty + 4 + sizeof vec_transport_params);
    // A length of 0 with a body that is not NULL writes the extension with
    // an empty body, which RFC 9001 §8.2 does not forbid: the parameters
    // are the QUIC version's and TLS counts no minimum. Only the pointer
    // decides whether the extension is written.
    n = srv_build_encrypted_extensions(out, sizeof out, 0, NULL, vec_transport_params, 0);
    CHECK(n == sizeof want_encrypted_extensions_empty + 4);

    // CH_TRANSPORT_PARAMS_MAX's exact boundary: the last body the builder
    // writes, and the first it refuses. The buffer holds one byte more than
    // the larger message needs, so the refusal cannot come from a short
    // buffer: a builder without the cap check would write all 267 bytes
    // here and the second case would report them.
    static uint8_t body[CH_TRANSPORT_PARAMS_MAX + 1];
    memset(body, 0x5a, sizeof body);
    uint8_t big[6 + 4 + CH_TRANSPORT_PARAMS_MAX + 1];
    n = srv_build_encrypted_extensions(big, sizeof big, 0, NULL, body, CH_TRANSPORT_PARAMS_MAX);
    CHECK(n == sizeof big - 1);
    n = srv_build_encrypted_extensions(big, sizeof big, 0, NULL, body, CH_TRANSPORT_PARAMS_MAX + 1);
    CHECK(n == 0);
}

// RFC 9846 §4.5.1 over a two-certificate chain: the handshake header, an
// empty certificate_request_context, the certificate_list length, and per
// entry a 3-byte length, the DER and a 2-byte empty extensions vector.
static const uint8_t want_certificate_header[] = {0x0b, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x12};

static void test_certificate(void) {
    static const uint8_t leaf[] = {0xa0, 0xa1, 0xa2};
    static const uint8_t issuer[] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4};
    const ch_cert chain[] = {
        {leaf,   sizeof leaf  },
        {issuer, sizeof issuer}
    };
    ch_identity id;
    memset(&id, 0, sizeof id);
    id.chain = chain;
    id.chain_count = 2;

    // 8 fixed bytes, then 5 + 3 for the leaf and 5 + 5 for the issuer.
    CHECK(srv_certificate_message_len(&id) == 26);
    CHECK(srv_build_certificate_header(out, sizeof out, &id) == sizeof want_certificate_header);
    CHECK(memcmp(out, want_certificate_header, sizeof want_certificate_header) == 0);

    static const uint8_t want_prefix[] = {0x00, 0x00, 0x03};
    CHECK(srv_build_certificate_entry_prefix(out, sizeof out, sizeof leaf) == sizeof want_prefix);
    CHECK(memcmp(out, want_prefix, sizeof want_prefix) == 0);

    static const uint8_t want_suffix[] = {0x00, 0x00};
    CHECK(srv_build_certificate_entry_suffix(out, sizeof out) == sizeof want_suffix);
    CHECK(memcmp(out, want_suffix, sizeof want_suffix) == 0);

    // The 3-byte cert_data length, at its last value and its first invalid
    // one.
    CHECK(srv_build_certificate_entry_prefix(out, sizeof out, 0xFFFFFF) == 3);
    CHECK(srv_build_certificate_entry_prefix(out, sizeof out, 0x1000000) == 0);
}

static void test_certificate_verify(void) {
    static const uint8_t sig[] = {0x01, 0x02, 0x03};
    static const uint8_t want[] = {0x0f, 0x00, 0x00, 0x07, 0x04, 0x03,
                                   0x00, 0x03, 0x01, 0x02, 0x03};
    size_t n =
        srv_build_certificate_verify(out, sizeof out, SIGALG_ECDSA_P256_SHA256, sig, sizeof sig);
    CHECK(built(n, want, sizeof want));

    // The signature vector's length rule, at both ends. A 65535-byte
    // signature is the last one that fits the two-byte field, and it needs a
    // signature that long to read: the refusal above it returns before it
    // reads a byte, but the case below it does not.
    CHECK(srv_build_certificate_verify(out, sizeof out, SIGALG_ECDSA_P256_SHA256, sig, 0) == 0);
    static uint8_t wide_sig[65536];
    static uint8_t wide_out[8 + 65536];
    memset(wide_sig, 0x11, sizeof wide_sig);
    CHECK(srv_build_certificate_verify(wide_out, sizeof wide_out, SIGALG_RSA_PSS_RSAE_SHA256,
                                       wide_sig, 65535) == 8 + 65535);
    CHECK(srv_build_certificate_verify(wide_out, sizeof wide_out, SIGALG_RSA_PSS_RSAE_SHA256,
                                       wide_sig, 65536) == 0);
}

static void test_finished(void) {
    uint8_t verify_data[SHA256_LEN];
    memset(verify_data, 0x5a, sizeof verify_data);
    size_t n = srv_build_finished(out, sizeof out, verify_data, sizeof verify_data);
    CHECK(n == 4 + SHA256_LEN);

    static const uint8_t want_header[] = {0x14, 0x00, 0x00, 0x20};
    CHECK(memcmp(out, want_header, sizeof want_header) == 0);
    CHECK(memcmp(out + 4, verify_data, sizeof verify_data) == 0);
}

static void test_key_update(void) {
    static const uint8_t want_not_requested[] = {0x18, 0x00, 0x00, 0x01, 0x00};
    static const uint8_t want_requested[] = {0x18, 0x00, 0x00, 0x01, 0x01};

    size_t n = srv_build_key_update(out, sizeof out, 0);
    CHECK(built(n, want_not_requested, sizeof want_not_requested));
    n = srv_build_key_update(out, sizeof out, 1);
    CHECK(built(n, want_requested, sizeof want_requested));

    // request_update has two legal values and the third is refused.
    CHECK(srv_build_key_update(out, sizeof out, 2) == 0);
    CHECK(srv_build_key_update(out, sizeof out, 0xff) == 0);
}

// The exact boundary pair CLAUDE.md asks of a length rule, for every builder:
// the last capacity that works is the message's own length, and one byte
// below it refuses.
static void test_builder_capacity(void) {
    selection sel = vec_selection();
    const size_t hello = sizeof want_server_hello;
    const size_t retry = sizeof want_hello_retry_request;

    CHECK(srv_build_server_hello(out, hello, &sel, vec_random, vec_session_id,
                                 sizeof vec_session_id, vec_share, sizeof vec_share) == hello);
    CHECK(srv_build_server_hello(out, hello - 1, &sel, vec_random, vec_session_id,
                                 sizeof vec_session_id, vec_share, sizeof vec_share) == 0);

    CHECK(srv_build_hello_retry_request(out, retry, &sel, vec_session_id, sizeof vec_session_id,
                                        vec_cookie, sizeof vec_cookie) == retry);
    CHECK(srv_build_hello_retry_request(out, retry - 1, &sel, vec_session_id, sizeof vec_session_id,
                                        vec_cookie, sizeof vec_cookie) == 0);

    CHECK(srv_build_compat_ccs(out, SRV_CCS_RECORD_LEN) == SRV_CCS_RECORD_LEN);
    CHECK(srv_build_compat_ccs(out, SRV_CCS_RECORD_LEN - 1) == 0);

    CHECK(srv_build_encrypted_extensions(out, 6, 0, NULL, NULL, 0) == 6);
    CHECK(srv_build_encrypted_extensions(out, 5, 0, NULL, NULL, 0) == 0);
    CHECK(srv_build_encrypted_extensions(out, 13, 0, NULL, vec_transport_params, 3) == 13);
    CHECK(srv_build_encrypted_extensions(out, 12, 0, NULL, vec_transport_params, 3) == 0);

    static const uint8_t sig[] = {0x01, 0x02, 0x03};
    CHECK(srv_build_certificate_verify(out, 11, SIGALG_ECDSA_P256_SHA256, sig, sizeof sig) == 11);
    CHECK(srv_build_certificate_verify(out, 10, SIGALG_ECDSA_P256_SHA256, sig, sizeof sig) == 0);

    uint8_t verify_data[SHA256_LEN];
    memset(verify_data, 0x5a, sizeof verify_data);
    CHECK(srv_build_finished(out, 4 + SHA256_LEN, verify_data, SHA256_LEN) == 4 + SHA256_LEN);
    CHECK(srv_build_finished(out, 3 + SHA256_LEN, verify_data, SHA256_LEN) == 0);

    CHECK(srv_build_key_update(out, 5, 0) == 5);
    CHECK(srv_build_key_update(out, 4, 0) == 0);

    ch_cert cert = {vec_share, 3};
    ch_identity id;
    memset(&id, 0, sizeof id);
    id.chain = &cert;
    id.chain_count = 1;
    CHECK(srv_build_certificate_header(out, 8, &id) == 8);
    CHECK(srv_build_certificate_header(out, 7, &id) == 0);
    CHECK(srv_build_certificate_entry_prefix(out, 3, 3) == 3);
    CHECK(srv_build_certificate_entry_prefix(out, 2, 3) == 0);
    CHECK(srv_build_certificate_entry_suffix(out, 2) == 2);
    CHECK(srv_build_certificate_entry_suffix(out, 1) == 0);
}

#endif
