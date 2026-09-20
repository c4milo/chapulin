// The handshake messages a ROLE=server build writes. srv_message.h states the
// contract every builder keeps: a pure function over one caller buffer, every
// byte through the wbuf writer (buf.h), and a return of the byte count written
// or 0 when cap is too short for the whole message.
//
// One definition here is not a builder, because a constant has nothing to
// write: srv_hrr_random holds the 32 bytes RFC 9846 §4.1.3 fixes, the same
// bytes handshake_parser.c:12-14 defines as hsp_hrr_magic for the client. A
// ROLE=server object does not compile that file, so it cannot link the
// client's copy. srv_message.h records that the duplication is owed a move to
// a file both roles compile.
#include "srv_message.h"

#ifdef CH_ROLE_SERVER

#include "buf.h"
#include "record.h"

const uint8_t srv_hrr_random[SRV_RANDOM] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

// The byte counts of the two fixed parts of a Certificate message
// (RFC 9846 §4.4.2), which srv_certificate_message_len adds up and
// srv_build_certificate_header writes.
//
// SRV_CERT_HEAD is the 4-byte handshake header, the 1-byte
// certificate_request_context length and the 3-byte certificate_list length.
// SRV_CERT_ENTRY_FRAME is the 3-byte cert_data length and the 2-byte empty
// extensions vector that bracket one certificate's DER.
#define SRV_CERT_HEAD 8
#define SRV_CERT_ENTRY_FRAME 5

// The largest value a 3-byte length field on the wire can carry. A cert_data
// length above it names no message, which is what
// srv_build_certificate_entry_prefix refuses.
#define SRV_U24_MAX 0xFFFFFFu

// The fields a ServerHello and a HelloRetryRequest both carry, in the order
// RFC 9846 §4.1.3 lists them. §4.1.4 gives the HelloRetryRequest the
// ServerHello's format and these five fields the same meaning
// (rfc9846.txt:1449-1452), so one writer serves both messages and the random
// value is the only thing the two callers pass differently.
//
// legacy_session_id_echo carries a one-byte length. srv_parse_client_hello
// refuses a legacy_session_id over SRV_SESSION_ID_MAX, which is 32, so the
// cast is in range for every caller that passes the bytes one ClientHello
// carried.
static void write_hello_head(wbuf *w, const selection *sel, const uint8_t *random32,
                             const uint8_t *session_id, size_t session_id_len) {
    wb_u16(w, SRV_LEGACY_VERSION);
    wb_bytes(w, random32, SRV_RANDOM);
    wb_u8(w, (uint8_t)session_id_len);
    wb_bytes(w, session_id, session_id_len);
    wb_u16(w, sel->suite);
    wb_u8(w, 0); // legacy_compression_method
}

// The supported_versions extension both messages carry (RFC 9846 §4.2.1). A
// server writes the one selected_version and not a list, so the body is two
// bytes wide whichever message carries it.
static void write_supported_versions(wbuf *w) {
    wb_u16(w, EXT_SUPPORTED_VERSIONS);
    wb_u16(w, 2);
    wb_u16(w, TLS13);
}

size_t srv_build_server_hello(uint8_t *out, size_t cap, const selection *sel,
                              const uint8_t random32[SRV_RANDOM], const uint8_t *session_id,
                              size_t session_id_len, const uint8_t *share, size_t share_len) {
    wbuf w;
    wb_init(&w, out, cap);

    wb_u8(&w, HS_SERVER_HELLO);
    size_t msg = wb_mark(&w, 3);
    write_hello_head(&w, sel, random32, session_id, session_id_len);

    size_t exts = wb_mark(&w, 2);
    write_supported_versions(&w);

    // key_share carrying the server's own KeyShareEntry (RFC 9846 §4.2.8):
    // the group, then the key_exchange bytes behind a two-byte length. The
    // caller passes CH_KEX_SERVER_SHARE bytes, which is 32 in a classic build
    // and 1120 under KEX=pq, so both length casts are in range.
    wb_u16(&w, EXT_KEY_SHARE);
    wb_u16(&w, (uint16_t)(2 + 2 + share_len));
    wb_u16(&w, sel->group);
    wb_u16(&w, (uint16_t)share_len);
    wb_bytes(&w, share, share_len);

    wb_patch16(&w, exts);
    wb_patch24(&w, msg);
    return w.err ? 0 : w.len;
}

size_t srv_build_hello_retry_request(uint8_t *out, size_t cap, const selection *sel,
                                     const uint8_t *session_id, size_t session_id_len,
                                     const uint8_t *cookie, size_t cookie_len) {
    wbuf w;
    wb_init(&w, out, cap);

    wb_u8(&w, HS_SERVER_HELLO);
    size_t msg = wb_mark(&w, 3);
    write_hello_head(&w, sel, srv_hrr_random, session_id, session_id_len);

    size_t exts = wb_mark(&w, 2);
    write_supported_versions(&w);

    // key_share carrying the group and no key (RFC 9846 §4.2.8): a
    // HelloRetryRequest's KeyShare body is the selected_group alone, which is
    // what names the group the second ClientHello must send a share for.
    wb_u16(&w, EXT_KEY_SHARE);
    wb_u16(&w, 2);
    wb_u16(&w, sel->group);

    // cookie (RFC 9846 §4.2.2), the bytes srv_cookie_mint produced. A mint
    // returns at most SRV_COOKIE_MAX bytes, which is 117, so both length casts
    // are in range.
    wb_u16(&w, EXT_COOKIE);
    wb_u16(&w, (uint16_t)(2 + cookie_len));
    wb_u16(&w, (uint16_t)cookie_len);
    wb_bytes(&w, cookie, cookie_len);

    wb_patch16(&w, exts);
    wb_patch24(&w, msg);
    return w.err ? 0 : w.len;
}

size_t srv_build_compat_ccs(uint8_t *out, size_t cap) {
    wbuf w;
    wb_init(&w, out, cap);

    // A record and not a handshake message: content type,
    // legacy_record_version, a length of 1 and the single byte 0x01.
    wb_u8(&w, REC_CCS);
    wb_u16(&w, SRV_LEGACY_VERSION);
    wb_u16(&w, 1);
    wb_u8(&w, 1);

    return w.err ? 0 : w.len;
}

size_t srv_build_encrypted_extensions(uint8_t *out, size_t cap, uint16_t record_size_limit,
                                      const ch_alpn_protocol *selected,
                                      const uint8_t *transport_params,
                                      size_t transport_params_len) {
    if (transport_params_len > CH_TRANSPORT_PARAMS_MAX) {
        return 0;
    }
    wbuf w;
    wb_init(&w, out, cap);

    wb_u8(&w, HS_ENCRYPTED_EXTENSIONS);
    size_t msg = wb_mark(&w, 3);
    size_t exts = wb_mark(&w, 2);

    // record_size_limit (RFC 8449 §4), the largest plaintext this server
    // accepts in one record. A caller that passes 0 sends no extension and
    // takes the 2^14 default.
    if (record_size_limit != 0) {
        wb_u16(&w, EXT_RECORD_SIZE_LIMIT);
        wb_u16(&w, 2);
        wb_u16(&w, record_size_limit);
    }

    // application_layer_protocol_negotiation (RFC 7301 §3.2): a
    // ProtocolNameList holding the one name the server selected.
    // ch_srv_accept holds every offered name to CH_ALPN_NAME_MAX bytes, which
    // is 32, so both length casts are in range.
    if (selected != NULL) {
        wb_u16(&w, EXT_ALPN);
        wb_u16(&w, (uint16_t)(2 + 1 + selected->name_len));
        wb_u16(&w, (uint16_t)(1 + selected->name_len));
        wb_u8(&w, (uint8_t)selected->name_len);
        wb_bytes(&w, selected->name, selected->name_len);
    }

    // quic_transport_parameters (RFC 9001 §8.2, rfc9001.txt:1922-1924):
    // the caller's encoded body, written unread, because its content
    // belongs to the QUIC version in use (rfc9001.txt:1926-1928). The
    // length check above holds it to CH_TRANSPORT_PARAMS_MAX, which is
    // 256, so the cast is in range. A caller that passes NULL sends no
    // extension, which is what every build in this tree does: §8.2
    // forbids the extension on a transport that is not QUIC
    // (rfc9001.txt:1945-1949) and srv_cfg.h refuses ROLE=server with
    // CH_TRANSPORT_QUIC, so no ch_cfg here carries a body to pass.
    if (transport_params != NULL) {
        wb_u16(&w, EXT_QUIC_TRANSPORT_PARAMS);
        wb_u16(&w, (uint16_t)transport_params_len);
        wb_bytes(&w, transport_params, transport_params_len);
    }

    wb_patch16(&w, exts);
    wb_patch24(&w, msg);
    return w.err ? 0 : w.len;
}

size_t srv_certificate_message_len(const ch_identity *id) {
    size_t n = SRV_CERT_HEAD;
    for (uint8_t i = 0; i < id->chain_count; i++) {
        n += SRV_CERT_ENTRY_FRAME + id->chain[i].len;
    }
    return n;
}

size_t srv_build_certificate_header(uint8_t *out, size_t cap, const ch_identity *id) {
    size_t total = srv_certificate_message_len(id);
    wbuf w;
    wb_init(&w, out, cap);

    wb_u8(&w, HS_CERTIFICATE);
    wb_u24(&w, (uint32_t)(total - 4));
    wb_u8(&w, 0); // certificate_request_context: empty, no CertificateRequest
    wb_u24(&w, (uint32_t)(total - SRV_CERT_HEAD));

    return w.err ? 0 : w.len;
}

size_t srv_build_certificate_entry_prefix(uint8_t *out, size_t cap, size_t cert_len) {
    if (cert_len > SRV_U24_MAX) {
        return 0;
    }
    wbuf w;
    wb_init(&w, out, cap);
    wb_u24(&w, (uint32_t)cert_len);
    return w.err ? 0 : w.len;
}

size_t srv_build_certificate_entry_suffix(uint8_t *out, size_t cap) {
    wbuf w;
    wb_init(&w, out, cap);
    wb_u16(&w, 0); // extensions: empty, for this entry and every other
    return w.err ? 0 : w.len;
}

size_t srv_build_certificate_verify(uint8_t *out, size_t cap, uint16_t sigalg, const uint8_t *sig,
                                    size_t sig_len) {
    if (sig_len == 0 || sig_len > UINT16_MAX) {
        return 0;
    }
    wbuf w;
    wb_init(&w, out, cap);

    wb_u8(&w, HS_CERTIFICATE_VERIFY);
    size_t msg = wb_mark(&w, 3);
    wb_u16(&w, sigalg);
    wb_u16(&w, (uint16_t)sig_len);
    wb_bytes(&w, sig, sig_len);
    wb_patch24(&w, msg);

    return w.err ? 0 : w.len;
}

size_t srv_build_finished(uint8_t *out, size_t cap, const uint8_t *verify_data, size_t hash_len) {
    wbuf w;
    wb_init(&w, out, cap);

    wb_u8(&w, HS_FINISHED);
    size_t msg = wb_mark(&w, 3);
    wb_bytes(&w, verify_data, hash_len);
    wb_patch24(&w, msg);

    return w.err ? 0 : w.len;
}

size_t srv_build_key_update(uint8_t *out, size_t cap, uint8_t request_update) {
    if (request_update > 1) {
        return 0;
    }
    wbuf w;
    wb_init(&w, out, cap);

    wb_u8(&w, HS_KEY_UPDATE);
    wb_u24(&w, 1);
    wb_u8(&w, request_update);

    return w.err ? 0 : w.len;
}

#endif // CH_ROLE_SERVER
