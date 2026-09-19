// Stub only. srv_message.h states the contract; no line below implements it.
// srv_parser.c states what the CH_SRV_STUB marker means and which gate reads it.
//
// One definition here is not a stub, because a constant has nothing to refuse:
// srv_hrr_random holds the 32 bytes RFC 9846 §4.1.3 fixes, the same bytes
// handshake_parser.c:12-14 defines as hsp_hrr_magic for the client. srv_message.h
// records that the duplication is owed a move to a file both roles compile.
#include "srv_message.h"

#ifdef CH_ROLE_SERVER

const uint8_t srv_hrr_random[SRV_RANDOM] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

size_t srv_build_server_hello(uint8_t *out, size_t cap, const selection *sel,
                              const uint8_t random32[SRV_RANDOM], const uint8_t *session_id,
                              size_t session_id_len, const uint8_t *share, size_t share_len) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)out;
    (void)cap;
    (void)sel;
    (void)random32;
    (void)session_id;
    (void)session_id_len;
    (void)share;
    (void)share_len;
    return 0;
}

size_t srv_build_hello_retry_request(uint8_t *out, size_t cap, const selection *sel,
                                     const uint8_t *session_id, size_t session_id_len,
                                     const uint8_t *cookie, size_t cookie_len) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)out;
    (void)cap;
    (void)sel;
    (void)session_id;
    (void)session_id_len;
    (void)cookie;
    (void)cookie_len;
    return 0;
}

size_t srv_build_compat_ccs(uint8_t *out, size_t cap) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)out;
    (void)cap;
    return 0;
}

size_t srv_build_encrypted_extensions(uint8_t *out, size_t cap, uint16_t record_size_limit,
                                      const ch_alpn_protocol *selected) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)out;
    (void)cap;
    (void)record_size_limit;
    (void)selected;
    return 0;
}

size_t srv_certificate_message_len(const ch_identity *id) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)id;
    // 0 is below the 8 bytes an empty message occupies, so a caller that used it
    // would write a header no message follows.
    return 0;
}

size_t srv_build_certificate_header(uint8_t *out, size_t cap, const ch_identity *id) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)out;
    (void)cap;
    (void)id;
    return 0;
}

size_t srv_build_certificate_entry_prefix(uint8_t *out, size_t cap, size_t cert_len) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)out;
    (void)cap;
    (void)cert_len;
    return 0;
}

size_t srv_build_certificate_entry_suffix(uint8_t *out, size_t cap) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)out;
    (void)cap;
    return 0;
}

size_t srv_build_certificate_verify(uint8_t *out, size_t cap, uint16_t sigalg, const uint8_t *sig,
                                    size_t sig_len) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)out;
    (void)cap;
    (void)sigalg;
    (void)sig;
    (void)sig_len;
    return 0;
}

size_t srv_build_finished(uint8_t *out, size_t cap, const uint8_t *verify_data, size_t hash_len) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)out;
    (void)cap;
    (void)verify_data;
    (void)hash_len;
    return 0;
}

size_t srv_build_key_update(uint8_t *out, size_t cap, uint8_t request_update) {
    // CH_SRV_STUB: not implemented yet; this call fails closed and writes nothing.
    (void)out;
    (void)cap;
    (void)request_update;
    return 0;
}

#endif // CH_ROLE_SERVER
