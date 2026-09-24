// The handshake messages a ROLE=server build writes, and the record of
// what it selected. It is the mirror of handshake_message.[ch]: every
// builder is a pure function over a caller buffer, writes through the
// wbuf writer (buf.h), and reaches no session, no transcript and no
// socket. srv_flight.c hashes and sends what these return. Only a
// ROLE=server build compiles it. docs/server.md states the role.
//
// One return convention covers every builder here, and it is
// hs_build_client_hello's (handshake_message.h): the call returns the
// byte count it wrote, or 0 when cap is too short for the whole
// message. A builder that returns 0 wrote nothing a caller may use, and
// the bytes at out are undefined; the caller answers
// ALERT_INTERNAL_ERROR, because a staging array too small for a message
// this build writes is a build mistake and not peer input. No builder
// truncates, and none reports a length larger than cap.
//
// Every multi-byte value moves byte by byte through wbuf, so no step
// assumes host endianness, and no builder does raw buffer arithmetic.
#ifndef CH_SRV_MESSAGE_H
#define CH_SRV_MESSAGE_H
#ifdef CH_ROLE_SERVER

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "handshake_message.h"
#include "srv_parser.h"

// The ServerHello.random value that marks a HelloRetryRequest (RFC 9846
// §4.2.3): the SHA-256 of "HelloRetryRequest", a fixed 32 bytes the
// server writes in place of a random value.
//
// The client's copy of the same 32 bytes is hsp_hrr_magic
// (handshake_parser.h), defined in handshake_parser.c, which a
// ROLE=server object does not compile, so a server build cannot link
// it. Two definitions of one constant is one thing with two names,
// which CLAUDE.md forbids; the fix is to move the constant to a file
// both roles compile, the treatment docs/server.md gives
// hrr_transcript and the CertificateVerify signed-content builder. The
// move is owed and is not this header's to make.
extern const uint8_t srv_hrr_random[SRV_RANDOM];

// The legacy_version both the ServerHello and the HelloRetryRequest
// carry, whatever version was negotiated: 0x0303 (RFC 9846 §4.2.3).
// TLS13 (handshake_message.h) is the value supported_versions carries
// beside it.
#define SRV_LEGACY_VERSION 0x0303

// The dummy change_cipher_spec record RFC 9846 Appendix E.4 has the
// server send immediately after its first handshake message
// (rfc9846.txt:6391-6393), which becomes a MUST once the client sent a
// non-empty legacy_session_id (rfc9846.txt:6401-6403). It is a record
// and not a handshake message: six fixed bytes, content type 20,
// legacy_record_version 0x0303, length 1, body 0x01. It never enters
// the transcript, because §4.1 hashes handshake messages and this is
// not one.
#define SRV_CCS_RECORD_LEN 6

// The stack frames srv_flight.c stages a protected message in, each the
// longest message its builder here can write. They sit beside the
// formats that fix them rather than beside the handler that declares
// the array, so a format that grows and a frame that did not are one
// diff and not two.
//
// SRV_CERT_VERIFY_MAX is a 4-byte handshake header, the 2-byte scheme,
// the 2-byte signature length and a signature of at most SRV_SIG_MAX
// bytes. SRV_FINISHED_MAX is a header over one verify_data.
// SRV_ENCRYPTED_EXTENSIONS_MAX is a header and an empty extension block
// (6), record_size_limit (6), and ALPN at this API's longest name
// (7 + CH_ALPN_NAME_MAX). A QUIC server sends no record_size_limit (RFC
// 9001 §4.1.3) and sends the caller's transport parameters in its place
// (§8.2): the type and length words (4) and a body of at most
// CH_TRANSPORT_PARAMS_MAX (cfg.h), which srv_build_encrypted_extensions
// refuses above. This constant first left the QUIC body out, and every
// QUIC server whose body passed about 45 bytes failed its
// EncryptedExtensions with CH_ECAP.
// SRV_CERT_HEAD_LEN and SRV_CERT_SUFFIX_LEN are a Certificate's head and
// one entry's suffix, which srv_certificate_message_len counts as
// SRV_CERT_HEAD and the 2 bytes of SRV_CERT_ENTRY_FRAME.
#define SRV_CERT_VERIFY_MAX (4 + 2 + 2 + SRV_SIG_MAX)
#define SRV_FINISHED_MAX (4 + SHA256_LEN)
#ifdef CH_TRANSPORT_QUIC
#define SRV_ENCRYPTED_EXTENSIONS_MAX (6 + 7 + CH_ALPN_NAME_MAX + 4 + CH_TRANSPORT_PARAMS_MAX)
#else
#define SRV_ENCRYPTED_EXTENSIONS_MAX (6 + 6 + 7 + CH_ALPN_NAME_MAX)
#endif
#define SRV_CERT_HEAD_LEN 8
#define SRV_CERT_SUFFIX_LEN 2

// What the server selected for one connection, written by srv_select
// (srv_flight.h) and read by the builders here, by srv_cookie.c and by
// srv_auth.c. Every member holds a value the peer will see in the
// clear, so no member is secret and every branch on one is public.
typedef struct {
    // The cipher suite, as a code point on the wire:
    // SUITE_CHACHA20_POLY1305_SHA256 (handshake_message.h), or under
    // -DCH_SUITE_AES_GCM SUITE_AES_128_GCM_SHA256 from a client that
    // offers no ChaCha20 (srv_select). Every record direction the server
    // keys runs it.
    uint16_t suite;

    // The transcript hash length the suite fixes
    // (rfc9846.txt:4055-4056), in bytes: SHA256_LEN under the suite
    // above, and 48 under TLS_AES_256_GCM_SHA384 when that suite
    // arrives. The member exists now so the key schedule, the cookie
    // and the Finished read one value rather than a constant that
    // would have to be hunted down later.
    uint8_t hash_len;

    // The NamedGroup of the key exchange, CH_KEX_GROUP
    // (handshake_message.h) in every build today.
    uint16_t group;

    // The SignatureScheme the CertificateVerify will carry:
    // SIGALG_ECDSA_P256_SHA256 or SIGALG_RSA_PSS_RSAE_SHA256
    // (handshake_message.h). It names the signing identity too, through
    // srv_identity_for (srv_auth.h), so the selection holds no second
    // member for the slot.
    uint16_t sigalg;

    // Set when the client named a group this build holds and sent no
    // KeyShareEntry for it, which RFC 9846 §4.2.1 makes the one
    // condition that requires a HelloRetryRequest
    // (rfc9846.txt:1158-1161, rfc9846.txt:1446-1449). It is never set
    // on a second ClientHello: the state machine has one retry by call
    // position, and srv_check_retry_hello is the only reader after the
    // first hello.
    uint8_t need_retry;

    // Set when a PSK authenticates this handshake, in which case the
    // server sends no Certificate and no CertificateVerify.
    //
    // It is 0 in every handshake this build runs. Whether a v1 server
    // accepts PSKs and issues tickets is docs/server.md's open
    // question five, so every handshake authenticates with a
    // certificate, which RFC 9846 permits: a server that selects no
    // PSK simply sends no pre_shared_key in its ServerHello. The
    // member exists so the PSK lane drops in without reshaping this
    // struct or the flight above it.
    uint8_t psk_selected;
} selection;

// Builds one ServerHello, handshake header included (RFC 9846 §4.2.3).
// It writes legacy_version SRV_LEGACY_VERSION, the 32 random bytes,
// legacy_session_id_echo copied from the client's legacy_session_id
// whatever its length (rfc9846.txt:1365-1368), sel->suite,
// legacy_compression_method 0, and two extensions:
// supported_versions carrying TLS13, and key_share carrying sel->group
// and the server's own share.
//
// Requires cap bytes at out; random32 pointing at SRV_RANDOM readable
// bytes the caller drew through ch_rand_bytes; session_id pointing at
// session_id_len readable bytes, 0 to SRV_SESSION_ID_MAX of them, the
// bytes the ClientHello carried; share pointing at share_len readable
// bytes, the server's KeyShareEntry.key_exchange, which is
// CH_KEX_SERVER_SHARE bytes (handshake_message.h).
//
// The caller passes a random value it drew for this message and never
// srv_hrr_random: a ServerHello carrying that value is a
// HelloRetryRequest, and srv_build_hello_retry_request is the call
// that writes one.
//
// Returns the message length in bytes, or 0 when cap is short.
size_t srv_build_server_hello(uint8_t *out, size_t cap, const selection *sel,
                              const uint8_t random32[SRV_RANDOM], const uint8_t *session_id,
                              size_t session_id_len, const uint8_t *share, size_t share_len);

// Builds one HelloRetryRequest, handshake header included (RFC 9846
// §4.2.4). The message has the ServerHello's format, and
// legacy_version, legacy_session_id_echo, cipher_suite and
// legacy_compression_method have the same meaning there
// (rfc9846.txt:1449-1452), so this builder writes the same fields with
// srv_hrr_random in place of the random value. Its extensions are
// supported_versions carrying TLS13, key_share carrying sel->group as
// a bare NamedGroup and no key, and cookie carrying the bytes
// srv_cookie_mint produced.
//
// The cookie is not optional here. A HelloRetryRequest that changes
// nothing the client offered is one the client aborts with
// illegal_parameter, and a stateless server needs the cookie to carry
// Hash(ClientHello1) forward (rfc9846.txt:1779-1783), so a caller that
// passes cookie_len 0 gets a message no conformant client accepts.
//
// Requires cap bytes at out; session_id and session_id_len as
// srv_build_server_hello takes them; cookie pointing at cookie_len
// readable bytes.
//
// Returns the message length in bytes, or 0 when cap is short.
size_t srv_build_hello_retry_request(uint8_t *out, size_t cap, const selection *sel,
                                     const uint8_t *session_id, size_t session_id_len,
                                     const uint8_t *cookie, size_t cookie_len);

// Writes the six bytes of the dummy change_cipher_spec record
// (rfc9846.txt:6391-6393). It is a record, so the caller sends it
// without sealing it and without adding it to the transcript.
//
// Requires cap bytes at out.
//
// Returns SRV_CCS_RECORD_LEN, or 0 when cap is below it.
size_t srv_build_compat_ccs(uint8_t *out, size_t cap);

// Builds one EncryptedExtensions, handshake header included (RFC 9846
// §4.4.1). It carries the extensions that apply to the connection and
// are not needed to establish the keys, and this server sends at most
// three of them: record_size_limit (RFC 8449) when record_size_limit is
// not 0, application_layer_protocol_negotiation (RFC 7301 §3.2) when
// selected is not NULL, and quic_transport_parameters (RFC 9001 §8.2,
// rfc9001.txt:1922-1924) when transport_params is not NULL.
//
// It sends no early_data extension, whatever the ClientHello offered,
// and that absence is what rejects 0-RTT (rfc9846.txt:2426-2428). It
// sends no supported_groups, which RFC 9846 §4.3.7 makes a SHOULD
// (rfc9846.txt:2122-2127) and this build declines. It echoes no
// server_name: the caller reads the name the client sent and the
// server binds nothing to it.
//
// The transport-parameters body is the caller's own encoded bytes and
// this builder reads none of them: RFC 9001 §8.2 makes their content
// the QUIC version's, not TLS's (rfc9001.txt:1926-1928). It is the
// server's half of what ch_cfg.transport_params is for the client, so
// the two directions share one field name and one cap. A TRANSPORT=tls
// or TRANSPORT=record server passes NULL here, because §8.2 forbids the
// extension on a transport that is not QUIC (rfc9001.txt:1945-1949). A
// QUIC server passes cfg.transport_params and its length, and
// SRV_ENCRYPTED_EXTENSIONS_MAX holds the largest of them.
//
// Requires cap bytes at out; record_size_limit holding the largest
// plaintext this server accepts in one record, sized to cfg.buf_len,
// or 0 to send no extension; selected pointing at the one
// ch_alpn_protocol the server chose out of cfg.alpn_protocols, or NULL
// when no protocol was negotiated; transport_params pointing at
// transport_params_len readable bytes, or NULL to send no extension,
// with the length read only when the pointer is not NULL.
//
// Returns the message length in bytes, or 0 when cap is short. A
// message with no extensions at all is legal and is 6 bytes: the
// 4-byte handshake header and a 2-byte empty extension block. It also
// returns 0, and writes nothing, for a transport_params_len above
// CH_TRANSPORT_PARAMS_MAX (cfg.h), which is caller error rather than a
// short buffer; srv_build_certificate_entry_prefix reports its own
// length refusal the same way.
size_t srv_build_encrypted_extensions(uint8_t *out, size_t cap, uint16_t record_size_limit,
                                      const ch_alpn_protocol *selected,
                                      const uint8_t *transport_params, size_t transport_params_len);

// The byte count the whole Certificate message occupies, header
// included, for one identity's chain (RFC 9846 §4.5.1). It is 4 bytes
// of handshake header, 1 byte of certificate_request_context length, 3
// bytes of certificate_list length, and then per entry 3 bytes of
// cert_data length, the certificate itself, and 2 bytes of an empty
// extensions vector.
//
// srv_send_certificate needs this count before it writes the first
// fragment, because the handshake header carries the whole message's
// length and the chain never sits in one buffer: the message is
// emitted in fragments sized to the peer's record limit
// (rfc9846.txt:3460-3462) and the chain stays in the caller's flash.
//
// Requires an identity whose chain points at chain_count entries.
//
// Returns the count, which is 8 for an identity with no entries. An
// empty certificate_list is not a message this server sends: RFC 9846
// §4.5.1 requires the end-entity certificate first
// (rfc9846.txt:2850-2851) and forbids an empty list
// (rfc9846.txt:2876), so srv_identity_for declines an unprovisioned
// slot and no caller reaches this function with one.
size_t srv_certificate_message_len(const ch_identity *id);

// Writes the fixed head of a Certificate message: the 4-byte handshake
// header whose length field is srv_certificate_message_len minus 4, a
// zero-length certificate_request_context, and the 3-byte
// certificate_list length. The context is empty because this server
// sent no CertificateRequest, which RFC 9846 §4.5.1 requires of a
// Certificate sent in reply to a ClientHello.
//
// Requires cap bytes at out and the identity srv_certificate_message_len
// was asked about.
//
// Returns the byte count written, which is 8, or 0 when cap is short.
size_t srv_build_certificate_header(uint8_t *out, size_t cap, const ch_identity *id);

// Writes the 3-byte cert_data length that precedes one certificate's
// DER inside the certificate_list.
//
// Requires cap bytes at out and a cert_len below 2^24.
//
// Returns the byte count written, which is 3, or 0 when cap is short
// or cert_len does not fit in three bytes.
size_t srv_build_certificate_entry_prefix(uint8_t *out, size_t cap, size_t cert_len);

// Writes the 2-byte empty extensions vector that follows one
// certificate's DER. Every entry carries one, including the last
// (RFC 9846 §4.5.1). This server sends no certificate extension:
// status_request is a MAY it declines (docs/server.md, "What the
// server declines, conformantly").
//
// Requires cap bytes at out.
//
// Returns the byte count written, which is 2, or 0 when cap is short.
size_t srv_build_certificate_entry_suffix(uint8_t *out, size_t cap);

// Builds one CertificateVerify, handshake header included (RFC 9846
// §4.5.2): the two-byte SignatureScheme and the signature as an opaque
// vector.
//
// It writes the signature it is given and judges nothing about it. The
// content that was signed is srv_hash_signed_content's (srv_auth.h),
// and the signature itself comes from the identity's signer.
//
// Requires cap bytes at out; sigalg holding sel->sigalg; sig pointing
// at sig_len readable bytes, with sig_len from 1 to 65535.
//
// Returns the message length in bytes, or 0 when cap is short or
// sig_len is 0 or above 65535.
size_t srv_build_certificate_verify(uint8_t *out, size_t cap, uint16_t sigalg, const uint8_t *sig,
                                    size_t sig_len);

// Builds one Finished, handshake header included (RFC 9846 §4.5.3):
// the verify_data and nothing else. Its length is the hash length the
// suite fixed, so the message is 4 + hash_len bytes
// (rfc9846.txt:3141-3143 states the same shape for the client's).
//
// Requires cap bytes at out; verify_data pointing at hash_len readable
// bytes, the value ks_verify_data (keysched.h) computed from the
// server handshake traffic secret; hash_len holding sel->hash_len.
//
// Returns the message length in bytes, or 0 when cap is short.
size_t srv_build_finished(uint8_t *out, size_t cap, const uint8_t *verify_data, size_t hash_len);

// Builds one KeyUpdate, handshake header included (RFC 9846 §4.7.3):
// one byte of request_update.
//
// The server both answers and initiates. RFC 9846 §4.7.3 requires an
// endpoint that receives a KeyUpdate with request_update set to
// update_requested to send one of its own with update_not_requested
// (rfc9846.txt:3362-3365 covers the byte's two legal values), and
// handshake_post.c already holds that one-response rule for the
// client, in a direction-neutral form.
//
// Requires cap bytes at out and a request_update of 0
// (update_not_requested) or 1 (update_requested).
//
// Returns the message length in bytes, which is 5, or 0 when cap is
// short or request_update is neither value.
size_t srv_build_key_update(uint8_t *out, size_t cap, uint8_t request_update);

#endif // CH_ROLE_SERVER
#endif
