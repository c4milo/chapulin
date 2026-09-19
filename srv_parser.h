// The ClientHello parser, and the wire constants a ROLE=server build
// reads. It is the mirror of handshake_parser.[ch] on the other side of
// the connection: a pure function over one caller buffer, with no I/O
// and no session state, so proof, fuzz and strictness builds reach it
// without the state machine. srv_flight.c decides what the result
// means. Only a ROLE=server build compiles it. docs/server.md states
// the role.
//
// It inverts the client's habit at exactly one point, and that point is
// the sharpest behavioral difference in the role. RFC 9846 §4.2.2 reads
// "Servers MUST ignore unrecognized extensions" (rfc9846.txt:1299), and
// §9.3 restates it as a protocol invariant (rfc9846.txt:4636-4637), so
// the extension loop's default arm skips an unknown extension by its
// own length and keeps negotiating. The client refuses on the same
// input: server_hello_ext_bit returns 0 for a type it does not know
// (handshake_parser.c:29) and its caller answers CH_EPROTO
// (handshake_parser.c:90-91). srv_ext_known below is the named
// predicate that draws the line, so a reader sees which side of it a
// type falls on without reading the loop.
//
// Every byte this file reads arrives before any key exists and before
// the peer has proved anything, so nothing here is secret: the parser
// takes no constant-time obligation, and every branch in it reads a
// value the client sent in the clear.
//
// All reading goes through the rbuf reader (buf.h). No raw buffer
// arithmetic exists here, and every multi-byte value moves byte by
// byte, so no step assumes host endianness.
#ifndef CH_SRV_PARSER_H
#define CH_SRV_PARSER_H
#ifdef CH_ROLE_SERVER

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "handshake_message.h"
#include "sha256.h"

// The ClientHello fields whose sizes RFC 9846 fixes.
//
// SRV_RANDOM is ClientHello.random, 32 bytes (rfc9846.txt:1358-1363
// gives the ServerHello's, and §4.1.2 gives the client's the same
// width). SRV_SESSION_ID_MAX is legacy_session_id, 0 to 32 bytes; the
// server echoes it whole in legacy_session_id_echo
// (rfc9846.txt:1365-1368) and it must survive a HelloRetryRequest
// (rfc9846.txt:1451), so the session holds a copy rather than a pointer
// into a buffer the next record overwrites.
#define SRV_RANDOM 32
#define SRV_SESSION_ID_MAX 32

// The cipher suites this build can select, one bit each, as
// srv_parse_client_hello reports the client's offer and srv_select
// reads it. A bit is set when the ClientHello listed that suite; a
// suite this build does not hold has no bit and its code point falls
// through the same ignore rule an unknown extension takes.
//
// One bit is defined today. RFC 9846 §9.1 names three suites
// (rfc9846.txt:4540-4543) and this build offers the first of them,
// TLS_CHACHA20_POLY1305_SHA256, alone. The other two are AEAD_AES_128_GCM
// and AEAD_AES_256_GCM, and this tree holds no AES a traffic key may
// reach: the only AES here is the software S-box table in quic_aes.c,
// admitted because QUIC Initial keys are public, and a TLS traffic key
// is secret, so that table would leak it through cache timing. Until a
// constant-time AES exists, this server does not meet §9.1 and no
// comment in this file claims it does. The two suites drop in as
// SRV_SUITE_AES_128_GCM and SRV_SUITE_AES_256_GCM beside this bit, with
// no other declaration in this header changing: selection.suite already
// carries the code point and selection.hash_len already carries the
// length the suite fixes (rfc9846.txt:4055-4056).
#define SRV_SUITE_CHACHA20_POLY1305 0x01

// The key exchange groups this build can select, one bit each, read
// from the client's supported_groups and from its key_share. One bit is
// defined per build, because the KEX axis holds the client's rule here
// too: a build offers x25519, or the X25519MLKEM768 hybrid under
// KEX=pq, and never both. CH_KEX_GROUP (handshake_message.h) is the
// code point this bit stands for. RFC 9846 §9.1 makes secp256r1 a MUST
// (rfc9846.txt:4548-4549), which this build does not meet either: the
// P-256 this tree holds is verify-only and variable time (p256.h), so a
// server key exchange over it needs the constant-time arithmetic
// docs/server.md prices under "p256_field.[ch]". That group drops in as
// a second bit and changes nothing else here.
#define SRV_GROUP_KEX 0x01

// The signature schemes this build can sign a CertificateVerify with,
// one bit each, read from the client's signature_algorithms. Both are
// RFC 9846 §9.1 CertificateVerify obligations (rfc9846.txt:4545-4547),
// and each one names the ch_identity slot that signs it: ecdsa_p256
// signs SRV_SIGALG_ECDSA_P256 and rsa_pss signs SRV_SIGALG_RSA_PSS. A
// slot the caller left unprovisioned makes the server decline that
// scheme, which srv_identity_for (srv_auth.h) reports.
//
// rsa_pkcs1_sha256 is absent on purpose and is not an omission. RFC
// 9846 §4.3.3 says the RSASSA-PKCS1-v1_5 code points "refer solely to
// signatures which appear in certificates ... and are not defined for
// use in signed TLS handshake messages" (rfc9846.txt:1882-1884), so no
// bit exists for a scheme that can never sign this message.
#define SRV_SIGALG_ECDSA_P256 0x01
#define SRV_SIGALG_RSA_PSS 0x02

// The recognized extensions, one bit each, in seen. The parser sets a
// bit when it has read that extension's body, and reads the mask after
// the loop to answer the two questions a single pass cannot: which
// required extension never arrived (rfc9846.txt:4595-4605), and whether
// the key exchange halves agree (rfc9846.txt:4599-4605). An extension
// outside this list is skipped by its length and sets no bit, which is
// §4.2.2's ignore rule (rfc9846.txt:1299).
#define SRV_EXT_SERVER_NAME 0x0001
#define SRV_EXT_SUPPORTED_GROUPS 0x0002
#define SRV_EXT_SIGNATURE_ALGORITHMS 0x0004
#define SRV_EXT_ALPN 0x0008
#define SRV_EXT_RECORD_SIZE_LIMIT 0x0010
#define SRV_EXT_PRE_SHARED_KEY 0x0020
#define SRV_EXT_SUPPORTED_VERSIONS 0x0040
#define SRV_EXT_COOKIE 0x0080
#define SRV_EXT_PSK_MODES 0x0100
#define SRV_EXT_KEY_SHARE 0x0200
#define SRV_EXT_EARLY_DATA 0x0400
#define SRV_EXT_PADDING 0x0800

// The two extension code points handshake_message.h does not declare,
// because no client this tree builds sends either one. early_data is
// RFC 9846 §4.2.10 and padding is RFC 7685; the server recognizes both
// so that §4.1.2's freeze rule can exclude them, and it acts on
// neither.
#define EXT_PADDING 21
#define EXT_EARLY_DATA 42

// The psk_key_exchange_modes values (RFC 9846 §4.2.9). The server must
// select a mode the client listed (rfc9846.txt:1150-1152), and
// psk_dhe_ke is the only one this build would ever select, because it
// runs a key exchange in every handshake.
#define SRV_PSK_KE 0x01
#define SRV_PSK_DHE_KE 0x02

// Everything srv_parse_client_hello learns from one ClientHello. The
// caller zeroes it; the parser fills it and reads none of it back.
//
// Three members point into the caller's message rather than copying:
// share, cookie and server_name. Each pointer dies at the next call
// that writes cfg.buf, the same lifetime handshake_parser.h gives
// server_hello_info.cookie, so whoever keeps one of those values copies
// it first. session_id is copied because it must outlive a
// HelloRetryRequest round trip (rfc9846.txt:1451).
typedef struct {
    uint8_t random[SRV_RANDOM];
    uint8_t session_id[SRV_SESSION_ID_MAX];
    uint8_t session_id_len;

    // The offer, reduced to what this build knows, as the bit lists
    // above define. A client that offers nothing this build holds
    // leaves the member at 0, and srv_select answers handshake_failure
    // (rfc9846.txt:1181-1184).
    uint8_t suites;
    uint8_t groups;  // from supported_groups
    uint8_t shares;  // from key_share: which group a KeyShareEntry carried
    uint8_t sigalgs; // from signature_algorithms

    // The KeyShareEntry.key_exchange bytes for the group this build
    // holds, and their length. NULL and 0 when the client sent no share
    // for that group, which is the input a HelloRetryRequest answers.
    // The parser checks the length against CH_KEX_CLIENT_SHARE
    // (handshake_message.h) and refuses any other, so a caller that
    // reads share_len reads a value it already knows.
    const uint8_t *share;
    size_t share_len;

    // The cookie extension the client echoed, which is present only in
    // a second ClientHello (rfc9846.txt:1444). srv_check_retry_hello
    // opens it with srv_cookie_open.
    const uint8_t *cookie;
    size_t cookie_len;

    // The one HostName of a server_name extension (RFC 6066 §3), with
    // no NUL. srv_read_client_hello copies it into cfg.srv.sni_buf when it
    // fits. The server reads no meaning from it: it holds no
    // certificate index and selects no identity by name.
    const uint8_t *server_name;
    size_t server_name_len;

    // The application protocol the server selected out of the client's
    // ALPN list: the index in cfg.alpn_protocols of the first offered
    // name the client also listed, or CH_ALPN_NONE (cfg.h) when the
    // caller offered none, when the client sent no ALPN extension, or
    // when the two lists do not intersect. The server's own preference
    // order decides, so the parser walks cfg.alpn_protocols outward and
    // the client's list inward.
    uint8_t alpn_selected;

    // The peer's record_size_limit (RFC 8449), or 0 when the extension
    // was absent. It is the largest plaintext the server may put in one
    // record, and 0 means the 2^14 default applies.
    uint16_t record_size_limit;

    // Which psk_key_exchange_modes values the client listed, as the
    // SRV_PSK_ bits above, and 0 when the extension was absent.
    uint8_t psk_modes;

    // Where the pre_shared_key extension's binder list starts, counted
    // in bytes from the start of body, and 0 when the client offered no
    // PSK. RFC 9846 §4.2.11.2 computes the binder over the ClientHello
    // truncated at exactly that point (rfc9846.txt:2586 states the
    // client's half of the same rule), so the byte count is the one
    // value a binder check cannot recover afterwards.
    //
    // This build selects no PSK and verifies no binder: whether a v1
    // server accepts PSKs and issues tickets is docs/server.md's open
    // question five, and until it is answered every handshake
    // authenticates with a certificate. The member is written anyway,
    // so the PSK lane drops in without reshaping this struct, and
    // selection.psk_selected stays 0 meanwhile.
    size_t truncated_len;

    // The recognized extensions this message carried, as the SRV_EXT_
    // bits above.
    uint16_t seen;

    // SHA-256 over the ClientHello fields RFC 9846 §4.1.2 forbids the
    // client to change across a HelloRetryRequest
    // (rfc9846.txt:1191-1213), accumulated as the parser walks. The
    // cookie the server mints carries this digest, and the second
    // ClientHello's digest is compared against it with ct_memeq, which
    // is how a stateless server checks the freeze rule without storing
    // the first message. The digest covers every byte of the message
    // except the five things §4.1.2 permits a second ClientHello to
    // change: the key_share the HelloRetryRequest asked for, an
    // early_data extension the second hello removes, the cookie the
    // second hello adds, the pre_shared_key extension, and the padding
    // extension's length.
    uint8_t frozen[SHA256_LEN];
} client_hello;

// Whether this build's extension loop recognizes a ClientHello
// extension type, which is the one line that separates §4.2.2's ignore
// rule from every check above it (rfc9846.txt:1299). A recognized type
// is parsed, takes a SRV_EXT_ bit, and makes trailing bytes inside its
// own body a decode_error (rfc9846.txt:1561-1565). An unrecognized type
// is skipped by its length, sets no bit, and reaches no check at all,
// so a ClientHello carrying GREASE code points still negotiates.
//
// It is a predicate and changes nothing. Returns 1 for a type this
// build parses and 0 for every other value, including a type this
// document defines and this build declines, such as post_handshake_auth
// and status_request (docs/server.md, "What the server declines,
// conformantly").
int srv_ext_known(uint16_t type);

// Whether an extension block carries two extensions of one type, which
// RFC 9846 §4.2 forbids (rfc9846.txt:1673-1674). It walks the block
// once per extension, comparing each type against the types before it,
// so it answers for every type including the ones srv_ext_known
// declines: a duplicate among unrecognized types is still a duplicate,
// and a seen mask over recognized types alone could not see it. The
// block is bounded by the ClientHello, which is bounded by
// cfg.buf_len, and the walk allocates nothing.
//
// Requires n readable bytes at exts, the extension block's body: the
// bytes after the two-byte extensions length and nothing else.
//
// Returns 1 when some type appears twice, and 0 otherwise, including
// for a block whose framing is malformed, because the caller's own
// walk reports that with decode_error and this predicate reaches no
// verdict about framing.
int srv_ext_duplicate(const uint8_t *exts, size_t n);

// Parses one ClientHello body (handshake header stripped) into ch, and
// writes the alert a refusal owes into *alert.
//
// The checks it makes, each with the obligation behind it, in the order
// the message presents them. legacy_version must be 0x0303, or
// protocol_version (rfc9846.txt:1253-1254). legacy_session_id is 0 to
// 32 bytes, or decode_error. cipher_suites is a non-empty even-length
// list, and every code point outside this build's suites is ignored
// (rfc9846.txt:4636-4637). legacy_compression_methods must be exactly
// one zero byte, or illegal_parameter (rfc9846.txt:1284-1288). The
// extension block must be present and must carry supported_versions
// listing 0x0304, or protocol_version (rfc9846.txt:1306-1313,
// rfc9846.txt:1742-1744). A second extension of one type is
// illegal_parameter (rfc9846.txt:1673-1674). Bytes left over inside a
// recognized extension's body are decode_error
// (rfc9846.txt:1561-1565). pre_shared_key, when present, must be the
// last extension, or illegal_parameter (rfc9846.txt:2564-2567), and
// must come with psk_key_exchange_modes (rfc9846.txt:2306-2307). With
// no pre_shared_key, both signature_algorithms and supported_groups
// must be present, or missing_extension (rfc9846.txt:4595-4605), and
// supported_groups without key_share or the reverse is
// missing_extension too (rfc9846.txt:4599-4605). A key_share entry for
// this build's group whose length is not CH_KEX_CLIENT_SHARE is
// illegal_parameter.
//
// One reading the missing-extension checks must not invite: an empty
// KeyShare.client_shares list is a present extension, not an absent
// one. RFC 9846 §9.2 permits it (rfc9846.txt:4599-4601), and a parser
// that answered missing_extension would refuse a strictly conformant
// client. The extension sets SRV_EXT_KEY_SHARE either way, and an empty
// list leaves ch->shares at 0, which is the input srv_select answers
// with a HelloRetryRequest.
//
// An early_data extension is recognized, takes its bit, and changes
// nothing else: this server answers 1-RTT, which is the first of the
// three behaviors RFC 9846 §4.2.10 permits (rfc9846.txt:2385-2401), and
// its EncryptedExtensions carries no early_data, which is the rejection
// signal (rfc9846.txt:2426-2428).
//
// Requires n readable bytes at body and a ch the caller has zeroed.
// offered and offered_count are cfg.alpn_protocols and cfg.alpn_count,
// the protocol names the caller offers; passing NULL and 0 offers none
// and leaves ch->alpn_selected at CH_ALPN_NONE. *alert is seeded by the
// caller and this parser overwrites it on every refusal, so the seed
// reaches the wire only through a path that returns CH_OK.
//
// Returns CH_OK with ch filled, or CH_EPROTO with *alert holding the
// description above. It writes no partial verdict: a refused message
// leaves ch holding whatever the walk reached, and the session dies, so
// no caller reads it.
int srv_parse_client_hello(const uint8_t *body, size_t n, client_hello *ch,
                           const ch_alpn_protocol *offered, size_t offered_count, uint8_t *alert);

#endif // CH_ROLE_SERVER
#endif
