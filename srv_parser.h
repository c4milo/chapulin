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

#include "buf.h"
#include "cfg.h"
#include "handshake_message.h"
#include "sha256.h"

// The ClientHello fields whose sizes RFC 9846 fixes.
//
// SRV_RANDOM is ClientHello.random, 32 bytes (rfc9846.txt:1358-1363
// gives the ServerHello's, and §4.2.2 gives the client's the same
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
// and AEAD_AES_256_GCM. A -DCH_SUITE_AES_GCM build offers the first of
// those two as well, and selects it only when the client offers no
// ChaCha20 (srv_flight.c), so a build that meets section 9.1 still
// prefers the cipher that is constant time by construction rather than
// by a statement about the part it runs on. A build without that define
// offers one suite and does not meet section 9.1, and no comment here
// claims it does. AEAD_AES_256_GCM needs a second hash length and is not
// offered at all.
#define SRV_SUITE_CHACHA20_POLY1305 0x01

#ifdef CH_SUITE_AES_GCM
// TLS_AES_128_GCM_SHA256, the suite section 9.1 makes mandatory to
// implement. Only a -DCH_SUITE_AES_GCM build reads this bit, and ct.h
// refuses that define unless the build has hardware AES and states that
// those instructions are constant time, because the AES=soft S-box is
// indexed with the key and a traffic key is secret (INV-26).
#define SRV_SUITE_AES_128_GCM 0x02
#endif

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
#define SRV_EXT_QUIC_TRANSPORT_PARAMS 0x1000

// One of those bits is recognized in order to be refused, and it is the
// one place this parser answers for a transport rather than for a
// message. quic_transport_parameters carries the endpoint's encoded QUIC
// transport parameters (RFC 9001 §8.2, rfc9001.txt:1921-1923), and §8.2
// requires a fatal unsupported_extension from an implementation that
// understands the extension when the transport is not QUIC
// (rfc9001.txt:1945-1949). A TRANSPORT=tls build is such a transport and
// refuses it; a TRANSPORT=quic server keeps the body and hands it to its
// caller, which srv_parser_ext.c's two arms carry. The
// extension needs its own bit to reach that answer, because §4.2.2's
// ignore rule would otherwise skip it and negotiate
// (rfc9846.txt:1299). handshake_parser.h states the client's matching
// answer, which its unadmitted arm reaches.
//
// A QUIC server replaces that refusal with two rules. Its reader stores
// the body and its length in two members this struct does not carry
// yet, and srv_flight.c hands them to cfg.on_transport_params (cfg.h),
// the mirror of what the client does with the server's body.
// check_required then answers a hello with this bit clear with
// missing_extension, which §8.2 makes an error of type 0x016d
// (rfc9001.txt:1930-1936). Neither rule is written here today, because
// no build could compile it and no test could reach it.

// The two extension code points handshake_message.h does not declare,
// because no client this tree builds sends either one. early_data is
// RFC 9846 §4.3.10 and padding is RFC 7685; the server recognizes both
// so that §4.2.2's freeze rule can exclude them, and it acts on
// neither.
#define EXT_PADDING 21
#define EXT_EARLY_DATA 42

// The psk_key_exchange_modes values (RFC 9846 §4.3.9). The server must
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
    //
    // The parser subtracts the inner content-type byte the wire value
    // counts (RFC 8449 §4), so a client advertising 0x4000 leaves 16383
    // here. handshake_parser_ee.c:25 is the client's matching step. A
    // value below 64 is refused with illegal_parameter before it lands
    // here, which §4 requires; the parser checks no upper bound, because
    // §4 forbids a server to enforce the protocol's maximum.
    uint16_t record_size_limit;

    // Which psk_key_exchange_modes values the client listed, as the
    // SRV_PSK_ bits above, and 0 when the extension was absent.
    uint8_t psk_modes;

    // Where the pre_shared_key extension's binder list starts, counted
    // in bytes from the start of body, and 0 when the client offered no
    // PSK. RFC 9846 §4.3.11.2 computes the binder over the ClientHello
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

    // SHA-256 over the ClientHello fields RFC 9846 §4.2.2 forbids the
    // client to change across a HelloRetryRequest
    // (rfc9846.txt:1191-1213), accumulated as the parser walks. The
    // cookie the server mints carries this digest, and the second
    // ClientHello's digest is compared against it with ct_memeq, which
    // is how a stateless server checks the freeze rule without storing
    // the first message. The digest covers every byte of the message
    // except the five things §4.2.2 permits a second ClientHello to
    // change: the key_share the HelloRetryRequest asked for, an
    // early_data extension the second hello removes, the cookie the
    // second hello adds, the pre_shared_key extension, and the padding
    // extension's length.
    uint8_t frozen[SHA256_LEN];

#ifdef CH_TRANSPORT_QUIC
    // The client's quic_transport_parameters body, as extension 0x39
    // carried it (RFC 9001 section 8.2, rfc9001.txt:1922-1924). It points
    // into cfg.buf, so it is valid until the next message overwrites that
    // buffer, and the driver hands it to the caller inside the same call.
    // chapulin reads none of it: its content belongs to the QUIC version
    // in use (rfc9001.txt:1926-1928).
    const uint8_t *transport_params;
    size_t transport_params_len;
#endif
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
// build recognizes, which is every type it parses plus
// quic_transport_parameters, the one it recognizes in order to refuse.
// Returns 0 for every other value, including a type this document
// defines and this build declines, such as post_handshake_auth and
// status_request (docs/server.md, "What the server declines,
// conformantly").
int srv_ext_known(uint16_t type);

// Whether an extension block carries two extensions of one type, which
// RFC 9846 §4.3 forbids (rfc9846.txt:1673-1674). It walks the block
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
// the message presents them. legacy_version is read and not judged:
// §4.2.2 has a server that sees supported_versions ignore it
// (rfc9846.txt:1306-1313), and a hello without supported_versions is
// refused for that absence below, so no value there changes a verdict.
// legacy_session_id is 0 to 32 bytes, or decode_error. cipher_suites
// is a non-empty even-length list, and every code point outside this
// build's suites is ignored (rfc9846.txt:4636-4637).
// legacy_compression_methods must be exactly one zero byte, or
// illegal_parameter (rfc9846.txt:1284-1288). The extension block must
// be present and must carry supported_versions listing 0x0304, or
// protocol_version (rfc9846.txt:1306-1313, rfc9846.txt:1742-1744). A
// second extension of one type is illegal_parameter
// (rfc9846.txt:1673-1674). Bytes left over inside a recognized
// extension's body are decode_error (rfc9846.txt:1561-1565).
// A quic_transport_parameters extension is unsupported_extension,
// because this transport is not QUIC (RFC 9001 §8.2,
// rfc9001.txt:1945-1949); the bit block above states the rule in full.
// pre_shared_key, when present, must be the last extension, or
// illegal_parameter (rfc9846.txt:2564-2567), and must come with
// psk_key_exchange_modes (rfc9846.txt:2306-2307). With no
// pre_shared_key, both signature_algorithms and supported_groups must
// be present, or missing_extension (rfc9846.txt:4595-4605), and
// supported_groups without key_share or the reverse is
// missing_extension too (rfc9846.txt:4599-4605). A key_share entry for
// this build's group whose length is not CH_KEX_CLIENT_SHARE is
// illegal_parameter, and so is one for a group supported_groups did
// not list, which §4.3.8 forbids the client to send. Every list of
// code points, names, shares, identities or binders must fill the
// length that frames it, and every length must sit inside the vector
// bounds RFC 9846 prints for it, or decode_error; the one bound not
// judged is the extension block's own lower bound of 8 bytes, because a
// shorter block is TLS 1.2 syntax and the missing supported_versions
// answers it with protocol_version. Nothing else is refused: a suite,
// group, scheme, version, mode or extension this build does not know
// is read and ignored, and so is a KeyShareEntry for a group this build
// does not hold, whatever supported_groups says about that group.
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
// three behaviors RFC 9846 §4.3.10 permits (rfc9846.txt:2385-2401), and
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

// What the parser's two files share, and nothing outside them uses. The
// parser is one concern in two files because one file of it ran past the
// 500-line limit, not because there are two concerns; webpki.h holds its
// seven files the same way and says the same thing about them. Treat
// everything below as a module internal: no lint stops a third file from
// calling srv_read_extension, and nothing else should.

// Everything one parse carries between the readers: the body's length,
// which truncated_len counts from, the output, the caller's ALPN offer,
// the alert slot and the running frozen digest.
typedef struct {
    size_t n;
    client_hello *ch;
    const ch_alpn_protocol *offered;
    size_t offered_count;
    uint8_t *alert;
    sha256 frozen;
} hello_parse;

// Writes the description a refusal owes and returns the refusal, so
// every refusal in either file is one line that names its alert.
static inline int srv_refuse(uint8_t *alert, uint8_t description) {
    *alert = description;
    return CH_EPROTO;
}

// Reads the two-byte length of a list of two-byte code points and holds
// it to the list's syntax: at least one code point, an even byte count,
// and no more bytes than the reader has left. The last term keeps the
// walks that follow at the list's own length on a message that lies
// about it. Returns 1 with *list_len written, or 0 for a length outside
// the syntax, which the caller answers with decode_error.
//
// That last term carries no verdict of its own, and no test guards it,
// because deleting it changes no answer its callers give. A list longer
// than the bytes left makes srv_list_has read past the end, which sets
// the reader's sticky error, and every caller then refuses with
// decode_error: parse_extension on rb_left, and parse_head on the
// compression bytes it reads next. The term makes that refusal happen
// here instead of two reads later, and nothing else, so a mutant that
// removes it is not a coverage hole and test/violations/ holds none.
static inline int srv_open_code_point_list(rbuf *r, size_t *list_len) {
    *list_len = rb_u16(r);
    return !r->err && *list_len >= 2 && (*list_len & 1) == 0 && *list_len <= rb_left(r);
}

// Whether the next list_len bytes of r, a list srv_open_code_point_list
// admitted, hold code. It reads the whole list either way, so r ends at
// the list's end, and a code point outside this build's tables is read
// and ignored (rfc9846.txt:4636-4637).
static inline int srv_list_has(rbuf *r, size_t list_len, uint16_t code) {
    int found = 0;
    for (size_t i = 0; i < list_len; i += 2) {
        if (rb_u16(r) == code) {
            found = 1;
        }
    }
    return found;
}

// Reads one recognized extension's body. e is bounded by the length the
// message gave that extension, so no reader walks past it; type is a
// value srv_ext_known answers 1 for; data_off is where the body starts,
// counted from the start of the ClientHello body, and only
// pre_shared_key reads it. Returns CH_OK, or CH_EPROTO with p->alert
// written. The caller holds the body to being read exactly, so a reader
// that leaves bytes behind is refused without checking for itself.
// Defined in srv_parser_ext.c.
int srv_read_extension(rbuf *e, uint16_t type, size_t data_off, hello_parse *p);

#endif // CH_ROLE_SERVER
#endif
