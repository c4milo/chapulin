// Optional C++ wrapper over the C API. Header-only and freestanding: it
// pulls in only <cstddef>/<cstdint> and the C headers, compiles under
// -fno-exceptions -fno-rtti, allocates nothing, and adds no runtime cost
// over the C calls it forwards to. The one thing it buys: a session wipes
// its keys when it leaves scope, so a missed ch_close cannot leak them.
//
// The caller still owns the lifetimes the C API owns — the receive
// buffer, the PSK or pin bytes, and the I/O context must outlive the
// Session, exactly as with ch_cfg.
//
// The wrapper forks with the object it forwards to. A TRANSPORT=tls
// object exports ch_connect, ch_read, ch_write and ch_close, and Session
// forwards them. A TRANSPORT=quic object exports none of the four and
// fifteen ch_quic_ entries instead, so Quic forwards those, and Config
// takes no Io and gains the transport parameters and the two QUIC
// callbacks. One transport compiles per build, so one of the two classes
// exists at a time.
#ifndef CHAPULIN_HPP
#define CHAPULIN_HPP

#include <cstddef>
#include <cstdint>

extern "C" {
#ifdef CH_TRANSPORT_QUIC
#include "quic.h"
#else
#include "tls.h"
#endif
#ifdef CH_TRUST_CA
#include "x509_ca.h"
#endif
}

namespace chapulin {

enum class Status : int {
    ok = CH_OK,
    io = CH_EIO,
    proto = CH_EPROTO,
    auth = CH_EAUTH,
    cap = CH_ECAP,
    closed = CH_ECLOSED,
    invalid = CH_EINVAL,
#ifdef CH_TRANSPORT_RECORD
    // The code a TRANSPORT=record read adds (cfg.h): no record has arrived
    // yet, and the session stays connected (rec.h, INV-13).
    again = CH_RECORD_AGAIN,
#endif
#ifdef CH_TRANSPORT_QUIC
    // The two codes a TRANSPORT=quic object adds (cfg.h). discard leaves
    // the session live: RFC 9001 §5.5 says a packet that fails to
    // unprotect is not necessarily an attack. aead_limit is RFC 9001
    // §6.6's integrity limit, which ends the session.
    discard = CH_QUIC_DISCARD,
    aead_limit = CH_QUIC_AEAD_LIMIT,
#endif
};

// The key-exchange group ch_tls.group reports: none until the
// handshake accepts the ServerHello's key_share, then the one group
// the build offers (cfg.h's CH_GROUP_* code points).
enum class Group : uint16_t {
    none = 0,
    x25519 = CH_GROUP_X25519,
    x25519mlkem768 = CH_GROUP_X25519MLKEM768,
};

#ifdef CH_TRUST_WEBPKI
// Session::alpn_selected() when the server selected no application
// protocol (cfg.h's CH_ALPN_NONE): the config offered none, or the
// server sent no ALPN extension. Every other value is an index into the
// list Config::alpn() was given. TRUST=webpki builds only, like the
// ch_cfg and ch_tls fields behind it.
constexpr int alpn_none = CH_ALPN_NONE;
#endif

// Non-owning byte views, so read/write take one argument instead of a
// pointer and a length. Deliberately minimal — no <span> dependency, to
// stay usable on the same freestanding toolchains the C core targets.
struct Bytes {
    uint8_t *data = nullptr;
    size_t size = 0;
    Bytes() = default;
    Bytes(uint8_t *p, size_t n) : data(p), size(n) {
    }
    template <size_t N> Bytes(uint8_t (&a)[N]) : data(a), size(N) {
    }
};

struct ConstBytes {
    const uint8_t *data = nullptr;
    size_t size = 0;
    ConstBytes() = default;
    ConstBytes(const uint8_t *p, size_t n) : data(p), size(n) {
    }
    ConstBytes(Bytes b) : data(b.data), size(b.size) {
    }
    template <size_t N> ConstBytes(const uint8_t (&a)[N]) : data(a), size(N) {
    }
};

#ifndef CH_TRANSPORT_QUIC
// Blocking I/O plus the random source, matching the C callback contract:
// send moves all n bytes and returns 0, anything else is failure; recv
// returns 1..n bytes or -1. Pass captureless functions (or lambdas that
// decay to function pointers) and one context. A TRANSPORT=quic object
// opens no socket and calls neither callback, so this type exists only
// here.
struct Io {
    int (*send)(void *ctx, const uint8_t *p, size_t n) = nullptr;
    int (*recv)(void *ctx, uint8_t *p, size_t n) = nullptr;
    void *ctx = nullptr;
};
#endif

#ifdef CH_TRANSPORT_QUIC
// Result of a TRANSPORT=quic call that writes bytes into the caller's
// buffer: Quic::crypto_out and Quic::seal. size counts the bytes written
// and is meaningful only when ok(). A Status::cap result means the buffer
// was short, nothing was written and the same call may run again with a
// larger one.
struct Written {
    int value = 0;
    size_t size = 0;
    bool ok() const {
        return value == CH_OK;
    }
    Status error() const {
        return static_cast<Status>(value);
    }
};

// Result of Quic::open: the recovered packet number, the plaintext length
// and which receive key set opened the packet (CH_QUIC_KEY_PREVIOUS,
// CH_QUIC_KEY_CURRENT or CH_QUIC_KEY_NEXT). All three are meaningful only
// when ok(); a Status::discard result means the caller drops the packet
// and keeps the session.
struct Opened {
    int value = 0;
    uint64_t packet_number = 0;
    size_t plaintext_len = 0;
    uint8_t key_set = 0;
    bool ok() const {
        return value == CH_OK;
    }
    Status error() const {
        return static_cast<Status>(value);
    }
};
#endif

// Result of a read: >0 bytes, 0 on a clean peer close, <0 on error.
struct Read {
    int value = 0;
    bool ok() const {
        return value > 0;
    }
    bool at_end() const {
        return value == 0;
    }
    size_t bytes() const {
        return value > 0 ? static_cast<size_t>(value) : 0;
    }
    Status error() const {
        return value < 0 ? static_cast<Status>(value) : Status::ok;
    }
};

// Builds a ch_cfg for exactly one auth mode. Construct with a receive
// buffer and I/O, then call psk() or pinned() — not both. A TRUST=webpki
// build calls anchors(), hostname() and now_seconds() instead.
class Config {
  public:
#ifdef CH_TRANSPORT_QUIC
    // A TRANSPORT=quic object opens no socket, so the buffer is the whole
    // constructor. It holds one encryption level's reassembled CRYPTO
    // bytes rather than records (docs/quic.md).
    explicit Config(Bytes recv_buffer) {
        cfg_.buf = recv_buffer.data;
        cfg_.buf_len = recv_buffer.size;
    }

    // The caller's own encoded QUIC transport parameters, copied unread
    // into the ClientHello (RFC 9001 §8.2). ch_quic_init requires them.
    Config &transport_params(ConstBytes body) {
        cfg_.transport_params = body.data;
        cfg_.transport_params_len = body.size;
        return *this;
    }

    // Reports that one direction at one encryption level can protect or
    // unprotect packets. Required: ch_quic_init refuses a config without
    // it, because a caller that never learns a level protects no packet.
    Config &on_level_ready(void (*callback)(void *ctx, uint8_t level, uint8_t direction)) {
        cfg_.on_level_ready = callback;
        return *this;
    }

    // Hands the server's transport parameters body to the caller.
    // Optional: with no callback the body is dropped and a missing
    // extension still fails the handshake.
    Config &on_transport_params(void (*callback)(void *ctx, const uint8_t *body, size_t n)) {
        cfg_.on_transport_params = callback;
        return *this;
    }

    // The context both callbacks above are handed (ch_cfg.io).
    Config &context(void *ctx) {
        cfg_.io = ctx;
        return *this;
    }
#else
    Config(Bytes recv_buffer, Io io) {
        cfg_.buf = recv_buffer.data;
        cfg_.buf_len = recv_buffer.size;
        cfg_.send = io.send;
        cfg_.recv = io.recv;
        cfg_.io = io.ctx;
    }
#endif

    // External pre-shared key with its identity. Setting both a PSK and a
    // pin leaves both fields set, which ch_connect rejects — the mistake
    // surfaces rather than resolving to one mode silently.
    Config &psk(ConstBytes key, ConstBytes identity) {
        cfg_.psk = key.data;
        cfg_.psk_len = key.size;
        cfg_.psk_id = identity.data;
        cfg_.psk_id_len = identity.size;
        return *this;
    }

    // Resume from a stored ticket: its identity and derived PSK, plus the
    // obfuscated age the ticket carried.
    Config &resume(ConstBytes derived_psk, ConstBytes identity, uint32_t obfuscated_age) {
        psk(derived_psk, identity);
        cfg_.resumption = 1;
        cfg_.obfuscated_age = obfuscated_age;
        return *this;
    }

    // Pinned server key, no PSK: an RSA modulus (256..384 raw big-endian
    // bytes) by default, or 64 raw P-256 bytes (X || Y) in a CH_PIN_ECDSA
    // build. ch_connect rejects a size the compiled algorithm cannot take.
    Config &pinned(ConstBytes server_pubkey) {
        cfg_.server_pubkey = server_pubkey.data;
        cfg_.server_pubkey_len = server_pubkey.size;
        return *this;
    }

    // Optional second pin, the staged "next" key during server key
    // rotation: the handshake accepts either and Session::pin_slot()
    // reports which. Same length rules as pinned(), and only valid
    // alongside it — ch_connect rejects a lone next pin.
    Config &pinned_next(ConstBytes server_pubkey) {
        cfg_.server_pubkey2 = server_pubkey.data;
        cfg_.server_pubkey2_len = server_pubkey.size;
        return *this;
    }

    Config &on_ticket(void (*callback)(void *ctx, const ch_ticket *ticket)) {
        cfg_.on_ticket = callback;
        return *this;
    }

    // Optional monotonic revocation epoch (docs/ca.md), CA builds
    // only: load reads the stored epoch, store persists a new one,
    // both returning 0 on success. ch_connect rejects one callback
    // without the other, and an epoch that is not an allowed date. A non-CA build
    // rejects either callback rather than leave revocation unenforced.
    Config &epoch(int (*load)(void *ctx, uint32_t *value), int (*store)(void *ctx, uint32_t value),
                  void *ctx) {
        cfg_.epoch_load = load;
        cfg_.epoch_store = store;
        cfg_.epoch_io = ctx;
        return *this;
    }

    // The epoch a saved ticket was issued under (ch_ticket::epoch).
    // A resumed session presents no certificate, so this is the only
    // revocation check left: ch_connect refuses a ticket older than
    // the stored epoch.
    Config &ticket_epoch(uint32_t value) {
        cfg_.ticket_epoch = value;
        return *this;
    }

    // Fail the handshake unless the key exchange is post-quantum
    // (ch_cfg.require_pq). A KEX=pq build checks the flag against the
    // group the ServerHello selected; a classic build cannot satisfy
    // it, and ch_connect rejects the config before any I/O.
    Config &require_pq(bool on) {
        cfg_.require_pq = on ? 1 : 0;
        return *this;
    }

#ifdef CH_TRUST_WEBPKI
    // Web PKI trust (ch_cfg.anchors and the fields after it), for a
    // TRUST=webpki build: the roots the chain must verify up to, the
    // hostname the leaf must name (an ASCII hostname, sent as
    // server_name; convert a U-label to its A-label first), and the
    // clock its dates are checked against, in seconds since
    // 1970-01-01T00:00:00Z. Set all three and no pinned(), and a PSK only
    // through resume() with ticket_binding(). The
    // array and the name are borrowed like every other byte view here.
    // ch_connect checks them (docs/webpki.md). ch_cfg has these fields
    // only in a TRUST=webpki build, so the setters exist only there too.
    Config &anchors(const ch_trust_anchor *list, size_t count) {
        cfg_.anchors = list;
        cfg_.anchor_count = count;
        return *this;
    }
    template <size_t N> Config &anchors(const ch_trust_anchor (&list)[N]) {
        return anchors(list, N);
    }

    Config &hostname(ConstBytes name) {
        cfg_.hostname = name.data;
        cfg_.hostname_len = name.size;
        return *this;
    }

    Config &now_seconds(uint64_t seconds) {
        cfg_.now_seconds = seconds;
        return *this;
    }

    // The binding of the ticket resume() presents: the bytes
    // ch_ticket.binding held. ch_connect refuses a ticket whose binding
    // does not name this hostname and these anchors (docs/webpki.md,
    // "Resumption").
    Config &ticket_binding(const uint8_t (&binding)[SHA256_LEN]) {
        cfg_.ticket_binding = binding;
        return *this;
    }

    // Application protocols to offer through ALPN (ch_cfg.alpn_protocols
    // and ch_cfg.alpn_count), in the order you prefer them: 1 to
    // CH_ALPN_MAX entries, each a name of 1 to CH_ALPN_NAME_MAX bytes,
    // none repeating another. Calling nothing offers nothing, which is
    // legal and sends no extension. The array is borrowed like every
    // other byte view here. Session::alpn_selected() reports which entry
    // the server picked.
    Config &alpn(const ch_alpn_protocol *list, size_t count) {
        cfg_.alpn_protocols = list;
        cfg_.alpn_count = count;
        return *this;
    }
    template <size_t N> Config &alpn(const ch_alpn_protocol (&list)[N]) {
        return alpn(list, N);
    }
#endif

    const ch_cfg &raw() const {
        return cfg_;
    }

  private:
    ch_cfg cfg_{};
};

#ifdef CH_TRUST_CA
// Result of a provisioning decode: the key length when ok().
struct Pubkey {
    int value = 0;
    size_t size = 0;
    bool ok() const {
        return value == CH_OK;
    }
    Status error() const {
        return static_cast<Status>(value);
    }
};

// Forwards ch_pubkey_from_pem: one PEM CERTIFICATE block to the key
// bytes Config::pinned() takes. CA-mode builds only, because only they
// link the certificate reader. Decoding is not authenticating — the
// block's signature, names and dates go unread, and the key is
// trustworthy because an operator pushed it, exactly as a raw pin is
// (x509_ca.h says the rest). The array sizes carry the C contract:
// der_scratch holds the decoded certificate during the call and nothing
// after it, and must not be the receive buffer of a live Session.
inline Pubkey pubkey_from_pem(ConstBytes pem, uint8_t (&der_scratch)[CH_X509_MAX],
                              uint8_t (&key)[CH_X509_KEY_MAX]) {
    Pubkey result;
    result.value = ch_pubkey_from_pem(pem.data, pem.size, der_scratch, key, &result.size);
    return result;
}
#endif

#ifndef CH_TRANSPORT_QUIC
// A session owns its ch_tls and closes it — wiping every key — when it is
// destroyed. Non-copyable and non-movable: allocate it where it lives
// (a static for firmware, a scope for tests), like the C ch_tls.
class Session {
  public:
    Session() = default;
    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;
    ~Session() {
        ch_close(&tls_);
    }

    Status connect(const Config &cfg) {
        return static_cast<Status>(ch_connect(&tls_, &cfg.raw()));
    }

    Status write(ConstBytes data) {
        return static_cast<Status>(ch_write(&tls_, data.data, data.size));
    }

    Read read(Bytes into) {
        return Read{ch_read(&tls_, into.data, into.size)};
    }

    // Which pin authenticated the server: 1 = pinned(), 2 = pinned_next(),
    // 0 before a pinned handshake completes. Public information, for
    // watching key rotation progress.
    int pin_slot() const {
        return tls_.pin_slot;
    }

    // The key-exchange group that ran (ch_tls.group): Group::none until
    // the handshake accepts the ServerHello's key_share.
    Group group() const {
        return static_cast<Group>(tls_.group);
    }

#ifdef CH_TRUST_WEBPKI
    // Which protocol the server selected through ALPN
    // (ch_tls.alpn_selected): an index into the list Config::alpn() was
    // given, or alpn_none when the server selected none. Read it after
    // connect() returns Status::ok and branch on it.
    int alpn_selected() const {
        return tls_.alpn_selected;
    }
#endif

    // The revocation epoch this session accepted, and whether writing
    // it failed. A failed write keeps the session alive, so the caller
    // must retry: call epoch_store with tls.epoch until it returns 0,
    // and alert an operator if it keeps failing (docs/ca.md).
    uint32_t epoch() const {
        return tls_.epoch;
    }
    bool epoch_store_failed() const {
        return tls_.epoch_store_failed != 0;
    }

    // What the peer presented and how the rule judged it (CH_EPOCH_*),
    // readable after a failed connect too. CH_EPOCH_REVOKED means the
    // peer's epoch is below the stored one and the server is not yet
    // reissued; CH_EPOCH_UNTRUSTED means the date should never have
    // been issued. Lattice headroom is CH_EPOCH_MAX - epoch().
    uint32_t epoch_seen() const {
        return tls_.epoch_seen;
    }
    int epoch_status() const {
        return tls_.epoch_status;
    }

    // Sends close_notify under live keys and wipes; safe to call more than
    // once, and the destructor calls it too.
    void close() {
        ch_close(&tls_);
    }

  private:
    ch_tls tls_{};
};
#else
// A QUIC session owns its ch_quic and closes it — wiping every key set —
// when it is destroyed. It forwards the fifteen ch_quic_ entries and adds
// nothing else: chapulin owns every key and the caller owns packet
// numbers, acknowledgments, loss recovery and streams (docs/quic.md).
// Non-copyable and non-movable, like Session and like the C ch_quic,
// whose hs.t points at its own t.
class Quic {
  public:
    Quic() = default;
    Quic(const Quic &) = delete;
    Quic &operator=(const Quic &) = delete;
    ~Quic() {
        ch_quic_close(&quic_);
    }

    // Validates the config and stages the ClientHello; crypto_out hands
    // those bytes out.
    Status init(const Config &cfg) {
        return static_cast<Status>(ch_quic_init(&quic_, &cfg.raw()));
    }

    // Installs the Initial keys from the Destination Connection ID. Call
    // it again after a Retry, with the server's Source Connection ID.
    Status initial_keys(ConstBytes dcid) {
        return static_cast<Status>(ch_quic_initial_keys(&quic_, dcid.data, dcid.size));
    }

    // Delivers one level's CRYPTO bytes in order and runs the state
    // machine until it needs more.
    Status crypto_in(uint8_t level, ConstBytes bytes) {
        return static_cast<Status>(ch_quic_crypto_in(&quic_, level, bytes.data, bytes.size));
    }

    // Takes the one handshake message owed at that level, whole or not at
    // all. An ok() result with size 0 means nothing is owed there.
    Written crypto_out(uint8_t level, Bytes into) {
        Written result;
        result.value = ch_quic_crypto_out(&quic_, level, into.data, into.size, &result.size);
        return result;
    }

    // Protects one packet into into: hdr carries the packet number field
    // the caller encoded, pn_len says how many of its last bytes those
    // are, and pn is that same number.
    Written seal(uint8_t level, uint64_t pn, size_t pn_len, ConstBytes hdr, ConstBytes pt,
                 Bytes into) {
        Written result;
        result.value = ch_quic_seal(&quic_, level, pn, pn_len, hdr.data, hdr.size, pt.data, pt.size,
                                    into.data, into.size, &result.size);
        return result;
    }

    // Removes header protection, recovers the packet number and removes
    // packet protection, in place in packet. On ok() the unprotected
    // header sits at the front and the plaintext follows it.
    Opened open(uint8_t level, Bytes packet, size_t pn_off, uint64_t largest_pn,
                uint64_t current_phase_lowest_pn) {
        Opened result;
        result.value = ch_quic_open(&quic_, level, packet.data, packet.size, pn_off, largest_pn,
                                    current_phase_lowest_pn, &result.key_set, &result.packet_number,
                                    &result.plaintext_len);
        return result;
    }

    // Whether a Retry packet's integrity tag validates. False means the
    // caller discards the packet; it is not a session error.
    bool retry_ok(ConstBytes pseudo, const uint8_t (&tag)[GCM_TAG]) const {
        return ch_quic_retry_ok(&quic_, pseudo.data, pseudo.size, tag) != 0;
    }

    // Advances the 1-RTT keys one phase and toggles the Key Phase bit.
    Status key_update() {
        return static_cast<Status>(ch_quic_key_update(&quic_));
    }

    // The Key Phase bit the current 1-RTT send set carries, 0 or 1. The
    // caller writes it into byte 0 before every short header it seals.
    uint8_t key_phase() const {
        return ch_quic_key_phase(&quic_);
    }

    // Wipes the previous 1-RTT receive key set, after which a packet from
    // the old key phase is a discard.
    void drop_previous_keys() {
        ch_quic_drop_previous_keys(&quic_);
    }

    // Wipes one encryption level's key sets in both directions.
    Status discard(uint8_t level) {
        return static_cast<Status>(ch_quic_discard(&quic_, level));
    }

    // CH_ST_START, CH_ST_CONNECTED, CH_ST_CLOSED or CH_ST_FAILED. It
    // reports the handshake complete, never confirmed: the caller sees
    // the HANDSHAKE_DONE frame, not chapulin.
    uint8_t state() const {
        return ch_quic_state(&quic_);
    }

    // The TLS alert description behind a failure, for a log or a test.
    uint8_t alert() const {
        return ch_quic_alert(&quic_);
    }

    // The transport error code the caller puts in CONNECTION_CLOSE. Read
    // it before close(), which replaces CH_ST_FAILED with CH_ST_CLOSED.
    uint64_t error_code() const {
        return ch_quic_error_code(&quic_);
    }

    // Wipes every secret a discard has not wiped yet; the destructor
    // calls it too, and calling it twice is safe.
    void close() {
        ch_quic_close(&quic_);
    }

  private:
    ch_quic quic_{};
};
#endif

} // namespace chapulin

#endif
