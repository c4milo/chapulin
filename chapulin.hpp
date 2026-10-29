// Optional C++ wrapper over the C API. Header-only and freestanding: it
// pulls in only <cstddef>/<cstdint> and the C headers, compiles under
// -fno-exceptions -fno-rtti, allocates nothing, and adds no runtime cost
// over the C calls it forwards to. The one thing it buys: a session wipes
// its keys when it leaves scope, so a missed ch_close cannot leak them.
// Status and each result type are [[nodiscard]], as each C call they
// carry is CH_MUST_USE (result.h), so the compiler warns where a caller
// drops one (docs/decisions.md 143).
//
// The caller still owns the lifetimes the C API owns — the receive
// buffer, the PSK or pin bytes, and the I/O context must outlive the
// Session, exactly as with ch_cfg.
//
// The wrapper forks with the object it forwards to. A TRANSPORT=tcp-blocking
// object exports ch_connect, ch_read, ch_write, ch_writable_len and
// ch_close, and Session forwards them. A TRANSPORT=quic-nonblocking object
// exports none of the five and
// eighteen ch_quic_ entries instead, so Quic forwards those, and Config
// takes no Io and gains the original version, a ticket's version, the
// transport parameters and the two QUIC callbacks. One transport compiles per build, so one of the
// two classes exists at a time. Both forward alert.h's two calls, which
// every object exports.
#ifndef CHAPULIN_HPP
#define CHAPULIN_HPP

#include <cstddef>
#include <cstdint>

extern "C" {
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#include "quic.h"
#else
#include "tls.h"
#endif
#ifdef CH_TRUST_CA
#include "x509_ca.h"
#endif
#ifdef CH_TRUST_WEBPKI
#include "pem_files.h"
#endif
#include "build.h"
}

namespace chapulin {

enum class [[nodiscard]] Status : int {
    ok = CH_OK,
    io = CH_EIO,
    proto = CH_EPROTO,
    auth = CH_EAUTH,
    cap = CH_ECAP,
    closed = CH_ECLOSED,
    invalid = CH_EINVAL,
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
    // The code a TRANSPORT=tcp-nonblocking read adds (cfg.h): no record has arrived
    // yet, and the session stays connected (tcp_nonblocking.h, INV-13).
    again = CH_RECORD_AGAIN,
#endif
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
    // The code a TCP read adds (result.h): the peer sent one KeyUpdate past
    // CH_KEY_UPDATE_RUN_MAX in a row (session.h), and the session is dead.
    key_update_limit = CH_KEY_UPDATE_LIMIT,
#endif
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    // The two codes a TRANSPORT=quic-nonblocking object adds (quic_cfg.h). discard leaves
    // the session live: RFC 9001 §5.5 says a packet that fails to
    // unprotect is not necessarily an attack. aead_limit is RFC 9001
    // §6.6's integrity limit, which ends the session.
    discard = CH_QUIC_DISCARD,
    aead_limit = CH_QUIC_AEAD_LIMIT,
#endif
};

// Forwards ch_result_text (result.h): a constant English text for a log line.
inline const char *status_text(Status status) {
    return ch_result_text(static_cast<int>(status));
}

// The key-exchange group ch_tls.group reports: none until the
// handshake accepts the ServerHello's key_share, then the group the
// ServerHello selected (cfg.h's CH_GROUP_* code points): the one group a
// raw or ca build offers, or any of the three a TRUST=webpki client lists
// or a server holds, secp256r1 among them.
enum class Group : uint16_t {
    none = 0,
    x25519 = CH_GROUP_X25519,
    x25519mlkem768 = CH_GROUP_X25519MLKEM768,
    secp256r1 = CH_GROUP_SECP256R1,
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

#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
// Blocking I/O plus the random source, matching the C callback contract:
// send returns the 1 to n bytes it moved, and the C call sends the rest
// in the next call; recv returns 1 to n bytes; any other value from
// either is failure. Pass captureless functions (or lambdas that
// decay to function pointers) and one context. A TRANSPORT=quic-nonblocking object
// opens no socket and calls neither callback, so this type exists only
// here.
struct Io {
    int (*send)(void *ctx, const uint8_t *p, size_t n) = nullptr;
    int (*recv)(void *ctx, uint8_t *p, size_t n) = nullptr;
    void *ctx = nullptr;
};
#endif

#ifdef CH_CPU_RUNTIME
// What your own probe of the CPU found, and what you state about it, in a
// host object (cpu_cfg.h): Config::cpu() writes CH_CPU_PROBED into
// ch_cfg.cpu, and the bit of each member that is true. Every init refuses
// a Config that never called it. chapulin probes nothing and writes no CPU
// state (docs/decisions.md 89).
struct Cpu {
    // The CPU has the AES and carry-less multiply instructions, and you
    // state that they run in constant time on it, in the mode the
    // session's thread runs in: CH_CPU_CONSTANT_TIME_AES.
    bool constant_time_aes = false;
    // You state that the widening multiply runs in constant time on this
    // CPU, in that mode: CH_CPU_CONSTANT_TIME_MULTIPLY, which runs the
    // native multiply in place of ct.h's 16x16 decomposition, and X25519
    // on the 51-bit-word field. On x86-64 the statement covers AVX-512
    // IFMA's 52-bit products too, which avx512_ifma runs beside this bit.
    // The mode is yours to set, DIT on arm64 and DOITM's policy on x86-64.
    bool constant_time_multiply = false;
    // The CPU has AVX2 and its operating system saves the 256-bit
    // registers: CH_CPU_AVX2, which runs the session's ChaCha20 keystream
    // in 256-bit vectors, and without avx512_ifma RSA verification's
    // public operation on rsa_avx2.c's 28-bit digits, or 27-bit above
    // 3,072 bits, four to a 256-bit register, for the moduli avx512_ifma
    // names. An x86-64 bit, which an arm64 object refuses.
    bool avx2 = false;
    // The CPU also has VAES and VPCLMULQDQ on those registers:
    // CH_CPU_VAES, which beside constant_time_aes runs AES-GCM's whole
    // blocks two to a register, and without it runs nothing. An x86-64
    // bit as well.
    bool vaes = false;
    // The CPU has the SHA-256 instructions, and you state that they run
    // in constant time on it, in that mode: CH_CPU_CONSTANT_TIME_SHA256.
    // On arm64 that is FEAT_SHA256, and on x86-64 the SHA extensions with
    // SSSE3 and SSE4.1. The session then hashes its transcript and
    // derives its keys over SHA-256 on them.
    bool constant_time_sha256 = false;
    // The same for the SHA-512 instructions, FEAT_SHA512:
    // CH_CPU_CONSTANT_TIME_SHA512. An arm64 bit, which an x86-64 object
    // refuses. Under TLS_AES_256_GCM_SHA384 the session then hashes its
    // transcript and derives its keys over SHA-384 on them.
    bool constant_time_sha512 = false;
    // The same for the SHA-3 instructions, FEAT_SHA3:
    // CH_CPU_CONSTANT_TIME_SHA3. An arm64 bit as well. The session then
    // runs SHA-3, SHAKE and ML-KEM's hashes on them, in an object that
    // clang compiled.
    bool constant_time_sha3 = false;
    // The CPU has AVX-512F and AVX-512 IFMA, and its operating system
    // saves the opmask and 512-bit registers: CH_CPU_AVX512_IFMA. It
    // states presence alone, as avx2 does, and with it the session runs
    // RSA verification's public operation on rsa_ifma.c's 52-bit digits,
    // eight to a 512-bit register, for an odd modulus of 2,048 bits or
    // more whose bit length is a multiple of 64, and its ChaCha20
    // keystream sixteen blocks a pass on chacha20_avx512.c in place of
    // avx2's kernel. Beside constant_time_multiply the session also signs
    // with RSA on rsa_ifma_sign.c and runs a Poly1305 update of 512 bytes
    // or more on poly1305_ifma.c. x509.c's chain links under TRUST=ca-rsa
    // run rsa_mont64.c whatever this says. An x86-64 bit, which an arm64
    // object refuses.
    bool avx512_ifma = false;
    // The CPU has AVX-512F, AVX-512BW and AVX-512VL, and VAES and
    // VPCLMULQDQ on the 512-bit registers, and its operating system saves
    // the opmask and 512-bit registers: CH_CPU_AVX512. It states presence
    // alone, as avx2 does. Beside vaes and constant_time_aes the session
    // runs each AES-GCM seal and open whole, four blocks to a 512-bit
    // register, on gcm_avx512_kernel.c. It picks nothing else, so you can
    // leave it clear and keep avx512_ifma's kernels. An x86-64 bit, which
    // an arm64 object refuses.
    bool avx512 = false;
    // The CPU has BMI2 and ADX: CH_CPU_BMI2_ADX. It states presence
    // alone, as avx2 does. Beside constant_time_multiply the session runs
    // an X25519 shared secret on x25519_adx.c's four 64-bit words, on MULX,
    // ADCX and ADOX. A public key runs on the wide field's table whatever
    // this says. An x86-64 bit, which an arm64 object refuses.
    bool bmi2_adx = false;
};
#endif

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
// A QUIC Version field value (quic_cfg.h): the original version
// Config::original_version() names and the version each packet call and
// Quic::switch_version() take. Any other value casts in, and C decides
// whether it derives that version's keys.
enum class QuicVersion : uint32_t {
    v1 = CH_QUIC_VERSION_1,
    v2 = CH_QUIC_VERSION_2,
};

// Result of a TRANSPORT=quic-nonblocking call that writes bytes into the caller's
// buffer: Quic::crypto_out and Quic::seal. size counts the bytes written
// and is meaningful only when ok(). A Status::cap result means the buffer
// was short, nothing was written and the same call may run again with a
// larger one.
struct [[nodiscard]] Written {
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
struct [[nodiscard]] Opened {
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

// Result of a read: >0 bytes, 0 once the peer's close_notify arrived, <0
// on error. The close_notify closes the peer's direction alone (tls.h), so
// after at_end() the session still writes until close().
struct [[nodiscard]] Read {
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
// build calls anchors(), hostname() and clock() instead.
class Config {
  public:
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    // A TRANSPORT=quic-nonblocking object opens no socket, so the buffer is the whole
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

    // The version of the client's first Initial packet
    // (ch_cfg.quic_original_version), which a client sends in and a server
    // reads off that packet. Required: both init calls refuse a Config
    // without one, and one whose keys the object does not derive.
    Config &original_version(QuicVersion version) {
        cfg_.quic_original_version = static_cast<uint32_t>(version);
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

#if defined(CH_TRUST_WEBPKI) || defined(CH_ROLE_SERVER)
    // The caller's clock (ch_cfg.now_seconds and clock_io): a function
    // that answers the seconds since 1970-01-01T00:00:00Z, and the context
    // it receives. Each init calls it once and judges the whole connection
    // at that instant (cfg.h).
    Config &clock(uint64_t (*now)(void *ctx), void *ctx) {
        cfg_.now_seconds = now;
        cfg_.clock_io = ctx;
        return *this;
    }
#endif

    // External pre-shared key with its identity. Setting both a PSK and a
    // pin leaves both fields set, which ch_connect rejects — the mistake
    // surfaces rather than resolving to one mode silently. So is an
    // identity that is not 1 to CH_TICKET_ID_MAX bytes (cfg.h).
    Config &psk(ConstBytes key, ConstBytes identity) {
        cfg_.psk = key.data;
        cfg_.psk_len = key.size;
        cfg_.psk_id = identity.data;
        cfg_.psk_id_len = identity.size;
        return *this;
    }

    // Resume from a ticket that ch_ticket_save kept during on_ticket
    // (ch_cfg.ticket), whose age is age_ms milliseconds on your clock
    // (ch_cfg.ticket_age_ms). Keep the rest of the Config as it is. The
    // connection is refused before a byte is sent when the age is above
    // the ticket's lifetime or above seven days, and on the other rules of
    // ticket.h: the ticket's epoch, binding and QUIC version. The ticket is
    // borrowed like every other byte view here.
    Config &resume(const ch_saved_ticket &ticket, uint64_t age_ms) {
        cfg_.ticket = &ticket;
        cfg_.ticket_age_ms = age_ms;
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

#ifdef CH_CPU_RUNTIME
    // Your description of this CPU, host objects only (ch_cfg.cpu).
    // Every init refuses a Config without one.
    Config &cpu(Cpu found) {
        cfg_.cpu = CH_CPU_PROBED | (found.constant_time_aes ? CH_CPU_CONSTANT_TIME_AES : 0U) |
                   (found.constant_time_multiply ? CH_CPU_CONSTANT_TIME_MULTIPLY : 0U) |
                   (found.avx2 ? CH_CPU_AVX2 : 0U) | (found.vaes ? CH_CPU_VAES : 0U) |
                   (found.constant_time_sha256 ? CH_CPU_CONSTANT_TIME_SHA256 : 0U) |
                   (found.constant_time_sha512 ? CH_CPU_CONSTANT_TIME_SHA512 : 0U) |
                   (found.constant_time_sha3 ? CH_CPU_CONSTANT_TIME_SHA3 : 0U) |
                   (found.avx512_ifma ? CH_CPU_AVX512_IFMA : 0U) |
                   (found.avx512 ? CH_CPU_AVX512 : 0U) | (found.bmi2_adx ? CH_CPU_BMI2_ADX : 0U);
        return *this;
    }
#endif

#ifdef CH_RAND_SESSION
    // The session's own randomness source, RAND=session builds only
    // (docs/entropy.md): every draw the session makes calls fill(ctx, p,
    // n), which must fill all n bytes from a CSPRNG and must not return
    // when it cannot. Every init refuses a Config without one.
    Config &rand_bytes(void (*fill)(void *ctx, uint8_t *p, size_t n), void *ctx) {
        cfg_.rand_bytes = fill;
        cfg_.rand_io = ctx;
        return *this;
    }
#endif

    // Fail the handshake unless the key exchange is post-quantum
    // (ch_cfg.require_pq). A KEX=pq or TRUST=webpki build checks the
    // flag against the group the ServerHello selected; a classic raw or
    // ca build cannot satisfy it, and ch_connect rejects the config
    // before any I/O.
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
    // 1970-01-01T00:00:00Z. Set all three, or spki_pins() alone, and no
    // pinned(); a PSK only through resume(). The
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

    // SPKI pins (ch_cfg.spki_pins): count SHA-256 digests of a DER
    // SubjectPublicKeyInfo, 1 to CH_SPKI_PIN_MAX. With pins set the client
    // offers RFC 7250 raw public keys, and pins without anchors() are a
    // whole configuration (webpki_cfg.h, webpki_pin.h).
    Config &spki_pins(const uint8_t *pins, size_t count) {
        cfg_.spki_pins = pins;
        cfg_.spki_pin_count = count;
        return *this;
    }
    template <size_t N> Config &spki_pins(const uint8_t (&pins)[N][CH_SPKI_PIN_LEN]) {
        return spki_pins(&pins[0][0], N);
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
struct [[nodiscard]] Pubkey {
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

#ifdef CH_TRUST_WEBPKI
// Result of a CA bundle decode: the anchor count when ok().
struct [[nodiscard]] Anchors {
    int value = 0;
    size_t count = 0;
    bool ok() const {
        return value == CH_OK;
    }
    Status error() const {
        return static_cast<Status>(value);
    }
};

// Forwards ch_anchors_from_pem: the CERTIFICATE blocks of a CA bundle
// file to the anchors that Config::anchors() takes. The call skips the
// text lines around them and refuses a BEGIN line of any other label.
// A root that decodes is not authenticated. The call reads no
// root's signature, dates or extensions. The roots are trusted because
// an operator placed the file (pem_files.h says the rest). The caller sizes
// both rooms: der, the DER's bytes, and anchors, anchor_max entries. The
// call refuses a bundle that does not fit them. The anchors point into
// der, which must outlive every Session that uses them. The chain and key
// calls of a server role have no forwarder, because this wrapper carries
// no server API.
inline Anchors anchors_from_pem(ConstBytes pem, Bytes der, ch_trust_anchor *anchors,
                                size_t anchor_max) {
    Anchors result;
    result.value = ch_anchors_from_pem(pem.data, pem.size, der.data, der.size, anchors, anchor_max,
                                       &result.count);
    return result;
}
#endif

#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)
// Forwards ch_ticket_obfuscated_age: age_ms plus the ticket's age_add,
// modulo 2^32 (ticket.h). Config::resume() needs none of it: the hello
// computes the value from the ticket and its age.
inline uint32_t ticket_obfuscated_age(const ch_ticket &ticket, uint64_t age_ms) {
    return ch_ticket_obfuscated_age(&ticket, age_ms);
}

// Forwards ch_ticket_save: copies the ticket on_ticket hands over, and the
// identity bytes it points at, into out, which Config::resume() takes.
inline Status ticket_save(ch_saved_ticket &out, const ch_ticket &ticket) {
    return static_cast<Status>(ch_ticket_save(&out, &ticket));
}
#endif

// Forwards ch_build_matches(&ch_build): whether the object this program
// links was compiled with the struct sizes, bounds and axes these headers
// compute under this program's defines (build.h). Call it once at
// startup and refuse to run when it answers false.
[[nodiscard]] inline bool build_matches() {
    return ch_build_matches(&ch_build) != 0;
}

#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
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

#if (!defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)) && !defined(CH_TRANSPORT_TCP_NONBLOCKING)
    // tls.h declares ch_connect only in a TRANSPORT=tcp-blocking object
    // with a client, so this forwarder exists only there.
    Status connect(const Config &cfg) {
        return static_cast<Status>(ch_connect(&tls_, &cfg.raw()));
    }
#endif

    Status write(ConstBytes data) {
        return static_cast<Status>(ch_write(&tls_, data.data, data.size));
    }

    // Forwards ch_writable_len: the most plaintext one write() seals into
    // cap bytes of records (tls.h).
    size_t writable_len(size_t cap) const {
        return ch_writable_len(&tls_, cap);
    }

    Read read(Bytes into) {
        return Read{ch_read(&tls_, into.data, into.size)};
    }

    // Which pin authenticated the server: 1 = pinned(), 2 = pinned_next(),
    // 0 before a pinned handshake completes. Public information, for
    // watching key rotation progress.
    int pin_slot() const {
        return ch_pin_slot(&tls_);
    }

    // The key-exchange group that ran (ch_tls.group): Group::none until
    // the handshake accepts the ServerHello's key_share.
    Group group() const {
        return static_cast<Group>(ch_group(&tls_));
    }

    // Whether a PSK authenticated the handshake (ch_tls.psk_selected):
    // true for a resumed session, false for a full one. Under
    // TRUST=webpki a server that declines the ticket gives a full
    // handshake and false.
    bool psk_selected() const {
        return ch_psk_selected(&tls_) != 0;
    }

#ifdef CH_TRUST_WEBPKI
    // Which protocol the server selected through ALPN
    // (ch_tls.alpn_selected): an index into the list Config::alpn() was
    // given, or alpn_none when the server selected none. Read it after
    // connect() returns Status::ok and branch on it.
    int alpn_selected() const {
        return ch_alpn_selected(&tls_);
    }
#endif

    // The revocation epoch this session accepted, and whether writing
    // it failed. A failed write keeps the session alive, so the caller
    // must retry: call epoch_store with tls.epoch until it returns 0,
    // and alert an operator if it keeps failing (docs/ca.md).
    uint32_t epoch() const {
        return ch_epoch(&tls_);
    }
    bool epoch_store_failed() const {
        return ch_epoch_store_failed(&tls_) != 0;
    }

    // What the peer presented and how the rule judged it (CH_EPOCH_*),
    // readable after a failed connect too. CH_EPOCH_REVOKED means the
    // peer's epoch is below the stored one and the server is not yet
    // reissued; CH_EPOCH_UNTRUSTED means the date should never have
    // been issued. Lattice headroom is CH_EPOCH_MAX - epoch().
    uint32_t epoch_seen() const {
        return ch_epoch_seen(&tls_);
    }
    int epoch_status() const {
        return ch_epoch_status(&tls_);
    }

    // Forward alert.h's two calls: the fatal alert this side's failure
    // chose, and the one the peer sent, 0 for none. A read or connect that
    // failed on the peer's fatal alert sent nothing, and alert_sent() is 0.
    uint8_t alert_sent() const {
        return ch_alert_sent(&tls_);
    }
    uint8_t alert_received() const {
        return ch_alert_received(&tls_);
    }

    // Sends this side's close_notify under live keys and wipes; safe to
    // call more than once, and the destructor calls it too. A read that
    // returned at_end() does not do this: call it once this side has
    // nothing more to write.
    void close() {
        ch_close(&tls_);
    }

    // Forwards ch_fail: fails a connected session with the fatal alert
    // description names, one of RFC 9846 §6.2's error alerts (tls.h).
    Status fail(uint8_t description) {
        return static_cast<Status>(ch_fail(&tls_, description));
    }

  private:
    ch_tls tls_{};
};
#else
// A QUIC session owns its ch_quic and closes it — wiping every key set —
// when it is destroyed. It forwards the eighteen ch_quic_ entries and
// alert.h's two calls and adds nothing else: chapulin owns every key and
// the caller owns packet numbers, acknowledgments, loss recovery and
// streams (docs/quic.md).
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

#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)
    // Validates the config and stages the ClientHello; crypto_out hands
    // those bytes out. quic.h declares the client's driver, this call
    // and the two CRYPTO calls below, only in an object with a client.
    Status init(const Config &cfg) {
        return static_cast<Status>(ch_quic_init(&quic_, &cfg.raw()));
    }
#endif

    // Installs the Initial keys from the Destination Connection ID. Call
    // it again after a Retry, with the server's Source Connection ID.
    Status initial_keys(ConstBytes dcid) {
        return static_cast<Status>(ch_quic_initial_keys(&quic_, dcid.data, dcid.size));
    }

#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)
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

    // Makes version the negotiated version, once, before the first CRYPTO
    // byte from the server is delivered (RFC 9369 section 4.1).
    Status switch_version(QuicVersion version) {
        return static_cast<Status>(ch_quic_switch_version(&quic_, static_cast<uint32_t>(version)));
    }
#endif

    // The version every Handshake and 1-RTT packet carries: the original
    // one until a client's switch_version().
    QuicVersion negotiated_version() const {
        return static_cast<QuicVersion>(ch_quic_negotiated_version(&quic_));
    }

    // Protects one packet into into: version is the packet's Version
    // field, the negotiated version at the 1-RTT level; hdr carries the
    // packet number field the caller encoded, pn_len says how many of its
    // last bytes those are, and pn is that same number.
    Written seal(uint8_t level, QuicVersion version, uint64_t pn, size_t pn_len, ConstBytes hdr,
                 ConstBytes pt, Bytes into) {
        Written result;
        result.value =
            ch_quic_seal(&quic_, level, static_cast<uint32_t>(version), pn, pn_len, hdr.data,
                         hdr.size, pt.data, pt.size, into.data, into.size, &result.size);
        return result;
    }

    // Seals the one CONNECTION_CLOSE packet a failed session sends at one
    // level, then wipes that level's write keys. close_frame is one
    // CONNECTION_CLOSE frame and nothing else; a second call at the same
    // level is refused.
    Written seal_close(uint8_t level, QuicVersion version, uint64_t pn, size_t pn_len,
                       ConstBytes hdr, ConstBytes close_frame, Bytes into) {
        Written result;
        result.value = ch_quic_seal_close(&quic_, level, static_cast<uint32_t>(version), pn, pn_len,
                                          hdr.data, hdr.size, close_frame.data, close_frame.size,
                                          into.data, into.size, &result.size);
        return result;
    }

    // Removes header protection, recovers the packet number and removes
    // packet protection, in place in packet. version is the packet's
    // Version field, the negotiated version at the 1-RTT level. On ok() the
    // unprotected header sits at the front and the plaintext follows it.
    Opened open(uint8_t level, QuicVersion version, Bytes packet, size_t pn_off,
                uint64_t largest_pn, uint64_t current_phase_lowest_pn) {
        Opened result;
        result.value = ch_quic_open(&quic_, level, static_cast<uint32_t>(version), packet.data,
                                    packet.size, pn_off, largest_pn, current_phase_lowest_pn,
                                    &result.key_set, &result.packet_number, &result.plaintext_len);
        return result;
    }

    // Whether a Retry packet's integrity tag validates in version, the
    // Retry's Version field. False means the caller discards the packet,
    // and any version but the original one is false; it is not a session
    // error.
    bool retry_ok(QuicVersion version, ConstBytes pseudo,
                  const uint8_t (&tag)[CH_QUIC_RETRY_TAG_LEN]) const {
        return ch_quic_retry_ok(&quic_, static_cast<uint32_t>(version), pseudo.data, pseudo.size,
                                tag) != 0;
    }

    // Advances the 1-RTT keys one phase and toggles the Key Phase bit.
    Status key_update() {
        return static_cast<Status>(ch_quic_key_update(&quic_));
    }

    // The Key Phase bit the current 1-RTT send set carries, 0 or 1. The
    // seal writes it into byte 0 of every short header it seals.
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

    // Forward alert.h's two calls on the session's ch_tls, so a caller
    // reads one pair across its Session and Quic objects: alert_sent()
    // answers what alert() answers, and alert_received() is 0, because
    // QUIC carries no alert record.
    uint8_t alert_sent() const {
        return ch_alert_sent(&quic_.t);
    }
    uint8_t alert_received() const {
        return ch_alert_received(&quic_.t);
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
