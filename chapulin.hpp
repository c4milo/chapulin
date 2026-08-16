// Optional C++ wrapper over the C API. Header-only and freestanding: it
// pulls in only <cstddef>/<cstdint> and the C headers, compiles under
// -fno-exceptions -fno-rtti, allocates nothing, and adds no runtime cost
// over the C calls it forwards to. The one thing it buys: a session wipes
// its keys when it leaves scope, so a missed ch_close cannot leak them.
//
// The caller still owns the lifetimes the C API owns — the receive
// buffer, the PSK or pin bytes, and the I/O context must outlive the
// Session, exactly as with ch_cfg.
#ifndef CHAPULIN_HPP
#define CHAPULIN_HPP

#include <cstddef>
#include <cstdint>

extern "C" {
#include "tls.h"
}

namespace chapulin {

enum class Status : int {
    ok = CH_OK,
    io = CH_EIO,
    proto = CH_EPROTO,
    auth = CH_EAUTH,
    cap = CH_ECAP,
    closed = CH_ECLOSED,
};

// Non-owning byte views, so read/write take one argument instead of a
// pointer and a length. Deliberately minimal — no <span> dependency, to
// stay usable on the same freestanding toolchains the C core targets.
struct Bytes {
    uint8_t *data = nullptr;
    size_t size = 0;
    Bytes() = default;
    Bytes(uint8_t *p, size_t n) : data(p), size(n) {}
    template <size_t N> Bytes(uint8_t (&a)[N]) : data(a), size(N) {}
};

struct ConstBytes {
    const uint8_t *data = nullptr;
    size_t size = 0;
    ConstBytes() = default;
    ConstBytes(const uint8_t *p, size_t n) : data(p), size(n) {}
    ConstBytes(Bytes b) : data(b.data), size(b.size) {}
    template <size_t N> ConstBytes(const uint8_t (&a)[N]) : data(a), size(N) {}
};

// Blocking I/O plus the random source, matching the C callback contract:
// send moves all n bytes and returns 0, anything else is failure; recv
// returns 1..n bytes or -1. Pass captureless functions (or lambdas that
// decay to function pointers) and one context.
struct Io {
    int (*send)(void *ctx, const uint8_t *p, size_t n) = nullptr;
    int (*recv)(void *ctx, uint8_t *p, size_t n) = nullptr;
    void *ctx = nullptr;
};

// Result of a read: >0 bytes, 0 on a clean peer close, <0 on error.
struct Read {
    int value = 0;
    bool ok() const { return value > 0; }
    bool at_end() const { return value == 0; }
    size_t bytes() const { return value > 0 ? static_cast<size_t>(value) : 0; }
    Status error() const { return value < 0 ? static_cast<Status>(value) : Status::ok; }
};

// Builds a ch_cfg for exactly one auth mode. Construct with a receive
// buffer and I/O, then call psk() or pinned() — not both.
class Config {
  public:
    Config(Bytes recv_buffer, Io io) {
        cfg_.buf = recv_buffer.data;
        cfg_.buf_len = recv_buffer.size;
        cfg_.send = io.send;
        cfg_.recv = io.recv;
        cfg_.io = io.ctx;
    }

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

    Config &on_ticket(void (*cb)(void *ctx, const ch_ticket *ticket)) {
        cfg_.on_ticket = cb;
        return *this;
    }

    const ch_cfg &raw() const { return cfg_; }

  private:
    ch_cfg cfg_{};
};

// A session owns its ch_tls and closes it — wiping every key — when it is
// destroyed. Non-copyable and non-movable: allocate it where it lives
// (a static for firmware, a scope for tests), like the C ch_tls.
class Session {
  public:
    Session() = default;
    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;
    ~Session() { ch_close(&tls_); }

    Status connect(const Config &cfg) {
        return static_cast<Status>(ch_connect(&tls_, &cfg.raw()));
    }

    Status write(ConstBytes data) {
        return static_cast<Status>(ch_write(&tls_, data.data, data.size));
    }

    Read read(Bytes into) { return Read{ch_read(&tls_, into.data, into.size)}; }

    // Sends close_notify under live keys and wipes; safe to call more than
    // once, and the destructor calls it too.
    void close() { ch_close(&tls_); }

  private:
    ch_tls tls_{};
};

} // namespace chapulin

#endif
