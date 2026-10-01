// Compiles chapulin.hpp under -fno-exceptions -fno-rtti and exercises the
// wrapper: the two Config modes, the read/write/close forwarding, the
// error mapping, and the destructor's key wipe. Links the C library, so
// it also proves the C headers include cleanly from C++.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "chapulin.hpp"

extern "C" {
#include "rand.h"
}

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);             \
        }                                                                                          \
    } while (0)

extern "C" [[noreturn]] void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)std::fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    std::abort();
}

#ifdef CH_RAND_SESSION
// Under RAND=session the object imports no ch_rand_bytes: each Config
// names this source with session_ctx as its context. It counts its draws
// so a test can see the session drew from it, and a draw that arrives
// without that context is a failure: Config::rand_bytes must pass both.
static int session_ctx;
static size_t session_draws = 0;
static void session_fill(void *ctx, uint8_t *p, size_t n) {
    CHECK(ctx == &session_ctx);
    session_draws++;
    for (size_t i = 0; i < n; i++) {
        p[i] = static_cast<uint8_t>(i * 7 + 1);
    }
}
#else
extern "C" void ch_rand_bytes(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = static_cast<uint8_t>(i * 7 + 1);
    }
}
#endif

// Gives a test Config the session's source in a RAND=session build, a
// description of the CPU in a host object and an answer about the
// widening multiply in a WIDEMUL=runtime build, and does nothing in the
// others.
static void with_source(chapulin::Config &cfg) {
#ifdef CH_RAND_SESSION
    cfg.rand_bytes(session_fill, &session_ctx);
#endif
#ifdef CH_CPU_RUNTIME
    cfg.cpu(chapulin::Cpu{});
#endif
#ifdef CH_WIDEMUL_RUNTIME
    cfg.widemul(chapulin::Widemul::not_stated);
#endif
    (void)cfg;
}

#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
// A send that always fails, so connect reaches I/O and stops there — that
// distinguishes a config that passed validation (io error) from one the
// library rejected (CH_EINVAL), without needing a real socket.
static int fail_send(void *, const uint8_t *, size_t) {
    return -1;
}
static int fail_recv(void *, uint8_t *, size_t) {
    return -1;
}
#endif

// Must match the algorithm the linked library object was built with; the
// Makefile passes the same define to both compiles. A TRUST=webpki object
// reads no pin, so it has no length to match, and a TRANSPORT=quic-nonblocking object
// reaches no pinned handshake through this wrapper yet.
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
#ifdef CH_TRUST_WEBPKI
#elif defined(CH_PIN_ECDSA)
constexpr size_t kPinLen = 64;
#else
constexpr size_t kPinLen = 384;
#endif
#endif

#ifdef CH_TRUST_CA
// The provisioning forwarder, against the build's own generated
// vectors: the CA-shaped intermediate yields its public key, and the
// leaf -- the file an operator pushes by mistake -- is refused with the
// key wiped. The armour comes from the helper the C tests use.
//
// The vectors follow the build's pinned algorithm, the way
// x509_strict_test.c picks its own. An RSA certificate handed to a
// P-256 verifier is refused, so naming one here made this test pass
// only under an rsa mode, and no cxx-check leg built a ca-ecdsa object
// to notice.
extern "C" {
#include "pem.h"
}
#include "x509_vectors.h"

#include "pem_armor.h"

#ifdef CH_PIN_ECDSA
static const uint8_t *const prov_ca = certv_int_p256;
static const size_t prov_ca_len = sizeof certv_int_p256;
static const size_t prov_key_len = 64;
static const uint8_t *const prov_leaf = certv_leaf_p256;
static const size_t prov_leaf_len = sizeof certv_leaf_p256;
#else
static const uint8_t *const prov_ca = certv_int_rsa;
static const size_t prov_ca_len = sizeof certv_int_rsa;
static const size_t prov_key_len = 384;
static const uint8_t *const prov_leaf = certv_leaf_rsa;
static const size_t prov_leaf_len = sizeof certv_leaf_rsa;
#endif

static void test_pubkey_from_pem() {
    static uint8_t pem[CH_PEM_MAX + 64];
    static uint8_t der[CH_X509_MAX];
    static uint8_t key[CH_X509_KEY_MAX];

    size_t n = pem_armor(prov_ca, prov_ca_len, 64, "\n", pem);
    chapulin::Pubkey got = chapulin::pubkey_from_pem({pem, n}, der, key);
    CHECK(got.ok());
    CHECK(got.size == prov_key_len);

    std::memset(key, 0xAB, sizeof key);
    n = pem_armor(prov_leaf, prov_leaf_len, 64, "\n", pem);
    got = chapulin::pubkey_from_pem({pem, n}, der, key);
    CHECK(!got.ok());
    CHECK(got.error() == chapulin::Status::invalid);
    CHECK(got.size == 0);
    bool wiped = true;
    for (size_t i = 0; i < sizeof key; i++) {
        if (key[i] != 0) {
            wiped = false;
        }
    }
    CHECK(wiped);
}
#endif

// Sized for whichever build floor is larger: a CA-mode build demands
// room for the whole Certificate flight (CH_TRUST_MIN_RXBUF is 3,098
// under the RSA defaults), a TRUST=webpki build room for four
// certificates (12,324), and a 2048-byte buffer there turns every
// would-be io result below into invalid.
static uint8_t rxbuf[CH_MIN_RXBUF > 2048 ? CH_MIN_RXBUF : 2048];

// The two TCP legs below take a chapulin::Io, which a TRANSPORT=quic-nonblocking
// build does not declare: that object opens no socket. test_quic covers
// the QUIC wrapper instead.
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
#ifdef CH_TRUST_WEBPKI
// The web PKI setters: a hostname and two anchors. The bytes are
// placeholders, because ch_connect checks only that each anchor field
// is set and non-empty, and every handshake here stops at the failing
// send, before a certificate arrives.
static const uint8_t kHost[] = {'s', '3', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'};
static const uint8_t kAnchorName[] = {0x30, 0x00};
static const uint8_t kAnchorSpki[] = {0x30, 0x00};
static const ch_trust_anchor kAnchors[2] = {
    {kAnchorName, sizeof kAnchorName, kAnchorSpki, sizeof kAnchorSpki},
    {kAnchorName, sizeof kAnchorName, kAnchorSpki, sizeof kAnchorSpki},
};

// The ALPN offer the rows below make: "h2" and "http/1.1", the two an
// HTTP client sends, and one name a byte over CH_ALPN_NAME_MAX, which
// ch_connect refuses.
static const uint8_t kH2[] = {'h', '2'};
static const uint8_t kHttp11[] = {'h', 't', 't', 'p', '/', '1', '.', '1'};
static const uint8_t kLongName[CH_ALPN_NAME_MAX + 1] = {'a'};
static const ch_alpn_protocol kAlpn[2] = {
    {kH2,     sizeof kH2    },
    {kHttp11, sizeof kHttp11},
};
static const ch_alpn_protocol kAlpnTooLong[1] = {
    {kLongName, sizeof kLongName}
};

// The one auth mode this build has: anchors, a hostname and a clock set
// through the typed setters, each of which writes its own ch_cfg field,
// pass ch_connect's config check and fail at the send. A PSK or a pin
// beside them, or a clock of 0, is refused before any I/O.
static void test_webpki_config(chapulin::Io io) {
    uint8_t psk[32];
    std::memset(psk, 0x0b, sizeof psk);
    const uint8_t id[] = {'d', 'e', 'v', '1'};
    {
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.anchors(kAnchors).hostname({kHost, sizeof kHost}).now_seconds(1789000000U);
        CHECK(cfg.raw().anchors == kAnchors && cfg.raw().anchor_count == 2);
        CHECK(cfg.raw().hostname == kHost && cfg.raw().hostname_len == sizeof kHost);
        CHECK(cfg.raw().now_seconds == 1789000000U);
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::io);
    }
    {
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.anchors(kAnchors, 1).hostname({kHost, sizeof kHost}).now_seconds(1789000000U);
        cfg.psk(chapulin::ConstBytes{psk, sizeof psk}, chapulin::ConstBytes{id, sizeof id});
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::invalid);
    }
    {
        // SPKI pins alone: no anchor, hostname or clock, and the config
        // passes, so connect reaches the transport.
        static const uint8_t pins[1][SHA256_LEN] = {{0x70}};
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.spki_pins(pins);
        CHECK(cfg.raw().spki_pins == &pins[0][0] && cfg.raw().spki_pin_count == 1);
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::io);
    }
    {
        // A ticket whose binding names nothing this config holds.
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.anchors(kAnchors, 1).hostname({kHost, sizeof kHost}).now_seconds(1789000000U);
        cfg.resume(chapulin::ConstBytes{psk, sizeof psk}, chapulin::ConstBytes{id, sizeof id}, 0)
            .ticket_binding(psk);
        CHECK(cfg.raw().ticket_binding == psk && cfg.raw().resumption == 1);
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::invalid);
    }
    {
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.anchors(kAnchors, 1).hostname({kHost, sizeof kHost}).now_seconds(1789000000U);
        cfg.pinned(chapulin::ConstBytes{psk, sizeof psk});
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::invalid);
    }
    {
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.anchors(kAnchors, 1).hostname({kHost, sizeof kHost}).now_seconds(0);
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::invalid);
    }
#ifdef CH_CPU_RUNTIME
    // The description of the CPU is written to ch_cfg.cpu: CH_CPU_PROBED
    // and the bit of each member that is true. One that was never written
    // stays 0, which connect refuses before any I/O, and so is AVX2 on
    // arm64, whose object does not define that bit (docs/decisions.md 89).
    {
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
#ifdef CH_RAND_SESSION
        cfg.rand_bytes(session_fill, &session_ctx);
#endif
#ifdef CH_WIDEMUL_RUNTIME
        cfg.widemul(chapulin::Widemul::not_stated);
#endif
        cfg.anchors(kAnchors, 1).hostname({kHost, sizeof kHost}).now_seconds(1789000000U);
        CHECK(cfg.raw().cpu == 0);
        chapulin::Session unset;
        CHECK(unset.connect(cfg) == chapulin::Status::invalid);
        cfg.cpu(chapulin::Cpu{});
        CHECK(cfg.raw().cpu == CH_CPU_PROBED);
        chapulin::Session probed;
        CHECK(probed.connect(cfg) == chapulin::Status::io);
        chapulin::Cpu stated;
        stated.constant_time_aes = true;
        stated.constant_time_multiply = true;
        cfg.cpu(stated);
        CHECK(cfg.raw().cpu ==
              (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_MULTIPLY));
        chapulin::Session both;
        CHECK(both.connect(cfg) == chapulin::Status::io);
        chapulin::Cpu x86;
        x86.avx2 = true;
        cfg.cpu(x86);
        CHECK(cfg.raw().cpu == (CH_CPU_PROBED | CH_CPU_AVX2));
        chapulin::Session avx2;
        CHECK(avx2.connect(cfg) == ((CH_CPU_DEFINED & CH_CPU_AVX2) != 0
                                        ? chapulin::Status::io
                                        : chapulin::Status::invalid));
    }
#endif
    // ALPN: the setter writes both ch_cfg fields, a valid offer reaches
    // I/O, and a session that never read an EncryptedExtensions reports
    // no selection. A name over CH_ALPN_NAME_MAX is refused.
    {
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.anchors(kAnchors, 1).hostname({kHost, sizeof kHost}).now_seconds(1789000000U);
        cfg.alpn(kAlpn);
        CHECK(cfg.raw().alpn_protocols == kAlpn && cfg.raw().alpn_count == 2);
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::io);
        CHECK(s.alpn_selected() == chapulin::alpn_none);
    }
    {
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.anchors(kAnchors, 1).hostname({kHost, sizeof kHost}).now_seconds(1789000000U);
        cfg.alpn(kAlpnTooLong, 1);
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::invalid);
    }
}
#else
// The two auth modes this build has, through Config's typed calls.
#if defined(CH_RAND_SESSION) && !defined(CH_TRUST_WEBPKI)
// RAND=session through Config::rand_bytes: a PSK Config with no source
// is refused before any byte is sent, and the same Config with a source
// reaches I/O, having drawn the ClientHello's random and key share from
// that source alone.
static void test_session_source(chapulin::Io io) {
    uint8_t psk[32];
    std::memset(psk, 0x0b, sizeof psk);
    const uint8_t id[] = {'d', 'e', 'v', '1'};
    {
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        cfg.psk(chapulin::ConstBytes{psk, sizeof psk}, chapulin::ConstBytes{id, sizeof id});
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::invalid);
    }
    {
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        cfg.rand_bytes(session_fill, &session_ctx);
        cfg.psk(chapulin::ConstBytes{psk, sizeof psk}, chapulin::ConstBytes{id, sizeof id});
        size_t before = session_draws;
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::io);
        CHECK(session_draws > before);
    }
}
#endif

static void test_psk_and_pinned_config(chapulin::Io io) {
    uint8_t psk[32];
    std::memset(psk, 0x0b, sizeof psk);
    const uint8_t id[] = {'d', 'e', 'v', '1'};

    // PSK mode: a valid config passes validation and dies at I/O.
    {
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.psk(chapulin::ConstBytes{psk, sizeof psk}, chapulin::ConstBytes{id, sizeof id});
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::io);
    }

    // Pinned mode: a valid config also reaches I/O. The fill is odd, so
    // the RSA build's even-pin reject does not fire.
    {
        uint8_t pin[kPinLen];
        std::memset(pin, 0x03, sizeof pin);
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.pinned(chapulin::ConstBytes{pin, sizeof pin});
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::io);
        // No ServerHello arrived, so the session reports no group and no
        // resumption.
        CHECK(s.group() == chapulin::Group::none);
        CHECK(!s.psk_selected());
        // The failed handshake chose an alert for the transport it could
        // not use, and no peer sent one (alert.h).
        CHECK(s.alert_sent() != 0 && s.alert_received() == 0);
    }

#ifdef CH_WIDEMUL_RUNTIME
    // The answer about the widening multiply is written to ch_cfg.widemul
    // as given; an unset one stays 0, which connect refuses before any I/O,
    // and either answer gets to I/O (docs/decisions.md 87).
    {
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
#ifdef CH_RAND_SESSION
        cfg.rand_bytes(session_fill, &session_ctx);
#endif
        cfg.psk(chapulin::ConstBytes{psk, sizeof psk}, chapulin::ConstBytes{id, sizeof id});
        CHECK(cfg.raw().widemul == 0);
        chapulin::Session unset;
        CHECK(unset.connect(cfg) == chapulin::Status::invalid);
        cfg.widemul(chapulin::Widemul::constant_time);
        CHECK(cfg.raw().widemul == CH_WIDEMUL_CONSTANT_TIME);
        chapulin::Session stated;
        CHECK(stated.connect(cfg) == chapulin::Status::io);
        cfg.widemul(chapulin::Widemul::not_stated);
        CHECK(cfg.raw().widemul == CH_WIDEMUL_NOT_STATED);
        chapulin::Session not_stated;
        CHECK(not_stated.connect(cfg) == chapulin::Status::io);
    }
#endif

    // require_pq: a classic build cannot satisfy it and rejects the
    // config before any I/O; a KEX=pq build lets it through to I/O and
    // checks it against the group the ServerHello selects.
    {
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.psk(chapulin::ConstBytes{psk, sizeof psk}, chapulin::ConstBytes{id, sizeof id});
        cfg.require_pq(true);
        chapulin::Session s;
#ifdef CH_KEX_PQ
        CHECK(s.connect(cfg) == chapulin::Status::io);
#else
        CHECK(s.connect(cfg) == chapulin::Status::invalid);
#endif
        CHECK(s.group() == chapulin::Group::none);
    }

    // Both pin slots set (key rotation): still a valid config, and the
    // slot report reads 0 until a pinned handshake completes.
    {
        uint8_t pin[kPinLen];
        uint8_t next[kPinLen];
        std::memset(pin, 0x03, sizeof pin);
        std::memset(next, 0x05, sizeof next);
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.pinned(chapulin::ConstBytes{pin, sizeof pin});
        cfg.pinned_next(chapulin::ConstBytes{next, sizeof next});
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::io);
        CHECK(s.pin_slot() == 0);
    }

    // A staged next pin without a current one is rejected before any I/O.
    {
        uint8_t next[kPinLen];
        std::memset(next, 0x05, sizeof next);
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.pinned_next(chapulin::ConstBytes{next, sizeof next});
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::invalid);
    }

    // Both modes at once is rejected before any I/O.
    {
        uint8_t pin[kPinLen];
        std::memset(pin, 0x03, sizeof pin);
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.psk(chapulin::ConstBytes{psk, sizeof psk}, chapulin::ConstBytes{id, sizeof id});
        cfg.pinned(chapulin::ConstBytes{pin, sizeof pin});
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::invalid);
    }

    // A resumed ticket: its age at its lifetime passes the checks and
    // fails at the socket, and one millisecond more is refused before any
    // I/O. The obfuscated age comes from a ticket with only age_add set.
    {
        ch_ticket ticket;
        std::memset(&ticket, 0, sizeof ticket);
        ticket.age_add = 0xfffffff0U;
        CHECK(chapulin::ticket_obfuscated_age(ticket, 0x20) == 0x10U);
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        with_source(cfg);
        cfg.resume(chapulin::ConstBytes{psk, sizeof psk}, chapulin::ConstBytes{id, sizeof id},
                   chapulin::ticket_obfuscated_age(ticket, 60000));
        cfg.ticket_age(60000, 60);
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::io);
        cfg.ticket_age(60001, 60);
        CHECK(s.connect(cfg) == chapulin::Status::invalid);
    }

    // writable_len forwards ch_writable_len, which reads the session's
    // peer_limit alone: a Session that never connected holds none, so it
    // answers 0.
    {
        chapulin::Session s;
        CHECK(s.writable_len(4096) == 0);
    }
}
#endif
#endif

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
static void level_ready(void *, uint8_t, uint8_t) {
}

// The QUIC leg: every one of the eighteen forwarders compiles, links against
// the packaged object and answers. The subject is the wrapper, not the
// answers, so this configuration is one the object refuses: it names no ALPN
// protocol, which RFC 9001 §8.1 makes mandatory, and no pin or PSK. Each call
// below then meets a dead session, and the expectation is what quic.h states
// that session answers.
static void test_quic() {
    static const uint8_t kParams[] = {0x01, 0x02, 0x03};
    chapulin::Config cfg(chapulin::Bytes{rxbuf});
    with_source(cfg);
    cfg.transport_params(chapulin::ConstBytes{kParams});
    cfg.original_version(chapulin::QuicVersion::v1);
    cfg.ticket_quic_version(chapulin::QuicVersion::v2);
    cfg.on_level_ready(level_ready);
    cfg.context(nullptr);
    CHECK(cfg.raw().quic_original_version == CH_QUIC_VERSION_1);
    CHECK(cfg.raw().ticket_quic_version == CH_QUIC_VERSION_2);

    chapulin::Quic q;
    CHECK(q.init(cfg) == chapulin::Status::invalid);
    // A refused init leaves no negotiated version, and a dead session
    // switches to none.
    CHECK(static_cast<uint32_t>(q.negotiated_version()) == 0);
    CHECK(q.switch_version(chapulin::QuicVersion::v2) == chapulin::Status::invalid);
    CHECK(q.initial_keys(chapulin::ConstBytes{kParams}) == chapulin::Status::invalid);
    // A dead session answers CRYPTO bytes with CH_EPROTO, not CH_EINVAL.
    CHECK(q.crypto_in(CH_LEVEL_INITIAL, chapulin::ConstBytes{kParams}) == chapulin::Status::proto);

    uint8_t packet[64];
    std::memset(packet, 0, sizeof packet);
    chapulin::Written staged = q.crypto_out(CH_LEVEL_INITIAL, chapulin::Bytes{packet});
    CHECK(!staged.ok() && staged.error() == chapulin::Status::invalid);

    uint8_t header[8];
    std::memset(header, 0, sizeof header);
    chapulin::Written sealed =
        q.seal(CH_LEVEL_APPLICATION, chapulin::QuicVersion::v1, 1, 4, chapulin::ConstBytes{header},
               chapulin::ConstBytes{kParams}, chapulin::Bytes{packet});
    CHECK(!sealed.ok() && sealed.error() == chapulin::Status::invalid);
    // A session refused at init holds no write key, so it owes no close.
    chapulin::Written closed = q.seal_close(CH_LEVEL_INITIAL, chapulin::QuicVersion::v1, 1, 4,
                                            chapulin::ConstBytes{header},
                                            chapulin::ConstBytes{kParams}, chapulin::Bytes{packet});
    CHECK(!closed.ok() && closed.error() == chapulin::Status::invalid);

    chapulin::Opened opened =
        q.open(CH_LEVEL_APPLICATION, chapulin::QuicVersion::v1, chapulin::Bytes{packet}, 1, 0, 0);
    CHECK(!opened.ok() && opened.error() == chapulin::Status::invalid);

    uint8_t tag[GCM_TAG];
    std::memset(tag, 0, sizeof tag);
    CHECK(!q.retry_ok(chapulin::QuicVersion::v1, chapulin::ConstBytes{header}, tag));

    CHECK(q.key_update() == chapulin::Status::invalid);
    CHECK(q.key_phase() == 0);
    q.drop_previous_keys();
    // Discarding a level whose keys were never installed is harmless, and
    // quic.h gives that call no state check at all.
    CHECK(q.discard(CH_LEVEL_INITIAL) == chapulin::Status::ok);
    CHECK(q.state() == CH_ST_FAILED);
    // No handshake failed, so no alert description was written. quic.h says
    // 0 there is close_notify and never a failure's description.
    CHECK(q.alert() == 0);
    CHECK(q.alert_sent() == q.alert() && q.alert_received() == 0);
    CHECK(q.error_code() != 0);
    q.close();
}
#endif

int main() {
    // The object cxx-check links was built under the defines this file
    // is compiled with, so its build record matches these headers.
    CHECK(chapulin::build_matches());
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    test_quic();
#else
    chapulin::Io io{fail_send, fail_recv, nullptr};
#ifdef CH_TRUST_WEBPKI
    test_webpki_config(io);
#else
    test_psk_and_pinned_config(io);
#ifdef CH_RAND_SESSION
    test_session_source(io);
#endif
#endif
#endif

    // The Session blocks above each destruct after a connect attempt, so
    // the RAII close path runs here without a crash; the C unit test pins
    // that close wipes the key material.

    // Read result mapping.
    {
        chapulin::Read r{5};
        CHECK(r.ok() && r.bytes() == 5 && !r.at_end());
        chapulin::Read closed{0};
        CHECK(closed.at_end() && !closed.ok());
        chapulin::Read err{CH_EAUTH};
        CHECK(!err.ok() && err.error() == chapulin::Status::auth);
    }

#ifdef CH_TRUST_CA
    test_pubkey_from_pem();
#endif

    if (failures > 0) {
        (void)std::fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)std::printf("hpp_test: all checks passed\n");
    return 0;
}
