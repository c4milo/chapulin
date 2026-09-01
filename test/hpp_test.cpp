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

extern "C" void ch_rand_bytes(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = static_cast<uint8_t>(i * 7 + 1);
    }
}

// A send that always fails, so connect reaches I/O and stops there — that
// distinguishes a config that passed validation (io error) from one the
// library rejected (CH_EINVAL), without needing a real socket.
static int fail_send(void *, const uint8_t *, size_t) {
    return -1;
}
static int fail_recv(void *, uint8_t *, size_t) {
    return -1;
}

// Must match the algorithm the linked library object was built with; the
// Makefile passes the same define to both compiles.
#ifdef CH_PIN_ECDSA
constexpr size_t kPinLen = 64;
#else
constexpr size_t kPinLen = 384;
#endif

#ifdef CH_TRUST_CA
// The provisioning forwarder, against the build's own generated
// vectors: the CA-shaped intermediate yields its 384-byte modulus, and
// the leaf -- the file an operator pushes by mistake -- is refused with
// the key wiped. The armour comes from the helper the C tests use.
extern "C" {
#include "pem.h"
}
#include "x509_vectors.h"

#include "pem_armor.h"

static void test_pubkey_from_pem() {
    static uint8_t pem[CH_PEM_MAX + 64];
    static uint8_t der[CH_X509_MAX];
    static uint8_t key[CH_X509_KEY_MAX];

    size_t n = pem_armor(certv_int_rsa, sizeof certv_int_rsa, 64, "\n", pem);
    chapulin::Pubkey got = chapulin::pubkey_from_pem({pem, n}, der, key);
    CHECK(got.ok());
    CHECK(got.size == 384);

    std::memset(key, 0xAB, sizeof key);
    n = pem_armor(certv_leaf_rsa, sizeof certv_leaf_rsa, 64, "\n", pem);
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

int main() {
    // Sized for whichever build floor is larger: a TRUST=ca build
    // demands room for the whole Certificate flight (CH_TRUST_MIN_RXBUF
    // is 3,098 under the RSA defaults), and a 2048-byte buffer there
    // turns every would-be io result below into invalid.
    static uint8_t rxbuf[CH_MIN_RXBUF > 2048 ? CH_MIN_RXBUF : 2048];
    chapulin::Io io{fail_send, fail_recv, nullptr};

    uint8_t psk[32];
    std::memset(psk, 0x0b, sizeof psk);
    const uint8_t id[] = {'d', 'e', 'v', '1'};

    // PSK mode: a valid config passes validation and dies at I/O.
    {
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
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
        cfg.pinned(chapulin::ConstBytes{pin, sizeof pin});
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::io);
    }

    // Both pin slots set (key rotation): still a valid config, and the
    // slot report reads 0 until a pinned handshake completes.
    {
        uint8_t pin[kPinLen];
        uint8_t next[kPinLen];
        std::memset(pin, 0x03, sizeof pin);
        std::memset(next, 0x05, sizeof next);
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
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
        cfg.pinned_next(chapulin::ConstBytes{next, sizeof next});
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::invalid);
    }

    // Both modes at once is rejected before any I/O.
    {
        uint8_t pin[kPinLen];
        std::memset(pin, 0x03, sizeof pin);
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        cfg.psk(chapulin::ConstBytes{psk, sizeof psk}, chapulin::ConstBytes{id, sizeof id});
        cfg.pinned(chapulin::ConstBytes{pin, sizeof pin});
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::invalid);
    }

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
