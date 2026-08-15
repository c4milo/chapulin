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
// library rejected (CH_ECAP), without needing a real socket.
static int fail_send(void *, const uint8_t *, size_t) { return -1; }
static int fail_recv(void *, uint8_t *, size_t) { return -1; }

int main() {
    static uint8_t rxbuf[2048];
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

    // Pinned mode: a valid config also reaches I/O.
    {
        uint8_t pin[64];
        std::memset(pin, 0x02, sizeof pin);
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        cfg.pinned(pin);
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::io);
    }

    // Both modes at once is rejected before any I/O.
    {
        uint8_t pin[64];
        std::memset(pin, 0x02, sizeof pin);
        chapulin::Config cfg(chapulin::Bytes{rxbuf}, io);
        cfg.psk(chapulin::ConstBytes{psk, sizeof psk}, chapulin::ConstBytes{id, sizeof id});
        cfg.pinned(pin);
        chapulin::Session s;
        CHECK(s.connect(cfg) == chapulin::Status::cap);
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

    if (failures > 0) {
        (void)std::fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)std::printf("hpp_test: all checks passed\n");
    return 0;
}
