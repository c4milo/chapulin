// libFuzzer harness for handshake_record.c: reading records off the wire
// and reassembling handshake messages that span several of them. Nothing
// else fuzzes this module, and the README names the connected phase as
// resting partly on the fuzzer, so this is that claim made true.
//
// The input is the record stream. cfg.recv hands it out, so the fuzzer
// controls the 5-byte headers, the length fields io_read_record reads at
// face value, and where messages break across records.
//
// It runs unencrypted: with keys up, random bytes fail the AEAD tag and
// never reach the reassembly loop, so the interesting paths would be
// unreachable. rec_open is covered by fuzz_record and by CBMC.
#include <stdint.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "handshake_record.h"
#include "session.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)cond;
    (void)file;
    (void)line;
    abort();
}

// handshake_record.c links io.c and record.c, which reach ch_handshake's
// hook through the library's own declarations. A call here is a bug.
void ch_rand_bytes(uint8_t *p, size_t n) {
    (void)p;
    (void)n;
    abort();
}

static const uint8_t *g_data;
static size_t g_size;
static size_t g_off;

// The ch_cfg contract: 1..n bytes, or -1. Handing back short reads lets
// the fuzzer split a record header across two transport reads as well.
static int recv_stream(void *io, uint8_t *p, size_t n) {
    (void)io;
    if (g_off >= g_size || n == 0) {
        return -1;
    }
    size_t avail = g_size - g_off;
    size_t take = n < avail ? n : avail;
    memcpy(p, g_data + g_off, take);
    g_off += take;
    return (int)take;
}

static int send_ok(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    g_data = data;
    g_size = size;
    g_off = 0;

    ch_tls t;
    memset(&t, 0, sizeof t);
    static uint8_t buf[0x4200];
    t.cfg.buf = buf;
    t.cfg.buf_len = sizeof buf;
    t.cfg.recv = recv_stream;
    t.cfg.send = send_ok;
    sha256_init(&t.transcript);

    handshake_state h;
    memset(&h, 0, sizeof h);
    h.t = &t;
    h.encrypted = 0;

    // Bounded so a stream of empty-but-valid records cannot spin here;
    // quiet_stream_capped already bounds that inside the module.
    for (int i = 0; i < 64; i++) {
        uint8_t type = 0;
        const uint8_t *raw = NULL;
        size_t raw_len = 0;
        if (hsr_next_msg(&h, &type, &raw, &raw_len) != CH_OK) {
            break;
        }
        // A yielded message lies inside the caller's buffer.
        CH_ASSERT(raw >= buf && raw_len <= sizeof buf);
        CH_ASSERT((size_t)(raw - buf) <= sizeof buf - raw_len);
        // The header the parsers will read agrees with the length the
        // reassembler reported, or every parser below is fed a lie.
        CH_ASSERT(raw_len >= 4);
        size_t msg_len = ((size_t)raw[1] << 16) | ((size_t)raw[2] << 8) | raw[3];
        CH_ASSERT(raw_len == 4 + msg_len);
    }
    return 0;
}
