// libFuzzer harness for the post-handshake path in handshake_post.c: the
// message dispatcher handle_post_handshake, which is static there, and the
// record loop hspost_read above it. The harness includes that translation
// unit to reach the static. The session is zeroed with a live buffer length,
// a send callback that swallows the KeyUpdate reply, and an on_ticket
// callback that touches every ch_ticket field so any bad pointer or length
// the ticket parser hands out trips AddressSanitizer.
//
// hspost_read refills through rec_open, so raw input fails the tag on the
// first refill and the loop stays unreachable. The harness therefore seals
// the input into records under the session's own key: the fuzzer drives the
// plaintext and the fragment boundaries, the AEAD is satisfied by
// construction, and the reassembly the README credits to the fuzzer is
// actually executed.
#include <stdint.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "record.h"
#include "session.h"
#include "tls.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)cond;
    (void)file;
    (void)line;
    abort();
}

// handshake.c pulls in ch_handshake, which references this hook.
// handle_post_handshake never drives a handshake, so a call here is a harness bug.
void ch_rand_bytes(uint8_t *p, size_t n) {
    (void)p;
    (void)n;
    abort();
}

static volatile uint64_t g_sink;

static int send_ok(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return 0; // "all n bytes moved" per the ch_cfg contract
}

static void on_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    uint64_t acc = ticket->lifetime_s + ticket->age_add + ticket->identity_len;
    for (size_t i = 0; i < sizeof ticket->psk; i++) {
        acc += ticket->psk[i];
    }
    for (size_t i = 0; i < ticket->identity_len; i++) {
        acc += ticket->identity[i];
    }
    g_sink += acc;
}

#include "handshake_post.c"

// The sealed record stream hspost_read reads back.
static uint8_t g_stream[0x8000];
static size_t g_stream_len;
static size_t g_stream_off;

static int recv_stream(void *io, uint8_t *p, size_t n) {
    (void)io;
    if (g_stream_off >= g_stream_len || n == 0) {
        return -1;
    }
    size_t avail = g_stream_len - g_stream_off;
    size_t take = n < avail ? n : avail;
    memcpy(p, g_stream + g_stream_off, take);
    g_stream_off += take;
    return (int)take;
}

// Seal the input as records, cutting fragments where the fuzzer says.
static void seal_stream(rec_dir *wr, const uint8_t *data, size_t size) {
    g_stream_len = 0;
    g_stream_off = 0;
    size_t off = 0;
    while (off < size && g_stream_len + 512 < sizeof g_stream) {
        size_t chunk = (size_t)data[off] + 1; // fuzzer picks the fragment
        if (chunk > size - off) {
            chunk = size - off;
        }
        size_t out_len = 0;
        if (rec_seal(wr, REC_HANDSHAKE, data + off, chunk, g_stream + g_stream_len,
                     sizeof g_stream - g_stream_len, &out_len) != 0) {
            return;
        }
        g_stream_len += out_len;
        off += chunk;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ch_tls t;
    memset(&t, 0, sizeof t);
    uint8_t buf[0x4200];
    t.cfg.buf = buf;
    t.cfg.buf_len = sizeof buf;
    t.cfg.send = send_ok;
    t.cfg.on_ticket = on_ticket;

    size_t used = 0;
    (void)handle_post_handshake(&t, data, size, &used);

    if (size == 0) {
        return 0;
    }
    // Both directions from one secret, so what the harness seals is what
    // hspost_read can open; both sequence counters start at zero.
    static const uint8_t secret[SHA256_LEN] = {0x2b, 0x7e, 0x15, 0x16};
    ch_tls u;
    memset(&u, 0, sizeof u);
    static uint8_t rbuf[0x4200];
    u.cfg.buf = rbuf;
    u.cfg.buf_len = sizeof rbuf;
    u.cfg.send = send_ok;
    u.cfg.recv = recv_stream;
    u.cfg.on_ticket = on_ticket;
    rec_dir wr;
    memset(&wr, 0, sizeof wr);
    rec_dir_init(&wr, secret);
    rec_dir_init(&u.rd, secret);
    seal_stream(&wr, data, size);
    (void)hspost_read(&u, 0);
    return 0;
}
