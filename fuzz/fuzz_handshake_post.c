// libFuzzer harness for handle_post_handshake, the post-handshake message
// dispatcher (NewSessionTicket and KeyUpdate). It is static in
// handshake_post.c, so the harness includes that translation unit to reach
// it. The session is zeroed with a live buffer length, a send callback that
// swallows the KeyUpdate reply, and an on_ticket callback that touches every
// ch_ticket field so any bad pointer or length the ticket parser hands out
// trips AddressSanitizer.
#include <stdint.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

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
    return 0;
}
