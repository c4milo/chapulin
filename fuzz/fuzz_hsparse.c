// libFuzzer harness for the two handshake message parsers that face
// pre-authentication attacker bytes: parse_sh (ServerHello) and parse_ee
// (EncryptedExtensions). Both are static in handshake.c, so the harness
// includes the translation unit to reach them. The parsers never call the
// session's random, transport, or alert hooks; those symbols are stubbed
// with abort() bodies so a reachable call fails loudly instead of linking
// the whole stack in.
#include <stdint.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "cfg.h"
#include "session.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)cond;
    (void)file;
    (void)line;
    abort();
}
void ch_rand_bytes(uint8_t *p, size_t n) {
    (void)p;
    (void)n;
    abort();
}
int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    (void)cfg;
    (void)p;
    (void)n;
    abort();
}
int io_read_record(const ch_cfg *cfg, uint8_t *buf, size_t cap, uint8_t *outer, size_t *reclen) {
    (void)cfg;
    (void)buf;
    (void)cap;
    (void)outer;
    (void)reclen;
    abort();
}
void tlsi_fail(ch_tls *t, uint8_t desc) {
    (void)t;
    (void)desc;
    abort();
}
int tlsi_send_alert(ch_tls *t, uint8_t level, uint8_t desc) {
    (void)t;
    (void)level;
    (void)desc;
    abort();
}

#include "handshake.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    sh_info si;
    memset(&si, 0, sizeof si);
    (void)parse_sh(data, size, &si);

    ch_tls t;
    memset(&t, 0, sizeof t);
    t.peer_limit = CH_TX_PT;
    hs h;
    memset(&h, 0, sizeof h);
    h.t = &t;
    (void)parse_ee(&h, data, size);
    return 0;
}
