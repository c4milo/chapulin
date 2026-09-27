// Proves, in a -DCH_SUITE_AES_GCM build: ch_writable_len (tls_write.c) is
// memory-safe and UB-free for any peer_limit, any suite code point, any
// write sequence number and any cap, the path that counts a KeyUpdate
// included. It is proof/writable_len_harness.c's first claim, over the
// build where that path compiles.
//
// Not proved: that no unsigned product on that path wraps. C defines
// unsigned wrap, so the checks run.sh turns on do not look for it, and
// tls_write.c states why no product there wraps. With
// --unsigned-overflow-check this formula returned no verdict in 10
// minutes, on 64 bits and on 32; test/key_limit_cases.h checks the answer
// at SIZE_MAX on the host.
//
// proof/writable_len_suite_harness.c proves the answer against the real
// ch_write at a bound. The two claims are apart because each costs a
// division, and docs/proofs.md splits a formula along its arithmetic.
// ch_write is not called, so its callees are stubs that fail the proof if
// it ever were.
#include "harness.h"

#include "handshake_post.h"
#include "io.h"
#include "record.h"
#include "session.h"
#include "tls.h"

#if !defined(CH_SUITE_AES_GCM)
#error "writable_len_suite_any proves the suite build; its launch line must pass -DCH_SUITE_AES_GCM"
#endif

uint64_t nondet_u64(void);

int io_send_all(const ch_cfg *cfg, const uint8_t *p, size_t n) {
    (void)cfg;
    (void)p;
    (void)n;
    __CPROVER_assert(0, "io_send_all unreachable: ch_writable_len sends nothing");
    return CH_EIO;
}

int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *out_len) {
    (void)d;
    (void)type;
    (void)pt;
    (void)n;
    (void)out;
    (void)cap;
    (void)out_len;
    __CPROVER_assert(0, "rec_seal unreachable: ch_writable_len seals nothing");
    return -1;
}

int hspost_send_key_update(ch_tls *t) {
    (void)t;
    __CPROVER_assert(0, "hspost_send_key_update unreachable: ch_writable_len sends nothing");
    return CH_EIO;
}

void tlsi_fail(ch_tls *t, uint8_t description) {
    (void)t;
    (void)description;
    __CPROVER_assert(0, "tlsi_fail unreachable: ch_writable_len fails nothing");
}

#include "tls_write.c"

static ch_tls any;

int main(void) {
    any.peer_limit = (uint16_t)nondet_u32();
    any.wr.suite = (uint16_t)nondet_u32();
    any.wr.seq = nondet_u64();
    (void)ch_writable_len(&any, nondet_size_t());
    return 0;
}
