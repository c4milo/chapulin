// The rows of docs/decisions.md 132 for one init call of a TRUST=webpki
// client: which configurations hash their anchors, and on which path.
// Every build of test/webpki_session_test.c runs them over ch_connect,
// the coverage build too. bin/webpki_loop_aes runs them over
// ch_record_init, and bin/quic_loop_aes over ch_quic_init. Each row reads
// the session's ch_tls.ticket_config_hash. Where the Makefile defines
// TEST_WEBPKI_TICKET_COUNTED, the binary links test/webpki_ticket_count.c,
// and the rows also read its count of the configuration hashes.
//
// The includer defines ticket_rows_init first. It runs its init call on
// cfg and writes the session's ch_tls.ticket_config_hash into stored. It
// answers 1 when the call accepts the configuration. check_ticket_rows
// starts from a configuration the call accepts. That configuration sets
// on_ticket and no PSK field. In a host object, its ch_cfg.cpu does not
// hold CH_CPU_CONSTANT_TIME_SHA256. What the rows hold:
//   - A session that takes no tickets and presents no ticket runs no
//     hash. Its ticket_config_hash stays all zero.
//   - A session that takes tickets runs one hash, on its own ch_cfg.cpu.
//     It stores the bytes that the portable path writes.
//   - A session that presents a ticket and takes none runs one hash, the
//     check of that ticket. Its field stays all zero, and the init call
//     accepts the ticket.
//   - A session that presents a ticket and takes tickets runs two hashes.
//   - In a host object on a CPU with the SHA-256 instructions, the first
//     and the third rows run again with CH_CPU_CONSTANT_TIME_SHA256. The
//     hash stores the portable path's bytes. The init call accepts a
//     ticket that the portable path bound.
//   - In a host object, a ticket under a value that cpu_value_ok refuses
//     runs no hash, and the init call refuses it. The value holds
//     CH_CPU_CONSTANT_TIME_SHA256, so a check of the ticket before the
//     cpu rule would run the instructions. This row runs on every CPU.
#ifndef CH_TEST_WEBPKI_TICKET_ROWS_H
#define CH_TEST_WEBPKI_TICKET_ROWS_H

#include "cpu.h"
#include "test_ticket.h"
#include "webpki_ticket.h"
#ifdef TEST_WEBPKI_TICKET_COUNTED
#include "webpki_ticket_count.h"
#endif

// What an init call accepted and wrote. Where counted is set, also the
// configuration hashes it ran and the cpu value of the last one.
typedef struct {
    int accepted;
    int counted;
    unsigned long hashes;
    uint32_t cpu;
    uint8_t stored[SHA256_LEN];
} ticket_row;

static const uint8_t ticket_rows_psk[SHA256_LEN] = {0x70, 0x73, 0x6b};
static const uint8_t ticket_rows_identity[8] = {'t', 'i', 'c', 'k', 'e', 't'};
static ch_saved_ticket ticket_rows_ticket;

// Presents a ticket under cfg: a PSK, an identity and the binding the
// portable path computes for cfg's hostname, anchors and pins.
static void ticket_rows_present(ch_cfg *cfg) {
    test_ticket_fill(&ticket_rows_ticket, ticket_rows_psk, sizeof ticket_rows_psk,
                     ticket_rows_identity, sizeof ticket_rows_identity, 3600);
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    ticket_rows_ticket.ticket.quic_version = cfg->quic_original_version;
#endif
    uint8_t hash[SHA256_LEN];
    webpki_ticket_config_hash(0, cfg, hash);
    webpki_ticket_binding(0, ticket_rows_psk, sizeof ticket_rows_psk, hash,
                          ticket_rows_ticket.ticket.binding);
    cfg->ticket = &ticket_rows_ticket;
}

// One init call on cfg. Where the binary counts, the counts start at 0
// for the call.
static ticket_row ticket_rows_run(const ch_cfg *cfg) {
    ticket_row row;
    memset(&row, 0, sizeof row);
#ifdef TEST_WEBPKI_TICKET_COUNTED
    webpki_ticket_config_hash_calls = 0;
    webpki_ticket_config_hash_cpu = 0;
#endif
    row.accepted = ticket_rows_init(cfg, row.stored);
#ifdef TEST_WEBPKI_TICKET_COUNTED
    row.counted = 1;
    row.hashes = webpki_ticket_config_hash_calls;
    row.cpu = webpki_ticket_config_hash_cpu;
#endif
    return row;
}

static int ticket_rows_zero(const uint8_t *p, size_t n) {
    uint8_t any = 0;
    for (size_t i = 0; i < n; i++) {
        any |= p[i];
    }
    return any == 0;
}

// A row whose init call accepted cfg and ran hashes configuration hashes,
// each on cfg's ch_cfg.cpu. It stored want, or all zero when want is
// NULL.
static int ticket_rows_ran(const ch_cfg *cfg, unsigned long hashes, const uint8_t *want) {
    ticket_row row = ticket_rows_run(cfg);
    int hashes_ok = !row.counted || row.hashes == hashes;
    int cpu_ok = !row.counted || hashes == 0 || row.cpu == CH_CFG_CPU(*cfg);
    int stored_ok = want == NULL ? ticket_rows_zero(row.stored, sizeof row.stored)
                                 : memcmp(row.stored, want, SHA256_LEN) == 0;
    return row.accepted && hashes_ok && cpu_ok && stored_ok;
}

#ifdef CH_CPU_RUNTIME
// The cpu rule comes before the check of a presented ticket: a value that
// cpu_value_ok refuses runs no hash, on any CPU.
static int ticket_rows_refused_first(const ch_cfg *base) {
    ch_cfg cfg = *base;
    cfg.cpu = CH_CPU_CONSTANT_TIME_SHA256;
    ticket_rows_present(&cfg);
    ticket_row row = ticket_rows_run(&cfg);
    return !row.accepted && (!row.counted || row.hashes == 0);
}

// The rows on the SHA-256 instructions, where this CPU has them.
static void check_ticket_rows_instructions(const ch_cfg *base, const uint8_t want[SHA256_LEN]) {
    uint32_t sha256_bit = test_cpu_hash_bits() & CH_CPU_CONSTANT_TIME_SHA256;
    if (sha256_bit == 0) {
        (void)printf("webpki ticket rows: SKIP the hash on the SHA-256 instructions: this CPU "
                     "lacks them\n");
        return;
    }
    ch_cfg cfg = *base;
    cfg.cpu |= sha256_bit;
    CHECK(ticket_rows_ran(&cfg, 1, want));
    cfg.on_ticket = NULL;
    ticket_rows_present(&cfg);
    CHECK(ticket_rows_ran(&cfg, 1, NULL));
}
#endif

static void check_ticket_rows(const ch_cfg *base) {
    uint8_t want[SHA256_LEN];
    webpki_ticket_config_hash(0, base, want);
    ch_cfg cfg = *base;
    cfg.on_ticket = NULL;
    CHECK(ticket_rows_ran(&cfg, 0, NULL));
    cfg = *base;
    CHECK(ticket_rows_ran(&cfg, 1, want));
    cfg.on_ticket = NULL;
    ticket_rows_present(&cfg);
    CHECK(ticket_rows_ran(&cfg, 1, NULL));
    cfg = *base;
    ticket_rows_present(&cfg);
    CHECK(ticket_rows_ran(&cfg, 2, want));
#ifdef CH_CPU_RUNTIME
    CHECK(ticket_rows_refused_first(base));
    check_ticket_rows_instructions(base, want);
#endif
}

#endif
