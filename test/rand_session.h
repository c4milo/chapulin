// The sources of random bytes a RAND=session build of the loop tests
// hands its sessions (docs/decisions.md 77, INV-4). Each session's ch_cfg
// names one session_source through rand_bytes = session_draw and rand_io =
// the source, and test/rand_session_cases.h reads what each source handed
// out. Included once, by a loop test built with -DCH_RAND_SESSION, before
// its own client and server configurations.
//
// A source is splitmix64 over a 64-bit seed. It is deterministic on
// purpose: two runs from one seed must replay a connection byte for byte.
// That makes it a test fixture and never a source a device uses, because
// a deterministic stream gives predictable keys to anyone who knows its
// seed (cfg.h).
#ifndef CH_TEST_RAND_SESSION_H
#define CH_TEST_RAND_SESSION_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "cfg.h"

#ifndef CH_RAND_SESSION
#error "test/rand_session.h is the fixture of a -DCH_RAND_SESSION build"
#endif

// The draws one source logs, and the bytes it keeps of them. A handshake
// draws at most five times on one side, so a source seeded before each
// handshake the checks read fills neither. A source that runs past them
// keeps counting and stops logging.
#define SESSION_DRAWS_MAX 16
#define SESSION_LOG_MAX 1024

typedef struct {
    uint64_t state;
    // Every call session_draw made from this source.
    size_t calls;
    // The first SESSION_DRAWS_MAX draws: where each starts in log, and
    // its length.
    size_t logged;
    size_t draw_off[SESSION_DRAWS_MAX];
    size_t draw_len[SESSION_DRAWS_MAX];
    uint8_t log[SESSION_LOG_MAX];
    size_t log_len;
} session_source;

// The two sources the loop tests hand out: the client's and the server's.
// A loopback's client and server are two sessions whose calls
// interleave, each drawing from its own source.
static session_source client_source;
static session_source server_source;

// Draws whose rand_io named neither source: a rand_draw that dropped its
// session's rand_io, or passed a pointer other than the one the session's
// ch_cfg holds.
static size_t stray_draws;

// Draws that went to ch_rand_bytes. rand.h declares the hook only for
// RAND=extern and RAND=drbg, and a RAND=session object neither defines
// nor imports it (lib-check). This binary defines it anyway, so a library
// draw that bypasses rand_draw still links, and a check counts it and
// fails. The mutants in test/violations/ need a build that links.
static size_t hook_draws;

void ch_rand_bytes(uint8_t *p, size_t n);
void ch_rand_bytes(uint8_t *p, size_t n) {
    hook_draws++;
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(0xa5U ^ i);
    }
}

static uint64_t splitmix_next(uint64_t *state) {
    *state += 0x9e3779b97f4a7c15ULL;
    uint64_t z = *state;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static session_source *known_source(const void *rand_io) {
    if (rand_io == &client_source) {
        return &client_source;
    }
    return rand_io == &server_source ? &server_source : NULL;
}

// Keeps a copy of one draw, while the log has room for it.
static void log_draw(session_source *s, const uint8_t *p, size_t n) {
    if (s->logged == SESSION_DRAWS_MAX || n > SESSION_LOG_MAX - s->log_len) {
        return;
    }
    s->draw_off[s->logged] = s->log_len;
    s->draw_len[s->logged] = n;
    memcpy(s->log + s->log_len, p, n);
    s->log_len += n;
    s->logged++;
}

// The callback every session's ch_cfg.rand_bytes names. A stray draw
// still writes bytes, none of them zero, so the handshake runs on and the
// counts are what fail.
static void session_draw(void *rand_io, uint8_t *p, size_t n) {
    session_source *s = known_source(rand_io);
    if (s == NULL) {
        stray_draws++;
        for (size_t i = 0; i < n; i++) {
            p[i] = (uint8_t)(0x5aU ^ i);
        }
        return;
    }
    uint64_t word = 0;
    for (size_t i = 0; i < n; i++) {
        if (i % 8 == 0) {
            word = splitmix_next(&s->state);
        }
        p[i] = (uint8_t)(word >> (8 * (i % 8)));
    }
    s->calls++;
    log_draw(s, p, n);
}

static void seed_source(session_source *s, uint64_t seed) {
    memset(s, 0, sizeof *s);
    s->state = seed;
}

// A source that reads no rand_io, which cfg.h allows a caller to leave
// NULL: the boundary of the refusal, whose other side is a NULL
// rand_bytes.
static size_t contextless_calls;

static void contextless_draw(void *rand_io, uint8_t *p, size_t n) {
    (void)rand_io;
    static uint64_t state = 0x243f6a8885a308d3ULL;
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)splitmix_next(&state);
    }
    contextless_calls++;
}

static void attach_source(ch_cfg *cfg, session_source *s) {
    cfg->rand_bytes = session_draw;
    cfg->rand_io = s;
}

// Whether draw k of s was the n bytes at p.
static int drawn_is(const session_source *s, size_t k, const uint8_t *p, size_t n) {
    return k < s->logged && s->draw_len[k] == n && memcmp(s->log + s->draw_off[k], p, n) == 0;
}

// What crossed during one handshake, each direction in the order it was
// sent.
#define SESSION_WIRE_MAX 8192
typedef struct {
    uint8_t to_server[SESSION_WIRE_MAX];
    size_t to_server_len;
    uint8_t to_client[SESSION_WIRE_MAX];
    size_t to_client_len;
} crossed;

// Appends n bytes to one direction. Returns 0 when they do not fit.
static int cross(uint8_t *wire, size_t *len, const uint8_t *p, size_t n) {
    if (n > SESSION_WIRE_MAX - *len) {
        return 0;
    }
    memcpy(wire + *len, p, n);
    *len += n;
    return 1;
}

#endif
