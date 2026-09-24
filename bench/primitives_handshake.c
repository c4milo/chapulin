// Whole handshakes for bench/primitives.c: this tree's record-mode client
// (rec.c) against this tree's record-mode server (srv_rec.c) in one
// process, the pairing test/rec_loop_test.c drives. bench/primitives.sh
// builds it from the Makefile's REC_LOOP_SRCS, the ROLE=both
// TRANSPORT=record source list, once per pinned algorithm: the default
// build pins an RSA modulus and CH_PIN_ECDSA pins a P-256 point.
//
// Each sample is one handshake from two fresh sessions to both ends
// connected. The clock is also read around every call into either
// driver, so a sample splits into the time spent inside the client's
// calls and the time spent inside the server's. The two parts do not add
// up to the whole: the rest is the clock reads themselves and the loop
// that carries bytes between the ends.
//
// The auth mode is pinned for the reason test/rec_loop_test.c gives:
// the client pins the server's own public key and hashes the one-entry
// chain below without reading it, so no certificate authority is
// needed. The server selects no PSK and has no KEX=pq half
// (srv_flight.h), so a resumed handshake and a hybrid one cannot run
// here.
//
// Built with -DBENCH_COUNT_CALLS and -finstrument-functions, the program
// times nothing. It runs one handshake per identity, then a second one
// during which it counts how many times each end calls each primitive in
// CALLS, and prints the counts. bench/notes-primitives.md multiplies the
// per-operation rows by them.
#include <stdio.h>
#include <string.h>

#include "primitives.h"
#include "rec.h"
#include "srv_rec.h"

#ifdef BENCH_COUNT_CALLS
#include "aead.h"
#include "hkdf.h"
#include "p256.h"
#include "p256_sign.h"
#include "rand.h"
#include "rsa.h"
#include "rsa_sign.h"
#include "sha256.h"
#include "x25519.h"
#endif

#ifdef CH_PIN_ECDSA
#include "p256_sign_vectors.h"
#else
#include "rsa_sign.h"
#include "rsa_sign_vectors.h"
#endif

#define CLIENT 0
#define SERVER 1
#define NEITHER (-1)
#define ROUNDS_MAX 4  // a 1-RTT handshake takes two
#define WIRE_MAX 4096 // room for one flight; the two calls that fill it check it
#define COOKIE_KEY_BYTE 7

// Valid DER that nothing on either side parses (test/rec_loop_test.c).
static const uint8_t cert_der[4] = {0x30, 0x02, 0x05, 0x00};
static const ch_cert chain[1] = {
    {cert_der, sizeof cert_der}
};
static uint8_t cookie_key[32];
static uint8_t client_buf[CH_MIN_RXBUF];
static uint8_t server_buf[CH_MIN_RXBUF];
static ch_record client;
static ch_record server;
static ch_cfg client_cfg;
static ch_cfg server_cfg;

// What the server pushed, waiting for the client to read it.
static struct {
    uint8_t bytes[WIRE_MAX];
    size_t len;
} to_client;

// Which end is running, and the time spent inside each end's calls
// during the current handshake.
static volatile int running = NEITHER;
static double side_ns[2];
static double side_start;

static void enter(int side) {
    running = side;
    side_start = bench_now_ns();
}

static void leave(int side) {
    side_ns[side] += bench_now_ns() - side_start;
    running = NEITHER;
}

static int never_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return -1;
}

static int never_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return -1;
}

static int push_to_client(void *io, const uint8_t *p, size_t n) {
    (void)io;
    if (to_client.len + n > sizeof to_client.bytes) {
        return -1;
    }
    memcpy(to_client.bytes + to_client.len, p, n);
    to_client.len += n;
    return 0;
}

// One identity the server signs with and the client pins.
typedef struct {
    const char *name;
    const char *client_name;
    const char *server_name;
    const uint8_t *pub;
    size_t pub_len;
#ifndef CH_PIN_ECDSA
    const uint8_t *d;
#endif
} identity;

#ifdef CH_PIN_ECDSA
static const identity IDENTITIES[] = {
    {"handshake_pinned_ecdsa_p256", "handshake_pinned_ecdsa_p256_client_side",
     "handshake_pinned_ecdsa_p256_server_side", p256_sign_vectors[0].pub,
     sizeof p256_sign_vectors[0].pub},
};
#else
static ch_rsa_priv rsa_key;
static const identity IDENTITIES[] = {
    {"handshake_pinned_rsa2048", "handshake_pinned_rsa2048_client_side",
     "handshake_pinned_rsa2048_server_side", rsa_sign_2048_n, sizeof rsa_sign_2048_n,
     rsa_sign_2048_d},
    {"handshake_pinned_rsa3072", "handshake_pinned_rsa3072_client_side",
     "handshake_pinned_rsa3072_server_side", rsa_sign_3072_n, sizeof rsa_sign_3072_n,
     rsa_sign_3072_d},
};
#endif
#define IDENTITY_COUNT (sizeof IDENTITIES / sizeof IDENTITIES[0])

static void set_identity(ch_identity *slot, const identity *id) {
    slot->chain = chain;
    slot->chain_count = 1;
    slot->pub = id->pub;
    slot->pub_len = id->pub_len;
#ifdef CH_PIN_ECDSA
    slot->priv = p256_sign_vectors[0].priv;
    slot->priv_len = sizeof p256_sign_vectors[0].priv;
#else
    memset(&rsa_key, 0, sizeof rsa_key);
    rsa_key.n_len = id->pub_len;
    memcpy(rsa_key.n, id->pub, id->pub_len);
    memcpy(rsa_key.d, id->d, id->pub_len);
    slot->priv = &rsa_key;
    slot->priv_len = sizeof rsa_key;
#endif
}

// The server provisions only the identity the client pins, because a
// pinned client offers the one signature scheme its build names.
static void configure(const identity *id) {
    memset(cookie_key, COOKIE_KEY_BYTE, sizeof cookie_key);
    memset(&server_cfg, 0, sizeof server_cfg);
    server_cfg.buf = server_buf;
    server_cfg.buf_len = sizeof server_buf;
    server_cfg.send = never_send;
    server_cfg.recv = never_recv;
    server_cfg.srv.cookie_key = cookie_key;
    server_cfg.srv.on_record_out = push_to_client;
#ifdef CH_PIN_ECDSA
    set_identity(&server_cfg.srv.ecdsa_p256, id);
#else
    set_identity(&server_cfg.srv.rsa_pss, id);
#endif
    memset(&client_cfg, 0, sizeof client_cfg);
    client_cfg.buf = client_buf;
    client_cfg.buf_len = sizeof client_buf;
    client_cfg.send = never_send;
    client_cfg.recv = never_recv;
    client_cfg.server_pubkey = id->pub;
    client_cfg.server_pubkey_len = id->pub_len;
}

// Moves everything the client owes into the server. Returns 0 on the
// first driver error.
static int client_to_server(void) {
    uint8_t wire[WIRE_MAX];
    size_t total = 0;
    for (;;) {
        size_t n = 0;
        enter(CLIENT);
        int rc = ch_record_out(&client, wire + total, sizeof wire - total, &n);
        leave(CLIENT);
        if (rc != CH_OK) {
            return 0;
        }
        if (n == 0) {
            break;
        }
        total += n;
    }
    if (total == 0) {
        return 1;
    }
    size_t consumed = 0;
    enter(SERVER);
    int rc = ch_srv_record_in(&server, wire, total, &consumed);
    leave(SERVER);
    return rc == CH_OK && consumed == total;
}

// Moves everything the server pushed into the client.
static int server_to_client(void) {
    if (to_client.len == 0) {
        return 1;
    }
    size_t consumed = 0;
    enter(CLIENT);
    int rc = ch_record_in(&client, to_client.bytes, to_client.len, &consumed);
    leave(CLIENT);
    int ok = rc == CH_OK && consumed == to_client.len;
    to_client.len = 0;
    return ok;
}

// One handshake from two fresh sessions. Fails the bench unless both
// ends end connected.
static void handshake_once(void) {
    to_client.len = 0;
    side_ns[CLIENT] = 0.0;
    side_ns[SERVER] = 0.0;
    enter(SERVER);
    int server_rc = ch_srv_record_init(&server, &server_cfg);
    leave(SERVER);
    enter(CLIENT);
    int client_rc = ch_record_init(&client, &client_cfg);
    leave(CLIENT);
    if (server_rc != CH_OK || client_rc != CH_OK) {
        bench_fail("a record driver refused its configuration");
    }
    for (int round = 0; round < ROUNDS_MAX; round++) {
        if (ch_record_state(&client) == CH_ST_CONNECTED &&
            ch_record_state(&server) == CH_ST_CONNECTED) {
            return;
        }
        if (!client_to_server() || !server_to_client()) {
            break;
        }
    }
    if (ch_record_state(&client) != CH_ST_CONNECTED ||
        ch_record_state(&server) != CH_ST_CONNECTED) {
        bench_fail("the handshake did not connect both ends");
    }
}

#ifndef BENCH_COUNT_CALLS
static void measure_identity(const identity *id) {
    double whole[BENCH_SAMPLES];
    double client_part[BENCH_SAMPLES];
    double server_part[BENCH_SAMPLES];
    configure(id);
    double start = bench_now_ns();
    handshake_once();
    double first = bench_now_ns() - start;
    size_t count = bench_sample_count(first);
    for (size_t s = 0; s < bench_warmup_count(first); s++) {
        handshake_once();
    }
    for (size_t s = 0; s < count; s++) {
        start = bench_now_ns();
        handshake_once();
        whole[s] = bench_now_ns() - start;
        client_part[s] = side_ns[CLIENT];
        server_part[s] = side_ns[SERVER];
    }
    bench_record(id->name, "op", 0, count, bench_stat_of(whole, count));
    bench_record(id->client_name, "op", 0, count, bench_stat_of(client_part, count));
    bench_record(id->server_name, "op", 0, count, bench_stat_of(server_part, count));
}

static void measure_handshakes(void) {
    for (size_t i = 0; i < IDENTITY_COUNT; i++) {
        measure_identity(&IDENTITIES[i]);
    }
}
#else
// The primitives whose calls the notes price, and how often each end
// called them in the last handshake. The hook compares the address it is
// handed against each function pointer here, as integers.
typedef struct {
    const char *name;
    void (*address)(void);
    unsigned long calls[2];
} counted;

static counted CALLS[] = {
    {"x25519",            (void (*)(void))x25519,            {0, 0}},
    {"x25519_base",       (void (*)(void))x25519_base,       {0, 0}},
    {"rsa_pss_sign",      (void (*)(void))rsa_pss_sign,      {0, 0}},
    {"rsa_pss_verify",    (void (*)(void))rsa_pss_verify,    {0, 0}},
    {"p256_sign",         (void (*)(void))p256_sign,         {0, 0}},
    {"p256_ecdsa_verify", (void (*)(void))p256_ecdsa_verify, {0, 0}},
    {"hkdf_extract",      (void (*)(void))hkdf_extract,      {0, 0}},
    {"hkdf_expand_label", (void (*)(void))hkdf_expand_label, {0, 0}},
    {"hmac_sha256",       (void (*)(void))hmac_sha256,       {0, 0}},
    {"sha256_final",      (void (*)(void))sha256_final,      {0, 0}},
    {"aead_seal",         (void (*)(void))aead_seal,         {0, 0}},
    {"aead_open",         (void (*)(void))aead_open,         {0, 0}},
    {"ch_rand_bytes",     (void (*)(void))ch_rand_bytes,     {0, 0}},
};
#define CALLS_COUNT (sizeof CALLS / sizeof CALLS[0])

// The hooks -finstrument-functions calls on every function entry and
// exit. They must not be instrumented themselves.
void __cyg_profile_func_enter(void *fn, void *site) __attribute__((no_instrument_function));
void __cyg_profile_func_exit(void *fn, void *site) __attribute__((no_instrument_function));

void __cyg_profile_func_enter(void *fn, void *site) {
    (void)site;
    int side = running;
    if (side == NEITHER) {
        return;
    }
    for (size_t i = 0; i < CALLS_COUNT; i++) {
        if ((uintptr_t)CALLS[i].address == (uintptr_t)fn) {
            CALLS[i].calls[side]++;
        }
    }
}

void __cyg_profile_func_exit(void *fn, void *site) {
    (void)fn;
    (void)site;
}

static void measure_handshakes(void) {
    printf("handshake,function,client_calls,server_calls\n");
    for (size_t i = 0; i < IDENTITY_COUNT; i++) {
        configure(&IDENTITIES[i]);
        handshake_once();
        for (size_t c = 0; c < CALLS_COUNT; c++) {
            CALLS[c].calls[CLIENT] = 0;
            CALLS[c].calls[SERVER] = 0;
        }
        handshake_once();
        for (size_t c = 0; c < CALLS_COUNT; c++) {
            printf("%s,%s,%lu,%lu\n", IDENTITIES[i].name, CALLS[c].name, CALLS[c].calls[CLIENT],
                   CALLS[c].calls[SERVER]);
        }
    }
}
#endif

const bench_group BENCH_HANDSHAKE = {"handshake", NULL, 0, measure_handshakes};
