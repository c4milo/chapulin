// The handshake buffer's rules, both ends (tcp_nonblocking.h, INV-73,
// docs/decisions.md 247): cfg.buf serves the handshake alone. A session
// gives it back, every byte wiped and its copy of the pointer gone, when
// it connects, when it fails and when ch_tcp_close ends it, and a
// connected session never reads or writes it.
//
// The last rule is held by the memory itself. The buffers come from mmap,
// and once both ends connect they become pages no access is allowed to.
// Then each path a connected session runs goes through: application data
// each way, a ticket, a ticket in two records, a KeyUpdate that rekeys the
// reader, each close_notify and ch_tcp_close. A path that touched either
// buffer would stop this binary with SIGSEGV. Included by
// test/tcp_nonblocking_loop_test.c after the close tests, whose two sends
// and their wires it uses.
#ifndef CH_TEST_TCP_NONBLOCKING_BUFFER_TESTS_H
#define CH_TEST_TCP_NONBLOCKING_BUFFER_TESTS_H

#include <sys/mman.h>
#include <unistd.h>

#include "test_write.h"

// A whole number of pages that holds len bytes, from mmap, or NULL.
static uint8_t *pages_for(size_t len, size_t *mapped) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    *mapped = (len + page - 1) / page * page;
    void *p = mmap(NULL, *mapped, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : (uint8_t *)p;
}

// The client reads every record the server sent through server_send,
// where it lies in held, and returns the plaintext bytes it read.
static size_t client_reads_held(ch_tcp_priv *client) {
    size_t plaintext = 0;
    uint8_t reply[CH_ALERT_RECORD_LEN];
    for (int i = 0; i < 16; i++) {
        ch_read_result result;
        int rc = ch_read_in_place(tls_public(&client->t), held.bytes + held.off,
                                  held.len - held.off, reply, sizeof reply, &result);
        CHECK(rc == CH_OK || rc == CH_TCP_AGAIN || rc == CH_ECLOSED);
        held.off += result.consumed;
        plaintext += result.pt_len;
        if (rc != CH_OK) {
            break;
        }
    }
    return plaintext;
}

// The server reads every record the client sent through client_send,
// where it lies in to_server, and returns the plaintext bytes it read.
static size_t server_reads_sent(ch_tcp_priv *server) {
    size_t plaintext = 0;
    uint8_t reply[CH_ALERT_RECORD_LEN];
    for (int i = 0; i < 16; i++) {
        ch_read_result result;
        int rc = ch_read_in_place(tls_public(&server->t), to_server.bytes + to_server.off,
                                  to_server.len - to_server.off, reply, sizeof reply, &result);
        CHECK(rc == CH_OK || rc == CH_TCP_AGAIN || rc == CH_ECLOSED);
        to_server.off += result.consumed;
        plaintext += result.pt_len;
        if (rc != CH_OK) {
            break;
        }
    }
    return plaintext;
}

// Every path a connected session runs, on both ends, while no access to
// either handshake buffer is allowed.
static void connected_paths(ch_tcp_priv *client, ch_tcp_priv *server) {
    memset(&held, 0, sizeof held);
    memset(&to_server, 0, sizeof to_server);
    client->t.cfg.send = client_send;
    server->t.cfg.send = server_send;
    static const uint8_t ping[4] = {'p', 'i', 'n', 'g'};
    CHECK(test_write(tls_public(&client->t), ping, sizeof ping) == CH_OK);
    CHECK(server_reads_sent(server) == sizeof ping);

    // A KeyUpdate the client owes goes before its data, and the server
    // rekeys its read direction for it.
    client->t.key_update_owed = 1;
    CHECK(test_write(tls_public(&client->t), ping, sizeof ping) == CH_OK);
    CHECK(server_reads_sent(server) == sizeof ping);

    // A ticket, a ticket in two records and data, from the server.
    uint8_t ticket_msg[32];
    size_t ticket_len = build_ticket(ticket_msg, sizeof ticket_msg);
    (void)hold_sealed(server, REC_HANDSHAKE, ticket_msg, ticket_len);
    (void)hold_sealed(server, REC_HANDSHAKE, ticket_msg, ticket_len / 2);
    CHECK(client_reads_held(client) == 0);
    (void)hold_sealed(server, REC_HANDSHAKE, ticket_msg + ticket_len / 2,
                      ticket_len - ticket_len / 2);
    CHECK(test_write(tls_public(&server->t), ping, sizeof ping) == CH_OK);
    CHECK(client_reads_held(client) == sizeof ping);

    // Both closes, each read where it lies, and the sessions ended.
    test_close(tls_public(&client->t));
    CHECK(server_reads_sent(server) == 0 && server->t.read_closed == 1);
    test_close(tls_public(&server->t));
    ch_tcp_close(tcp_public(client));
    ch_tcp_close(tcp_public(server));
}

static void test_connected_session_reads_no_buffer(ch_tcp_priv *client, ch_tcp_priv *server,
                                                   const ch_cfg *ccfg, const ch_cfg *scfg) {
    size_t client_mapped = 0;
    size_t server_mapped = 0;
    uint8_t *client_pages = pages_for(sizeof cli_buf, &client_mapped);
    uint8_t *server_pages = pages_for(sizeof srv_buf, &server_mapped);
    CHECK(client_pages != NULL && server_pages != NULL);
    if (client_pages == NULL || server_pages == NULL) {
        return;
    }
    ch_cfg c = *ccfg;
    ch_cfg s = *scfg;
    c.buf = client_pages;
    c.buf_len = sizeof cli_buf;
    s.buf = server_pages;
    s.buf_len = sizeof srv_buf;
    (void)run_handshake(client, server, &c, &s);
    CHECK(ch_tcp_state(tcp_public(client)) == CH_ST_CONNECTED);
    CHECK(ch_tcp_state(tcp_public(server)) == CH_ST_CONNECTED);
    CHECK(all_zero(client_pages, sizeof cli_buf) && all_zero(server_pages, sizeof srv_buf));
    CHECK(mprotect(client_pages, client_mapped, PROT_NONE) == 0);
    CHECK(mprotect(server_pages, server_mapped, PROT_NONE) == 0);
    connected_paths(client, server);
    CHECK(munmap(client_pages, client_mapped) == 0);
    CHECK(munmap(server_pages, server_mapped) == 0);
}

// Each end gives its buffer back on a failure and on a close before it
// connects. The client fails on a server flight whose last byte is
// flipped, which holds a protected record whose tag does not match; the
// server is closed halfway, with the ClientHello in its buffer.
static void test_buffers_given_back_early(ch_tcp_priv *client, ch_tcp_priv *server,
                                          const ch_cfg *ccfg, const ch_cfg *scfg) {
    test_read_reset();
    to_client.len = 0;
    CHECK(server_init(server, scfg) == CH_OK);
    CHECK(client_init(client, ccfg) == CH_OK);
    CHECK(client_to_server(client, server));
    CHECK(!all_zero(srv_buf, sizeof srv_buf));
    CHECK(to_client.len > 0);
    to_client.bytes[to_client.len - 1] ^= 1;
    expect_refusal = 1;
    CHECK(!server_to_client(client));
    expect_refusal = 0;
    CHECK(ch_tcp_state(tcp_public(client)) == CH_ST_FAILED);
    CHECK(client->t.cfg.buf == NULL && all_zero(cli_buf, sizeof cli_buf));

    ch_tcp_close(tcp_public(server));
    CHECK(server->t.cfg.buf == NULL && all_zero(srv_buf, sizeof srv_buf));
    ch_tcp_close(tcp_public(client));
}

// The rules above on fresh pairs, then a header no peer may send, which a
// connected client refuses once its five bytes are there.
static void test_handshake_buffer(ch_tcp_priv *client, ch_tcp_priv *server) {
    ch_cfg ccfg;
    ch_cfg scfg;
    server_config(&scfg);
    client_config(&ccfg);
    test_buffers_given_back_early(client, server, &ccfg, &scfg);
    test_connected_session_reads_no_buffer(client, server, &ccfg, &scfg);
    (void)run_handshake(client, server, &ccfg, &scfg);
    read_oversize_header(client);
}

#endif
