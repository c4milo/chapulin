// Resumption over the record transport, both halves in one process: this
// tree's server issues a ticket after a full handshake, this tree's client
// takes it through ch_read and on_ticket, and a second connection resumes
// with it and no certificate. Included by test/rec_loop_test.c after
// test/rec_read_tests.h, whose held records and held_recv it reads.
//
// The client offers the ticket alone, with no signature scheme beside it,
// because that is the one resumed hello this client writes (handshake.h).
// So a server that passes the ticket over has no certificate path to take,
// and answers missing_extension: every refusal row below reads that alert
// where a hello that also offered a scheme would get a full handshake
// instead, which bin/srv_flight_test checks.
#ifndef CH_TEST_REC_RESUME_TESTS_H
#define CH_TEST_REC_RESUME_TESTS_H

#include "srv_resume.h"

static const uint8_t loop_ticket_key[SRV_TICKET_KEY_LEN] = {
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80};
static const uint8_t other_loop_ticket_key[SRV_TICKET_KEY_LEN] = {
    0x62, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80};

// The server's clock when the first ticket is issued.
#define LOOP_NOW 1700000000U

// One ticket as a caller stores it: the fields on_ticket hands over.
typedef struct {
    uint8_t identity[CH_TICKET_ID_MAX];
    size_t identity_len;
    uint8_t psk[SHA256_LEN];
    uint32_t lifetime_s;
    uint32_t age_add;
} kept_ticket;

static kept_ticket last_ticket;
static size_t tickets_kept;

static void keep_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    CHECK(ticket->identity_len <= sizeof last_ticket.identity);
    memcpy(last_ticket.identity, ticket->identity, ticket->identity_len);
    last_ticket.identity_len = ticket->identity_len;
    memcpy(last_ticket.psk, ticket->psk, SHA256_LEN);
    last_ticket.lifetime_s = ticket->lifetime_s;
    last_ticket.age_add = ticket->age_add;
    tickets_kept++;
}

// Hands what the server pushed after the handshake to the connected client
// through ch_read, as a caller's recv would. The records carry the ticket
// and no application data, so the read waits.
static void take_post_handshake(ch_record *client) {
    memset(&held, 0, sizeof held);
    memcpy(held.bytes, to_client.bytes, to_client.len);
    held.len = to_client.len;
    to_client.len = 0;
    client->t.cfg.recv = held_recv;
    client->t.cfg.on_ticket = keep_ticket;
    uint8_t got[16];
    CHECK(ch_read(&client->t, got, sizeof got) == CH_RECORD_AGAIN);
    CHECK(held.off == held.len);
}

// The client configuration that presents t: the PSK fields and no pin.
static void resume_config(ch_cfg *cfg, const kept_ticket *t) {
    client_config(cfg);
    cfg->server_pubkey = NULL;
    cfg->server_pubkey_len = 0;
    cfg->psk = t->psk;
    cfg->psk_len = SHA256_LEN;
    cfg->psk_id = t->identity;
    cfg->psk_id_len = t->identity_len;
    cfg->resumption = 1;
    cfg->obfuscated_age = t->age_add + 5000; // five seconds in milliseconds
}

// Runs one handshake the server must refuse, and returns the alert it chose.
static uint8_t refused(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                       const ch_cfg *scfg) {
    expect_refusal = 1;
    (void)run_handshake(client, server, ccfg, scfg);
    expect_refusal = 0;
    CHECK(ch_record_state(server) == CH_ST_FAILED);
    CHECK(ch_record_state(client) != CH_ST_CONNECTED);
    return ch_record_alert(server);
}

static void test_resumption(void) {
    static ch_record client;
    static ch_record server;
    ch_cfg scfg;
    ch_cfg ccfg;

    // The full handshake, and the ticket it ends with: the whole lifetime,
    // from a server that sent its Certificate and CertificateVerify.
    server_config(&scfg);
    scfg.srv.ticket_key = loop_ticket_key;
    scfg.srv.now_seconds = LOOP_NOW;
    client_config(&ccfg);
    io_calls = 0;
    tickets_kept = 0;
    (void)run_handshake(&client, &server, &ccfg, &scfg);
    CHECK(ch_record_state(&client) == CH_ST_CONNECTED);
    CHECK(ch_record_state(&server) == CH_ST_CONNECTED);
    CHECK(server.t.psk_selected == 0 && server.t.sigalg == SIGALG_RSA_PSS_RSAE_SHA256);
    // ServerHello, EncryptedExtensions, Certificate, CertificateVerify,
    // Finished, then the ticket.
    CHECK(records_pushed == 6);
    take_post_handshake(&client);
    CHECK(tickets_kept == 1 && last_ticket.lifetime_s == SRV_TICKET_LIFETIME);
    CHECK(last_ticket.identity_len == SRV_TICKET_LEN);
    kept_ticket first = last_ticket;

    // The resumed handshake: the client presents the ticket and pins
    // nothing, the server sends no Certificate, and both ends derive one
    // exporter secret. The server issues a fresh ticket whose lifetime ends
    // where the first one's does.
    resume_config(&ccfg, &first);
    scfg.srv.now_seconds = LOOP_NOW + 5;
    (void)run_handshake(&client, &server, &ccfg, &scfg);
    CHECK(ch_record_state(&client) == CH_ST_CONNECTED);
    CHECK(ch_record_state(&server) == CH_ST_CONNECTED);
    CHECK(server.t.psk_selected == 1 && server.t.sigalg == 0);
    // psk_dhe_ke runs the key exchange again, over the same group.
    CHECK(client.t.group == LOOP_GROUP && server.t.group == LOOP_GROUP);
    // ServerHello, EncryptedExtensions and Finished, then the ticket.
    CHECK(records_pushed == 4);
    uint8_t from_client[SHA256_LEN];
    uint8_t from_server[SHA256_LEN];
    CHECK(ch_export(&client.t, "EXPORTER-Channel-Binding", NULL, 0, from_client,
                    sizeof from_client) == CH_OK);
    CHECK(ch_export(&server.t, "EXPORTER-Channel-Binding", NULL, 0, from_server,
                    sizeof from_server) == CH_OK);
    CHECK(memcmp(from_client, from_server, SHA256_LEN) == 0);
    take_post_handshake(&client);
    CHECK(tickets_kept == 2 && last_ticket.lifetime_s == SRV_TICKET_LIFETIME - 5);
    CHECK(memcmp(last_ticket.psk, first.psk, SHA256_LEN) != 0);
    CHECK(io_calls == 0);

    // The lifetime's exact boundary on the server's clock: the first
    // ticket resumes at the last valid second and not one second later.
    resume_config(&ccfg, &first);
    scfg.srv.now_seconds = (uint64_t)LOOP_NOW + SRV_TICKET_LIFETIME;
    (void)run_handshake(&client, &server, &ccfg, &scfg);
    CHECK(server.t.psk_selected == 1 && ch_record_state(&client) == CH_ST_CONNECTED);
    // At the end of its lifetime the chain has nothing left to give.
    CHECK(to_client.len == 0 && records_pushed == 3);
    scfg.srv.now_seconds = (uint64_t)LOOP_NOW + SRV_TICKET_LIFETIME + 1;
    CHECK(refused(&client, &server, &ccfg, &scfg) == ALERT_MISSING_EXTENSION);

    // A ticket issued after the server's clock reads is refused.
    scfg.srv.now_seconds = LOOP_NOW - 1;
    CHECK(refused(&client, &server, &ccfg, &scfg) == ALERT_MISSING_EXTENSION);

    // A server holding another ticket key cannot open the ticket.
    scfg.srv.now_seconds = LOOP_NOW + 5;
    scfg.srv.ticket_key = other_loop_ticket_key;
    CHECK(refused(&client, &server, &ccfg, &scfg) == ALERT_MISSING_EXTENSION);
    scfg.srv.ticket_key = loop_ticket_key;

    // One byte of the ticket moved: it no longer opens.
    kept_ticket tampered = first;
    tampered.identity[40] ^= 0x01;
    resume_config(&ccfg, &tampered);
    CHECK(refused(&client, &server, &ccfg, &scfg) == ALERT_MISSING_EXTENSION);

    // The right ticket under the wrong PSK: the ticket opens, and the
    // binder the client computed with its PSK does not match, which is
    // decrypt_error.
    kept_ticket wrong_psk = first;
    wrong_psk.psk[0] ^= 0x01;
    resume_config(&ccfg, &wrong_psk);
    CHECK(refused(&client, &server, &ccfg, &scfg) == ALERT_DECRYPT_ERROR);

    // No clock: the full handshake completes and no ticket follows it, and
    // the ticket a client presents is not judged.
    client_config(&ccfg);
    scfg.srv.now_seconds = 0;
    (void)run_handshake(&client, &server, &ccfg, &scfg);
    CHECK(ch_record_state(&server) == CH_ST_CONNECTED);
    CHECK(records_pushed == 5 && to_client.len == 0);
    resume_config(&ccfg, &first);
    CHECK(refused(&client, &server, &ccfg, &scfg) == ALERT_MISSING_EXTENSION);
}

#endif
