// Two ticket rows of test/webpki_loop_test.c, which includes this file
// and whose helpers it reads (docs/decisions.md 55 and 132).
//   - check_declined_ticket_resumes: a server declines a ticket, and the
//     ticket that the declined session received resumes under the server
//     that sealed it, with the binding that on_ticket gave it.
//   - check_late_on_ticket: a caller sets on_ticket in the session after
//     ch_record_init. The init call saw no on_ticket and wrote no
//     ticket_config_hash, so the session gives the server's ticket to no
//     one.
#ifndef CH_TEST_WEBPKI_LOOP_TICKETS_H
#define CH_TEST_WEBPKI_LOOP_TICKETS_H

// scfg is the server that declined the kept ticket and sealed the one the
// declined session received, which kept now holds.
static void check_declined_ticket_resumes(const ch_cfg *scfg) {
    ch_cfg ccfg;
    size_t count = kept.count;
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    present_kept(&ccfg);
    CHECK(run(&ccfg, scfg));
    CHECK(client.t.psk_selected == 1 && server.t.psk_selected == 1);
    CHECK(kept.count == count + 1);
}

static void check_late_on_ticket(void) {
    ch_cfg scfg;
    ch_cfg ccfg;
    server_config(&scfg, ticket_key);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    ccfg.on_ticket = NULL;
    size_t count = kept.count;
    memset(&to_client, 0, sizeof to_client);
    CHECK(ch_srv_record_init(&server, &scfg) == CH_OK);
    CHECK(ch_record_init(&client, &ccfg) == CH_OK);
    client.t.cfg.on_ticket = keep_ticket;
    for (int round = 0; round < 4 && ch_record_state(&client) != CH_ST_CONNECTED; round++) {
        CHECK(client_to_server());
        if (ch_record_state(&client) != CH_ST_CONNECTED) {
            CHECK(server_to_client());
        }
    }
    CHECK(ch_record_state(&client) == CH_ST_CONNECTED);
    // The ticket record arrives after the handshake, and ch_read reads it.
    uint8_t got[16];
    CHECK(to_client.len > to_client.off);
    CHECK(ch_read(&client.t, got, sizeof got) == CH_RECORD_AGAIN);
    CHECK(to_client.off == to_client.len);
    CHECK(client.t.takes_tickets == 0 && kept.count == count);
}

#endif
