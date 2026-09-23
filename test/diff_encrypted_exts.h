// The EncryptedExtensions rows of the handshake message differential,
// over the framing and build tokens test/diff_handshake_parser.h defines.
// Split from that header, which holds the ServerHello rows, to keep each
// under the 500-line cap. Included by test/diff_test.c after that header
// (single translation unit).
#ifndef CH_DIFF_ENCRYPTED_EXTS_H
#define CH_DIFF_ENCRYPTED_EXTS_H

#include "diff_handshake_parser.h"

// The server_name acknowledgements an EncryptedExtensions row may carry
// (RFC 6066 §3): mut 5 writes one empty acknowledgement, which only a
// build that sent server_name admits; mut 7 writes it twice, and mut 6
// writes one carrying a byte of data, which no build admits.
static void hspd_ee_server_name(wbuf *w, size_t mut) {
    size_t empty_acks = 0;
    if (mut == 5 || mut == 7) {
        empty_acks = mut == 5 ? 1 : 2;
    }
    for (size_t i = 0; i < empty_acks; i++) {
        wb_u16(w, HSPD_SERVER_NAME);
        wb_u16(w, 0);
    }
    if (mut == 6) {
        wb_u16(w, HSPD_SERVER_NAME);
        wb_u16(w, 1);
        wb_u8(w, 0x78);
    }
}

#ifdef CH_TRUST_WEBPKI
// The ALPN offer a row makes: the first count names of
// hspd_alpn_names, as the ch_alpn_protocol array the C parser matches
// against and as the ProtocolNameList hex the model reads them back
// from (RFC 7301 §3.1). A count of 0 writes the "-" token, the offer a
// raw or ca hello makes and a webpki caller may make.
static void hspd_alpn_offer(size_t count, ch_alpn_protocol *offer, char *token, size_t cap) {
    uint8_t list[3 * (1 + 8)];
    wbuf w;
    wb_init(&w, list, sizeof list);
    for (size_t i = 0; i < count; i++) {
        const uint8_t *name = (const uint8_t *)hspd_alpn_names[i];
        size_t name_len = strlen(hspd_alpn_names[i]);
        offer[i].name = name;
        offer[i].name_len = name_len;
        wb_u8(&w, (uint8_t)name_len);
        wb_bytes(&w, name, name_len);
    }
    if (w.err) {
        die("handshake_parser: ALPN offer buffer too small");
    }
    if (count == 0) {
        (void)snprintf(token, cap, "-");
        return;
    }
    char hex[2 * sizeof list + 1];
    (void)hex_encode(hex, list, w.len);
    (void)snprintf(token, cap, "%s", hex);
}
#endif

// The ALPN extension a row may carry (RFC 7301 §3.2). mut 9 selects one
// name of the offer table, which the row's own offer may or may not
// hold; mut 10 selects a protocol no table lists; mut 11 sends an empty
// ProtocolName and mut 12 sends two, both bodies §3.2 refuses; mut 13
// sends the extension twice. Every other row carries none.
static void hspd_ee_alpn(wbuf *w, size_t mut, size_t pick) {
    if (mut < 9 || mut > 13) {
        return;
    }
    uint8_t list[2 * (1 + 8)];
    wbuf l;
    wb_init(&l, list, sizeof list);
    if (mut == 11) {
        wb_u8(&l, 0); // an empty ProtocolName: §3.1 gives it 1..255 bytes
    } else if (mut == 10) {
        wb_u8(&l, 2);
        wb_bytes(&l, (const uint8_t *)"h3", 2);
    } else {
        size_t count = mut == 12 ? 2 : 1; // §3.2: exactly one name
        for (size_t i = 0; i < count; i++) {
            const char *name = hspd_alpn_names[(pick + i) % HSPD_ALPN_MAX];
            wb_u8(&l, (uint8_t)strlen(name));
            wb_bytes(&l, (const uint8_t *)name, strlen(name));
        }
    }
    if (l.err) {
        die("handshake_parser: ALPN list buffer too small");
    }
    size_t copies = mut == 13 ? 2 : 1;
    for (size_t i = 0; i < copies; i++) {
        wb_u16(w, HSPD_ALPN);
        wb_u16(w, (uint16_t)(2 + l.len));
        wb_u16(w, (uint16_t)l.len);
        wb_bytes(w, list, l.len);
    }
}

// The EncryptedExtensions extension block (§4.4.1), with the row's one
// deviation written into it.
static void hspd_ee_build(wbuf *w, size_t mut, size_t pick, int have_limit, uint16_t limit) {
    size_t exts = wb_mark(w, 2);
    if (have_limit) {
        wb_u16(w, HSPD_RECORD_SIZE_LIMIT);
        wb_u16(w, mut == 0 ? 3 : 2);
        wb_u16(w, limit);
        if (mut == 0) {
            wb_u8(w, 0); // one u16 exactly, per §4.3
        }
    }
    if (mut == 1) { // a server may volunteer supported_groups
        wb_u16(w, HSPD_SUPPORTED_GROUPS);
        wb_u16(w, 4);
        wb_u16(w, 2);
        wb_u16(w, HSPD_X25519);
    }
    if (mut == 2) { // never offered, so §4.3's unsupported_extension
        wb_u16(w, HSPD_EARLY_DATA);
        wb_u16(w, 0);
    }
    if (mut == 3) { // a key_share belongs in the ServerHello
        wb_u16(w, HSPD_KEY_SHARE);
        wb_u16(w, 2);
        wb_u16(w, HSPD_X25519);
    }
    hspd_ee_server_name(w, mut);
    hspd_ee_alpn(w, mut, pick);
    wb_patch16(w, exts);
    if (mut == 4) {
        wb_u8(w, 0); // trailing octet past the vector
    }
    if (mut == 8) {
        // A whole supported_groups inside the message and outside the
        // vector. §4.4.1 ends the message at the vector; a parser that
        // walked the message instead would read it and accept.
        wb_u16(w, HSPD_SUPPORTED_GROUPS);
        wb_u16(w, 4);
        wb_u16(w, 2);
        wb_u16(w, HSPD_X25519);
    }
}

static void diff_hs_encrypted_exts(void) {
    for (int i = 0; i < 400; i++) {
        size_t mut = rng_below(14);
        int have_limit = rng_below(2) == 0;
        // RFC 8449 §4 floors the limit at 64; straddle it.
        uint16_t limit = (uint16_t)(60 + rng_below(16330));
        // How many protocols this row's ClientHello offered, and which
        // one the ALPN mutations select. A raw or ca build offers none,
        // so HSPD_ALPN_MAX is 0 there and every ALPN row is a response
        // the client never requested.
        size_t offer_count = rng_below(HSPD_ALPN_OFFER_MAX + 1);
        size_t pick = rng_below(HSPD_ALPN_MAX);

        uint8_t body[HSPD_BODY_MAX];
        wbuf w;
        wb_init(&w, body, sizeof body);
        hspd_ee_build(&w, mut, pick, have_limit, limit);
        if (w.err) {
            die("handshake_parser: EncryptedExtensions buffer too small");
        }

        // The C parser lowers the caller's limit and stores it less the
        // inner content-type octet the limit covers; the model reports
        // the extension's own value. Seed high so any accepted limit
        // lowers it, and undo the -1 here.
        uint16_t peer_limit = 0xffff;
        uint8_t alert = 0;
        char alpn_token[64];
#ifdef CH_TRUST_WEBPKI
        ch_alpn_protocol offer[HSPD_ALPN_MAX];
        hspd_alpn_offer(offer_count, offer, alpn_token, sizeof alpn_token);
        uint8_t selected = CH_ALPN_NONE;
        int rc = hsp_parse_encrypted_exts(body, w.len, &peer_limit, offer, offer_count, &selected,
                                          &alert);
        char picked[8] = "-";
        if (selected != CH_ALPN_NONE) {
            (void)snprintf(picked, sizeof picked, "%u", (unsigned)selected);
        }
        const char *selection = picked;
#else
        // No build but TRUST=webpki offers a protocol, so no build but
        // that one can report a selection.
        (void)offer_count;
        (void)snprintf(alpn_token, sizeof alpn_token, "-");
        int rc = hsp_parse_encrypted_exts(body, w.len, &peer_limit, &alert);
        const char *selection = "-";
#endif
        char want[64];
        if (rc != CH_OK) {
            (void)snprintf(want, sizeof want, "ERR hs_encrypted_extensions reject");
        } else if (peer_limit == 0xffff) {
            (void)snprintf(want, sizeof want, "ok - %s", selection);
        } else {
            (void)snprintf(want, sizeof want, "ok %u %s", (unsigned)peer_limit + 1U, selection);
        }
        char cmd[2 * (HSPD_BODY_MAX + 4) + 96];
        char arg[80];
        (void)snprintf(arg, sizeof arg, "%s %s", HSPD_SNI_TOKEN, alpn_token);
        hspd_request(cmd, sizeof cmd, "hs_encrypted_extensions", arg, HSPD_ENCRYPTED_EXTENSIONS,
                     body, w.len);
        expect(cmd, want);
    }
}

#endif
