// Handshake message parsing differential section: the four server-to-
// client messages handshake_parser.c reads before the peer is authenticated —
// ServerHello (including HelloRetryRequest), EncryptedExtensions,
// Certificate, and CertificateVerify. Every row builds one message,
// runs the C parser and the Lean spec on it, and compares. This header
// holds the framing, the build tokens and the first two messages;
// test/diff_handshake_certificate.h holds the other two.
// Included by test/diff_test.c after diff_driver.h (single translation unit).
#ifndef CH_DIFFHANDSHAKE_PARSER_H
#define CH_DIFFHANDSHAKE_PARSER_H

#include "buf.h"
#include "cfg.h"
#include "handshake_message.h"
#include "handshake_parser.h"

// HandshakeType values (RFC 9846 §4).
#define HSPD_SERVER_HELLO 2
#define HSPD_ENCRYPTED_EXTENSIONS 8
#define HSPD_CERTIFICATE 11
#define HSPD_CERTIFICATE_VERIFY 15

// ExtensionType values this section builds with (RFC 9846 §4.3,
// RFC 8449 §4).
#define HSPD_SERVER_NAME 0
#define HSPD_SUPPORTED_GROUPS 10
#define HSPD_ALPN 16
#define HSPD_RECORD_SIZE_LIMIT 28
#define HSPD_PRE_SHARED_KEY 41
#define HSPD_EARLY_DATA 42
#define HSPD_SUPPORTED_VERSIONS 43
#define HSPD_COOKIE 44
#define HSPD_KEY_SHARE 51

// The trust mode fixes three more narrowings, as the KEX token fixes
// the group. A TRUST=webpki ClientHello sends server_name, so the model
// admits its empty acknowledgement (`sni`); it may offer application
// protocols, so the model admits one selection from that offer
// (`hspd_alpn_names`); and it offers five signature schemes, so the
// model admits three of them in CertificateVerify (`webpki`). The raw
// and ca builds send no server_name, offer no protocol and offer the
// one pinned scheme.
// The protocols a row's ALPN extension selects from: "h2" and
// "http/1.1" are what an HTTP client sends, and "x" is the shortest
// ProtocolName RFC 7301 §3.1 admits. Every build builds from this
// table; only a TRUST=webpki hello may offer any of them, so
// HSPD_ALPN_OFFER_MAX is 0 in the other builds and every ALPN row there
// is a response the client never requested.
#define HSPD_ALPN_MAX 3
static const char *const hspd_alpn_names[HSPD_ALPN_MAX] = {"h2", "http/1.1", "x"};
#ifdef CH_TRUST_WEBPKI
#define HSPD_SNI_TOKEN "sni"
#define HSPD_ALPN_OFFER_MAX HSPD_ALPN_MAX
#else
#define HSPD_SNI_TOKEN "nosni"
#define HSPD_ALPN_OFFER_MAX 0
#endif

#define HSPD_X25519 0x001d
#define HSPD_X25519MLKEM768 0x11ec
#define HSPD_SUITE 0x1303 // TLS_CHACHA20_POLY1305_SHA256

// The build offers one group (CH_KEX_GROUP); the model takes the
// matching Makefile KEX token so both narrow the same way, like the
// signature scheme token below. The wrong-group mutation writes the
// other build's group, so each build's run diffs the cross-build
// refusal: a classic client refuses a hybrid selection and a hybrid
// client refuses a classic one.
#ifdef CH_KEX_PQ
#define HSPD_KEX_TOKEN "pq"
#define HSPD_OTHER_GROUP HSPD_X25519
#else
#define HSPD_KEX_TOKEN "x25519"
#define HSPD_OTHER_GROUP HSPD_X25519MLKEM768
#endif

// Sized for the hybrid build's largest ServerHello body: the 38-byte
// prefix, the extension-block length, the supported_versions and
// pre_shared_key extensions, and a key_share extension whose
// extension_data is 4 octets of group and length plus the 1120-byte
// share. The command and hex buffers below derive from this, so they
// scale with it.
#define HSPD_BODY_MAX 1280

// The C parsers take a message body; the model takes the whole
// Handshake structure of RFC 9846 §4 — msg_type, uint24 length, then
// the body those two frame. Every request reframes the body so the two
// sides read the same message. `arg` is the op's leading arguments,
// space-separated, or "" for the ops that take none.
static void hspd_request(char *cmd, size_t cap, const char *op, const char *arg, uint8_t type,
                         const uint8_t *body, size_t n) {
    uint8_t msg[HSPD_BODY_MAX + 4];
    wbuf w;
    wb_init(&w, msg, sizeof msg);
    wb_u8(&w, type);
    wb_u24(&w, (uint32_t)n);
    wb_bytes(&w, body, n);
    if (w.err) {
        die("handshake_parser: framing buffer too small");
    }
    char hex[2 * sizeof msg + 1];
    (void)hex_encode(hex, msg, w.len);
    (void)snprintf(cmd, cap, "%s %s%s%s", op, arg, arg[0] != '\0' ? " " : "", hex);
}

// What the row put in the message, for the cases where C's answer alone
// cannot say what the model should have replied.
typedef struct {
    int psk_offered;   // hsp_parse_server_hello's psk_mode
    int psk_ext;       // a pre_shared_key response is in the message
    unsigned identity; // the selected_identity it carries
} hspd_sh_plan;

static void hspd_sh_row(const hspd_sh_plan *plan, const uint8_t *body, size_t n) {
    server_hello_info info;
    memset(&info, 0, sizeof info);
    int rc = hsp_parse_server_hello(body, n, &info, plan->psk_offered);

    // Three refusals the C parser defers to handshake.c:352 and the
    // model makes at parse time: a ServerHello with no usable key
    // share, a selected_identity outside the single index this client
    // offers, and a retry carrying no cookie — the only change a retry
    // can ask this client for (RFC 9846 §4.2.4). Each ends the
    // handshake on both sides; only the layer that ends it differs, so
    // project C down to the model's boundary rather than weaken the
    // model to match the split.
    int deferred =
        info.hrr ? info.cookie == NULL : !info.have_share || (plan->psk_ext && !info.psk_ok);

    // The want buffer holds the largest accepted reply: "sh ", the
    // share's hex (2240 characters in the hybrid build), and the
    // identity — or "hrr " and the cookie's hex.
    char want[2 * CH_KEX_SERVER_SHARE + 2 * HSP_COOKIE_MAX + 64];
    if (rc != CH_OK || deferred) {
        (void)snprintf(want, sizeof want, "ERR hs_server_hello reject");
    } else if (info.hrr) {
        char cookie_hex[2 * HSP_COOKIE_MAX + 1];
        (void)hex_encode(cookie_hex, info.cookie, info.cookie_len);
        (void)snprintf(want, sizeof want, "hrr %s", cookie_hex);
    } else {
        // The model reports the selected group and the whole
        // key_exchange value; the C parser stores the group and splits
        // the value into server_ct and server_pub (hybrid) or stores
        // server_pub alone, so the row reassembles the wire order —
        // ML-KEM ciphertext first (RFC 10024).
        char share_hex[2 * CH_KEX_SERVER_SHARE + 1];
#ifdef CH_KEX_PQ
        size_t ct_hex_len = hex_encode(share_hex, info.server_ct, MLKEM_CT_LEN);
        (void)hex_encode(share_hex + ct_hex_len, info.server_pub, X25519_LEN);
#else
        (void)hex_encode(share_hex, info.server_pub, X25519_LEN);
#endif
        (void)snprintf(want, sizeof want, "sh %u %s %s", (unsigned)info.group, share_hex,
                       plan->psk_ext ? "0" : "-");
    }

    char cmd[2 * (HSPD_BODY_MAX + 4) + 64];
    char arg[16];
    (void)snprintf(arg, sizeof arg, "%s %s", plan->psk_offered ? "psk" : "nopsk", HSPD_KEX_TOKEN);
    hspd_request(cmd, sizeof cmd, "hs_server_hello", arg, HSPD_SERVER_HELLO, body, n);
    expect(cmd, want);
}

// legacy_version through legacy_compression_method (§4.2.3).
static void hspd_sh_prefix(wbuf *w, size_t mut, const uint8_t *random) {
    wb_u16(w, mut == 0 ? 0x0304 : 0x0303);
    wb_bytes(w, random, 32);
    if (mut == 1) { // an echo we never offered
        wb_u8(w, 4);
        wb_bytes(w, random, 4);
    } else {
        wb_u8(w, 0); // handshake_message.c offers an empty legacy_session_id
    }
    wb_u16(w, mut == 2 ? 0x1301 : HSPD_SUITE);
    wb_u8(w, mut == 3 ? 1 : 0); // legacy_compression_method
}

// supported_versions, which §9.2 requires in both messages.
static void hspd_sh_version_ext(wbuf *w, size_t mut) {
    if (mut == 4) {
        return;
    }
    wb_u16(w, HSPD_SUPPORTED_VERSIONS);
    wb_u16(w, mut == 5 ? 3 : 2);
    wb_u16(w, mut == 6 ? 0x0303 : 0x0304);
    if (mut == 5) {
        wb_u8(w, 0); // §4.3.1's selected_version is one u16, not a list
    }
}

// The retry branch's extensions (§4.2.4): the cookie, and the key_share
// a retry may not carry.
static void hspd_sh_retry_exts(wbuf *w, size_t mut, const uint8_t *cookie, size_t cookie_len) {
    if (mut != 7) {
        wb_u16(w, HSPD_COOKIE);
        wb_u16(w, (uint16_t)(cookie_len + 2));
        wb_u16(w, (uint16_t)(mut == 8 ? 0 : cookie_len));
        wb_bytes(w, cookie, cookie_len);
    }
    if (mut == 9) { // a retry selecting the build's group is §4.2.4 illegal
        wb_u16(w, HSPD_KEY_SHARE);
        wb_u16(w, 2);
        wb_u16(w, CH_KEX_GROUP);
    }
    if (mut == 16) { // §4.2.4 lists no pre_shared_key for a retry
        wb_u16(w, HSPD_PRE_SHARED_KEY);
        wb_u16(w, 2);
        wb_u16(w, 0);
    }
}

// The ServerHello branch's extensions (§4.2.3): the key share, and a
// pre_shared_key response — admissible only when the ClientHello
// offered one (§4.3), which mut 13 defies.
static void hspd_sh_share_exts(wbuf *w, size_t mut, hspd_sh_plan *plan, const uint8_t *share) {
    if (mut != 10) {
        wb_u16(w, HSPD_KEY_SHARE);
        wb_u16(w, (uint16_t)(CH_KEX_SERVER_SHARE + 4));
        // mut 11: the other build's group, so each run diffs the
        // cross-build refusal.
        wb_u16(w, mut == 11 ? HSPD_OTHER_GROUP : CH_KEX_GROUP);
        wb_u16(w, (uint16_t)(mut == 12 ? CH_KEX_SERVER_SHARE - 1 : CH_KEX_SERVER_SHARE));
        wb_bytes(w, share, CH_KEX_SERVER_SHARE);
    }
    if (plan->psk_offered ? rng_below(2) == 0 : mut == 13) {
        plan->psk_ext = 1;
        plan->identity = rng_below(4) == 0 ? 1 : 0;
        wb_u16(w, HSPD_PRE_SHARED_KEY);
        wb_u16(w, 2);
        wb_u16(w, (uint16_t)plan->identity);
    }
}

// Writes the extensions vector's length into the two octets at exts.
// end is the offset the vector stops at, which every row but one takes
// from the block it wrote. wb_patch16 cannot do this, because it always
// measures to w->len; the w->err guard is wb_patch16's, and it is here
// for the same reason: a writer that overflowed never wrote the two
// octets at exts.
static void hspd_sh_patch_vector(wbuf *w, size_t exts, size_t end) {
    if (w->err) {
        return;
    }
    size_t n = end - exts - 2;
    w->p[exts] = (uint8_t)(n >> 8);
    w->p[exts + 1] = (uint8_t)n;
}

static void diff_hs_server_hello(void) {
    for (int i = 0; i < 600; i++) {
        hspd_sh_plan plan = {0};
        plan.psk_offered = (int)rng_below(2);
        int hrr = rng_below(4) == 0;
        // One deliberate deviation per row, drawn from the menu the RFC
        // and the profile between them make illegal; 18 and up leave
        // the message on profile.
        size_t mut = rng_below(21);

        uint8_t random[32];
        rng_fill(random, sizeof random);
        if (hrr) {
            memcpy(random, hsp_hrr_magic, sizeof random);
        }
        uint8_t share[CH_KEX_SERVER_SHARE];
        rng_fill(share, sizeof share);
        uint8_t cookie[HSP_COOKIE_MAX];
        size_t cookie_len = 1 + rng_below(HSP_COOKIE_MAX);
        rng_fill(cookie, cookie_len);

        uint8_t body[HSPD_BODY_MAX];
        wbuf w;
        wb_init(&w, body, sizeof body);
        hspd_sh_prefix(&w, mut, random);
        size_t exts = wb_mark(&w, 2);
        hspd_sh_version_ext(&w, mut);
        size_t after_version = w.len;
        if (hrr) {
            hspd_sh_retry_exts(&w, mut, cookie, cookie_len);
        } else {
            hspd_sh_share_exts(&w, mut, &plan, share);
        }
        if (mut == 14) { // no ServerHello carries early_data
            wb_u16(&w, HSPD_EARLY_DATA);
            wb_u16(&w, 0);
        }
        // Every row but mut 17 gives the vector the whole block. Mut 17
        // gives it supported_versions alone, so every later extension
        // lies inside the message and outside the vector: §4.2.3 ends
        // the message at the vector, and a parser that walked the
        // message instead would read them all and accept.
        hspd_sh_patch_vector(&w, exts, mut == 17 ? after_version : w.len);
        if (w.err) {
            die("handshake_parser: ServerHello buffer too small");
        }
        if (mut == 15) {
            wb_u8(&w, 0); // §4 makes the extension vector's length exact
        }
        hspd_sh_row(&plan, body, w.len);
    }
}

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
