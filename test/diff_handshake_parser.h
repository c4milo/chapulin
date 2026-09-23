// Handshake message parsing differential section: the four server-to-
// client messages handshake_parser.c reads before the peer is authenticated —
// ServerHello (including HelloRetryRequest), EncryptedExtensions,
// Certificate, and CertificateVerify. Every row builds one message,
// runs the C parser and the Lean spec on it, and compares. This header
// holds the framing, the build tokens and the ServerHello;
// test/diff_encrypted_exts.h holds EncryptedExtensions and
// test/diff_handshake_certificate.h the other two.
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
#define HSPD_SUITE 0x1303     // TLS_CHACHA20_POLY1305_SHA256
#define HSPD_SUITE_AES 0x1301 // TLS_AES_128_GCM_SHA256

// The suites the build's ClientHello offers, as the Makefile's SUITE
// value spells them: ChaCha20 alone, or ChaCha20 and AES-128-GCM from
// the SUITE=aesgcm TRUST=webpki client (docs/decisions.md entry 45).
// mut 2 writes a suite the build did not offer: AES-128-GCM in the
// one-suite builds, so each run diffs that refusal, and
// TLS_AES_256_GCM_SHA384, which no build offers, in the two-suite one.
#ifdef CH_CLIENT_TWO_SUITES
#define HSPD_SUITE_TOKEN "aesgcm"
#define HSPD_UNOFFERED_SUITE 0x1302
#define HSPD_ACCEPTED_SUITE(info) ((info).suite)
#else
#define HSPD_SUITE_TOKEN "chacha"
#define HSPD_UNOFFERED_SUITE HSPD_SUITE_AES
#define HSPD_ACCEPTED_SUITE(info) HSPD_SUITE
#endif

// The build offers one group (CH_KEX_GROUP); the model takes the
// matching Makefile KEX token so both narrow the same way, like the
// signature scheme token below. The wrong-group mutation writes the
// other build's group, so each build's run diffs the cross-build
// refusal: a classic client refuses a hybrid selection and a hybrid
// client refuses a classic one.
//
// The KEX=pq TRUST=webpki build lists both groups and sends a share for
// the hybrid alone (docs/decisions.md entry 39), and the model's
// two-groups token says so. A retry there may name x25519 and a
// ServerHello may select it with a 32-byte share; every other build
// refuses both.
#ifdef CH_KEX_TWO_GROUPS
#define HSPD_KEX_TOKEN "two-groups"
#define HSPD_OTHER_GROUP HSPD_X25519
#define HSPD_RETRY_GROUP(info) ((info).retry_group)
#elif defined(CH_KEX_PQ)
#define HSPD_KEX_TOKEN "pq"
#define HSPD_OTHER_GROUP HSPD_X25519
#else
#define HSPD_KEX_TOKEN "x25519"
#define HSPD_OTHER_GROUP HSPD_X25519MLKEM768
#endif
#ifndef HSPD_RETRY_GROUP
#define HSPD_RETRY_GROUP(info) 0
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
    int retry_x25519;  // a retry names x25519, which only two-groups admits
    int retry_bare;    // that retry carries no cookie
    int sh_x25519;     // a ServerHello selects x25519 with a 32-byte share
    uint16_t suite;    // the cipher_suite an on-profile row carries
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
    int deferred = info.hrr ? info.cookie == NULL && HSPD_RETRY_GROUP(info) == 0
                            : !info.have_share || (plan->psk_ext && !info.psk_ok);

    // The want buffer holds the largest accepted reply: "sh ", the
    // share's hex (2240 characters in the hybrid build), and the
    // identity — or "hrr " and the cookie's hex.
    char want[2 * CH_KEX_SERVER_SHARE + 2 * HSP_COOKIE_MAX + 64];
    if (rc != CH_OK || deferred) {
        (void)snprintf(want, sizeof want, "ERR hs_server_hello reject");
    } else if (info.hrr) {
        // The model prints "-" for a retry field the message did not
        // carry, and the retry's key_share names its group in decimal.
        char cookie_hex[2 * HSP_COOKIE_MAX + 1] = "-";
        if (info.cookie != NULL) {
            (void)hex_encode(cookie_hex, info.cookie, info.cookie_len);
        }
        char group[8] = "-";
        if (HSPD_RETRY_GROUP(info) != 0) {
            (void)snprintf(group, sizeof group, "%u", (unsigned)HSPD_RETRY_GROUP(info));
        }
        (void)snprintf(want, sizeof want, "hrr %s %s %u", cookie_hex, group,
                       (unsigned)HSPD_ACCEPTED_SUITE(info));
    } else {
        // The model reports the selected group and the whole
        // key_exchange value; the C parser stores the group and splits
        // the value into server_ct and server_pub (hybrid) or stores
        // server_pub alone, so the row reassembles the wire order —
        // ML-KEM ciphertext first (RFC 10024).
        char share_hex[2 * CH_KEX_SERVER_SHARE + 1];
#ifdef CH_KEX_PQ
        size_t ct_hex_len = 0;
        if (info.group == HSPD_X25519MLKEM768) {
            ct_hex_len = hex_encode(share_hex, info.server_ct, MLKEM_CT_LEN);
        }
        (void)hex_encode(share_hex + ct_hex_len, info.server_pub, X25519_LEN);
#else
        (void)hex_encode(share_hex, info.server_pub, X25519_LEN);
#endif
        (void)snprintf(want, sizeof want, "sh %u %s %s %u", (unsigned)info.group, share_hex,
                       plan->psk_ext ? "0" : "-", (unsigned)HSPD_ACCEPTED_SUITE(info));
    }

    char cmd[2 * (HSPD_BODY_MAX + 4) + 64];
    char arg[32]; // "nopsk two-groups aesgcm" and its terminator
    (void)snprintf(arg, sizeof arg, "%s %s %s", plan->psk_offered ? "psk" : "nopsk", HSPD_KEX_TOKEN,
                   HSPD_SUITE_TOKEN);
    hspd_request(cmd, sizeof cmd, "hs_server_hello", arg, HSPD_SERVER_HELLO, body, n);
    expect(cmd, want);
}

// legacy_version through legacy_compression_method (§4.2.3).
static void hspd_sh_prefix(wbuf *w, size_t mut, const hspd_sh_plan *plan, const uint8_t *random) {
    wb_u16(w, mut == 0 ? 0x0304 : 0x0303);
    wb_bytes(w, random, 32);
    if (mut == 1) { // an echo we never offered
        wb_u8(w, 4);
        wb_bytes(w, random, 4);
    } else {
        wb_u8(w, 0); // handshake_message.c offers an empty legacy_session_id
    }
    wb_u16(w, mut == 2 ? HSPD_UNOFFERED_SUITE : plan->suite);
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
// a retry may not carry. A row that names x25519 writes the key_share a
// two-groups retry may carry, and may leave the cookie off, since the
// group is then the change the retry asks for.
static void hspd_sh_retry_exts(wbuf *w, size_t mut, const hspd_sh_plan *plan, const uint8_t *cookie,
                               size_t cookie_len) {
    if (plan->retry_x25519 && mut != 9) {
        wb_u16(w, HSPD_KEY_SHARE);
        wb_u16(w, 2);
        wb_u16(w, HSPD_X25519);
    }
    if (mut != 7 && !plan->retry_bare) {
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
        // The build's own share, or, when sh_x25519 is set, the 32-byte
        // x25519 share a two-groups ServerHello answers a retry naming
        // x25519 with. mut 11 writes the other group over the share, so
        // each run diffs the cross-build refusal, and mut 12 shortens the
        // share by one byte.
        size_t len = CH_KEX_SERVER_SHARE;
        uint16_t group = CH_KEX_GROUP;
        uint16_t other = HSPD_OTHER_GROUP;
#ifdef CH_KEX_TWO_GROUPS
        if (plan->sh_x25519) {
            len = X25519_LEN;
            group = HSPD_X25519;
            other = HSPD_X25519MLKEM768;
        }
#endif
        wb_u16(w, HSPD_KEY_SHARE);
        wb_u16(w, (uint16_t)(len + 4));
        wb_u16(w, mut == 11 ? other : group);
        wb_u16(w, (uint16_t)(mut == 12 ? len - 1 : len));
        wb_bytes(w, share, len);
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

// The row's on-profile shape. The shapes only a two-groups build admits
// are drawn in every build, so the others diff their refusal: a retry
// naming x25519, with and without a cookie. A ServerHello selecting
// x25519 is drawn only in the two-groups build, because the others
// refuse it as mut 11 already does. The suite is ChaCha20, or either
// offered suite in the two-suite build.
static void hspd_sh_draw_shapes(hspd_sh_plan *plan, int hrr) {
    plan->retry_x25519 = hrr && rng_below(3) == 0;
    plan->retry_bare = plan->retry_x25519 && rng_below(2) == 0;
    plan->suite = HSPD_SUITE;
#ifdef CH_CLIENT_TWO_SUITES
    // Either offered suite, in a retry or a ServerHello alike.
    if (rng_below(2) == 0) {
        plan->suite = HSPD_SUITE_AES;
    }
#endif
#ifdef CH_KEX_TWO_GROUPS
    plan->sh_x25519 = !hrr && rng_below(3) == 0;
#endif
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
        hspd_sh_draw_shapes(&plan, hrr);

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
        hspd_sh_prefix(&w, mut, &plan, random);
        size_t exts = wb_mark(&w, 2);
        hspd_sh_version_ext(&w, mut);
        size_t after_version = w.len;
        if (hrr) {
            hspd_sh_retry_exts(&w, mut, &plan, cookie, cookie_len);
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

#endif
