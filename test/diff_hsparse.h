// Handshake message parsing differential section: the four server-to-
// client messages hsparse.c reads before the peer is authenticated —
// ServerHello (including HelloRetryRequest), EncryptedExtensions,
// Certificate, and CertificateVerify. Every row builds one message,
// runs the C parser and the Lean spec on it, and compares.
// Included by test/diff_test.c after diff_driver.h (single translation unit).
#ifndef CH_DIFFHSPARSE_H
#define CH_DIFFHSPARSE_H

#include "buf.h"
#include "cfg.h"
#include "hsmsg.h"
#include "hsparse.h"

// HandshakeType values (RFC 9846 §4).
#define HSPD_SERVER_HELLO 2
#define HSPD_ENCRYPTED_EXTENSIONS 8
#define HSPD_CERTIFICATE 11
#define HSPD_CERTIFICATE_VERIFY 15

// ExtensionType values this section builds with (RFC 9846 §4.2,
// RFC 8449 §4).
#define HSPD_SERVER_NAME 0
#define HSPD_SUPPORTED_GROUPS 10
#define HSPD_RECORD_SIZE_LIMIT 28
#define HSPD_PRE_SHARED_KEY 41
#define HSPD_EARLY_DATA 42
#define HSPD_SUPPORTED_VERSIONS 43
#define HSPD_COOKIE 44
#define HSPD_KEY_SHARE 51

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
        die("hsparse: framing buffer too small");
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
    // can ask this client for (RFC 9846 §4.1.4). Each ends the
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
        // The model reports the whole key_exchange value; the C parser
        // splits it into server_ct and server_pub (hybrid) or stores
        // server_pub alone, so the row reassembles the wire order —
        // ML-KEM ciphertext first (RFC 10024).
        char share_hex[2 * CH_KEX_SERVER_SHARE + 1];
#ifdef CH_KEX_PQ
        size_t ct_hex_len = hex_encode(share_hex, info.server_ct, MLKEM_CT_LEN);
        (void)hex_encode(share_hex + ct_hex_len, info.server_pub, X25519_LEN);
#else
        (void)hex_encode(share_hex, info.server_pub, X25519_LEN);
#endif
        (void)snprintf(want, sizeof want, "sh %s %s", share_hex, plan->psk_ext ? "0" : "-");
    }

    char cmd[2 * (HSPD_BODY_MAX + 4) + 64];
    char arg[16];
    (void)snprintf(arg, sizeof arg, "%s %s", plan->psk_offered ? "psk" : "nopsk", HSPD_KEX_TOKEN);
    hspd_request(cmd, sizeof cmd, "hs_server_hello", arg, HSPD_SERVER_HELLO, body, n);
    expect(cmd, want);
}

// legacy_version through legacy_compression_method (§4.1.3).
static void hspd_sh_prefix(wbuf *w, size_t mut, const uint8_t *random) {
    wb_u16(w, mut == 0 ? 0x0304 : 0x0303);
    wb_bytes(w, random, 32);
    if (mut == 1) { // an echo we never offered
        wb_u8(w, 4);
        wb_bytes(w, random, 4);
    } else {
        wb_u8(w, 0); // hsmsg.c offers an empty legacy_session_id
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
        wb_u8(w, 0); // §4.2.1's selected_version is one u16, not a list
    }
}

// The retry branch's extensions (§4.1.4): the cookie, and the key_share
// a retry may not carry.
static void hspd_sh_retry_exts(wbuf *w, size_t mut, const uint8_t *cookie, size_t cookie_len) {
    if (mut != 7) {
        wb_u16(w, HSPD_COOKIE);
        wb_u16(w, (uint16_t)(cookie_len + 2));
        wb_u16(w, (uint16_t)(mut == 8 ? 0 : cookie_len));
        wb_bytes(w, cookie, cookie_len);
    }
    if (mut == 9) { // a retry selecting the build's group is §4.1.4 illegal
        wb_u16(w, HSPD_KEY_SHARE);
        wb_u16(w, 2);
        wb_u16(w, CH_KEX_GROUP);
    }
    if (mut == 16) { // §4.1.4 lists no pre_shared_key for a retry
        wb_u16(w, HSPD_PRE_SHARED_KEY);
        wb_u16(w, 2);
        wb_u16(w, 0);
    }
}

// The ServerHello branch's extensions (§4.1.3): the key share, and a
// pre_shared_key response — admissible only when the ClientHello
// offered one (§4.2), which mut 13 defies.
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

static void diff_hs_server_hello(void) {
    for (int i = 0; i < 600; i++) {
        hspd_sh_plan plan = {0};
        plan.psk_offered = (int)rng_below(2);
        int hrr = rng_below(4) == 0;
        // One deliberate deviation per row, drawn from the menu the RFC
        // and the profile between them make illegal; 17 and up leave
        // the message on profile.
        size_t mut = rng_below(20);

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
        if (hrr) {
            hspd_sh_retry_exts(&w, mut, cookie, cookie_len);
        } else {
            hspd_sh_share_exts(&w, mut, &plan, share);
        }
        if (mut == 14) { // no ServerHello carries early_data
            wb_u16(&w, HSPD_EARLY_DATA);
            wb_u16(&w, 0);
        }
        wb_patch16(&w, exts);
        if (w.err) {
            die("hsparse: ServerHello buffer too small");
        }
        if (mut == 15) {
            wb_u8(&w, 0); // §4 makes the extension vector's length exact
        }
        hspd_sh_row(&plan, body, w.len);
    }
}

// The EncryptedExtensions extension block (§4.3.1), with the row's one
// deviation folded in.
static void hspd_ee_build(wbuf *w, size_t mut, int have_limit, uint16_t limit) {
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
    if (mut == 5) { // a server_name ack the client never asked for
        wb_u16(w, HSPD_SERVER_NAME);
        wb_u16(w, 0);
    }
    wb_patch16(w, exts);
    if (mut == 4) {
        wb_u8(w, 0); // trailing octet past the vector
    }
}

static void diff_hs_encrypted_exts(void) {
    for (int i = 0; i < 400; i++) {
        size_t mut = rng_below(8);
        int have_limit = rng_below(2) == 0;
        // RFC 8449 §4 floors the limit at 64; straddle it.
        uint16_t limit = (uint16_t)(60 + rng_below(16330));

        uint8_t body[HSPD_BODY_MAX];
        wbuf w;
        wb_init(&w, body, sizeof body);
        hspd_ee_build(&w, mut, have_limit, limit);
        if (w.err) {
            die("hsparse: EncryptedExtensions buffer too small");
        }

        // The C parser lowers the caller's limit and stores it less the
        // inner content-type octet the limit covers; the model reports
        // the extension's own value. Seed high so any accepted limit
        // lowers it, and undo the -1 here.
        uint16_t peer_limit = 0xffff;
        uint8_t alert = 0;
        int rc = hsp_parse_encrypted_exts(body, w.len, &peer_limit, &alert);
        char want[64];
        if (rc != CH_OK) {
            (void)snprintf(want, sizeof want, "ERR hs_encrypted_extensions reject");
        } else if (peer_limit == 0xffff) {
            (void)snprintf(want, sizeof want, "ok -");
        } else {
            (void)snprintf(want, sizeof want, "ok %u", (unsigned)peer_limit + 1U);
        }
        char cmd[2 * (HSPD_BODY_MAX + 4) + 64];
        hspd_request(cmd, sizeof cmd, "hs_encrypted_extensions", "", HSPD_ENCRYPTED_EXTENSIONS,
                     body, w.len);
        expect(cmd, want);
    }
}

// The certificate_request_context and the CertificateEntry list
// (§4.4.2), with the row's one deviation folded in.
static void hspd_cert_build(wbuf *w, size_t mut, size_t entries, const uint8_t *leaf,
                            size_t leaf_len) {
    if (mut == 1) { // §4.4.2: the client's context is empty
        wb_u8(w, 2);
        wb_u16(w, 0);
    } else {
        wb_u8(w, 0);
    }
    size_t list = wb_mark(w, 3);
    for (size_t e = 0; e < entries; e++) {
        size_t n = e == 0 ? leaf_len : 1 + rng_below(64);
        wb_u24(w, (uint32_t)n);
        wb_bytes(w, leaf, n);
        if (mut == 2) { // a per-entry extension the profile never offers
            wb_u16(w, 4);
            wb_u16(w, HSPD_RECORD_SIZE_LIMIT);
            wb_u16(w, 2);
        } else {
            wb_u16(w, 0);
        }
    }
    wb_patch24(w, list);
    if (mut == 3) {
        wb_u8(w, 0); // trailing octet past the exact-fill list
    }
}

static void diff_hs_certificate(void) {
    for (int i = 0; i < 400; i++) {
        size_t mut = rng_below(6);
        size_t entries = mut == 0 ? 0 : 1 + rng_below(3);

        uint8_t leaf[200];
        size_t leaf_len = 1 + rng_below(sizeof leaf);
        rng_fill(leaf, leaf_len);

        uint8_t body[HSPD_BODY_MAX];
        wbuf w;
        wb_init(&w, body, sizeof body);
        hspd_cert_build(&w, mut, entries, leaf, leaf_len);
        if (w.err) {
            die("hsparse: Certificate buffer too small");
        }

        const uint8_t *clist = NULL;
        size_t clist_len = 0;
        uint8_t alert = 0;
        int rc = hsp_parse_certificate(body, w.len, &clist, &clist_len, &alert);
        char want[2 * sizeof leaf + 64];
        if (mut <= 3) {
            // Framing the C parser decides for itself — an empty list,
            // a nonempty certificate_request_context, a trailing octet
            // — plus mut 2, an entry extension the client never
            // offered: §4.4.2 makes it an unsupported_extension, but
            // hsp_parse_certificate hands the list on without reading
            // the entries, so that one refusal lives a layer up. The CA
            // build makes it in x509_verify_leaf (empty per-entry
            // extensions required); the pinned build never parses the
            // entries at all — it hashes the certificate into the
            // transcript and authenticates by the signature, so the
            // unread extension changes nothing an attacker can use. The
            // model refuses it either way; see CONTRACT.md's split
            // table.
            (void)snprintf(want, sizeof want, "ERR hs_certificate reject");
            CH_ASSERT(mut == 2 || rc != CH_OK);
        } else {
            char leaf_hex[2 * sizeof leaf + 1];
            (void)hex_encode(leaf_hex, leaf, leaf_len);
            (void)snprintf(want, sizeof want, "ok %zu %s", entries, leaf_hex);
            CH_ASSERT(rc == CH_OK && clist_len == w.len - 4);
        }
        char cmd[2 * (HSPD_BODY_MAX + 4) + 64];
        hspd_request(cmd, sizeof cmd, "hs_certificate", "", HSPD_CERTIFICATE, body, w.len);
        expect(cmd, want);
    }
}

static void diff_hs_certificate_verify(void) {
    // The build pins exactly one signature algorithm; the model takes
    // its name so both narrow the same way (RFC 9846 §4.4.3).
#if CH_PIN_SIGALG == SIGALG_ECDSA_P256_SHA256
    const char *scheme = "p256";
#else
    const char *scheme = "rsa";
#endif
    for (int i = 0; i < 400; i++) {
        size_t mut = rng_below(6);
        uint8_t sig[300];
        size_t sig_len = 1 + rng_below(sizeof sig);
        rng_fill(sig, sig_len);

        uint8_t body[HSPD_BODY_MAX];
        wbuf w;
        wb_init(&w, body, sizeof body);
        wb_u16(&w, mut == 0 ? 0x0401 : CH_PIN_SIGALG);
        wb_u16(&w, (uint16_t)(mut == 1 ? sig_len + 1 : sig_len));
        wb_bytes(&w, sig, sig_len);
        if (mut == 2) {
            wb_u8(&w, 0); // trailing octet past the exact-fill signature
        }
        if (w.err) {
            die("hsparse: CertificateVerify buffer too small");
        }

        const uint8_t *csig = NULL;
        size_t csig_len = 0;
        uint8_t alert = 0;
        int rc = hsp_parse_certificate_verify(body, w.len, &csig, &csig_len, &alert);
        char want[2 * sizeof sig + 64];
        if (rc != CH_OK) {
            (void)snprintf(want, sizeof want, "ERR hs_certificate_verify reject");
        } else {
            char sig_hex[2 * sizeof sig + 1];
            (void)hex_encode(sig_hex, csig, csig_len);
            (void)snprintf(want, sizeof want, "ok %u %s", (unsigned)CH_PIN_SIGALG, sig_hex);
        }
        char cmd[2 * (HSPD_BODY_MAX + 4) + 64];
        hspd_request(cmd, sizeof cmd, "hs_certificate_verify", scheme, HSPD_CERTIFICATE_VERIFY,
                     body, w.len);
        expect(cmd, want);
    }
}

#endif
