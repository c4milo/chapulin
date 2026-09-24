// TRUST=webpki public-key reader, signature-algorithm reader and verify
// dispatch differential section (webpki_spki.c, webpki_sigalg.c against
// spec/lean/Spec/WebpkiSpki.lean and spec/lean/Spec/WebpkiSigalg.lean).
//
// Signatures: the Lean spec mints a signature over a random TBS for
// every admitted algorithm under a key of its family (webpki_sign), and
// hands back the signer's SPKI in its own encoding. The rows rotate six
// pairings: RSA with SHA-256 and SHA-384 over the three diff_rsa.h
// moduli, and ECDSA with SHA-256 and SHA-384 under P-256 and P-384 —
// so P-256 with SHA-384 (the digest cut) and P-384 with SHA-256 (the
// pad) are each signed by the spec's integer rule and checked by the
// C's byte rule. The C must read the spec's SPKI and accept the
// signature, which the driver requires outright, and both sides must
// agree on each mutation: a flipped TBS byte, a flipped signature byte,
// a signature one byte short, the other hash of the family, the other
// family, and the previous row's signer. TBS lengths cover every DER
// length form and both sides of the 3072-byte cap.
//
// Readers: every spec-minted SPKI, and the four AlgorithmIdentifiers
// with the refused ones beside them, go to both sides whole, with a
// random single-byte change, cut short, and with a trailing byte. The C
// readers take a stream and the spec takes the whole TLV, so a C
// acceptance counts only when it consumed the whole input.
//
// Included by test/diff_test.c after diff_driver.h and diff_rsa.h
// (single translation unit): the RSA keys and DIFF_RSA_N_MAX come from
// there. bin/diff builds with -DCH_TRUST_WEBPKI, so the C admits the
// RSA-4096 key the spec signs with.
//
// spec/lean/Main.lean serves the ops:
//   webpki_spki <spki>          -> "ok <rsa|p256|p384> <key>" / "ERR webpki_spki reject"
//   webpki_sigalg <der>         -> "ok <name>" / "ERR webpki_sigalg reject"
//   webpki_verify <name> <spki> <tbs> <sig>     -> "1" / "0"
//   webpki_sign <name> rsa <n> <d> <tbs>        -> "<spki> <sig>" / FAIL
//   webpki_sign <name> p256|p384 <d> <k> <tbs>  -> "<spki> <sig>" / FAIL
#ifndef CH_DIFF_WEBPKI_SIGALG_H
#define CH_DIFF_WEBPKI_SIGALG_H

#include "buf.h"
#include "webpki.h"

// Signature rows, a multiple of the six pairings.
#define DIFF_WEBPKI_ROWS 36
// The longest TBS a row signs: one byte over the 3072-byte cap.
#define DIFF_WEBPKI_TBS_MAX (CH_WEBPKI_CERT_MAX + 1)
// The largest SPKI (RSA-4096, 550 bytes) and signature (512 bytes), with
// room for one trailing byte.
#define DIFF_WEBPKI_SPKI_MAX 560
#define DIFF_WEBPKI_SIG_MAX 520
// Line buffers: every byte argument crosses as two hex characters.
#define DIFF_WEBPKI_LINE_MAX                                                                       \
    (2 * (DIFF_WEBPKI_TBS_MAX + DIFF_WEBPKI_SPKI_MAX + 2 * DIFF_RSA_N_MAX) + 64)

// WEBPKI_SIG_* values by line-protocol name, index = value.
static const char *const diff_webpki_sigalg_names[5] = {"-", "rsa_sha256", "rsa_sha384",
                                                        "ecdsa_sha256", "ecdsa_sha384"};
static const char *const diff_webpki_key_names[4] = {"-", "rsa", "p256", "p384"};

// The C side of webpki_spki: the reply the spec gives for the same bytes.
static void diff_webpki_c_spki(const uint8_t *der, size_t n, char *reply, size_t reply_len) {
    rbuf r;
    rb_init(&r, der, n);
    webpki_spki out;
    if (!webpki_read_spki(&r, &out) || rb_left(&r) != 0 || out.alg > WEBPKI_KEY_P384) {
        (void)snprintf(reply, reply_len, "ERR webpki_spki reject");
        return;
    }
    char key_hex[2 * DIFF_RSA_N_MAX + 1];
    (void)hex_encode(key_hex, out.key, out.key_len);
    (void)snprintf(reply, reply_len, "ok %s %s", diff_webpki_key_names[out.alg], key_hex);
}

static void diff_webpki_compare_spki(const uint8_t *der, size_t n) {
    static char cmd[2 * DIFF_WEBPKI_SPKI_MAX + 32];
    static char want[2 * DIFF_RSA_N_MAX + 32];
    char der_hex[2 * DIFF_WEBPKI_SPKI_MAX + 1];
    (void)hex_encode(der_hex, der, n);
    (void)snprintf(cmd, sizeof cmd, "webpki_spki %s", der_hex);
    diff_webpki_c_spki(der, n, want, sizeof want);
    expect(cmd, want);
}

static void diff_webpki_compare_sigalg(const uint8_t *der, size_t n) {
    char der_hex[2 * 80 + 1];
    char cmd[2 * 80 + 32];
    rbuf r;
    rb_init(&r, der, n);
    uint8_t sigalg = 0;
    int ok = webpki_read_sigalg(&r, &sigalg) && rb_left(&r) == 0 && sigalg >= 1 && sigalg <= 4;
    char want[64];
    if (ok) {
        (void)snprintf(want, sizeof want, "ok %s", diff_webpki_sigalg_names[sigalg]);
    } else {
        (void)snprintf(want, sizeof want, "ERR webpki_sigalg reject");
    }
    (void)hex_encode(der_hex, der, n);
    (void)snprintf(cmd, sizeof cmd, "webpki_sigalg %s", der_hex);
    expect(cmd, want);
}

// The whole input, one random byte changed, cut short, and one byte
// longer. compare is the section's C-and-spec comparison for that reader.
static void diff_webpki_perturb(const uint8_t *der, size_t n, size_t cap,
                                void (*compare)(const uint8_t *, size_t)) {
    uint8_t changed[DIFF_WEBPKI_SPKI_MAX];
    compare(der, n);
    memcpy(changed, der, n);
    changed[rng_below(n)] ^= (uint8_t)(1 + rng_below(255));
    compare(changed, n);
    compare(der, rng_below(n));
    if (n < cap) {
        memcpy(changed, der, n);
        changed[n] = (uint8_t)rng_next();
        compare(changed, n + 1);
    }
}

// The C side of webpki_verify: the SPKI read whole, then the dispatch.
static const char *diff_webpki_c_verify(uint8_t sigalg, const uint8_t *spki, size_t spki_len,
                                        const uint8_t *tbs, size_t tbs_len, const uint8_t *sig,
                                        size_t sig_len) {
    rbuf r;
    rb_init(&r, spki, spki_len);
    webpki_spki signer;
    if (!webpki_read_spki(&r, &signer) || rb_left(&r) != 0) {
        return "0";
    }
    webpki_cert cert;
    memset(&cert, 0, sizeof cert);
    cert.tbs = tbs;
    cert.tbs_len = tbs_len;
    cert.sigalg = sigalg;
    cert.sig = sig;
    cert.sig_len = sig_len;
    return webpki_verify(&cert, &signer) ? "1" : "0";
}

static void diff_webpki_compare_verify(uint8_t sigalg, const uint8_t *spki, size_t spki_len,
                                       const uint8_t *tbs, size_t tbs_len, const uint8_t *sig,
                                       size_t sig_len) {
    static char cmd[DIFF_WEBPKI_LINE_MAX];
    static char spki_hex[2 * DIFF_WEBPKI_SPKI_MAX + 1];
    static char tbs_hex[2 * DIFF_WEBPKI_TBS_MAX + 1];
    static char sig_hex[2 * DIFF_WEBPKI_SIG_MAX + 1];
    (void)hex_encode(spki_hex, spki, spki_len);
    (void)hex_encode(tbs_hex, tbs, tbs_len);
    (void)hex_encode(sig_hex, sig, sig_len);
    (void)snprintf(cmd, sizeof cmd, "webpki_verify %s %s %s %s", diff_webpki_sigalg_names[sigalg],
                   spki_hex, tbs_hex, sig_hex);
    expect(cmd, diff_webpki_c_verify(sigalg, spki, spki_len, tbs, tbs_len, sig, sig_len));
}

// One pairing of algorithm and signer family, and the other hash and
// the other family's algorithm a mutation swaps in.
typedef struct {
    uint8_t sigalg;
    uint8_t other_hash;
    uint8_t other_family;
    uint8_t key_alg;
} diff_webpki_pairing;

static const diff_webpki_pairing diff_webpki_pairings[6] = {
    {WEBPKI_SIG_RSA_SHA256,   WEBPKI_SIG_RSA_SHA384,   WEBPKI_SIG_ECDSA_SHA256, WEBPKI_KEY_RSA },
    {WEBPKI_SIG_RSA_SHA384,   WEBPKI_SIG_RSA_SHA256,   WEBPKI_SIG_ECDSA_SHA384, WEBPKI_KEY_RSA },
    {WEBPKI_SIG_ECDSA_SHA256, WEBPKI_SIG_ECDSA_SHA384, WEBPKI_SIG_RSA_SHA256,   WEBPKI_KEY_P256},
    {WEBPKI_SIG_ECDSA_SHA384, WEBPKI_SIG_ECDSA_SHA256, WEBPKI_SIG_RSA_SHA384,   WEBPKI_KEY_P256},
    {WEBPKI_SIG_ECDSA_SHA256, WEBPKI_SIG_ECDSA_SHA384, WEBPKI_SIG_RSA_SHA256,   WEBPKI_KEY_P384},
    {WEBPKI_SIG_ECDSA_SHA384, WEBPKI_SIG_ECDSA_SHA256, WEBPKI_SIG_RSA_SHA384,   WEBPKI_KEY_P384},
};

// A TBS length for row i: the DER length-form edges and the cap first,
// then random lengths past the two-octet form's start.
static size_t diff_webpki_tbs_len(int i) {
    static const size_t edges[] = {
        1, 127, 128, 255, 256, CH_WEBPKI_CERT_MAX, CH_WEBPKI_CERT_MAX + 1};
    if ((size_t)i < sizeof edges / sizeof edges[0]) {
        return edges[i];
    }
    return 257 + rng_below(700);
}

// Writes the webpki_sign request for row i's signer into cmd.
static void diff_webpki_sign_request(char *cmd, size_t cmd_len, int i, const diff_webpki_pairing *p,
                                     const char *tbs_hex) {
    const char *name = diff_webpki_sigalg_names[p->sigalg];
    if (p->key_alg == WEBPKI_KEY_RSA) {
        (void)snprintf(cmd, cmd_len, "webpki_sign %s rsa %s %s %s", name,
                       diff_rsa_moduli[(i / 6) % 3], diff_rsa_private_exponents[(i / 6) % 3],
                       tbs_hex);
        return;
    }
    size_t scalar_len = p->key_alg == WEBPKI_KEY_P256 ? 32 : 48;
    uint8_t d[48];
    uint8_t k[48];
    rng_fill(d, scalar_len);
    rng_fill(k, scalar_len);
    // A clear top bit keeps d and k below the order; a set low bit rules
    // out zero.
    d[0] &= 0x7f;
    k[0] &= 0x7f;
    d[scalar_len - 1] |= 1;
    k[scalar_len - 1] |= 1;
    char d_hex[2 * 48 + 1];
    char k_hex[2 * 48 + 1];
    (void)hex_encode(d_hex, d, scalar_len);
    (void)hex_encode(k_hex, k, scalar_len);
    (void)snprintf(cmd, cmd_len, "webpki_sign %s %s %s %s %s", name,
                   diff_webpki_key_names[p->key_alg], d_hex, k_hex, tbs_hex);
}

// Splits a webpki_sign reply into the SPKI and signature bytes.
static void diff_webpki_parse_signed(const char *reply, uint8_t *spki, size_t *spki_len,
                                     uint8_t *sig, size_t *sig_len) {
    const char *space = strchr(reply, ' ');
    if (space == NULL) {
        die("webpki_sign: malformed spec response");
    }
    size_t spki_hex_len = (size_t)(space - reply);
    size_t sig_hex_len = strlen(space + 1);
    *spki_len = spki_hex_len / 2;
    *sig_len = sig_hex_len / 2;
    if (spki_hex_len % 2 != 0 || sig_hex_len % 2 != 0 || *spki_len > DIFF_WEBPKI_SPKI_MAX - 1 ||
        *sig_len > DIFF_WEBPKI_SIG_MAX - 1 || !hex_decode(spki, reply, *spki_len) ||
        !hex_decode(sig, space + 1, *sig_len)) {
        die("webpki_sign: malformed spec response");
    }
}

// Every mutation of one minted row, each compared between C and spec.
static void diff_webpki_mutations(const diff_webpki_pairing *p, const uint8_t *spki,
                                  size_t spki_len, uint8_t *tbs, size_t tbs_len, uint8_t *sig,
                                  size_t sig_len, const uint8_t *previous_spki,
                                  size_t previous_len) {
    size_t at = rng_below(tbs_len);
    tbs[at] ^= 0x01;
    diff_webpki_compare_verify(p->sigalg, spki, spki_len, tbs, tbs_len, sig, sig_len);
    tbs[at] ^= 0x01;
    at = rng_below(sig_len);
    uint8_t delta = (uint8_t)(1 + rng_below(255));
    sig[at] ^= delta;
    diff_webpki_compare_verify(p->sigalg, spki, spki_len, tbs, tbs_len, sig, sig_len);
    sig[at] ^= delta;
    diff_webpki_compare_verify(p->sigalg, spki, spki_len, tbs, tbs_len, sig, sig_len - 1);
    diff_webpki_compare_verify(p->other_hash, spki, spki_len, tbs, tbs_len, sig, sig_len);
    diff_webpki_compare_verify(p->other_family, spki, spki_len, tbs, tbs_len, sig, sig_len);
    if (previous_len != 0) {
        diff_webpki_compare_verify(p->sigalg, previous_spki, previous_len, tbs, tbs_len, sig,
                                   sig_len);
    }
}

static void diff_webpki_signatures(void) {
    static char cmd[DIFF_WEBPKI_LINE_MAX];
    static char reply[2 * (DIFF_WEBPKI_SPKI_MAX + DIFF_WEBPKI_SIG_MAX) + 8];
    static char tbs_hex[2 * DIFF_WEBPKI_TBS_MAX + 1];
    static uint8_t tbs[DIFF_WEBPKI_TBS_MAX];
    uint8_t spki[DIFF_WEBPKI_SPKI_MAX];
    uint8_t sig[DIFF_WEBPKI_SIG_MAX];
    uint8_t previous[DIFF_WEBPKI_SPKI_MAX] = {0};
    size_t previous_len = 0;
    for (int i = 0; i < DIFF_WEBPKI_ROWS; i++) {
        const diff_webpki_pairing *p = &diff_webpki_pairings[i % 6];
        size_t tbs_len = diff_webpki_tbs_len(i);
        rng_fill(tbs, tbs_len);
        (void)hex_encode(tbs_hex, tbs, tbs_len);
        diff_webpki_sign_request(cmd, sizeof cmd, i, p, tbs_hex);
        query(cmd, reply, sizeof reply);
        size_t spki_len = 0;
        size_t sig_len = 0;
        diff_webpki_parse_signed(reply, spki, &spki_len, sig, &sig_len);

        // The accept path: the C must take the spec's SPKI and signature
        // outright, not merely agree with the spec, unless the TBS is
        // over the cap, where both must refuse.
        const char *want = tbs_len <= CH_WEBPKI_CERT_MAX ? "1" : "0";
        if (strcmp(diff_webpki_c_verify(p->sigalg, spki, spki_len, tbs, tbs_len, sig, sig_len),
                   want) != 0) {
            (void)fprintf(stderr,
                          "diff mismatch: C webpki_verify on a spec-minted row\n  cmd: %s\n", cmd);
            exit(1);
        }
        diff_webpki_compare_verify(p->sigalg, spki, spki_len, tbs, tbs_len, sig, sig_len);
        diff_webpki_perturb(spki, spki_len, DIFF_WEBPKI_SPKI_MAX, diff_webpki_compare_spki);
        diff_webpki_mutations(p, spki, spki_len, tbs, tbs_len, sig, sig_len, previous,
                              previous_len);
        memcpy(previous, spki, spki_len);
        previous_len = spki_len;
    }
}

// The four admitted AlgorithmIdentifiers, then the refused encodings
// docs/webpki.md names: SHA-1 under both families, RSA-PSS with a NULL,
// and each family with the other's parameter form.
static const char *const diff_webpki_sigalg_der[] = {
    "300d06092a864886f70d01010b0500", "300d06092a864886f70d01010c0500",
    "300a06082a8648ce3d040302",       "300a06082a8648ce3d040303",
    "300d06092a864886f70d0101050500", "300906072a8648ce3d0401",
    "300d06092a864886f70d01010a0500", "300c06082a8648ce3d0403020500",
    "300b06092a864886f70d01010b",
};

static void diff_webpki_sigalgs(void) {
    for (size_t i = 0; i < sizeof diff_webpki_sigalg_der / sizeof diff_webpki_sigalg_der[0]; i++) {
        uint8_t der[40];
        size_t n = strlen(diff_webpki_sigalg_der[i]) / 2;
        if (n > sizeof der - 1 || !hex_decode(der, diff_webpki_sigalg_der[i], n)) {
            die("webpki_sigalg: malformed driver constant");
        }
        for (int j = 0; j < 24; j++) {
            diff_webpki_perturb(der, n, sizeof der, diff_webpki_compare_sigalg);
        }
    }
}

static void diff_webpki_sigalg(void) {
    diff_webpki_sigalgs();
    diff_webpki_signatures();
}

#endif
