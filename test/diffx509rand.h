// Randomized certificate rows whose bytes the spec never signed. Both
// parsers must reject every row here, so the oracle is blunt: the
// value is DER agreement and crash coverage over shapes no
// hand-written row reaches, not killing an epoch-reader mutation.
// The rows that carry a real CA signature live in diffx509signed.h.
//
// Included by diffx509.h after certd_collect and certd_mint_dated
// exist; this is not a standalone translation unit.
#ifndef CH_DIFFX509RAND_H
#define CH_DIFFX509RAND_H

#define CERTD_RAND_NOISE_ROWS 150
#define CERTD_RAND_EDIT_ROWS 400
#define CERTD_RAND_PAIR_ROWS 100
#define CERTD_RAND_NOISE_MAX 400

// The fixed material one randomized pass works from. A struct rather
// than six parameters keeps each row function under the complexity
// limit. Every member is a constant the pass forwards unchanged: the
// CA key in particular is never randomized, because the spec derives
// the RSA modulus size from the integer while rsa.c reads the byte
// length handed in, and a leading zero byte makes the two disagree.
typedef struct {
    const char *alg; // "rsa" or "p256", never mutated
    const char *ca_hex;
    const uint8_t *ca_key;
    size_t ca_len;
    const char *leaf_hex;
    size_t cap; // the certificate size both sides bound against
} certd_rand_ctx;

static long certd_rand_rows;

// Defined in diffx509signed.h, which builds on the context and row
// function above. diffx509.h includes that header after this one, so
// the pass function at the end of this file needs the declaration.
static void certd_mint_rows(const certd_rand_ctx *ctx);

// Reads CH_DIFF_X509_ROWS as a pass multiplier. A value that is not a
// number, or zero, keeps 1 — the count `make check` runs. The nightly
// seed loop raises it, so the same binary does depth there and stays
// fast in the PR lane.
static unsigned long certd_rand_multiplier(void) {
    const char *text = getenv("CH_DIFF_X509_ROWS");
    if (text == NULL) {
        return 1;
    }
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 0);
    if (end == text || *end != 0 || value == 0) {
        return 1;
    }
    return value;
}

// True when the build's own parser can answer for alg, and the cap
// this build enforces is the cap the spec models. x509.c bounds an
// entry by CH_X509_MAX, which cfg.h lets a build override, while the
// spec hard-codes 768 and 1536. A build that raised the cap accepts
// certificates the spec rejects, so it sits the randomized rows out
// rather than reporting that difference as a divergence.
static int certd_rand_gate(const char *alg, size_t *cap) {
    *cap = strcmp(alg, "rsa") == 0 ? CH_X509_DEFAULT_MAX_RSA : CH_X509_DEFAULT_MAX_ECDSA;
    if (strcmp(alg, certd_build_alg) != 0) {
        return 0;
    }
    return (size_t)CH_X509_MAX == *cap;
}

// The C parser's own verdict on one list, rendered as the oracle line
// the spec must reproduce. The return code decides first: x509.c
// writes key, key_len and ca_slot only on the success path, so those
// fields are read only under CH_OK. Nothing here predicts an answer
// and nothing dies on an accept — for random bytes the C side is the
// whole expectation, which is what the differential is for.
static void certd_rand_row(const certd_rand_ctx *ctx, const uint8_t *list, size_t list_len) {
    static char list_hex[2 * CERTD_LIST_MAX + 1];
    static char cmd[2 * CERTD_LIST_MAX + 1024];
    static char want[2 * 384 + 32];
    static char key_hex[2 * 384 + 1];
    x509_leaf_info info;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    int rc = x509_verify_leaf(list, list_len, ctx->ca_key, ctx->ca_len, NULL, 0, &info, &alert);
    if (rc != CH_OK) {
        (void)snprintf(want, sizeof want, "ERR x509 reject");
    } else {
        (void)hex_encode(key_hex, info.key, info.key_len);
        if (info.epoch_ok) {
            (void)snprintf(want, sizeof want, "ok %s %u", key_hex, (unsigned)info.epoch);
        } else {
            (void)snprintf(want, sizeof want, "ok %s -", key_hex);
        }
    }
    (void)hex_encode(list_hex, list, list_len);
    (void)snprintf(cmd, sizeof cmd, "x509parse %s %s %s", ctx->alg, ctx->ca_hex, list_hex);
    // A zero-length field would reach the spec as a dropped token and
    // change the op's arity, which answers "ERR unknown op or bad
    // args" and reads as a divergence rather than the harness bug it
    // is. hex_encode never emits one; this catches a future caller.
    if (strstr(cmd, "  ") != NULL) {
        die("cert: randomized row built an empty field");
    }
    certd_rows++;
    certd_rand_rows++;
    expect(cmd, want);
}

// Uniform bytes as a whole CertificateEntry list, length 1..400.
// Never 0: hex_encode renders an empty buffer as "-", a different row
// from the one this means to send.
static size_t certd_rand_noise(uint8_t *list) {
    size_t n = 1 + rng_below(CERTD_RAND_NOISE_MAX);
    rng_fill(list, n);
    return n;
}

// Uniform certificate bytes inside canonical list framing, so
// read_entry succeeds and parse_certificate runs on noise instead of
// rejecting at the u24. One draw in five takes this path.
static size_t certd_rand_framed_noise(uint8_t *list) {
    static uint8_t cert[CERTD_RAND_NOISE_MAX];
    size_t n = 1 + rng_below(CERTD_RAND_NOISE_MAX);
    rng_fill(cert, n);
    return put_entry(list, cert, n);
}

static void certd_rand_noise_rows(const certd_rand_ctx *ctx) {
    static uint8_t list[CERTD_LIST_MAX];
    for (int i = 0; i < CERTD_RAND_NOISE_ROWS; i++) {
        size_t n = rng_below(5) == 0 ? certd_rand_framed_noise(list) : certd_rand_noise(list);
        certd_rand_row(ctx, list, n);
    }
}

// Replaces the TLV at off with a drawn edit: random content of the
// same length, a different tag, one byte shorter, one byte longer, or
// random bytes over the whole TLV. Returns the edited length, or 0
// when the result would outgrow the splice buffers.
//
// The offset always comes from certd_sites, which certd_collect fills
// with real TLV starts. splice aborts the whole run on an offset that
// is not a child-TLV boundary, so an arbitrary offset must never
// reach it.
static size_t certd_rand_edit(uint8_t *out, const uint8_t *cert, size_t cert_len, size_t off) {
    static uint8_t repl[X509MUT_CAP];
    tlv_shape s;
    tlv_read(cert + off, cert_len - off, &s);
    size_t total = s.header_len + s.content_len;
    size_t repl_len = 0;
    switch (rng_below(5)) {
    case 0: // same shape, random content
        repl_len = put_header(repl, cert[off], s.content_len);
        rng_fill(repl + repl_len, s.content_len);
        repl_len += s.content_len;
        break;
    case 1: // another tag over the same content
        repl_len = put_header(repl, (uint8_t)(rng_next() >> 56), s.content_len);
        memcpy(repl + repl_len, cert + off + s.header_len, s.content_len);
        repl_len += s.content_len;
        break;
    case 2: // one content byte short
        if (s.content_len == 0) {
            return 0;
        }
        repl_len = put_header(repl, cert[off], s.content_len - 1);
        memcpy(repl + repl_len, cert + off + s.header_len, s.content_len - 1);
        repl_len += s.content_len - 1;
        break;
    case 3: // one content byte long
        repl_len = put_header(repl, cert[off], s.content_len + 1);
        memcpy(repl + repl_len, cert + off + s.header_len, s.content_len);
        repl[repl_len + s.content_len] = (uint8_t)(rng_next() >> 56);
        repl_len += s.content_len + 1;
        break;
    default: // random bytes over the whole TLV
        repl_len = 1 + rng_below(total + 8);
        rng_fill(repl, repl_len);
        break;
    }
    // splice re-encodes every enclosing length, so each level can grow
    // by two bytes. Leave that room rather than let splice abort.
    if (repl_len > sizeof repl || cert_len - total + repl_len + 32 > X509MUT_CAP) {
        return 0;
    }
    return splice(out, cert, cert_len, off, total, repl, repl_len);
}

static void certd_rand_edit_rows(const certd_rand_ctx *ctx, const uint8_t *cert, size_t cert_len) {
    static uint8_t mutant[X509MUT_CAP];
    static uint8_t list[CERTD_LIST_MAX];
    certd_collect(cert, cert_len);
    for (int i = 0; i < CERTD_RAND_EDIT_ROWS; i++) {
        size_t off = certd_sites[rng_below(certd_site_count)];
        size_t n = certd_rand_edit(mutant, cert, cert_len, off);
        if (n == 0) {
            continue;
        }
        certd_rand_row(ctx, list, put_entry(list, mutant, n));
    }
}

// Two entries built from the same certificate, with the second one
// edited and the framing lengths drawn around the bounds both sides
// enforce. A chain the CA never signed must reject on both sides
// whatever the framing says.
static void certd_rand_pair_rows(const certd_rand_ctx *ctx, const uint8_t *cert, size_t cert_len) {
    static uint8_t mutant[X509MUT_CAP];
    static uint8_t list[CERTD_LIST_MAX];
    for (int i = 0; i < CERTD_RAND_PAIR_ROWS; i++) {
        size_t off = certd_sites[rng_below(certd_site_count)];
        size_t n = certd_rand_edit(mutant, cert, cert_len, off);
        if (n == 0) {
            continue;
        }
        size_t w = put_entry(list, cert, cert_len);
        w += put_entry(list + w, mutant, n);
        // One draw in four states a length the entry does not have.
        if (rng_below(4) == 0) {
            size_t claim = rng_below(2) == 0 ? ctx->cap : ctx->cap + 1;
            list[0] = (uint8_t)(claim >> 16);
            list[1] = (uint8_t)(claim >> 8);
            list[2] = (uint8_t)claim;
        }
        certd_rand_row(ctx, list, w);
    }
}

// The blunt lane for one algorithm: mint one certificate to edit, then
// run the noise, edit and pair tiers. Returns without a row when the
// build cannot answer for this algorithm.
static void certd_rand_pass(const char *alg, const char *ca_hex, const char *leaf_hex) {
    static uint8_t ca_key[384];
    static uint8_t list[CERTD_LIST_MAX];
    static uint8_t cert[CERTD_CERT_MAX + 8];
    certd_rand_ctx ctx;
    size_t cap = 0;
    if (!certd_rand_gate(alg, &cap)) {
        return;
    }
    size_t ca_len = strlen(ca_hex) / 2;
    if (!hex_decode(ca_key, ca_hex, ca_len)) {
        die("cert: malformed CA key hex");
    }
    ctx.alg = alg;
    ctx.ca_hex = ca_hex;
    ctx.ca_key = ca_key;
    ctx.ca_len = ca_len;
    ctx.leaf_hex = leaf_hex;
    ctx.cap = cap;
    size_t list_len =
        certd_mint(alg, certd_serial_hex, certd_name_hex, leaf_hex, certd_exts_hex, list);
    size_t cert_len = list_len - 5;
    memcpy(cert, list + 3, cert_len);
    for (unsigned long pass = 0; pass < certd_rand_multiplier(); pass++) {
        certd_rand_noise_rows(&ctx);
        certd_rand_edit_rows(&ctx, cert, cert_len);
        certd_rand_pair_rows(&ctx, cert, cert_len);
        certd_mint_rows(&ctx);
    }
}

#endif
