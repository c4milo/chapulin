// The TRUST=webpki arm of test/tls_client.c: the anchor, the SPKI pins,
// the hostname, the clock and the ALPN offer it reads from its arguments
// and the environment, and the lines e2e.sh asserts on once connected.
// Included by that file under CH_TRUST_WEBPKI, after unhex.
#ifndef CH_TEST_TLS_CLIENT_WEBPKI_H
#define CH_TEST_TLS_CLIENT_WEBPKI_H

// A TRUST=webpki anchor is two whole DER fields of a root certificate:
// its subject Name TLV and its SubjectPublicKeyInfo. e2e.sh writes each
// to its own file, so this client reads bytes and parses no certificate.
static uint8_t g_anchor_name[512];
static uint8_t g_anchor_spki[CH_WEBPKI_KEY_MAX + 64];
static ch_trust_anchor g_anchors[1];

// The whole file, or 0 when it does not open or does not fit.
static size_t read_der_file(const char *path, uint8_t *out, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return 0;
    }
    size_t n = fread(out, 1, cap, f);
    int overflowed = fgetc(f) != EOF;
    (void)fclose(f);
    return overflowed ? 0 : n;
}

// WEBPKI_PINS carries SPKI pins, the SHA-256 of a DER
// SubjectPublicKeyInfo in hex, comma separated. Unset or empty sets none.
static uint8_t g_pins[CH_SPKI_PIN_MAX * SHA256_LEN];

static int setup_pins(ch_cfg *cfg) {
    const char *list = getenv("WEBPKI_PINS");
    if (list == NULL || list[0] == '\0') {
        return 0;
    }
    char text[CH_SPKI_PIN_MAX * (2 * SHA256_LEN + 1)];
    (void)snprintf(text, sizeof text, "%s", list);
    size_t count = 0;
    for (char *pin = text; pin != NULL; count++) {
        char *comma = strchr(pin, ',');
        if (comma != NULL) {
            *comma = '\0';
        }
        if (count == CH_SPKI_PIN_MAX ||
            unhex(pin, g_pins + count * SHA256_LEN, SHA256_LEN) != SHA256_LEN) {
            (void)fprintf(stderr, "webpki: WEBPKI_PINS holds up to %d 64-digit hex pins\n",
                          CH_SPKI_PIN_MAX);
            return -1;
        }
        pin = comma != NULL ? comma + 1 : NULL;
    }
    cfg->spki_pins = g_pins;
    cfg->spki_pin_count = count;
    return 0;
}

// Owns the "webpki:name-file,spki-file" form, and "webpki:-", which sets
// no anchor, for SPKI pins alone. The hostname, the clock and the pins
// come from WEBPKI_HOST, WEBPKI_NOW and WEBPKI_PINS, the way REQUIRE_PQ
// passes the post-quantum flag, so the positional arguments stay as they
// are. ch_connect judges the whole; this reads what is set.
static int setup_webpki(char *spec, ch_cfg *cfg) {
    const char *host = getenv("WEBPKI_HOST");
    const char *now = getenv("WEBPKI_NOW");
    if (host != NULL) {
        cfg->hostname = (const uint8_t *)host;
        cfg->hostname_len = strlen(host);
    }
    cfg->now_seconds = now != NULL ? strtoull(now, NULL, 10) : 0;
    if (setup_pins(cfg) != 0) {
        return -1;
    }
    if (strcmp(spec, "-") == 0) {
        return 0;
    }
    char *comma = strchr(spec, ',');
    if (comma == NULL) {
        (void)fprintf(stderr, "webpki: need name-file,spki-file, or - for pins alone\n");
        return -1;
    }
    *comma = '\0';
    g_anchors[0].name = g_anchor_name;
    g_anchors[0].name_len = read_der_file(spec, g_anchor_name, sizeof g_anchor_name);
    g_anchors[0].spki = g_anchor_spki;
    g_anchors[0].spki_len = read_der_file(comma + 1, g_anchor_spki, sizeof g_anchor_spki);
    if (g_anchors[0].name_len == 0 || g_anchors[0].spki_len == 0) {
        (void)fprintf(stderr, "webpki: could not read the anchor files\n");
        return -1;
    }
    cfg->anchors = g_anchors;
    cfg->anchor_count = 1;
    return 0;
}

// WEBPKI_ALPN carries the protocols to offer, comma separated, the way
// WEBPKI_HOST carries the hostname: "h2,http/1.1". Unset or empty
// offers none, which sends no extension. Splits the text in place, so
// each name points into g_alpn_text and outlives the call.
static char g_alpn_text[256];
static ch_alpn_protocol g_alpn[CH_ALPN_MAX];

static void setup_alpn(ch_cfg *cfg) {
    const char *list = getenv("WEBPKI_ALPN");
    if (list == NULL || list[0] == '\0') {
        return;
    }
    (void)snprintf(g_alpn_text, sizeof g_alpn_text, "%s", list);
    size_t count = 0;
    char *name = g_alpn_text;
    while (name != NULL && count < CH_ALPN_MAX) {
        char *comma = strchr(name, ',');
        if (comma != NULL) {
            *comma = '\0';
        }
        g_alpn[count].name = (const uint8_t *)name;
        g_alpn[count].name_len = strlen(name);
        count++;
        name = comma != NULL ? comma + 1 : NULL;
    }
    cfg->alpn_protocols = g_alpn;
    cfg->alpn_count = count;
}

// The lines e2e asserts against: the certificate type the server chose,
// and the protocol it selected, by name, or "none" when it sent no ALPN
// extension to an offer.
static void report_webpki(const ch_cfg *cfg, const ch_tls *tls) {
    (void)fprintf(stderr, "cert type %u\n", (unsigned)tls->server_cert_type);
    if (cfg->alpn_count == 0) {
        return;
    }
    if (tls->alpn_selected == CH_ALPN_NONE) {
        (void)fprintf(stderr, "alpn none\n");
        return;
    }
    const ch_alpn_protocol *picked = &cfg->alpn_protocols[tls->alpn_selected];
    (void)fprintf(stderr, "alpn %.*s\n", (int)picked->name_len, (const char *)picked->name);
}

#endif
