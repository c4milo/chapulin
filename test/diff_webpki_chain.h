// TRUST=webpki chain walk differential section (webpki.c against
// spec/Spec/Webpki.lean).
//
// Every corpus and capture row is compared as it stands, and then under
// mutations of its own inputs:
//
//   - the clock one and two seconds either way, and a day and a year
//     either way, which steps the four rows that sit on a validity
//     boundary past it
//   - the hostname replaced by each of the five the corpus uses
//   - each anchor dropped in turn, the anchor array emptied, and every
//     anchor's key swapped for one no corpus certificate is signed
//     under, so an anchor that names an issuer without verifying it is
//     compared
//   - the entry list cut after each entry, one entry dropped, the last
//     entry repeated to one past the flight cap, and DIFF_CHAIN_BYTES
//     single bytes of the list changed
//
// The reply carries the verdict's name and, when the chain verified,
// the leaf key the walk copied out: "ok <rsa|p256|p384> <key>", or one
// of "rejected", "expired", "unauthenticated" and "unknown_ca". Those
// four are exactly the pairs of return code and alert the C tells apart,
// and test/webpki_chain_test.c pins which alert each one is.
//
// The clock travels as the packed date webpki_pack_seconds produces, not
// as seconds: the C runs that conversion once per connection and
// diff_webpki_pack compares it against the spec's own separately.
//
// Included by test/diff_test.c after diff_driver.h (single translation
// unit). spec/Main.lean serves the op:
//   webpki_chain <packed clock> <hostname> <anchors> <list>
// where <anchors> is "-" or "name.spki" hex pairs joined by commas.
#ifndef CH_DIFF_WEBPKI_CHAIN_H
#define CH_DIFF_WEBPKI_CHAIN_H

// ch_cfg carries the anchors, the hostname and the clock only in a
// TRUST=webpki build, so webpki.c compiles only there and this section
// runs under `make diff-webpki` alone. bin/diff and bin/diff_pq print
// the skip line below instead.
#ifdef CH_TRUST_WEBPKI

#include "buf.h"
#include "handshake_message.h"
#include "webpki.h"
#include "webpki_corpus.h"

// The largest list any row or mutation carries: the flight cap plus one
// entry, each at the certificate cap.
#define DIFF_CHAIN_ENTRIES ((size_t)CH_WEBPKI_FLIGHT_ENTRIES + 1)
#define DIFF_CHAIN_LIST_MAX (DIFF_CHAIN_ENTRIES * (CH_WEBPKI_CERT_MAX + 5))
// One request line: the op, the clock, the hostname, the anchors and the
// list, all in hex.
#define DIFF_CHAIN_ANCHOR_HEX ((size_t)2 * CH_WEBPKI_ANCHOR_MAX * (256 + 2 * CH_WEBPKI_KEY_MAX + 32))
#define DIFF_CHAIN_LINE_MAX ((size_t)2 * DIFF_CHAIN_LIST_MAX + DIFF_CHAIN_ANCHOR_HEX + 1024)
#define DIFF_CHAIN_REPLY_MAX ((size_t)2 * CH_WEBPKI_KEY_MAX + 64)
// Single bytes of a list changed, one drawn from each stride.
#define DIFF_CHAIN_BYTES 24

static long diff_chain_rows;
static long diff_chain_accepted;

static const char *const diff_chain_key_names[4] = {"-", "rsa", "p256", "p384"};

// One row's inputs, so a mutation can change one of them and leave the
// rest. The anchors point into the corpus header.
typedef struct {
    const webpki_corpus_anchor *anchors;
    size_t anchor_count;
    const char *hostname;
    uint64_t now_seconds;
    const uint8_t *list;
    size_t list_len;
} diff_chain_case;

// The list of a row's Certificate message. The corpus messages are
// well-formed, so a malformed one is a driver bug.
static void diff_chain_list(const webpki_corpus_chain *row, const uint8_t **list,
                            size_t *list_len) {
    rbuf r;
    rb_init(&r, row->message, row->message_len);
    uint8_t msg_type = rb_u8(&r);
    size_t body_len = rb_u24(&r);
    uint8_t context_len = rb_u8(&r);
    size_t len = rb_u24(&r);
    if (r.err || msg_type != 11 || body_len != row->message_len - 4 || context_len != 0 ||
        len != rb_left(&r)) {
        die("webpki_chain: a corpus message is not a Certificate message");
    }
    *list = rb_bytes(&r, len);
    *list_len = len;
    if (*list == NULL) {
        die("webpki_chain: a corpus list is malformed");
    }
}

// The C side: the verdict name, and the leaf key when the chain verified.
static void diff_chain_c_reply(const diff_chain_case *c, char *reply, size_t cap) {
    ch_trust_anchor anchors[CH_WEBPKI_ANCHOR_MAX];
    ch_cfg cfg;
    webpki_leaf_info leaf;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    memset(&cfg, 0, sizeof cfg);
    if (c->anchor_count > CH_WEBPKI_ANCHOR_MAX) {
        die("webpki_chain: a case over CH_WEBPKI_ANCHOR_MAX anchors");
    }
    for (size_t i = 0; i < c->anchor_count; i++) {
        anchors[i].name = c->anchors[i].name;
        anchors[i].name_len = c->anchors[i].name_len;
        anchors[i].spki = c->anchors[i].spki;
        anchors[i].spki_len = c->anchors[i].spki_len;
    }
    cfg.anchors = anchors;
    cfg.anchor_count = c->anchor_count;
    cfg.hostname = (const uint8_t *)c->hostname;
    cfg.hostname_len = strlen(c->hostname);
    cfg.now_seconds = c->now_seconds;
    memset(&leaf, 0, sizeof leaf);
    int rc = webpki_verify_chain(c->list, c->list_len, &cfg, &leaf, &alert);
    if (rc == CH_OK) {
        if (leaf.alg > WEBPKI_KEY_P384 || leaf.key_len > CH_WEBPKI_KEY_MAX) {
            die("webpki_chain: an accepted chain outside webpki.h's ranges");
        }
        static char key_hex[2 * CH_WEBPKI_KEY_MAX + 1];
        (void)hex_encode(key_hex, leaf.key, leaf.key_len);
        (void)snprintf(reply, cap, "ok %s %s", diff_chain_key_names[leaf.alg], key_hex);
        return;
    }
    if (rc == CH_EPROTO) {
        (void)snprintf(reply, cap, "rejected");
    } else if (alert == ALERT_CERTIFICATE_EXPIRED) {
        (void)snprintf(reply, cap, "expired");
    } else if (alert == ALERT_UNKNOWN_CA) {
        (void)snprintf(reply, cap, "unknown_ca");
    } else {
        (void)snprintf(reply, cap, "unauthenticated");
    }
}

// The anchors as the op spells them: "-" for none, else "name.spki" hex
// pairs joined by commas. Returns the characters written.
static size_t diff_chain_anchors_hex(char *out, const diff_chain_case *c) {
    if (c->anchor_count == 0) {
        out[0] = '-';
        out[1] = '\0';
        return 1;
    }
    size_t at = 0;
    for (size_t i = 0; i < c->anchor_count; i++) {
        if (i > 0) {
            out[at++] = ',';
        }
        at += hex_encode(out + at, c->anchors[i].name, c->anchors[i].name_len);
        out[at++] = '.';
        at += hex_encode(out + at, c->anchors[i].spki, c->anchors[i].spki_len);
    }
    out[at] = '\0';
    return at;
}

static void diff_chain_compare(const diff_chain_case *c) {
    static char cmd[DIFF_CHAIN_LINE_MAX];
    static char want[DIFF_CHAIN_REPLY_MAX];
    if (c->list_len > DIFF_CHAIN_LIST_MAX) {
        die("webpki_chain: a driver list over DIFF_CHAIN_LIST_MAX");
    }
    int at = snprintf(cmd, sizeof cmd, "webpki_chain %llu ",
                      (unsigned long long)webpki_pack_seconds(c->now_seconds));
    at += (int)hex_encode(cmd + at, (const uint8_t *)c->hostname, strlen(c->hostname));
    cmd[at++] = ' ';
    at += (int)diff_chain_anchors_hex(cmd + at, c);
    cmd[at++] = ' ';
    (void)hex_encode(cmd + at, c->list, c->list_len);
    diff_chain_c_reply(c, want, sizeof want);
    diff_chain_rows++;
    diff_chain_accepted += want[0] == 'o';
    expect(cmd, want);
}

// The entries of a list, as offsets into it, so a mutation can reframe
// them. Returns the count.
static size_t diff_chain_split(const uint8_t *list, size_t list_len, size_t *off, size_t *len) {
    rbuf r;
    rb_init(&r, list, list_len);
    size_t count = 0;
    while (rb_left(&r) > 0) {
        if (count == DIFF_CHAIN_ENTRIES) {
            die("webpki_chain: a corpus list over the entry cap");
        }
        size_t cert_len = rb_u24(&r);
        off[count] = r.off;
        len[count] = cert_len;
        const uint8_t *cert = rb_bytes(&r, cert_len);
        if (cert == NULL || rb_u16(&r) != 0 || r.err) {
            die("webpki_chain: a corpus entry is malformed");
        }
        count++;
    }
    return count;
}

// Frames count entries, each named by its offset and length in source,
// into a CertificateEntry list. Returns its length.
static size_t diff_chain_frame(uint8_t *out, const uint8_t *source, const size_t *off,
                               const size_t *len, size_t count) {
    wbuf w;
    wb_init(&w, out, DIFF_CHAIN_LIST_MAX);
    for (size_t i = 0; i < count; i++) {
        wb_u24(&w, (uint32_t)len[i]);
        wb_bytes(&w, source + off[i], len[i]);
        wb_u16(&w, 0);
    }
    if (w.err) {
        die("webpki_chain: a reframed list over DIFF_CHAIN_LIST_MAX");
    }
    return w.len;
}

// The clock stepped around each row's own. A row that sits on a
// validity boundary — the corpus carries four of them — is compared one
// second past it here, and a day and a year either way move the clock
// well outside every validity.
static void diff_chain_clocks(const diff_chain_case *base) {
    static const int64_t steps[8] = {1, -1, 2, -2, 86400, -86400, 31536000, -31536000};
    for (size_t i = 0; i < 8; i++) {
        diff_chain_case c = *base;
        int64_t moved = (int64_t)base->now_seconds + steps[i];
        c.now_seconds = moved < 0 ? 0 : (uint64_t)moved;
        diff_chain_compare(&c);
    }
}

// Every hostname the corpus uses, so a row is compared against a name
// its leaf does not carry as well as against its own.
static const char *const diff_chain_hosts[] = {"s3.example.test", "other.example.test",
                                               "a.b.example.test", "example.com",
                                               "s3.amazonaws.com"};
#define DIFF_CHAIN_HOST_COUNT (sizeof diff_chain_hosts / sizeof diff_chain_hosts[0])

static void diff_chain_hostnames(const diff_chain_case *base) {
    for (size_t i = 0; i < DIFF_CHAIN_HOST_COUNT; i++) {
        diff_chain_case c = *base;
        c.hostname = diff_chain_hosts[i];
        diff_chain_compare(&c);
    }
}

// Each anchor dropped in turn, and the array emptied.
static void diff_chain_anchor_sets(const diff_chain_case *base) {
    static webpki_corpus_anchor kept[CH_WEBPKI_ANCHOR_MAX];
    diff_chain_case c = *base;
    c.anchor_count = 0;
    diff_chain_compare(&c);
    for (size_t drop = 0; drop < base->anchor_count; drop++) {
        size_t n = 0;
        for (size_t i = 0; i < base->anchor_count; i++) {
            if (i != drop) {
                kept[n++] = base->anchors[i];
            }
        }
        c.anchors = kept;
        c.anchor_count = n;
        diff_chain_compare(&c);
    }
}

// Every anchor's key swapped for a key no corpus certificate is signed
// under, so each anchor's Name still names an issuer and no anchor
// verifies one.
static void diff_chain_anchor_keys(const diff_chain_case *base,
                                   const webpki_corpus_anchor *other) {
    static webpki_corpus_anchor swapped[CH_WEBPKI_ANCHOR_MAX];
    if (base->anchor_count == 0) {
        return;
    }
    for (size_t i = 0; i < base->anchor_count; i++) {
        swapped[i] = base->anchors[i];
        swapped[i].spki = other->spki;
        swapped[i].spki_len = other->spki_len;
    }
    diff_chain_case c = *base;
    c.anchors = swapped;
    diff_chain_compare(&c);
}

// The list cut after each entry, one entry dropped, and the last entry
// repeated until the list holds one entry past the flight cap.
static void diff_chain_entry_sets(const diff_chain_case *base) {
    static uint8_t framed[DIFF_CHAIN_LIST_MAX];
    size_t off[DIFF_CHAIN_ENTRIES];
    size_t len[DIFF_CHAIN_ENTRIES];
    size_t plan_off[DIFF_CHAIN_ENTRIES];
    size_t plan_len[DIFF_CHAIN_ENTRIES];
    size_t count = diff_chain_split(base->list, base->list_len, off, len);
    diff_chain_case c = *base;
    c.list = framed;
    for (size_t keep = 0; keep <= count; keep++) {
        c.list_len = diff_chain_frame(framed, base->list, off, len, keep);
        diff_chain_compare(&c);
    }
    for (size_t drop = 0; drop < count; drop++) {
        size_t n = 0;
        for (size_t i = 0; i < count; i++) {
            if (i != drop) {
                plan_off[n] = off[i];
                plan_len[n] = len[i];
                n++;
            }
        }
        c.list_len = diff_chain_frame(framed, base->list, plan_off, plan_len, n);
        diff_chain_compare(&c);
    }
    for (size_t i = 0; i < count; i++) {
        plan_off[i] = off[i];
        plan_len[i] = len[i];
    }
    for (size_t take = count + 1; take <= DIFF_CHAIN_ENTRIES; take++) {
        plan_off[take - 1] = off[count - 1];
        plan_len[take - 1] = len[count - 1];
        size_t total = 0;
        for (size_t i = 0; i < take; i++) {
            total += plan_len[i] + 5;
        }
        if (total > DIFF_CHAIN_LIST_MAX) {
            break;
        }
        c.list_len = diff_chain_frame(framed, base->list, plan_off, plan_len, take);
        diff_chain_compare(&c);
    }
}

// Single bytes of the list changed, one drawn from each stride.
static void diff_chain_bytes(const diff_chain_case *base) {
    static uint8_t changed[DIFF_CHAIN_LIST_MAX];
    diff_chain_case c = *base;
    memcpy(changed, base->list, base->list_len);
    c.list = changed;
    size_t stride = base->list_len < DIFF_CHAIN_BYTES ? 1 : base->list_len / DIFF_CHAIN_BYTES;
    for (size_t start = 0; start + stride <= base->list_len; start += stride) {
        size_t at = start + (stride > 1 ? rng_below(stride) : 0);
        uint8_t delta = (uint8_t)(1 + rng_below(255));
        changed[at] ^= delta;
        diff_chain_compare(&c);
        changed[at] ^= delta;
    }
}

// One row: its own inputs, then one family of mutations at a time.
static void diff_chain_row(const webpki_corpus_chain *row, const webpki_corpus_anchor *other) {
    diff_chain_case base;
    base.anchors = row->anchors;
    base.anchor_count = row->anchor_count;
    base.hostname = row->hostname;
    base.now_seconds = row->now_seconds;
    diff_chain_list(row, &base.list, &base.list_len);
    diff_chain_compare(&base);
    diff_chain_clocks(&base);
    diff_chain_hostnames(&base);
    diff_chain_anchor_sets(&base);
    diff_chain_anchor_keys(&base, other);
    diff_chain_entry_sets(&base);
    diff_chain_bytes(&base);
}

static void diff_webpki_chain(void) {
    size_t minted = sizeof webpki_corpus_chains / sizeof webpki_corpus_chains[0];
    size_t captured = sizeof webpki_capture_chains / sizeof webpki_capture_chains[0];
    // The impostor anchor of the anchor_key_mismatch row is the key every
    // row's anchor is swapped for: a P-384 key no corpus certificate is
    // signed under.
    const webpki_corpus_anchor *other = &webpki_corpus_chains[minted - 2].anchors[0];
    for (size_t i = 0; i < minted; i++) {
        diff_chain_row(&webpki_corpus_chains[i], other);
    }
    long minted_rows = diff_chain_rows;
    long minted_accepted = diff_chain_accepted;
    for (size_t i = 0; i < captured; i++) {
        diff_chain_row(&webpki_capture_chains[i], other);
    }
    (void)printf("diff: webpki_chain: %ld minted rows (%ld accepted), %ld captured rows "
                 "(%ld accepted), C == spec\n",
                 minted_rows, minted_accepted, diff_chain_rows - minted_rows,
                 diff_chain_accepted - minted_accepted);
}

#else

static void diff_webpki_chain(void) {
    (void)printf("diff: webpki_chain: skipped, the walk compiles under TRUST=webpki only\n");
}

#endif

#endif
