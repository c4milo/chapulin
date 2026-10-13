// The rows of test/diff_pem_files_test.c that drive pem_files.h's three
// calls whole: a chain file, a CA bundle and a P-256 key file. A row
// builds each file from random parts and then breaks it, under rooms the
// rows draw. Included by that file alone, after the helpers it declares.
#ifndef CH_DIFF_PEM_FILES_CALLS_H
#define CH_DIFF_PEM_FILES_CALLS_H

// The most entries a row gives either call: past the 255 certificates a
// chain holds.
#define ENTRIES_MAX 300
static uint8_t chain_der[ROOM_MAX];
static uint8_t bundle_der[ROOM_MAX];

// One pemchain row: a DER room of der_len bytes and chain_max entries.
static void row_chain(const uint8_t *p, size_t n, size_t der_len, size_t chain_max) {
    static ch_cert chain[ENTRIES_MAX];
    static const uint8_t *parts[ENTRIES_MAX];
    static size_t lens[ENTRIES_MAX];
    uint8_t count = 0;
    if (ch_chain_from_pem(p, n, chain_der, der_len, chain, chain_max, &count) == CH_OK) {
        for (size_t i = 0; i < count; i++) {
            parts[i] = chain[i].der;
            lens[i] = chain[i].len;
        }
        reply_list(parts, lens, count);
    } else {
        (void)snprintf(want, sizeof want, "ERR pemchain reject");
    }
    char head[96];
    (void)snprintf(head, sizeof head, "pemchain %zu %zu", der_len, chain_max);
    request(head, p, n);
    compare();
}

// One pemanchors row: a DER room of der_len bytes and anchor_max entries.
// The spec replies each anchor as its Name's hex and its key's, a space
// between them. Commas join the anchors. So a Name that ends a byte early
// or late shows.
static void row_anchors(const uint8_t *p, size_t n, size_t der_len, size_t anchor_max) {
    static ch_trust_anchor anchors[ENTRIES_MAX];
    size_t count = 0;
    if (ch_anchors_from_pem(p, n, bundle_der, der_len, anchors, anchor_max, &count) == CH_OK) {
        size_t at = 3;
        memcpy(want, "ok ", 3);
        for (size_t i = 0; i < count; i++) {
            if (at + 2 * (anchors[i].name_len + anchors[i].spki_len) + 3 >= WANT_MAX) {
                die("a reply outgrew the want buffer");
            }
            if (i != 0) {
                want[at++] = ',';
            }
            at += hex_encode(want + at, anchors[i].name, anchors[i].name_len);
            want[at++] = ' ';
            at += hex_encode(want + at, anchors[i].spki, anchors[i].spki_len);
        }
        want[at] = '\0';
    } else {
        (void)snprintf(want, sizeof want, "ERR pemanchors reject");
    }
    char head[96];
    (void)snprintf(head, sizeof head, "pemanchors %zu %zu", der_len, anchor_max);
    request(head, p, n);
    compare();
}

// The rooms of a row: a DER room that every text here fits, or a small
// one; and as many entries as the text may hold, or fewer.
static size_t draw_der_len(void) {
    return rng_below(3) == 0 ? 1 + rng_below(8000) : ROOM_MAX;
}

static size_t draw_entries(void) {
    return rng_below(3) == 0 ? rng_below(14) : ENTRIES_MAX;
}

// A chain of count synthetic certificates under a chain's text rule.
// Now and then a leaf is large, so a small room fills. Now and then a
// block is random bytes in place of a certificate, which the chain's
// check of each certificate's outer fields refuses.
static size_t chain_text(size_t count) {
    static uint8_t cert[PFD_CERT_MAX];
    static const char *const chain_gaps[] = {"", "\n", "\r\n", "\n\n"};
    size_t n = 0;
    for (size_t i = 0; i < count; i++) {
        if (i != 0) {
            const char *gap = chain_gaps[rng_below(4)];
            memcpy(text + n, gap, strlen(gap));
            n += strlen(gap);
        }
        uint8_t point[64];
        draw_point(point);
        size_t pad = rng_below(4) == 0 ? rng_below(6000) : rng_below(200);
        pfd_cert_shape shape = {(int)rng_below(2), (int)rng_below(2), pad, 0};
        size_t c = pfd_cert(cert, sizeof cert, point, shape);
        if (rng_below(10) == 0) {
            rng_fill(cert, c);
        }
        n += pem_armor(cert, c, 64, eols[rng_below(2)], text + n);
    }
    return n;
}

// A bundle of count synthetic certificates with random text around them.
static size_t bundle_text(size_t count) {
    static uint8_t cert[1024];
    size_t n = 0;
    for (size_t i = 0; i <= count; i++) {
        // Mostly the name and comment lines a bundle carries; now and
        // then any gap, which may break the rule.
        const char *gap = rng_below(8) == 0 ? gaps[rng_below(sizeof gaps / sizeof *gaps)]
                                            : gaps[6 + rng_below(2)];
        memcpy(text + n, gap, strlen(gap));
        n += strlen(gap);
        if (i == count) {
            break;
        }
        uint8_t point[64];
        draw_point(point);
        pfd_cert_shape shape = {(int)rng_below(2), (int)rng_below(2), rng_below(200), 0};
        size_t c = pfd_cert(cert, sizeof cert, point, shape);
        n += pem_armor(cert, c, 64, eols[rng_below(2)], text + n);
    }
    return n;
}

// count copies of one small certificate, each a block after an LF, which
// both text rules take. Returns the text's length, and the DER's length
// in *der_len.
static size_t copies_text(size_t count, size_t *der_len) {
    static uint8_t cert[512];
    uint8_t point[64];
    draw_point(point);
    pfd_cert_shape shape = {0, 0, 0, 0};
    size_t c = pfd_cert(cert, sizeof cert, point, shape);
    size_t n = 0;
    for (size_t i = 0; i < count; i++) {
        n += pem_armor(cert, c, 0, "\n", text + n);
    }
    *der_len = count * c;
    return n;
}

// A scalar the rows draw: random, with the edges of 1 to n - 1 and past
// them some of the time.
static void draw_scalar(uint8_t scalar[32]) {
    static const uint8_t n_order[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                                        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
    rng_fill(scalar, 32);
    switch (rng_below(10)) {
    case 0:
        memset(scalar, 0, 32);
        scalar[31] = (uint8_t)rng_below(2);
        break;
    case 1:
        memcpy(scalar, n_order, 32);
        scalar[31] = (uint8_t)(scalar[31] - 1 + rng_below(3));
        break;
    case 2:
        memset(scalar, 0xff, 32);
        break;
    default:
        scalar[0] &= 0x7f;
        break;
    }
}

// One pemkey row. A device object takes the cpu value 0 alone, and the
// value picks no point, so the spec takes none.
static void row_key(const uint8_t *p, size_t n, const uint8_t *leaf, size_t leaf_len) {
    uint8_t priv[32];
    uint8_t pub[64];
    if (ch_p256_key_from_pem(0, p, n, leaf, leaf_len, priv, pub) == CH_OK) {
        (void)snprintf(want, sizeof want, "ok ");
        size_t at = 3 + hex_encode(want + 3, priv, 32);
        want[at++] = ' ';
        (void)hex_encode(want + at, pub, 64);
    } else {
        (void)snprintf(want, sizeof want, "ERR pemkey reject");
    }
    size_t at = (size_t)snprintf(cmd, sizeof cmd, "pemkey ");
    at += n == 0 ? (size_t)snprintf(cmd + at, sizeof cmd - at, "-") : hex_encode(cmd + at, p, n);
    cmd[at++] = ' ';
    if (leaf_len == 0) {
        cmd[at++] = '-';
        cmd[at] = '\0';
    } else {
        (void)hex_encode(cmd + at, leaf, leaf_len);
    }
    compare();
}

// The EC PARAMETERS block that a key file may hold above its key, into
// dst. It takes one of six shapes:
//  - prime256v1's, or secp384r1's;
//  - prime256v1's with a byte after it, with a byte changed, or without
//    its last byte;
//  - none.
// Returns its length.
static size_t parameters_block(uint8_t *dst) {
    static const uint8_t prime256v1[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
                                         0x3d, 0x03, 0x01, 0x07, 0x00};
    static const uint8_t secp384r1[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
    uint8_t der[sizeof prime256v1];
    memcpy(der, prime256v1, sizeof der);
    switch (rng_below(9)) {
    case 0:
        return pem_armor_label("EC PARAMETERS", secp384r1, sizeof secp384r1, 64, "\n", dst);
    case 1:
        return pem_armor_label("EC PARAMETERS", der, sizeof der, 64, "\n", dst);
    case 2:
        der[rng_below(sizeof der - 1)] ^= (uint8_t)(1 + rng_below(255));
        return pem_armor_label("EC PARAMETERS", der, sizeof der - 1, 64, "\n", dst);
    case 3:
        return 0;
    case 4:
        return pem_armor_label("EC PARAMETERS", der, sizeof der - 2, 64, "\n", dst);
    default:
        return pem_armor_label("EC PARAMETERS", der, sizeof der - 1, 64, eols[rng_below(2)], dst);
    }
}

static void diff_key_files(void) {
    static uint8_t leaf[1024];
    uint8_t der[CH_PEM_KEY_DER_MAX + 64];
    for (int i = 0; i < 300; i++) {
        uint8_t scalar[32];
        uint8_t priv[32];
        uint8_t point65[P256_POINT_LEN];
        uint8_t point[64];
        draw_scalar(scalar);
        if (p256_ecdh_keygen(WIDEMUL_BUILD_ANSWER, scalar, priv, point65)) {
            memcpy(point, point65 + 1, 64);
        } else {
            draw_point(point);
        }
        // The leaf names the scalar's point most of the time, and the file
        // carries it or another point or none.
        uint8_t leaf_point[64];
        memcpy(leaf_point, point, 64);
        if (rng_below(6) == 0) {
            draw_point(leaf_point);
        }
        pfd_cert_shape cert_shape = {1, 0, rng_below(100), 0};
        size_t leaf_len = pfd_cert(leaf, sizeof leaf, leaf_point, cert_shape);
        uint8_t file_point[64];
        memcpy(file_point, point, 64);
        if (rng_below(6) == 0) {
            draw_point(file_point);
        }
        pfd_key_shape shape = draw_key_shape();
        int pkcs8 = (int)rng_below(2);
        size_t d = pkcs8 ? pfd_pkcs8(der, sizeof der, scalar, file_point, shape)
                         : pfd_ec_private_key(der, sizeof der, scalar, file_point, shape);
        size_t width =
            pem_armor_widths[rng_below(sizeof pem_armor_widths / sizeof *pem_armor_widths)];
        // An EC PARAMETERS block above the key half of the time, and now
        // and then twice. The call takes it above a SEC 1 key alone.
        size_t n = rng_below(2) == 0 ? parameters_block(text) : 0;
        if (n != 0 && rng_below(8) == 0) {
            n += parameters_block(text + n);
        }
        n += pem_armor_label(pkcs8 ? "PRIVATE KEY" : "EC PRIVATE KEY", der, d, width,
                             eols[rng_below(2)], text + n);
        row_key(text, n, leaf, leaf_len);
        n = mutate(text, n, sizeof text);
        row_key(text, n, leaf, leaf_len);
    }
    // The key file's text cap, at it and one past it, for a key under its
    // EC PARAMETERS block.
    uint8_t scalar[32] = {0};
    scalar[31] = 7;
    uint8_t priv[32];
    uint8_t point65[P256_POINT_LEN];
    (void)p256_ecdh_keygen(WIDEMUL_BUILD_ANSWER, scalar, priv, point65);
    pfd_cert_shape cert_shape = {1, 0, 0, 0};
    size_t leaf_len = pfd_cert(leaf, sizeof leaf, point65 + 1, cert_shape);
    size_t d = pfd_ec_private_key(der, sizeof der, scalar, point65 + 1, pfd_key_full);
    static const uint8_t prime256v1[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                                         0xce, 0x3d, 0x03, 0x01, 0x07};
    size_t n = pem_armor_label("EC PARAMETERS", prime256v1, sizeof prime256v1, 64, "\n", text);
    n += pem_armor_label("EC PRIVATE KEY", der, d, 64, "\n", text + n);
    memset(text + n, '\n', CH_PEM_KEY_TEXT_MAX + 1 - n);
    row_key(text, CH_PEM_KEY_TEXT_MAX, leaf, leaf_len);
    row_key(text, CH_PEM_KEY_TEXT_MAX + 1, leaf, leaf_len);
}

// A chain of one certificate of exactly der_len bytes, into text.
static size_t chain_of_one(size_t der_len) {
    static uint8_t cert[PFD_CERT_MAX];
    uint8_t point[64];
    draw_point(point);
    size_t pad = pfd_pad_for(der_len, point);
    pfd_cert_shape shape = {1, 0, pad, 0};
    if (pad == 0 || pfd_cert(cert, sizeof cert, point, shape) != der_len) {
        die("no certificate of the asked length");
    }
    return pem_armor(cert, der_len, 64, "\n", text);
}

// Each limit of the chain and the bundle, at its last admitted value and
// one past it. The limits are the DER room, the entries and a chain's
// 255.
static void diff_limits(void) {
    row_chain(text, chain_of_one(12288), 12288, 1);
    row_chain(text, chain_of_one(12288), 12287, 1);
    size_t der_len = 0;
    size_t n = copies_text(13, &der_len);
    row_chain(text, n, der_len, 13);
    row_chain(text, n, der_len - 1, 13);
    row_chain(text, n, der_len, 12);
    row_anchors(text, n, der_len, 13);
    row_anchors(text, n, der_len - 1, 13);
    row_anchors(text, n, der_len, 12);
    n = copies_text(255, &der_len);
    row_chain(text, n, der_len, ENTRIES_MAX);
    n = copies_text(256, &der_len);
    row_chain(text, n, der_len, ENTRIES_MAX);
    row_anchors(text, n, der_len, ENTRIES_MAX);
}

static void diff_calls(void) {
    for (int i = 0; i < 200; i++) {
        size_t n = chain_text(1 + rng_below(13));
        size_t der_len = draw_der_len();
        size_t entries = draw_entries();
        row_chain(text, n, der_len, entries);
        n = mutate(text, n, sizeof text);
        row_chain(text, n, der_len, entries);
        n = blocks_text(rng_below(14), 300);
        row_chain(text, n, der_len, entries);
        n = bundle_text(rng_below(14));
        row_anchors(text, n, der_len, entries);
        n = mutate(text, n, sizeof text);
        row_anchors(text, n, der_len, entries);
    }
    diff_limits();
    diff_key_files();
}

#endif
