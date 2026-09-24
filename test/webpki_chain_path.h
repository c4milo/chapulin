// The path the TRUST=webpki chain walk reports (webpki.h): how many
// entries it read, leaf first, and which anchor verified the last of
// them. The SPKI pins may name any key on that path (webpki_pin.h), so a
// path one entry too long lets a pin on an unread certificate through,
// and a wrong anchor index lets a pin on another anchor through.
//
// Included by test/webpki_chain_test.c after its helpers: row_named,
// row_list and walk are that file's.
#ifndef CH_TEST_WEBPKI_CHAIN_PATH_H
#define CH_TEST_WEBPKI_CHAIN_PATH_H

// One accepted row and the path the walk must report for it.
typedef struct {
    const char *name;
    uint8_t path_entries;
    uint8_t anchor_index;
} expected_path;

// The corpus comments and the capture chains name each path: aws sends
// three entries and the walk stops at entry 1; letsencrypt sends four
// and stops at entry 2; rekeyed_intermediate needs all three. The
// captures carry the five published roots in the order AmazonRootCA1,
// SFSRootCAG2, GTSRootR1, GTSRootR4, ISRGRootX2, and each chain ends at
// a different one: acme-v02 reads its leaf, YE2 and Root YE, and ISRG
// Root X2 verifies Root YE, so its fourth entry, X2 under X1, stays
// unread.
static const expected_path expected_paths[] = {
    {"aws",                          2, 0},
    {"gcs",                          2, 0},
    {"r2",                           2, 0},
    {"letsencrypt",                  3, 0},
    {"p384_leaf",                    2, 0},
    {"rekeyed_intermediate",         3, 0},
    {"s3.amazonaws.com",             2, 0},
    {"storage.googleapis.com",       2, 2},
    {"r2.cloudflarestorage.com",     2, 3},
    {"acme-v02.api.letsencrypt.org", 3, 4},
};

// A corpus or capture row by name.
static const webpki_corpus_chain *row_by_name(const char *name) {
    for (size_t i = 0; i < sizeof webpki_corpus_chains / sizeof webpki_corpus_chains[0]; i++) {
        if (strcmp(webpki_corpus_chains[i].name, name) == 0) {
            return &webpki_corpus_chains[i];
        }
    }
    for (size_t i = 0; i < sizeof webpki_capture_chains / sizeof webpki_capture_chains[0]; i++) {
        if (strcmp(webpki_capture_chains[i].name, name) == 0) {
            return &webpki_capture_chains[i];
        }
    }
    (void)fprintf(stderr, "FAIL no row named %s\n", name);
    failures++;
    return NULL;
}

// The walk over a row's own list, under the row's configuration with its
// anchors replaced. Returns the return code and leaves the path in leaf.
static int walk_under(const webpki_corpus_chain *row, const webpki_corpus_anchor *anchors,
                      size_t anchor_count, webpki_leaf_info *leaf) {
    webpki_corpus_chain changed = *row;
    changed.anchors = anchors;
    changed.anchor_count = anchor_count;
    const uint8_t *list = NULL;
    size_t list_len = 0;
    uint8_t alert = 0;
    CHECK(row_list(row, &list, &list_len));
    return walk(&changed, list, list_len, leaf, &alert);
}

static void test_path_outputs(void) {
    for (size_t i = 0; i < sizeof expected_paths / sizeof expected_paths[0]; i++) {
        const expected_path *want = &expected_paths[i];
        const webpki_corpus_chain *row = row_by_name(want->name);
        if (row == NULL) {
            continue;
        }
        webpki_leaf_info leaf;
        int rc = walk_under(row, row->anchors, row->anchor_count, &leaf);
        if (rc != CH_OK || leaf.path_entries != want->path_entries ||
            leaf.anchor_index != want->anchor_index) {
            (void)fprintf(stderr, "FAIL %s: rc %d path %u anchor %u, want path %u anchor %u\n",
                          want->name, rc, leaf.path_entries, leaf.anchor_index, want->path_entries,
                          want->anchor_index);
            failures++;
        }
    }
}

// The anchor index follows the anchor that verified, not the first one
// configured and not the first one naming the issuer. The aws chain
// under the P-384 root then its own ends at index 1. The r2 chain under
// two anchors with the P-384 root's Name, the impostor key first and the
// real key second, which is a root re-keyed under one Name, ends at the
// second: the first names the issuer and verifies nothing. The same two
// anchors the other way round end at index 0.
static void test_anchor_index(void) {
    const webpki_corpus_chain *aws = row_named(ROW_AWS, "aws");
    const webpki_corpus_chain *r2 = row_named(ROW_R2, "r2");
    const webpki_corpus_chain *impostor = row_named(ROW_ANCHOR_KEY_MISMATCH, "anchor_key_mismatch");
    webpki_leaf_info leaf;
    webpki_corpus_anchor anchors[2] = {r2->anchors[0], aws->anchors[0]};
    CHECK(walk_under(aws, anchors, 2, &leaf) == CH_OK);
    CHECK(leaf.path_entries == 2 && leaf.anchor_index == 1);
    anchors[0] = impostor->anchors[0];
    anchors[1] = r2->anchors[0];
    CHECK(walk_under(r2, anchors, 2, &leaf) == CH_OK);
    CHECK(leaf.path_entries == 2 && leaf.anchor_index == 1);
    anchors[0] = r2->anchors[0];
    anchors[1] = impostor->anchors[0];
    CHECK(walk_under(r2, anchors, 2, &leaf) == CH_OK);
    CHECK(leaf.path_entries == 2 && leaf.anchor_index == 0);
}

// An anchor whose subject Name equals the issuer Name and whose key
// does not verify the signature authorizes nothing: the corpus row
// anchor_key_mismatch carries the P-384 root's Name over another key,
// and the same chain under the real root is accepted.
static void test_anchor_name_alone(void) {
    const webpki_corpus_chain *r2 = row_named(ROW_R2, "r2");
    const webpki_corpus_chain *impostor = row_named(ROW_ANCHOR_KEY_MISMATCH, "anchor_key_mismatch");
    CHECK(impostor->anchor_count == 1 && r2->anchor_count == 1);
    CHECK(impostor->anchors[0].name_len == r2->anchors[0].name_len &&
          memcmp(impostor->anchors[0].name, r2->anchors[0].name, r2->anchors[0].name_len) == 0);
    CHECK(impostor->anchors[0].spki_len != r2->anchors[0].spki_len ||
          memcmp(impostor->anchors[0].spki, r2->anchors[0].spki, r2->anchors[0].spki_len) != 0);
    CHECK(impostor->message == r2->message);
}

#endif
