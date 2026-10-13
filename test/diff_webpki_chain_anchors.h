// The chain differential's row of many anchors (test/diff_webpki_chain.h):
// a row's anchors after decoys, more than the twelve a cap allowed before
// docs/decisions.md 131. It sits in a header of its own so that file stays
// under the 500 lines lint-size holds. Included by that file alone, after
// diff_chain_compare.
#ifndef CH_DIFF_WEBPKI_CHAIN_ANCHORS_H
#define CH_DIFF_WEBPKI_CHAIN_ANCHORS_H

// The row's anchors after decoys, DIFF_CHAIN_ANCHORS in all, so the
// anchor that verifies sits at an index past twelve. Each decoy carries
// other's key under a Name no certificate names, so the walk compares its
// Name and verifies nothing under it.
static void diff_chain_many_anchors(const diff_chain_case *base,
                                    const webpki_corpus_anchor *other) {
    static const uint8_t decoy_name[] = {0x30, 0x10, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55,
                                         0x04, 0x03, 0x0c, 0x05, 'd',  'e',  'c',  'o',  'y'};
    static webpki_corpus_anchor many[DIFF_CHAIN_ANCHORS];
    if (base->anchor_count == 0 || base->anchor_count > DIFF_CHAIN_ANCHORS) {
        return;
    }
    size_t decoys = DIFF_CHAIN_ANCHORS - base->anchor_count;
    for (size_t i = 0; i < decoys; i++) {
        many[i] = *other;
        many[i].name = decoy_name;
        many[i].name_len = sizeof decoy_name;
    }
    for (size_t i = 0; i < base->anchor_count; i++) {
        many[decoys + i] = base->anchors[i];
    }
    diff_chain_case c = *base;
    c.anchors = many;
    c.anchor_count = DIFF_CHAIN_ANCHORS;
    diff_chain_compare(&c);
}

#endif
