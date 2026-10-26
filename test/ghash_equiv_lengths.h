// bin/ghash_equiv_test's AEAD cases at every length within a block and a
// byte of a multiple of a pass, for 4, 8, 16, 31 to 33, 64, 127 and 128
// passes, up to a TLS record's 16 KiB, under the associated data lengths
// of a TLS record header and of a QUIC header. On arm64 the passes run on
// gcm_arm64_passes.h's assembly, which pairs two passes from 32 passes up
// (docs/decisions.md 158), so the counts hold each count of passes in a
// last short pair. Included by test/ghash_equiv_test.c only, which
// declares compare_aead, AEAD_PASS_BYTES, MAX_DATA and the failure count.
#ifndef CH_GHASH_EQUIV_LENGTHS_H
#define CH_GHASH_EQUIV_LENGTHS_H

static void run_aead_edges(void) {
    static const size_t edge_aad[] = {5, 21};
    static const size_t edge_passes[] = {4, 8, 16, 31, 32, 33, 64, 127, 128};
    for (size_t a = 0; a < sizeof edge_aad / sizeof edge_aad[0]; a++) {
        for (size_t p = 0; p < sizeof edge_passes / sizeof edge_passes[0]; p++) {
            for (size_t d = 0; d <= 2 * AES_BLOCK + 2; d++) {
                size_t n = edge_passes[p] * (size_t)AEAD_PASS_BYTES + d - (AES_BLOCK + 1);
                if (n > MAX_DATA) {
                    continue;
                }
                char case_name[64];
                (void)snprintf(case_name, sizeof case_name, "aead aad %zu, payload %zu",
                               edge_aad[a], n);
                compare_aead(case_name, edge_aad[a], n);
                if (failures > 0) {
                    return;
                }
            }
        }
    }
}

#endif
