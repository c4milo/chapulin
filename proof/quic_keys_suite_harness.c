// Proves: in a -DCH_SUITE_AES_GCM QUIC build, quic_keys_init_suite,
// quic_hp_key_init_suite and quic_keys_update are memory safe over each
// of the three suites and a secret as long as that suite's hash, and they
// derive what RFC 9001 §5.1 and §6.1 say at that suite: every
// HKDF-Expand-Label runs at suite_hash_len(suite) under one of the four
// labels of the QUIC version the call was given, "quic key" and "quic
// hp" write suite_key_len(suite) bytes, "quic ku" writes the hash length,
// and each set records its suite and starts its §6.6 count at 0. The
// update keeps the set's suite. The version is any value, and
// quic_version.h names its labels.
//
// HKDF is the contract stub below, which asserts those lengths; hkdf's
// own harnesses prove the real function, and test/quic_suite_test.c
// checks the derivations against an independent computation.
#include "harness.h"

#include <string.h>

#include "hkdf.h"
#include "quic_version.h"
#include "suite.h"

#if !defined(CH_SUITE_AES_GCM) || !defined(CH_TRANSPORT_QUIC_NONBLOCKING)
#error                                                                                             \
    "quic_keys_suite proves the QUIC suite build: -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_SUITE_AES_GCM"
#endif

uint64_t nondet_u64(void);

static size_t expected_hash_len;
static size_t expected_key_len;
static uint32_t expected_version;

void hkdf_expand_label(size_t hash_len, const uint8_t *secret, const char *label,
                       const uint8_t *ctx, size_t ctx_len, uint8_t *out, size_t out_len) {
    quic_labels labels = quic_version_labels(expected_version);
    __CPROVER_assert(hash_len == expected_hash_len, "label: the suite's hash");
    __CPROVER_assert(__CPROVER_r_ok(secret, hash_len), "label: secret readable");
    __CPROVER_assert(ctx_len == 0, "label: QUIC labels take no context");
    (void)ctx;
    __CPROVER_assert(__CPROVER_w_ok(out, out_len), "label: output writable");
    int key_or_hp = strcmp(label, labels.key) == 0 || strcmp(label, labels.hp) == 0;
    int ku = strcmp(label, labels.ku) == 0;
    __CPROVER_assert(key_or_hp || ku || strcmp(label, labels.iv) == 0,
                     "label: one of the four labels of the version the call was given");
    if (key_or_hp) {
        __CPROVER_assert(out_len == expected_key_len, "label: the suite's key length");
    }
    if (ku) {
        __CPROVER_assert(out_len == expected_hash_len, "label: the next secret at the hash");
    }
    fill_nondet(out, out_len);
}

#include "quic_keys.c"

int main(void) {
    uint16_t suite = SUITE_CHACHA20_POLY1305_SHA256;
    uint8_t pick = nondet_u8();
    __CPROVER_assume(pick < 3);
    if (pick == 1) {
        suite = SUITE_AES_128_GCM_SHA256;
    }
    if (pick == 2) {
        suite = SUITE_AES_256_GCM_SHA384;
    }
    expected_hash_len = suite_hash_len(suite);
    expected_key_len = suite_key_len(suite);
    expected_version = nondet_u32();
    // Any description of the CPU: the three calls hand it to the hash
    // entries and read none of it themselves (hkdf.h).
    uint32_t cpu = nondet_u32();

    uint8_t secret[HKDF_HASH_MAX];
    fill_nondet(secret, sizeof secret);
    quic_keys k;
    quic_keys_init_suite(cpu, &k, expected_version, secret, suite);
    __CPROVER_assert(k.suite == suite && k.sealed == 0, "init: the set records its suite");

    fill_nondet(secret, sizeof secret);
    quic_hp_key h;
    quic_hp_key_init_suite(cpu, &h, expected_version, secret, suite);
    __CPROVER_assert(h.suite == suite, "hp: the key records its suite");

    // The update reads and rewrites the same secret. The set's key bytes
    // and its count are havocked first, its suite is the row's.
    fill_nondet(secret, sizeof secret);
    fill_nondet(k.key, sizeof k.key);
    fill_nondet(k.iv, sizeof k.iv);
    k.sealed = nondet_u64();
    quic_keys_update(cpu, secret, &k, expected_version);
    __CPROVER_assert(k.suite == suite && k.sealed == 0,
                     "update: the suite stays, the count restarts");
    return 0;
}
