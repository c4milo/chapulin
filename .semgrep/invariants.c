// Violation file for semgrep --test: each `ruleid:` line must be
// flagged by the named rule, each `ok:` line must not. This file
// never compiles and never should; it proves the tripwires trip.
#include <stdint.h>
#include <stddef.h>

// ruleid: inv-2-freestanding
#include <stdio.h>
// ruleid: inv-2-freestanding
#include <stdlib.h>
// ruleid: inv-2-freestanding
#include <time.h>

typedef struct {
    uint64_t seq;
} fake_dir;

// The key type quic_aes.h declares. This fixture gives it a body,
// which the tree's own headers no longer do: quic_aes.h declares it
// incomplete and quic_aes_key.h holds the body, so a library source
// that does not include that header cannot declare one at all. The body
// is here because the lines below take a pointer to one and write a
// field of one, and semgrep --test needs a file it can parse.
typedef struct {
    uint8_t round_keys[176];
} fake_round_keys;

typedef struct {
    fake_round_keys key;
} aes_public_key;

// A function pointer of the shape aes_encrypt_block has. The value
// branch of inv-26-aes-public-keys-only exists for this: a pointer
// that holds an aes_ entry, and a later call through the pointer that
// names no aes_ symbol at all.
typedef void (*block_fn)(const aes_public_key *k, const uint8_t *in, uint8_t *out);

// ok: inv-18-no-global-mutable-state
static const uint8_t table[4] = {1, 2, 3, 4};
// ruleid: inv-18-no-global-mutable-state
static int g_counter;
// ruleid: inv-18-no-global-mutable-state
static uint8_t g_key[32] = {0};

// ok: inv-18-no-global-mutable-state
static int helper(int x);

void ch_rand_bytes(uint8_t *p, size_t n);
void aead_seal(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_len,
               const uint8_t *pt, size_t n, uint8_t *out, uint8_t *tag);
int memcmp(const void *a, const void *b, size_t n);
int pkcs1_verify(const uint8_t *sig, size_t n);
int x509_read_header(void *r, uint8_t tag, size_t *out_len);
int asn1_get_tag(const uint8_t *p, size_t n);
int der_parse(const uint8_t *sig, size_t n, uint8_t *r, uint8_t *s);
int x509_verify_leaf(const uint8_t *list, size_t list_len, const uint8_t *ca_key_a, size_t ca_a_len,
                     const uint8_t *ca_key_b, size_t ca_b_len, void *out, uint8_t *alert);
long time(long *t);
void *malloc(size_t n);
void free(void *p);
void aes_encrypt_block(const aes_public_key *k, const uint8_t *in, uint8_t *out);
void gcm_seal(const aes_public_key *k, const uint8_t *nonce, const uint8_t *pt, size_t pt_len,
              uint8_t *out, uint8_t *tag);
void take_block_fn(block_fn f);

static int helper(int x) {
    fake_dir d;
    // ruleid: inv-10-seq-reset-only-in-record
    d.seq = 0;
    fake_dir *pd = &d;
    // ruleid: inv-10-seq-reset-only-in-record
    pd->seq = 0;
    // ok: inv-10-seq-reset-only-in-record
    d.seq = 1;

    uint8_t buf[32];
    // ruleid: inv-4-randomness-sites
    ch_rand_bytes(buf, sizeof buf);

    // ruleid: inv-1-seal-only-in-record
    aead_seal(buf, buf, buf, 0, buf, 0, buf, buf);

    // ruleid: inv-16-no-variable-time-compare
    return memcmp(buf, buf, 32) == x;
}

int use_everything(void) {
    // ruleid: inv-2-no-allocator
    void *p = malloc(16);
    // ruleid: inv-2-no-allocator
    free(p);

    uint8_t buf[32];
    size_t len = 0;
    // ruleid: inv-5-profiled-cert-parser
    x509_read_header(0, 0x30, &len);
    // ruleid: inv-5-profiled-cert-parser
    asn1_get_tag(buf, sizeof buf);
    // ruleid: inv-5-profiled-cert-parser
    der_parse(buf, sizeof buf, buf, buf);
    // ruleid: inv-20-cert-entry-point
    x509_verify_leaf(buf, sizeof buf, buf, sizeof buf, buf, sizeof buf, 0, buf);
    // ruleid: inv-20-no-time-calls
    time(0);

    // Two ways to make a key without calling anything. The rule reads
    // neither, and it no longer needs to: in the tree this type is
    // incomplete outside quic_aes_key.h's three readers, so both lines
    // are a compiler error there rather than a pattern to match.
    // ok: inv-26-aes-public-keys-only
    aes_public_key uninitialized;
    // ok: inv-26-aes-public-keys-only
    aes_public_key k = {{{0}}};
    // ruleid: inv-26-aes-public-keys-only
    aes_encrypt_block(&k, buf, buf);
    // ruleid: inv-26-aes-public-keys-only
    gcm_seal(&uninitialized, buf, buf, 0, buf, buf);

    // The name used as a value rather than called. Each of these three
    // leaves the call branch nothing to match, so the value branch is
    // what fires.
    // ruleid: inv-26-aes-public-keys-only
    block_fn fp = aes_encrypt_block;
    // ruleid: inv-26-aes-public-keys-only
    take_block_fn(&aes_encrypt_block);
    // ruleid: inv-26-aes-public-keys-only
    take_block_fn(aes_encrypt_block);
    // The call through the pointer names no aes_ symbol, so no branch
    // matches it. The line above is where the rule fires instead.
    // ok: inv-26-aes-public-keys-only
    fp(&k, buf, buf);
    // A write to a field of a key the file already holds. No branch
    // matches this either. In the tree it is a compiler error outside
    // quic_aes_key.h's three readers, and inside them it is the shape
    // docs/invariants.md INV-26 states as the review obligation.
    // ok: inv-26-aes-public-keys-only
    k.key.round_keys[0] = buf[0];

    // ruleid: inv-6-no-pkcs1
    return pkcs1_verify(0, 0) + helper(1);
}
