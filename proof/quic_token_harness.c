// Proves: ch_srv_quic_token_mint writes only inside the caller's buffer and
// writes the layout quic_token.h prints, and ch_srv_quic_token_check reads
// only inside the token and the address it is handed and answers each of its
// four codes for the reason quic_token.h gives.
//
// The properties, over unconstrained inputs at the module's real bound: any
// key, any address length at all, any connection ID length a uint8_t holds,
// any instant, any lifetime, any capacity up to CH_QUIC_TOKEN_MAX, and any
// token of up to one byte past CH_QUIC_TOKEN_MAX. Memory safety and absence
// of UB on both calls, which is what the automatic checks discharge; the
// CH_ASSERTs in quic_token.c never fire. For the mint: a CH_OK answer writes
// the type byte, the instant, both lengths and both connection IDs where the
// layout puts them, at the length the connection IDs fix; a refusal writes
// neither the buffer nor *out_len; and CH_QUIC_TOKEN_MAX always suffices. For
// the check: every answer but CH_OK leaves *cids as it was; CH_EINVAL answers
// exactly the address lengths outside 1 to CH_QUIC_TOKEN_ADDRESS_MAX;
// CH_EPROTO answers only a token that is empty or whose first byte is not
// QUIC_TOKEN_TYPE_RETRY, and CH_EAUTH only one whose first byte is; and a
// CH_OK answer means a Retry token whose length its two length bytes fix,
// each at most CH_QUIC_DCID_MAX, whose issue instant is at most the lifetime
// before now and not after it, and whose connection IDs are the bytes *cids
// now holds.
//
// What it does not prove, and why. SHA-256 is the contract stub in harness.h,
// so hmac_sha256 runs over a digest CBMC picks freshly each call. That makes
// the tag comparison unconstrained, which is what lets this formula reach
// CH_OK over every token at all, and it puts the round trip and the address
// binding out of its reach: that a minted token checks, and that the same
// token at another address or under another key does not. The round trip,
// the address and key cases and the tamper sweep are tested instead, in
// test/quic_token_tests.h, and sha256_harness.c proves the hash itself.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

uint64_t nondet_u64(void);

#include "quic_token.c"

// One byte more than the longest token and the longest address the format
// admits, so the check covers a token that is too long, and both calls an
// address that is.
#define TOKEN_BUF (CH_QUIC_TOKEN_MAX + 1)
#define ADDRESS_BUF (CH_QUIC_TOKEN_ADDRESS_MAX + 1)

// The token's bytes before the first connection ID: the type byte, the
// eight bytes of the instant and the first length byte.
#define HEAD 10

static uint8_t key[CH_QUIC_TOKEN_KEY_LEN];
static uint8_t address[ADDRESS_BUF];
static uint8_t minted[CH_QUIC_TOKEN_MAX];
static uint8_t before[CH_QUIC_TOKEN_MAX];
static uint8_t token[TOKEN_BUF];

// The instant a token carries at offset 1, the most significant byte first.
static uint64_t instant_at(const uint8_t *t) {
    uint64_t seconds = 0;
    for (int i = 1; i <= 8; i++) {
        seconds = (seconds << 8) | t[i];
    }
    return seconds;
}

// A ch_quic_retry_cids with every field unconstrained, stored through the
// struct's own types.
static void havoc_cids(ch_quic_retry_cids *cids) {
    fill_nondet(cids->original_dcid, sizeof cids->original_dcid);
    fill_nondet(cids->retry_scid, sizeof cids->retry_scid);
    cids->original_dcid_len = nondet_u8();
    cids->retry_scid_len = nondet_u8();
}

static void prove_mint(void) {
    fill_nondet(key, sizeof key);
    fill_nondet(address, sizeof address);
    fill_nondet(minted, sizeof minted);
    memcpy(before, minted, sizeof before);
    ch_quic_retry_cids cids;
    havoc_cids(&cids);

    size_t address_len = nondet_size_t();
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof minted);
    uint64_t issued = nondet_u64();
    size_t out_len = nondet_size_t();
    size_t out_len_before = out_len;

    int rc =
        ch_srv_quic_token_mint(key, address, address_len, &cids, issued, minted, cap, &out_len);

    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL || rc == CH_ECAP,
                     "mint answers one of its three codes");
    int args_ok = address_len >= 1 && address_len <= CH_QUIC_TOKEN_ADDRESS_MAX &&
                  cids.original_dcid_len <= CH_QUIC_DCID_MAX &&
                  cids.retry_scid_len <= CH_QUIC_DCID_MAX;
    size_t total = (size_t)43 + cids.original_dcid_len + cids.retry_scid_len;
    __CPROVER_assert((rc == CH_EINVAL) == !args_ok, "CH_EINVAL answers exactly the bad arguments");
    if (rc == CH_ECAP) {
        __CPROVER_assert(cap < total, "CH_ECAP answers only a capacity below the token");
    }
    if (args_ok && cap == CH_QUIC_TOKEN_MAX) {
        __CPROVER_assert(rc == CH_OK, "CH_QUIC_TOKEN_MAX always suffices");
    }
    if (rc != CH_OK) {
        __CPROVER_assert(out_len == out_len_before, "a refusal leaves *out_len alone");
        for (size_t i = 0; i < sizeof minted; i++) {
            __CPROVER_assert(minted[i] == before[i], "a refusal writes no token byte");
        }
        return;
    }

    __CPROVER_assert(out_len == total && out_len <= cap,
                     "a minted token fits cap and is as long as its connection IDs make it");
    __CPROVER_assert(minted[0] == QUIC_TOKEN_TYPE_RETRY, "the first byte is the Retry type");
    __CPROVER_assert(instant_at(minted) == issued, "bytes 1 to 8 are the issue instant");
    size_t o = cids.original_dcid_len;
    __CPROVER_assert(minted[HEAD - 1] == o, "byte 9 is the first length");
    __CPROVER_assert(minted[HEAD + o] == cids.retry_scid_len,
                     "the second length follows the first ID");
    for (size_t i = 0; i < o; i++) {
        __CPROVER_assert(minted[HEAD + i] == cids.original_dcid[i], "the first ID is in place");
    }
    for (size_t i = 0; i < cids.retry_scid_len; i++) {
        __CPROVER_assert(minted[HEAD + o + 1 + i] == cids.retry_scid[i],
                         "the second ID is in place");
    }
}

static void prove_check(void) {
    fill_nondet(key, sizeof key);
    fill_nondet(address, sizeof address);
    fill_nondet(token, sizeof token);
    ch_quic_retry_cids got;
    havoc_cids(&got);
    ch_quic_retry_cids was = got;

    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof token);
    size_t address_len = nondet_size_t();
    uint64_t now = nondet_u64();
    uint64_t lifetime = nondet_u64();

    int rc = ch_srv_quic_token_check(key, token, n, address, address_len, now, lifetime, &got);

    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL || rc == CH_EPROTO || rc == CH_EAUTH,
                     "check answers one of its four codes");
    int address_ok = address_len >= 1 && address_len <= CH_QUIC_TOKEN_ADDRESS_MAX;
    __CPROVER_assert((rc == CH_EINVAL) == !address_ok,
                     "CH_EINVAL answers exactly the bad address lengths");
    int retry = n > 0 && token[0] == QUIC_TOKEN_TYPE_RETRY;
    if (rc == CH_EPROTO) {
        __CPROVER_assert(!retry, "CH_EPROTO answers only a token that is not a Retry token");
    }
    if (rc == CH_EAUTH) {
        __CPROVER_assert(retry, "CH_EAUTH answers only a Retry token");
    }
    if (rc != CH_OK) {
        __CPROVER_assert(got.original_dcid_len == was.original_dcid_len &&
                             got.retry_scid_len == was.retry_scid_len,
                         "a refusal writes no length");
        for (size_t i = 0; i < CH_QUIC_DCID_MAX; i++) {
            __CPROVER_assert(got.original_dcid[i] == was.original_dcid[i] &&
                                 got.retry_scid[i] == was.retry_scid[i],
                             "a refusal writes no connection ID byte");
        }
        return;
    }

    __CPROVER_assert(retry, "CH_OK answers only a Retry token");
    size_t o = got.original_dcid_len;
    size_t r = got.retry_scid_len;
    __CPROVER_assert(o <= CH_QUIC_DCID_MAX && r <= CH_QUIC_DCID_MAX,
                     "each connection ID fits the array *cids gives it");
    __CPROVER_assert(n == 43 + o + r, "the token is as long as its two length bytes make it");
    uint64_t issued = instant_at(token);
    __CPROVER_assert(now >= issued, "a token issued after now never checks");
    __CPROVER_assert(now - issued <= lifetime, "a token older than the lifetime never checks");
    __CPROVER_assert(token[HEAD - 1] == o && token[HEAD + o] == r,
                     "the lengths reported are the ones the token carried");
    for (size_t i = 0; i < o; i++) {
        __CPROVER_assert(got.original_dcid[i] == token[HEAD + i], "the first ID is the token's");
    }
    for (size_t i = 0; i < r; i++) {
        __CPROVER_assert(got.retry_scid[i] == token[HEAD + o + 1 + i],
                         "the second ID is the token's");
    }
}

int main(void) {
    prove_mint();
    prove_check();
    return 0;
}
