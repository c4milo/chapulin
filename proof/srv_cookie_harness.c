// Proves: srv_cookie_mint writes only inside the caller's buffer and reports
// the length the hash fixes, and srv_cookie_open reads only inside the bytes
// the client echoed and reports one of its two verdicts.
//
// The properties, over unconstrained inputs at the module's real bound.
// Memory safety and absence of UB on both calls, which is what the automatic
// checks discharge. The mint's length contract: zero, or a length that fits
// cap and equals the format's own. The sufficiency of SRV_COOKIE_MAX, which
// srv_flight.h asserts against HSP_COOKIE_MAX -- at that capacity the mint
// always succeeds. And the open's: a CH_OK answer reports a hash length the
// caller's buffer holds, over a cookie whose length is the one its suite
// fixes.
//
// What it does not prove, and why. SHA-256 is the contract stub in harness.h,
// so hmac_sha256 runs over a digest CBMC picks freshly each call. That makes
// the MAC comparison unconstrained and puts the round trip -- a minted cookie
// opens back to what it carried -- out of reach of this formula. The round
// trip and the tamper sweep are tested instead, in test/srv_cookie_tests.h,
// and sha256_harness.c proves the hash itself.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

uint16_t nondet_u16(void);

#include "srv_cookie.c"

// One byte more than the longest cookie the format admits, so the open case
// covers a cookie that is too long as well as every length below it.
#define COOKIE_BUF (SRV_COOKIE_MAX + 1)

static uint8_t key[SRV_COOKIE_KEY_LEN];
static uint8_t ch1_hash[SRV_COOKIE_HASH_MAX];
static uint8_t frozen[SHA256_LEN];
static uint8_t minted[SRV_COOKIE_MAX];
static uint8_t cookie[COOKIE_BUF];

static void prove_mint(void) {
    fill_nondet(key, sizeof key);
    fill_nondet(ch1_hash, sizeof ch1_hash);
    fill_nondet(frozen, sizeof frozen);

    size_t hash_len = nondet_size_t();
    __CPROVER_assume(hash_len <= SRV_COOKIE_HASH_MAX);
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof minted);

    size_t n =
        srv_cookie_mint(key, nondet_u16(), nondet_u16(), ch1_hash, hash_len, frozen, minted, cap);

    __CPROVER_assert(n <= cap, "a minted cookie fits the buffer it was given");
    __CPROVER_assert(n == 0 || n == 5 + hash_len + SHA256_LEN + SHA256_LEN,
                     "a minted cookie is as long as the hash it carries makes it");
    // srv_flight.h asserts SRV_COOKIE_MAX against HSP_COOKIE_MAX, so the
    // constant has to be sufficient for every cookie this mint can write.
    if (cap == SRV_COOKIE_MAX && hash_len >= SHA256_LEN) {
        __CPROVER_assert(n != 0, "SRV_COOKIE_MAX always suffices");
    }
}

static void prove_open(void) {
    fill_nondet(key, sizeof key);
    fill_nondet(cookie, sizeof cookie);

    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof cookie);

    uint16_t suite;
    uint16_t group;
    size_t hash_len;
    uint8_t out_hash[SRV_COOKIE_HASH_MAX];
    uint8_t out_frozen[SHA256_LEN];

    int rc = srv_cookie_open(key, cookie, n, &suite, &group, out_hash, &hash_len, out_frozen);

    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "open answers one of its two verdicts");
    if (rc == CH_OK) {
        __CPROVER_assert(hash_len <= SRV_COOKIE_HASH_MAX,
                         "the reported hash length fits the buffer the caller supplies");
        __CPROVER_assert(n == 5 + hash_len + SHA256_LEN + SHA256_LEN,
                         "an opened cookie is as long as the suite it names makes it");
    }
}

int main(void) {
    prove_mint();
    prove_open();
    return 0;
}
