// Proves: srv_ticket_seal writes only inside the caller's buffer and
// reports either nothing or the whole ticket, and srv_ticket_open reads
// only inside the bytes it was given, reports one of its two verdicts, and
// hands back an ALPN length the caller's name field holds.
//
// The properties, over unconstrained inputs at the module's real bound.
// Memory safety and absence of UB on both calls, which is what the
// automatic checks discharge. The seal's length contract: 0, or exactly
// SRV_TICKET_LEN, and SRV_TICKET_LEN whenever cap and alpn_len allow it.
// The open's: CH_OK only for exactly SRV_TICKET_LEN bytes whose first is
// SRV_TICKET_VERSION, with alpn_len at most CH_ALPN_NAME_MAX, and a refusal
// that leaves the contents zeroed.
//
// The ticket is at most SRV_TICKET_LEN bytes, which is the real bound: a
// ticket of any other length is refused before the AEAD runs. The open
// case offers one byte more, so the formula covers a ticket that is too
// long as well as every length below it.
//
// What it does not prove, and why. aead_seal and aead_open are contract
// stubs here: they assert what srv_ticket.c must hand them and write an
// unconstrained ciphertext, tag or body. So the formula holds srv_ticket.c
// to the AEAD's contract and reads every body the AEAD could release,
// alpn_len above CH_ALPN_NAME_MAX included, but the round trip -- a sealed
// ticket opens back to what it carried under its own key and no other --
// is not proved here. test/srv_ticket_tests.h tests that and the tamper
// sweep, and aead_harness.c proves the AEAD's framing.
#include "harness.h"

#include <string.h>

uint16_t nondet_u16(void);
uint64_t nondet_u64(void);
int nondet_int(void);

#include "aead.h"

void aead_seal(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
               size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[AEAD_TAG]) {
    __CPROVER_assert(__CPROVER_r_ok(key, AEAD_KEY), "aead_seal: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AEAD_NONCE), "aead_seal: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len), "aead_seal: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "aead_seal: plaintext readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(ct, n), "aead_seal: ciphertext writable");
    __CPROVER_assert(__CPROVER_w_ok(tag, AEAD_TAG), "aead_seal: tag writable");
    fill_nondet(ct, n);
    fill_nondet(tag, AEAD_TAG);
}

int aead_open(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
              size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[AEAD_TAG],
              uint8_t *pt) {
    __CPROVER_assert(__CPROVER_r_ok(key, AEAD_KEY), "aead_open: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AEAD_NONCE), "aead_open: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len), "aead_open: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(ct, n), "aead_open: ciphertext readable");
    __CPROVER_assert(__CPROVER_r_ok(tag, AEAD_TAG), "aead_open: tag readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(pt, n), "aead_open: plaintext writable");
    // A tag either verifies or it does not, and on a mismatch aead.h
    // writes nothing, so only the success arm releases a body.
    if (nondet_int()) {
        fill_nondet(pt, n);
        return 1;
    }
    return 0;
}

#include "srv_ticket.c"

#define TICKET_BUF (SRV_TICKET_LEN + 1)

static uint8_t key[SRV_TICKET_KEY_LEN];
static uint8_t nonce[AEAD_NONCE];
static uint8_t sealed[TICKET_BUF];
static uint8_t ticket[TICKET_BUF];

static void prove_seal(void) {
    fill_nondet(key, sizeof key);
    fill_nondet(nonce, sizeof nonce);
    // Every member through its own type.
    srv_ticket_contents c;
    c.auth_seconds = nondet_u64();
    c.suite = nondet_u16();
    c.alpn_len = nondet_u8();
    fill_nondet(c.alpn, sizeof c.alpn);
    fill_nondet(c.psk, sizeof c.psk);

    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof sealed);

    size_t n = srv_ticket_seal(key, nonce, &c, sealed, cap);

    __CPROVER_assert(n <= cap, "a sealed ticket fits the buffer it was given");
    __CPROVER_assert(n == 0 || n == SRV_TICKET_LEN, "a ticket is SRV_TICKET_LEN bytes or none");
    if (cap >= SRV_TICKET_LEN && c.alpn_len <= CH_ALPN_NAME_MAX) {
        __CPROVER_assert(n == SRV_TICKET_LEN, "SRV_TICKET_LEN always suffices");
        __CPROVER_assert(sealed[0] == SRV_TICKET_VERSION, "the version byte leads the ticket");
    }
}

static void prove_open(void) {
    fill_nondet(key, sizeof key);
    fill_nondet(ticket, sizeof ticket);

    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof ticket);

    srv_ticket_contents c;
    int rc = srv_ticket_open(key, ticket, n, &c);

    __CPROVER_assert(rc == CH_OK || rc == CH_EAUTH, "open answers one of its two verdicts");
    if (rc == CH_OK) {
        __CPROVER_assert(n == SRV_TICKET_LEN, "only a ticket of the one length opens");
        __CPROVER_assert(ticket[0] == SRV_TICKET_VERSION, "only this format's version opens");
        __CPROVER_assert(c.alpn_len <= CH_ALPN_NAME_MAX,
                         "the ALPN length fits the name field the caller reads");
    } else {
        __CPROVER_assert(c.auth_seconds == 0 && c.suite == 0 && c.alpn_len == 0,
                         "a refusal leaves the contents zeroed");
        __CPROVER_assert(c.psk[0] == 0 && c.psk[SHA256_LEN - 1] == 0,
                         "a refusal leaves no PSK behind");
    }
}

int main(void) {
    prove_seal();
    prove_open();
    return 0;
}
