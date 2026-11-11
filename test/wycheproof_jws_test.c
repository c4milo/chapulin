// ch_jws_verify and ch_base64url_decode against Wycheproof: every case of
// ecdsa_secp256r1_sha256_p1363_test.json under ES256, of the three
// rsa_signature_*_sha256_test.json suites under RS256 and of
// ed25519_test.json under EdDSA, and every token of
// json_web_signature_test.json whose key ch_jws_verify can take. A valid
// case must verify and an invalid one must not. A case Wycheproof leaves
// to the implementation may do either. The header is
// bin/wycheproof_jws_vectors.h, which make wycheproof writes, and
// test/gen_wycheproof_jws.py states what the script decides for a token
// and what the calls here decide.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "jws.h"
#include "wycheproof_jws_vectors.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#define COUNT(a) (sizeof(a) / sizeof(a)[0])

typedef struct {
    size_t valid;
    size_t invalid;
    size_t acceptable;
    size_t acceptable_taken;
    size_t failures;
} tally;

// Counts one case of kind against what the calls did.
static void count(tally *t, int kind, int accepted, const char *what, int tc_id) {
    if (kind == 2) {
        t->acceptable++;
        t->acceptable_taken += (size_t)accepted;
        return;
    }
    t->valid += (size_t)(kind == 1);
    t->invalid += (size_t)(kind == 0);
    if (accepted != kind) {
        printf("FAIL Wycheproof %s tcId %d: %s\n", what, tc_id,
               kind ? "a valid signature was refused" : "an invalid signature verified");
        t->failures++;
    }
}

// A caller's check of one compact token: two '.' characters, a signature
// part that ch_base64url_decode takes, and a signature that verifies over
// the first two parts. The caller has read the header already.
static int token_verifies(size_t i) {
    const char *token = wp_jws_tokens[i].token;
    size_t token_len = wp_jws_tokens[i].token_len;
    size_t dots = 0;
    size_t second = 0;
    for (size_t at = 0; at < token_len; at++) {
        if (token[at] == '.') {
            dots++;
            second = at;
        }
    }
    if (dots != 2) {
        return 0;
    }
    uint8_t sig[CH_JWS_SIG_LEN_MAX + 3];
    size_t sig_len = 0;
    if (ch_base64url_decode((const uint8_t *)token + second + 1, token_len - second - 1, sig,
                            sizeof sig, &sig_len) != CH_OK) {
        return 0;
    }
    return ch_jws_verify(wp_jws_tokens[i].algorithm, wp_jws_tokens[i].key,
                         wp_jws_tokens[i].key_len, (const uint8_t *)token, second, sig,
                         sig_len) == CH_OK;
}

int main(void) {
    tally cases = {0};
    for (size_t i = 0; i < COUNT(wp_jws_cases); i++) {
        int accepted = ch_jws_verify(wp_jws_cases[i].algorithm, wp_jws_cases[i].key,
                                     wp_jws_cases[i].key_len, wp_jws_cases[i].msg,
                                     wp_jws_cases[i].msg_len, wp_jws_cases[i].sig,
                                     wp_jws_cases[i].sig_len) == CH_OK;
        count(&cases, wp_jws_cases[i].kind, accepted, wp_jws_cases[i].suite, wp_jws_cases[i].tc_id);
    }
    tally tokens = {0};
    size_t other = 0;
    size_t caller_refused = 0;
    for (size_t i = 0; i < COUNT(wp_jws_tokens); i++) {
        int accepted = wp_jws_tokens[i].caller_ok && token_verifies(i);
        other += (size_t)wp_jws_tokens[i].other;
        caller_refused += (size_t)!wp_jws_tokens[i].caller_ok;
        count(&tokens, wp_jws_tokens[i].kind, accepted, "json_web_signature",
              wp_jws_tokens[i].tc_id);
    }
    if (cases.failures != 0 || tokens.failures != 0) {
        return 1;
    }
    printf("Wycheproof JWS: %zu signature cases, %zu valid, %zu invalid and %zu acceptable, of "
           "which %zu verified; every verdict matches\n",
           COUNT(wp_jws_cases), cases.valid, cases.invalid, cases.acceptable,
           cases.acceptable_taken);
    printf("Wycheproof JWS: %zu tokens, %zu valid and %zu invalid; the caller's check of the "
           "JWK and the header refused %zu, and the calls judged the rest; %zu true signatures "
           "of an algorithm with no call did not verify as RS256; %d tokens of a key type with "
           "no call were not run\n",
           COUNT(wp_jws_tokens), tokens.valid, tokens.invalid, caller_refused, other,
           WP_JWS_TOKENS_SKIPPED);
    return 0;
}
