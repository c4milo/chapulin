// libFuzzer harness for webpki_verify_leaf_pin, the rule a TRUST=webpki
// client with SPKI pins and no anchors runs on the server's Certificate
// flight before authentication (docs/decisions.md 65). The input plays
// the pins and the raw CertificateEntry list:
//   - byte 0, modulo CH_SPKI_PIN_MAX + 1, is the pin count;
//   - that many pins of SHA256_LEN bytes follow it;
//   - the rest is the list. It ends where the input ends, so a read past
//     the list's end reads past the fuzzer's buffer, and AddressSanitizer
//     reports it.
// An input too short for its pins is skipped.
//
// The seed corpus under fuzz/corpus/fuzz_webpki_leaf_pin holds one input
// per distinct CertificateEntry list in test/webpki_corpus.h: the 21 lists
// of the minted chains, leaf_over_cert_max's 5,558-byte leaf included, and
// the 4 lists of the captures. One more seed, r2_leaf_at_cap, is a list of
// one entry: the r2 leaf rebuilt at CH_WEBPKI_LEAF_PIN_CERT_MAX bytes, as
// test/webpki_leaf_pins.h rebuilds it. libFuzzer generates no input longer
// than its longest seed, so that seed is what lets an input carry an entry
// at the cap. Each seed carries one pin: the SHA-256 of its leaf's
// SubjectPublicKeyInfo as webpki_read_certificate_key reads it, so the
// fuzzer starts on the path that copies the key out, or 32 bytes of 0x5a
// where that reader refuses the leaf. The harness asserts nothing beyond
// what the sanitizers check: no crash, no UB.
#include <stdint.h>
#include <string.h>

#include "cfg.h"
#include "handshake_message.h"
#include "sha256.h"
#include "webpki_pin.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }
    size_t pin_count = data[0] % (CH_SPKI_PIN_MAX + 1);
    size_t pins_len = pin_count * SHA256_LEN;
    if (size - 1 < pins_len) {
        return 0;
    }
    ch_cfg cfg;
    webpki_leaf_info leaf;
    memset(&cfg, 0, sizeof cfg);
    memset(&leaf, 0, sizeof leaf);
    cfg.spki_pins = data + 1;
    cfg.spki_pin_count = pin_count;
    const uint8_t *list = data + 1 + pins_len;
    size_t list_len = size - 1 - pins_len;
    // The caller's seed, per the webpki_pin.h contract.
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    (void)webpki_verify_leaf_pin(list, list_len, &cfg, &leaf, &alert);
    return 0;
}
