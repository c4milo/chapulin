// libFuzzer harness for webpki_verify_raw_key, the rule a TRUST=webpki
// client with SPKI pins runs on the server's Certificate flight when the
// server chose the RFC 7250 RawPublicKey type (docs/decisions.md 49). The
// input plays the pins and the raw CertificateEntry list:
//   - byte 0, modulo CH_SPKI_PIN_MAX + 1, is the pin count;
//   - that many pins of SHA256_LEN bytes follow it;
//   - the rest is the list. It ends where the input ends, so a read past
//     the list's end reads past the fuzzer's buffer, and AddressSanitizer
//     reports it.
// An input too short for its pins is skipped.
//
// The seed corpus under fuzz/corpus/fuzz_webpki_raw_key holds one input
// per distinct SubjectPublicKeyInfo in test/webpki_auth_vectors.h's raw
// rows and in test/webpki_corpus.h, read as test/diff_webpki_pin.h reads
// them: 27 keys, RSA-2048, RSA-4096, P-256 and P-384. Each is the one
// entry of a list, after one pin, the SHA-256 of that key, so the fuzzer
// starts on the path that copies the key out. The gcs and
// s3.amazonaws.com anchors are RSA-4096 keys of CH_WEBPKI_SPKI_MAX bytes.
// One more seed, entry_over_spki_max, carries CH_SPKI_PIN_MAX pins and
// one entry a byte past CH_WEBPKI_SPKI_MAX, so the fuzzer also starts on
// the refusal at the cap with every pin in place. Every seed is shorter
// than 4096 bytes, so libFuzzer's default limit of 4096 bytes sets how
// long an input may grow: room for every pin and seven entries at the
// cap. The harness asserts nothing beyond what AddressSanitizer checks.
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
    webpki_leaf_info key;
    memset(&cfg, 0, sizeof cfg);
    memset(&key, 0, sizeof key);
    cfg.spki_pins = data + 1;
    cfg.spki_pin_count = pin_count;
    const uint8_t *list = data + 1 + pins_len;
    size_t list_len = size - 1 - pins_len;
    // The caller's seed, per the webpki_pin.h contract.
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    (void)webpki_verify_raw_key(list, list_len, &cfg, &key, &alert);
    return 0;
}
