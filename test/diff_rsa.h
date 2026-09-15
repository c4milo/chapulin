// RSASSA-PSS differential section: the Lean spec mints a signature
// (rsa_sign) over a random digest with a fixed test keypair, and the C
// verifier must accept it, reject a copy with one mutated hash byte,
// and reject three one-byte signature flips (trailer position, padding
// region, top byte).
// The spec's own verifier is cross-checked on the same inputs, so the
// section still exercises the oracle before rsa.[ch] land. The C side
// only ever verifies; the private exponent stays on the spec side.
//
// The signature crosses the pipe as raw k-octet hex (no DER: PKCS #1
// PSS signatures are a plain octet string, unlike ECDSA). Three keys —
// 2048, 3072 and 4096-bit moduli — rotate so every size a build admits
// is tested: the spec verifies any modulus, and the C admits up to
// CH_RSA_MODULUS_MAX bytes (rsa.h), 512 only when a build sets it there,
// so bin/diff builds with -DCH_RSA_MODULUS_MAX=512 (the Makefile's
// RSA_WIDE_DEF) and diff_rsa_check_c stops on a build whose bound is
// below a sampled modulus.
// Included by test/diff_test.c after diff_driver.h (single translation unit).
#ifndef CH_DIFFRSA_H
#define CH_DIFFRSA_H

#ifdef __has_include
#if __has_include("rsa.h")
#include "rsa.h"
#define DIFF_HAVE_RSA 1
#endif
#endif

// Fixed public exponent for every test key (F4).
#define DIFF_RSA_E 65537
// Largest modulus the RSA sections sign under, in bytes (RSA-4096).
#define DIFF_RSA_N_MAX 512
// Rows per section: a multiple of the three moduli, and of the six
// modulus-and-digest pairings diff_rsa_pkcs1.h rotates through.
#define DIFF_RSA_ROWS 48

// 2048-bit test key: modulus and private exponent, big-endian hex.
static const char *const diff_rsa_n2048 =
    "be337a9001c83d0600ee3bbca7da1b6e0d15788328639c9f365c73f77abd9883"
    "299c22b03501f5b7010161d19630cdae706c0f9e6b91af6d5426db74348e8882"
    "dd70cf69662ce8a39613dfe7619a964a58bc1a3b1a258ce97b53b62f9c7bf275"
    "183a9330294624b81b31a39884c74fc0d3f591df511f533cb25fcce3de95b6b2"
    "1c3eea8f275098ef0f2aec983b81c15266f8dd05c638067b24129de3981569fc"
    "4f735f2c0edac01d9de3d7009f8aef5601ff4769f18431796d0ffdfccf530f81"
    "8a5bfb273f6da386aade6beafa38bdd42deeb5305a1736aa88e060f577757a54"
    "1afd0d725b42ec863b58c525c6f29debeb40158b55834cf2ca868443a6f9928f";
static const char *const diff_rsa_d2048 =
    "35fb1645d8bba3d6185d84c6be3cc09c334a6cb18cbcf8ae971716329ebb4095"
    "b9317f06d38482e03580d6ea4cddfd020d161e38affee0f2fe7728c18a4909a5"
    "5a83b1da100d9ed90eb7054cfdfe89b9000622cbb35804ee1efa5b32980ef579"
    "162f49a6d98ff6cbe9abe4ea5c84d4b5bd726cbc1ca1ef55c2aa3dd44e4fdf51"
    "9f7e8e20cb9ce85c1c70557e2f7b3d5d98c16775cc688eb6c79980a34edf2860"
    "b577607bdff218b35f2740def79fcb4d530e05714ded3bc8f75896a97621ef60"
    "58fadf1cb2dd9b0894613f2e8b67c68ef330f0c72cb62edc4bccdb738c09a25d"
    "f87d4d7aec1f8972be2f09c9c8a595c8eedfad974628b3f891fe28c2dcdd2b81";

// 3072-bit test key: modulus and private exponent, big-endian hex.
static const char *const diff_rsa_n3072 =
    "e9d26f221079cc18141338902c501646e0ebfa2d892c7d14ceebef13197041b0"
    "e370510fa9f7db7db28cb25c9d8ba8c26488e39274380d10ec07cf389fd28436"
    "57b93cd72fd4b7ac61d5943679263e8c67b918704ff60177f8c3c66cd9639785"
    "7a20b83f837ab0f9037f23560ec93a8d2292597209148a1d355680f72323e282"
    "b37c199032f593103804c5ca28f515b4bcc3af8021f789181d0c9831135469a0"
    "ceb0d19b1c63cd3cc3c0bc2cc2a4285961f141d869436b53db609bc84968c509"
    "d9f01da596f80b2169ac41f196f28431bb13a24ad54d29ef991ed6eaf6f7de4d"
    "e4dad9fefe88fdf9ce2d0058627de3f9005c70a00ca7a151d354ff4829307ac9"
    "18deea6699a45532e031cceb47e0f2c834e242cb0e997417499345ef23ee074d"
    "d4fc46da69b3c05d9c644b429f0d7233deb151264d42546a9b67d22c78a5c541"
    "3b725a403991191261513926e9072d762e6b584369ab9a85cc1ed0fa2a295756"
    "a3ac761066876c7e40d5e44042a731d25343c3c201ec5225c97b1367397d7fc3";
static const char *const diff_rsa_d3072 =
    "0c8abdc1faac4326fa275b1e05f7cdc4c38524dd9316bb26db3fe08a5fba466b"
    "c73cb111c15b8ad4753802cbe0fa2aca87e5fd29a53e3f1a81ee9bf8e79467d9"
    "c5097f4548f584b1f9c021111847d58c66769139afb051bd2e5a21fc98b48a33"
    "7357949fce324de7d828d656640dfb2c0832081b8bcd243e1381ae57e89f4b79"
    "189e36d37b48478e7e7d686142f7d27ae807d4696fbe52b0e3c3572e8560e916"
    "e26a02f43fa8ed7602f205a5f3a8268494dd02067faef41a2d66eddee7c12240"
    "736e1b67ea830993240b8189570a84ed4e4e17c6024f9962ca684c7ed8604f53"
    "cd115bffe313d221ae7fd6ffa3cc5dfb7c33f0b54767cca9e30055d888736b4a"
    "68d38273b1291f6872769197a22de6cbc00b0710466be4154eeb2cfb42c5ff4f"
    "7d9aa5873806738e1aa7bc9793510a5a427de560c93dd9b3dadb6931cb097b69"
    "0651cbe0ac50e1669c2d6d6958340ca6193a43c4b02f3d626f99f525c6826475"
    "11f97ddf33f1e701fad583c11eb8fbbf75c5a4929f78a706676408c4a4dfde81";

// 4096-bit test key: modulus and private exponent, big-endian hex. The
// modulus is DIFF_RSA_N_MAX bytes, the top of the webpki build's gate.
static const char *const diff_rsa_n4096 =
    "bd6084cdd3a650bf010d72921a82bca1f919505356fc875a21d7b504fe1cf599"
    "adcaeaf7ef4ef24953bd54f6b871c0db35e489e2ecb482205048ed9be07f6659"
    "0830c94ed64009a99a3d5d53ac29d4eff014fc6ea576162f835d5ffc539c2ba8"
    "3514a96414959593984adc02a5f57e3d4dd56877627b8c303f25beafcb03d827"
    "6b7f30f372569b8f277f324530801ed2fa81f0e44101ef11903ed0d15ba3f99b"
    "5ccc31d2c8280696ab037217f8fce614378793178912122b518d4d98c69637e3"
    "2ed1e7bd870c897ef06a811427998ac2b1e0ad70a67fe6905433c8798e70e162"
    "fd8203217c9656954bde22d96297e9ed6376a8e17744c67718264ec58aa6e2f1"
    "fec3de8819721712a74029e562f69e4995cb65781a14b1455f8d4c9b6b498c16"
    "e9410020c13d018b7adc19c6fb38e3fe628cd6384efd9ae83185d26fd08a1899"
    "a04898a8ab9de7cacfd9efe4ede205b1c6c2f01a468dde1141bce3a2fa52e4fb"
    "021c4af11869e10ab8c0c3bd44985a23d99c95fb9dc7cb50dd167bb440e3a2be"
    "bb7b0c54bed2c4a92ca8d04126e3ef6655cd72d68b7a3862aeaf8c2e8950806b"
    "19c41f5d0f36cb758b39ba3ba7f3181c12fe6b3183016bec00cded237816b435"
    "0ecd1b67150b1f37a36f2e08f9ad765af87ba7de0ac45a3b0b1bcf2e3541b901"
    "32575d2dc53ec1c9173fae1c6b6d7114e257477ce77db120fd0aff630261548f";
static const char *const diff_rsa_d4096 =
    "1dc0e25cac44d47ee3481cee138d8d86d7ea403d37ccd3e9e1fdfab4dec53cae"
    "79285e790c77978829c89f66bc07ddf312fe9078bf692f8b557c7fc873cc7b0f"
    "6b42aefe31ef3c6abc8efe46127b3d620d3db42e20d4f2c60d9a4810642fd9de"
    "c2fd8cb79551add47df83fa4dd8a3a86a089f25b2a1ff075f6c094106e91c60e"
    "3b776fab70156764bb21e2e0b804092916040062fc4bb4d1f4f074427b116ce5"
    "6f53ada848f0f0f2b9ca557755694bda1ff759b18d999c9283179e4f6ddeaac7"
    "de27f5d99ddee70e089bd322902e317cf166dec3ca2fb77bdef4312a82a9fd8a"
    "08a66548dced89e0f45b36ed21ee6d9471d772252a65fb2b39a21b278791e77f"
    "34aded3fd9b4cd6e9998364839b11c5bf6ef6e0549a78bd8dabd27c8a25d7fb3"
    "ee30a5f5d8000d524dae2d23613044406e0d66a66f3924f93dfd3b53cce5c132"
    "f82f6b41941cbcc0024704d625d193c84d5e9fb4f1966f3be4ff8b84d40abe65"
    "65dd45334cb7dd33a78678267aae312276c765a9e870b45f6e239c715c61b766"
    "8d6e6386b2e1e16064637a3bc233286dbefe725a084619d930fc0386f77f790d"
    "c89dea3d021640924297f3ca6ce451dec16045573a5950d2fd7a0187a94d060e"
    "6d44ff114317a8fcd01dafb653e1495c39b9f0a6ad220e23e923734b4f04eb2c"
    "d98d882b14249480e43ccfd2f91cfc0f3cd94b5e078d4b9bad4ba1f1f0131291";

// The three keys in rotation order; both RSA sections index them by row.
static const char *const diff_rsa_moduli[3] = {diff_rsa_n2048, diff_rsa_n3072, diff_rsa_n4096};
static const char *const diff_rsa_private_exponents[3] = {diff_rsa_d2048, diff_rsa_d3072,
                                                          diff_rsa_d4096};

#ifdef DIFF_HAVE_RSA
// Runs the C verifier over one minted row: accept the good signature,
// reject the mutated hash, and reject three one-byte signature flips.
static void diff_rsa_check_c(const char *n_hex, size_t n_len, const uint8_t *hash,
                             const uint8_t *bad, const char *sig_hex, size_t sig_len,
                             const char *hash_hex) {
    uint8_t n[DIFF_RSA_N_MAX];
    uint8_t sig[DIFF_RSA_N_MAX];
    if (n_len > sizeof n || !hex_decode(n, n_hex, n_len) || !hex_decode(sig, sig_hex, sig_len)) {
        die("rsa: malformed key or signature");
    }
    // A build whose bound is below the sampled modulus would refuse the
    // row at the size gate and report a divergence the spec cannot see;
    // the domains must agree before a verdict means anything. A runtime
    // check rather than a static one, because lint-tidy compiles this
    // driver without the define.
    if (n_len > CH_RSA_MODULUS_MAX) {
        die("rsa: CH_RSA_MODULUS_MAX is below the sampled modulus; build with "
            "-DCH_RSA_MODULUS_MAX=512");
    }
    if (rsa_pss_verify(n, n_len, hash, sig, sig_len) != 1) {
        (void)fprintf(stderr, "diff mismatch: C rsa_pss_verify rejected\n  h: %s\n", hash_hex);
        exit(1);
    }
    if (rsa_pss_verify(n, n_len, bad, sig, sig_len) != 0) {
        (void)fprintf(stderr, "diff mismatch: C rsa_pss_verify accepted a mutated hash\n  h: %s\n",
                      hash_hex);
        exit(1);
    }

    // A one-byte signature flip must be rejected too. The mutated
    // hash above only exercises the final compare; a signature flip
    // scrambles the whole recovered EM through RSAVP1, so these
    // exercise the earlier reject branches (the s >= n gate, the
    // trailer, the top bits, the padding walk) instead. Flip at the
    // trailer position (last byte), inside the padding region (EM
    // is PS || 0x01 || salt || H || 0xbc, so PS spans the low
    // n_len - 66 bytes), and at the top byte.
    size_t flip[3];
    flip[0] = sig_len - 1;
    flip[1] = 1 + rng_below(n_len - 67);
    flip[2] = 0;
    for (size_t j = 0; j < 3; j++) {
        uint8_t bad_sig[DIFF_RSA_N_MAX];
        memcpy(bad_sig, sig, sig_len);
        bad_sig[flip[j]] ^= (uint8_t)(1 + rng_below(255));
        if (rsa_pss_verify(n, n_len, hash, bad_sig, sig_len) != 0) {
            (void)fprintf(stderr,
                          "diff mismatch: C rsa_pss_verify accepted a mutated signature\n"
                          "  flipped byte: %zu\n  h: %s\n",
                          flip[j], hash_hex);
            exit(1);
        }
    }
    comparisons += 5;
}
#endif

static void diff_rsa(void) {
#ifndef DIFF_HAVE_RSA
    (void)fprintf(stderr, "diff: rsa: spec-only pass, rsa.h not present yet\n");
#endif
    for (int i = 0; i < DIFF_RSA_ROWS; i++) {
        // Rotate the three moduli across iterations.
        const char *n_hex = diff_rsa_moduli[i % 3];
        const char *d_hex = diff_rsa_private_exponents[i % 3];
        size_t n_len = strlen(n_hex) / 2;

        uint8_t hash[32];
        uint8_t salt[32];
        rng_fill(hash, sizeof hash);
        rng_fill(salt, sizeof salt);
        char hash_hex[65];
        char salt_hex[65];
        (void)hex_encode(hash_hex, hash, sizeof hash);
        (void)hex_encode(salt_hex, salt, sizeof salt);

        // The spec signs the digest under the fixed salt; the reply is
        // the raw k-octet signature as hex. The command carries n and d
        // as hex, then the exponent, the salt and the hash; the reply
        // buffer holds the hex, the newline and the terminator.
        char cmd[4 * DIFF_RSA_N_MAX + 256];
        (void)snprintf(cmd, sizeof cmd, "rsa_sign %s %s %d %s %s", n_hex, d_hex, DIFF_RSA_E,
                       salt_hex, hash_hex);
        char sig_hex[2 * DIFF_RSA_N_MAX + 2];
        query(cmd, sig_hex, sizeof sig_hex);
        size_t sig_len = strlen(sig_hex) / 2;
        if (sig_len != n_len || strlen(sig_hex) % 2 != 0) {
            die("rsa_sign: malformed spec response");
        }

        // A one-byte flip of the digest must be rejected everywhere.
        uint8_t bad[32];
        memcpy(bad, hash, sizeof bad);
        bad[rng_below(sizeof bad)] ^= (uint8_t)(1 + rng_below(255));
        char bad_hex[65];
        (void)hex_encode(bad_hex, bad, sizeof bad);

        // Cross-check the spec's own verifier on the minted signature.
        (void)snprintf(cmd, sizeof cmd, "rsa_verify %s %d %s %s", n_hex, DIFF_RSA_E, hash_hex,
                       sig_hex);
        expect(cmd, "1");
        (void)snprintf(cmd, sizeof cmd, "rsa_verify %s %d %s %s", n_hex, DIFF_RSA_E, bad_hex,
                       sig_hex);
        expect(cmd, "0");

#ifdef DIFF_HAVE_RSA
        diff_rsa_check_c(n_hex, n_len, hash, bad, sig_hex, sig_len, hash_hex);
#endif
    }
}

#endif
