// RSASSA-PSS differential section: the Lean spec mints a signature
// (rsa_sign) over a random digest with a fixed test keypair, and the C
// verifier must accept it and reject a copy with one mutated hash byte.
// The spec's own verifier is cross-checked on the same inputs, so the
// section still exercises the oracle before rsa.[ch] land. The C side
// only ever verifies; the private exponent stays on the spec side.
//
// The signature crosses the pipe as raw k-octet hex (no DER: PKCS #1
// PSS signatures are a plain octet string, unlike ECDSA). Two keys, a
// 2048-bit and a 3072-bit modulus, alternate so both moduli are tested.
// Included by test/diff.c after diffdrv.h (single translation unit).
#ifndef CH_DIFFRSA_H
#define CH_DIFFRSA_H

#ifdef __has_include
#if __has_include("rsa.h")
#include "rsa.h"
#define DIFF_HAVE_RSA 1
#endif
#endif

// Fixed public exponent for both test keys (F4).
#define DIFF_RSA_E 65537

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

static void diff_rsa(void) {
#ifndef DIFF_HAVE_RSA
    (void)fprintf(stderr, "diff: rsa: spec-only pass, rsa.h not present yet\n");
#endif
    for (int i = 0; i < 40; i++) {
        // Alternate the two moduli across iterations.
        const char *nh = (i & 1) ? diff_rsa_n3072 : diff_rsa_n2048;
        const char *dh = (i & 1) ? diff_rsa_d3072 : diff_rsa_d2048;
        size_t nlen = strlen(nh) / 2;

        uint8_t hash[32];
        uint8_t salt[32];
        rng_fill(hash, sizeof hash);
        rng_fill(salt, sizeof salt);
        char hh[65];
        char sh[65];
        (void)hex_enc(hh, hash, sizeof hash);
        (void)hex_enc(sh, salt, sizeof salt);

        // The spec signs the digest under the fixed salt; the reply is
        // the raw k-octet signature as hex.
        char cmd[2048];
        (void)snprintf(cmd, sizeof cmd, "rsa_sign %s %s %d %s %s", nh, dh, DIFF_RSA_E, sh, hh);
        char sigh[1024];
        query(cmd, sigh, sizeof sigh);
        size_t siglen = strlen(sigh) / 2;
        if (siglen != nlen || strlen(sigh) % 2 != 0) {
            die("rsa_sign: malformed spec response");
        }

        // A one-byte flip of the digest must be rejected everywhere.
        uint8_t bad[32];
        memcpy(bad, hash, sizeof bad);
        bad[rng_below(sizeof bad)] ^= (uint8_t)(1 + rng_below(255));
        char bh[65];
        (void)hex_enc(bh, bad, sizeof bad);

        // Cross-check the spec's own verifier on the minted signature.
        (void)snprintf(cmd, sizeof cmd, "rsa_verify %s %d %s %s", nh, DIFF_RSA_E, hh, sigh);
        expect(cmd, "1");
        (void)snprintf(cmd, sizeof cmd, "rsa_verify %s %d %s %s", nh, DIFF_RSA_E, bh, sigh);
        expect(cmd, "0");

#ifdef DIFF_HAVE_RSA
        uint8_t n[384];
        uint8_t sig[384];
        if (nlen > sizeof n || !hex_dec(n, nh, nlen) || !hex_dec(sig, sigh, siglen)) {
            die("rsa: malformed key or signature");
        }
        if (rsa_pss_verify(n, nlen, hash, sig, siglen) != 1) {
            (void)fprintf(stderr, "diff mismatch: C rsa_pss_verify rejected\n  h: %s\n", hh);
            exit(1);
        }
        if (rsa_pss_verify(n, nlen, bad, sig, siglen) != 0) {
            (void)fprintf(stderr,
                          "diff mismatch: C rsa_pss_verify accepted a mutated hash\n  h: %s\n", hh);
            exit(1);
        }
        comparisons += 2;
#endif
    }
}

#endif
