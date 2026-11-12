#!/usr/bin/env python3
"""Convert Wycheproof's suites that hold private keys into a C header for
test/wycheproof_jws_sign_test.c, which holds ch_jws_sign to them.

Usage: gen_wycheproof_jws_sign.py <wycheproof-checkout> <output.h>

The suites are in testvectors_v1/ at the commit tools/toolchain.env pins,
the checkout make wycheproof already fetches:

- rsa_pkcs1_2048_sig_gen_test.json and its 1024, 1536, 3072 and 4096
  twins: RSASSA-PKCS1-v1_5 signature generation. Each SHA-256 group holds
  a private key as a JWK, and each case a message and its signature;
- json_web_signature_test.json: whole tokens in JWS Compact
  Serialization, with the private JWK that signed the valid ones.

An RS256 signature is a function of the key and the input. So a row
with want 1 names the bytes ch_jws_sign must write. A row with want 0
names a key ch_jws_sign must refuse:

- a modulus under 2048 bits, RFC 7518 section 3.3's floor;
- a public exponent other than 65537. ch_rsa_priv holds no exponent, and
  each signer checks its signature under 65537, so no signature of such a
  key leaves.

A token row comes from a valid token under a private JWK that a caller
would sign with: its "use" is absent or "sig", its "key_ops" is absent or
holds "sign", and its "alg" is RS256 for an RSA key or ES256 for a P-256
key. The input is the token's first two parts. For RS256 the token's
third part is the signature ch_jws_sign must write. An ES256 signature
takes fresh noise, so the test signs the input under the JWK's d and
verifies the result under the JWK's x and y.

Wycheproof's Ed25519 suite holds public keys alone, so it gives no row
here: RFC 8032's vectors in test/jws_sign_test.c hold the EdDSA signer.

The script writes a key in ch_rsa_priv's form: n and d in the modulus's
length, and p, q, dp, dq and qinv in half of it, each padded on the left
with zero bytes. The suites' keys with the public exponent 3 have one
prime twice as long as the other, and ch_rsa_priv has no form for such
primes. The script writes zero bytes for the five values of such a key,
as rsa_key.h permits for a caller that signs with n and d alone.

The output lands in bin/, never in the tree, as gen_wycheproof.py's
does.
"""

import base64
import json
import sys
from pathlib import Path

SIG_GEN_BITS = (1024, 1536, 2048, 3072, 4096)
MODULUS_BITS_MIN = 2048
PUBLIC_EXPONENT = 65537


def c_bytes(data):
    return ", ".join("0x%02x" % b for b in data) if data else "0"


def unb64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def padded(value, length):
    """The big-endian value in length bytes, padded on the left."""
    value = value.lstrip(b"\x00")
    assert len(value) <= length
    return bytes(length - len(value)) + value


class Writer:
    def __init__(self):
        self.blobs = []
        self.keys = []

    def blob(self, data):
        name = "wp_jws_sign_blob_%d" % len(self.blobs)
        self.blobs.append("static const uint8_t %s[%d] = {%s};" % (name, max(len(data), 1),
                                                                    c_bytes(data)))
        return name

    def rsa_key(self, jwk):
        """Adds the private JWK as one row of ch_rsa_priv's fields and
        returns the row's index."""
        n = unb64url(jwk["n"]).lstrip(b"\x00")
        n_len = len(n)
        assert n_len % 2 == 0
        fields = [self.blob(n), self.blob(padded(unb64url(jwk["d"]), n_len))]
        crt = [unb64url(jwk[name]).lstrip(b"\x00") for name in ("p", "q", "dp", "dq", "qi")]
        if len(crt[0]) != n_len // 2 or len(crt[1]) != n_len // 2:
            crt = [b""] * 5
        fields += [self.blob(padded(value, n_len // 2)) for value in crt]
        self.keys.append("    {%s, %d}," % (", ".join(fields), n_len))
        return len(self.keys) - 1


def for_signing(jwk, alg):
    """Whether a caller would sign under alg with this private JWK (RFC
    7517 sections 4.2, 4.3 and 4.4)."""
    return (jwk.get("use") in (None, "sig")
            and (jwk.get("key_ops") is None or "sign" in jwk["key_ops"])
            and jwk.get("alg") == alg)


def main():
    src, out = Path(sys.argv[1]) / "testvectors_v1", Path(sys.argv[2])
    w = Writer()
    rsa_cases = []
    es256_cases = []

    def add_rsa(suite, tc_id, key, msg, sig, want):
        rsa_cases.append('    {"%s", %d, %d, %s, %d, %s, %d, %d},'
                         % (suite, tc_id, key, w.blob(msg), len(msg), w.blob(sig), len(sig), want))

    for bits in SIG_GEN_BITS:
        name = "rsa_pkcs1_%d_sig_gen" % bits
        suite = json.load(open(src / (name + "_test.json")))
        for group in suite["testGroups"]:
            if group["sha"] != "SHA-256":
                continue
            exponent = int(group["privateKey"]["publicExponent"], 16)
            want = 1 if bits >= MODULUS_BITS_MIN and exponent == PUBLIC_EXPONENT else 0
            key = w.rsa_key(group["privateKeyJwk"])
            for test in group["tests"]:
                # Wycheproof marks a case acceptable only for a weak key.
                assert (test["result"] == "valid") == (want == 1), test["tcId"]
                add_rsa(name, test["tcId"], key, bytes.fromhex(test["msg"]),
                        bytes.fromhex(test["sig"]), want)

    skipped = 0
    suite = json.load(open(src / "json_web_signature_test.json"))
    for group in suite["testGroups"]:
        jwk = group.get("private") or {}
        valid = [test for test in group["tests"] if test["result"] == "valid"]
        rsa = jwk.get("kty") == "RSA" and for_signing(jwk, "RS256")
        p256 = jwk.get("kty") == "EC" and jwk.get("crv") == "P-256" and for_signing(jwk, "ES256")
        if not rsa and not p256:
            skipped += len(valid)
            continue
        if rsa:
            assert int.from_bytes(unb64url(jwk["e"]), "big") == PUBLIC_EXPONENT
            key = w.rsa_key(jwk)
        else:
            d = w.blob(padded(unb64url(jwk["d"]), 32))
            public = w.blob(padded(unb64url(jwk["x"]), 32) + padded(unb64url(jwk["y"]), 32))
        for test in valid:
            header, payload, signature = test["jws"].split(".")
            signing_input = (header + "." + payload).encode()
            assert json.loads(unb64url(header))["alg"] == jwk["alg"], test["tcId"]
            if rsa:
                add_rsa("json_web_signature", test["tcId"], key, signing_input,
                        unb64url(signature), 1)
            else:
                es256_cases.append("    {%d, %s, %s, %s, %d},"
                                   % (test["tcId"], d, public, w.blob(signing_input),
                                      len(signing_input)))

    lines = ["// Generated by test/gen_wycheproof_jws_sign.py from Wycheproof's suites.",
             "#ifndef CH_WYCHEPROOF_JWS_SIGN_VECTORS_H",
             "#define CH_WYCHEPROOF_JWS_SIGN_VECTORS_H", "",
             "#include <stddef.h>", "#include <stdint.h>", ""]
    lines += w.blobs
    lines += ["", "// A private RSA key in ch_rsa_priv's fields: n and d are n_len bytes, and",
              "// the other five are n_len / 2 bytes.",
              "static const struct {", "    const uint8_t *n;", "    const uint8_t *d;",
              "    const uint8_t *p;", "    const uint8_t *q;", "    const uint8_t *dp;",
              "    const uint8_t *dq;", "    const uint8_t *qinv;", "    size_t n_len;",
              "} wp_jws_sign_rsa_keys[] = {"]
    lines += w.keys
    lines += ["};", "",
              "// want is 1 when ch_jws_sign must write sig, and 0 when it must refuse the",
              "// key (test/gen_wycheproof_jws_sign.py).",
              "static const struct {", "    const char *suite;", "    int tc_id;",
              "    size_t key;", "    const uint8_t *msg;", "    size_t msg_len;",
              "    const uint8_t *sig;", "    size_t sig_len;", "    int want;",
              "} wp_jws_sign_rsa_cases[] = {"]
    lines += rsa_cases
    lines += ["};", "",
              "// d is the 32-byte scalar, and key is X then Y, the form ch_jws_verify takes.",
              "static const struct {", "    int tc_id;", "    const uint8_t *d;",
              "    const uint8_t *key;", "    const uint8_t *input;", "    size_t input_len;",
              "} wp_jws_sign_es256_cases[] = {"]
    lines += es256_cases
    lines += ["};", "", "#define WP_JWS_SIGN_TOKENS_SKIPPED %d" % skipped, "", "#endif", ""]
    out.write_text("\n".join(lines))
    wanted = sum(1 for case in rsa_cases if case.endswith(" 1},"))
    print("gen_wycheproof_jws_sign: %d RS256 signatures, %d RS256 cases of a key with no "
          "signer, %d ES256 inputs, %d valid tokens of a key with no signer"
          % (wanted, len(rsa_cases) - wanted, len(es256_cases), skipped))


if __name__ == "__main__":
    main()
