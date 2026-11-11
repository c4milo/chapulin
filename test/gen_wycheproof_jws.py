#!/usr/bin/env python3
"""Convert Wycheproof's suites for a JWS check into a C header for
test/wycheproof_jws_test.c.

Usage: gen_wycheproof_jws.py <wycheproof-checkout> <output.h>

The suites are in testvectors_v1/ at the commit tools/toolchain.env pins,
the checkout make wycheproof already fetches:

- ecdsa_secp256r1_sha256_p1363_test.json: ECDSA P-256 with the signature
  as R then S, the form of JWS's ES256 (RFC 7518 section 3.4);
- rsa_signature_2048_sha256_test.json and its 3072 and 4096 twins:
  RSASSA-PKCS1-v1_5 with SHA-256, JWS's RS256;
- ed25519_test.json: JWS's EdDSA;
- json_web_signature_test.json: whole tokens in JWS Compact
  Serialization, with the JWK of the key.

Each case of the first three is a key, a message, a signature and a
verdict. The message is the JWS Signing Input ch_jws_verify takes. A key
is written in ch_jws_verify's form: RFC 3110's for RSA, X then Y for
P-256, and the 32 bytes for Ed25519.

A token case is a JWK and a token. ch_jws_verify takes a key's bytes and
reads no JSON, so jws.h gives the JWK and the token's header to the
caller. This script does the caller's part, and caller_ok is 1 when all
of it holds:

- the JWK is for signatures: its "use" is absent or "sig", and its
  "key_ops" is absent or holds "verify" (RFC 7517 sections 4.2 and 4.3);
- the JWK's "alg" is absent, or is the one algorithm chapulin has for the
  key's type, RS256 for an RSA key and ES256 for a P-256 key (RFC 7517
  section 4.4). A key for PS256 or RS384 has no call;
- the token has three parts, and its first part is canonical base64url
  of a JSON object whose "alg" names that algorithm.

The test refuses a token whose caller_ok is 0, as a caller does, and
passes the others to the C calls. Wycheproof marks a token invalid when
any of this fails, though its signature may be a true one: tcId 331 and
332 carry RS256 signatures under a key registered for PS512, and 353 to
356 carry true signatures under keys registered for encryption.

One more kind of row runs the C calls where no caller would. A valid
token under an RSA key for PS256, PS384, PS512, RS384 or RS512 holds a
true signature of that algorithm, and the test requires that it does not
verify as RS256. A key of any other type, such as an HMAC secret or a
P-521 key, has no form ch_jws_verify takes: the script counts its tokens
and writes no row.

The output lands in bin/, never in the tree, as gen_wycheproof.py's
does.
"""

import base64
import json
import re
import sys
from pathlib import Path

RS256, ES256, EDDSA = 1, 2, 3
KIND = {"invalid": 0, "valid": 1, "acceptable": 2}
URL_TEXT = re.compile(r"^[A-Za-z0-9_-]*$")


def c_bytes(data):
    return ", ".join("0x%02x" % b for b in data) if data else "0"


def rsa_key(n, e):
    """RFC 3110 section 2's form: the exponent's length, the exponent and
    the modulus, each with no leading zero byte."""
    n = n.lstrip(b"\x00")
    e = e.lstrip(b"\x00")
    assert 0 < len(e) < 256
    return bytes([len(e)]) + e + n


def unb64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def header_names(token, alg):
    """Whether the token is three parts whose first is canonical base64url
    of a JSON object with "alg" equal to alg."""
    if not isinstance(token, str):
        return False
    parts = token.split(".")
    if len(parts) != 3 or not URL_TEXT.match(parts[0]) or len(parts[0]) % 4 == 1:
        return False
    try:
        raw = unb64url(parts[0])
        if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != parts[0]:
            return False
        header = json.loads(raw)
    except ValueError:
        return False
    return isinstance(header, dict) and header.get("alg") == alg


class Writer:
    def __init__(self):
        self.blobs = []
        self.count = 0

    def blob(self, data):
        name = "wp_jws_blob_%d" % self.count
        self.count += 1
        self.blobs.append("static const uint8_t %s[%d] = {%s};" % (name, max(len(data), 1),
                                                                    c_bytes(data)))
        return name


def main():
    src, out = Path(sys.argv[1]) / "testvectors_v1", Path(sys.argv[2])
    w = Writer()
    cases = []

    def add_cases(suite_name, algorithm, key_of):
        suite = json.load(open(src / suite_name))
        for group in suite["testGroups"]:
            key = key_of(group)
            key_name = w.blob(key)
            for test in group["tests"]:
                msg = bytes.fromhex(test["msg"])
                sig = bytes.fromhex(test["sig"])
                cases.append('    {"%s", %d, %d, %s, %d, %s, %d, %s, %d, %d},'
                             % (suite_name[:-len("_test.json")], test["tcId"], algorithm, key_name,
                                len(key), w.blob(msg), len(msg), w.blob(sig), len(sig),
                                KIND[test["result"]]))

    def p256_key(group):
        point = bytes.fromhex(group["publicKey"]["uncompressed"])
        assert len(point) == 65 and point[0] == 4
        return point[1:]

    def rsa_group_key(group):
        public = group["publicKey"]
        return rsa_key(bytes.fromhex(public["modulus"]), bytes.fromhex(public["publicExponent"]))

    def ed_key(group):
        key = bytes.fromhex(group["publicKey"]["pk"])
        assert len(key) == 32
        return key

    add_cases("ecdsa_secp256r1_sha256_p1363_test.json", ES256, p256_key)
    for bits in (2048, 3072, 4096):
        add_cases("rsa_signature_%d_sha256_test.json" % bits, RS256, rsa_group_key)
    add_cases("ed25519_test.json", EDDSA, ed_key)

    tokens = []
    skipped = 0
    suite = json.load(open(src / "json_web_signature_test.json"))
    for group in suite["testGroups"]:
        jwk = group.get("public")
        if jwk is None or jwk.get("kty") not in ("RSA", "EC") or (
                jwk["kty"] == "EC" and jwk.get("crv") != "P-256"):
            skipped += len(group["tests"])
            continue
        if jwk["kty"] == "RSA":
            key = rsa_key(unb64url(jwk["n"]), unb64url(jwk["e"]))
            algorithm, name = RS256, "RS256"
        else:
            x, y = unb64url(jwk["x"]), unb64url(jwk["y"])
            assert len(x) == 32 and len(y) == 32
            key = x + y
            algorithm, name = ES256, "ES256"
        for_signatures = jwk.get("use") in (None, "sig") and (
            jwk.get("key_ops") is None or "verify" in jwk["key_ops"])
        has_call = jwk.get("alg") in (None, name)
        key_name = w.blob(key)
        for test in group["tests"]:
            token = test["jws"]
            if not isinstance(token, str):
                token = ""
            text = token.encode()
            if not has_call and test["result"] == "valid":
                # A true signature of an algorithm with no call: it must
                # not verify as RS256, whatever its header says.
                tokens.append("    {%d, %d, %s, %d, (const char *)%s, %d, 1, 0, 1},"
                              % (test["tcId"], algorithm, key_name, len(key), w.blob(text),
                                 len(text)))
                continue
            caller_ok = 1 if for_signatures and has_call and header_names(token, name) else 0
            # A token the caller refuses is refused whatever Wycheproof
            # says of it, and Wycheproof says invalid of each one here.
            assert caller_ok or test["result"] == "invalid", test["tcId"]
            tokens.append("    {%d, %d, %s, %d, (const char *)%s, %d, %d, %d, 0},"
                          % (test["tcId"], algorithm, key_name, len(key), w.blob(text), len(text),
                             caller_ok, KIND[test["result"]]))

    lines = ["// Generated by test/gen_wycheproof_jws.py from Wycheproof's suites.",
             "#ifndef CH_WYCHEPROOF_JWS_VECTORS_H", "#define CH_WYCHEPROOF_JWS_VECTORS_H", "",
             "#include <stddef.h>", "#include <stdint.h>", ""]
    lines += w.blobs
    lines += ["", "// kind is 1 for a valid case, 0 for an invalid one, and 2 for one Wycheproof",
              "// leaves to the implementation.",
              "static const struct {", "    const char *suite;", "    int tc_id;",
              "    uint8_t algorithm;", "    const uint8_t *key;", "    size_t key_len;",
              "    const uint8_t *msg;", "    size_t msg_len;", "    const uint8_t *sig;",
              "    size_t sig_len;", "    int kind;", "} wp_jws_cases[] = {"]
    lines += cases
    lines += ["};", "",
              "// caller_ok is the caller's part of the check (test/gen_wycheproof_jws.py).",
              "// other is 1 for a true signature of an algorithm chapulin has no call for,",
              "// which must not verify under RS256.",
              "static const struct {", "    int tc_id;", "    uint8_t algorithm;",
              "    const uint8_t *key;", "    size_t key_len;", "    const char *token;",
              "    size_t token_len;", "    int caller_ok;", "    int kind;", "    int other;",
              "} wp_jws_tokens[] = {"]
    lines += tokens
    lines += ["};", "", "#define WP_JWS_TOKENS_SKIPPED %d" % skipped, "", "#endif", ""]
    out.write_text("\n".join(lines))
    print("gen_wycheproof_jws: %d cases, %d tokens, %d tokens of a key type with no call"
          % (len(cases), len(tokens), skipped))


if __name__ == "__main__":
    main()
