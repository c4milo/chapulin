#!/usr/bin/env python3
"""Regenerates test/jws_vectors.h.

Usage: python3 test/gen_jws_vectors.py

ch_jws_verify checks a JWS signature under a public key (jws.h,
docs/decisions.md 221). This script mints keys with OpenSSL, writes one
compact JWS for each (RFC 7515 section 7.1), and signs it with OpenSSL:

- RS256: RSASSA-PKCS1-v1_5 over SHA-256 (RFC 7518 section 3.3). The key
  is in RFC 3110 section 2's form, as ch_jws_verify takes it: an exponent
  length, the exponent and the modulus, each without leading zero bytes.
  The keys cover 2048 bits, the floor of RFC 7518 section 3.3, with the
  exponents 3 and 65537, and 3072 and 4096 bits, the bound of jws.h. Two
  more keys sit one byte outside the bounds, 2040 and 4104 bits, each
  with a signature OpenSSL accepts, so a test can show that the call
  refuses the key and not the signature.
- ES256: ECDSA P-256 over SHA-256 (RFC 7518 section 3.4). The key is the
  64 bytes of X then Y, and the signature is R then S, 32 bytes each,
  which the script takes out of OpenSSL's DER.
- EdDSA: Ed25519 (RFC 8037 section 3.1). The key is the 32-byte public
  key, and the signature is 64 bytes.

The commands, per key:

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:<bits>
    -pkeyopt rsa_keygen_pubexp:<e> -out key.pem
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem
  openssl genpkey -algorithm ED25519 -out key.pem
  openssl dgst -sha256 -sign key.pem -out sig input
  openssl dgst -sha256 -verify pub.pem -signature sig input
  openssl pkeyutl -sign -rawin -inkey key.pem -in input -out sig
  openssl pkeyutl -verify -rawin -pubin -inkey pub.pem -in input -sigfile sig

Every signature is verified with OpenSSL before it is written. Python's
base64 module writes the base64url text, so the header's tokens also hold
ch_base64url_encode and ch_base64url_decode to a second implementation.
The keys are fresh on every run, so the header changes when it is
regenerated; vectors are regenerate-never-edit snapshots.
"""

import base64
import json
import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).parent
OUT = HERE / "jws_vectors.h"

RS256, ES256, EDDSA = 1, 2, 3

# (bits, exponent, subject, in bounds)
RSA_KEYS = [
    (2048, 65537, "rs256 2048", True),
    (2048, 3, "rs256 2048 e=3", True),
    (3072, 65537, "rs256 3072", True),
    (4096, 65537, "rs256 4096", True),
    (2040, 65537, "rs256 2040, one byte under the floor", False),
    (4104, 65537, "rs256 4104, one byte over the bound", False),
]
EC_SUBJECTS = ["es256 one", "es256 two, with a longer subject to move the lengths"]
ED_SUBJECTS = ["eddsa one", "eddsa two, with a longer subject to move the lengths"]


def run(*args, data=None):
    return subprocess.run(args, input=data, capture_output=True, check=True).stdout


def unhex(text):
    return bytes.fromhex("".join(text.split()).replace(":", ""))


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def signing_input(alg_name, subject):
    header = json.dumps({"alg": alg_name, "typ": "JWT"}, separators=(",", ":")).encode()
    claims = json.dumps({"iss": "chapulin test", "sub": subject}, separators=(",", ":")).encode()
    return b64url(header) + b"." + b64url(claims)


def rsa_numbers(key):
    text = run("openssl", "pkey", "-in", key, "-noout", "-text").decode()
    mod = text.split("modulus:")[1].split("publicExponent:")[0]
    exp = int(text.split("publicExponent:")[1].split()[0])
    return unhex(mod).lstrip(b"\x00"), exp


def minimal(value):
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def der_integers(der, size=32):
    """r and s out of an ECDSA-Sig-Value, each as size bytes."""
    assert der[0] == 0x30
    i = 2
    out = []
    for _ in range(2):
        assert der[i] == 0x02
        n = der[i + 1]
        out.append(der[i + 2:i + 2 + n].lstrip(b"\x00").rjust(size, b"\x00"))
        i += 2 + n
    return out[0] + out[1]


def sign_sha256(tmp, key, msg):
    msg_path = tmp / "msg"
    msg_path.write_bytes(msg)
    sig_path = tmp / "sig"
    pub_path = tmp / "pub.pem"
    run("openssl", "dgst", "-sha256", "-sign", key, "-out", str(sig_path), str(msg_path))
    run("openssl", "pkey", "-in", key, "-pubout", "-out", str(pub_path))
    run("openssl", "dgst", "-sha256", "-verify", str(pub_path), "-signature", str(sig_path),
        str(msg_path))
    return sig_path.read_bytes()


def sign_ed25519(tmp, key, msg):
    msg_path = tmp / "msg"
    msg_path.write_bytes(msg)
    sig_path = tmp / "sig"
    pub_path = tmp / "pub.pem"
    run("openssl", "pkey", "-in", key, "-pubout", "-out", str(pub_path))
    run("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", str(msg_path), "-out",
        str(sig_path))
    run("openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(pub_path), "-in",
        str(msg_path), "-sigfile", str(sig_path))
    return sig_path.read_bytes()


def c_array(name, data):
    lines = []
    for i in range(0, len(data), 16):
        lines.append("    " + ", ".join("0x%02x" % b for b in data[i:i + 16]) + ",")
    return "static const uint8_t %s[%d] = {\n%s\n};\n" % (name, len(data), "\n".join(lines))


def c_text(name, data):
    lines = []
    for i in range(0, len(data), 76):
        lines.append('    "%s"' % data[i:i + 76].decode())
    return "static const char %s[] =\n%s;\n" % (name, "\n".join(lines))


def main():
    out = [
        "// Generated by test/gen_jws_vectors.py; regenerate, never edit.",
        "#ifndef CH_JWS_VECTORS_H",
        "#define CH_JWS_VECTORS_H",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
    ]
    rows = []

    def emit(alg, field, text, sig, in_bounds):
        index = len(rows)
        token = text + b"." + b64url(sig)
        out.extend([c_array("jws_key_%d" % index, field), c_text("jws_token_%d" % index, token),
                    c_array("jws_sig_%d" % index, sig)])
        rows.append((alg, index, len(text), in_bounds))

    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        key = str(tmp / "key.pem")
        for bits, e, subject, in_bounds in RSA_KEYS:
            run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:%d" % bits,
                "-pkeyopt", "rsa_keygen_pubexp:%d" % e, "-out", key)
            n, exp = rsa_numbers(key)
            assert exp == e and len(n) == bits // 8
            e_bytes = minimal(e)
            text = signing_input("RS256", subject)
            sig = sign_sha256(tmp, key, text)
            assert len(sig) == len(n)
            emit(RS256, bytes([len(e_bytes)]) + e_bytes + n, text, sig, in_bounds)
        for subject in EC_SUBJECTS:
            run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-out", key)
            pub_der = run("openssl", "pkey", "-in", key, "-pubout", "-outform", "DER")
            assert pub_der[-65] == 0x04
            text = signing_input("ES256", subject)
            emit(ES256, pub_der[-64:], text, der_integers(sign_sha256(tmp, key, text)), True)
        for subject in ED_SUBJECTS:
            run("openssl", "genpkey", "-algorithm", "ED25519", "-out", key)
            field = run("openssl", "pkey", "-in", key, "-pubout", "-outform", "DER")[-32:]
            text = signing_input("EdDSA", subject)
            sig = sign_ed25519(tmp, key, text)
            assert len(sig) == 64
            emit(EDDSA, field, text, sig, True)
    out += [
        "// token is a compact JWS (RFC 7515 section 7.1): its first input_len",
        "// characters are the JWS Signing Input, and the text after the '.' that",
        "// follows them is the base64url of sig. in_bounds is 0 for an RSA key",
        "// whose modulus is one byte outside jws.h's bounds.",
        "typedef struct {",
        "    uint8_t algorithm;",
        "    const uint8_t *key;",
        "    size_t key_len;",
        "    const char *token;",
        "    size_t token_len;",
        "    size_t input_len;",
        "    const uint8_t *sig;",
        "    size_t sig_len;",
        "    int in_bounds;",
        "} jws_vector;",
        "",
        "static const jws_vector jws_vectors[] = {",
    ]
    for alg, i, input_len, in_bounds in rows:
        out.append("    {%d, jws_key_%d, sizeof jws_key_%d, jws_token_%d, sizeof jws_token_%d - 1, "
                   "%d, jws_sig_%d, sizeof jws_sig_%d, %d},"
                   % (alg, i, i, i, i, input_len, i, i, 1 if in_bounds else 0))
    out += ["};", "", "#endif", ""]
    OUT.write_text("\n".join(out))


if __name__ == "__main__":
    main()
