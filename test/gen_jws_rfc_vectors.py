#!/usr/bin/env python3
"""Regenerates test/jws_rfc_vectors.h.

Usage: python3 test/gen_jws_rfc_vectors.py

The examples the JOSE RFCs print, as ch_jws_verify takes them
(docs/decisions.md 221):

- RFC 7515 appendix A.2, RS256 with a 2048-bit key: the JWK's "n" and
  "e" (rfc7515.txt:2252-2258) and the complete JWS
  (rfc7515.txt:2364-2374);
- RFC 7515 appendix A.3, ES256: the JWK's "x" and "y"
  (rfc7515.txt:2454-2455) and the complete JWS (rfc7515.txt:2499-2505);
- RFC 8037 appendix A.4 and A.5, EdDSA with Ed25519: the JWK's "x"
  (rfc8037.txt:482) and the complete JWS (rfc8037.txt:571-573).

The script reads each value out of the RFC text docs/rfcs/ carries,
whose bytes SHA256SUMS holds, so no value is typed by hand. It checks
the first word of each line range and the length of each signature, and
stops if a range holds other text or ends early.
It decodes each key from base64url with Python's base64 module and
writes it in ch_jws_verify's form. It runs no cryptography, so a vector
that verifies is the RFC's own key and signature.

For ch_jws_sign's test it also writes the two private keys of RFC 7515:
appendix A.2's RSA key as the fields of a ch_rsa_priv, "d", "p", "q",
"dp", "dq" and "qi" (rfc7515.txt:2259-2279), and appendix A.3's P-256
scalar "d" (rfc7515.txt:2456). It checks the RSA fields against each
other with Python's integers first: n is p times q, and each exponent is
the one RFC 8017 section 3.2 defines.

And it writes the five Ed25519 vectors of RFC 8032 section 7.1
(rfc8032.txt:1340-1620): each secret key, public key, message and
signature. It takes the hexadecimal lines under each label, and requires
the message to have the length its label states.
"""

import base64
import pathlib

HERE = pathlib.Path(__file__).parent
RFCS = HERE.parent / "docs" / "rfcs"
OUT = HERE / "jws_rfc_vectors.h"

RS256, ES256, EDDSA = 1, 2, 3


def lines(rfc, first, last):
    """The text of lines first to last, 1-based, with no white space."""
    text = (RFCS / rfc).read_text().split("\n")
    return "".join("".join(line.split()) for line in text[first - 1:last])


def member(rfc, first, last, name):
    """A JWK member's value: the text between its quotes."""
    text = lines(rfc, first, last)
    prefix = '"%s":"' % name
    assert text.startswith(prefix), (rfc, first, text[:20])
    value = text[len(prefix):]
    return value[:value.index('"')]


def unb64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def token(rfc, first, last, header, sig_len):
    """A complete JWS: its signing input and its decoded signature."""
    text = lines(rfc, first, last)
    assert text.startswith(header + "."), (rfc, first, text[:30])
    assert text.count(".") == 2, (rfc, first)
    signing_input, _, signature = text.rpartition(".")
    sig = unb64url(signature)
    assert len(sig) == sig_len, (rfc, first, len(sig))
    return text.encode(), len(signing_input), sig


def ed25519_vectors():
    """RFC 8032 section 7.1: (secret key, public key, message, signature)."""
    text = (RFCS / "rfc8032.txt").read_text().split("\n")
    start = next(i for i, line in enumerate(text) if line.startswith("7.1.  Test Vectors for Ed25519"))
    end = next(i for i, line in enumerate(text) if line.startswith("7.2.  "))
    vectors = []
    fields = None
    current = None
    for line in text[start:end]:
        stripped = line.strip()
        if stripped.startswith("-----TEST"):
            fields = {"SECRET KEY": "", "PUBLIC KEY": "", "MESSAGE": "", "SIGNATURE": ""}
            vectors.append(fields)
            current = None
            continue
        if fields is None:
            continue
        label = stripped.rstrip(":").split(" (")[0]
        if label in fields:
            current = label
            if label == "MESSAGE":
                fields["length"] = int(stripped.split("length ")[1].split(" ")[0])
            continue
        # A line of hexadecimal digits belongs to the field above it. A
        # page's footer and header, and a blank line, belong to none.
        if current and stripped and all(c in "0123456789abcdef" for c in stripped):
            fields[current] += stripped
    out = []
    for fields in vectors:
        secret, public, message, signature = (bytes.fromhex(fields[k]) for k in (
            "SECRET KEY", "PUBLIC KEY", "MESSAGE", "SIGNATURE"))
        assert len(secret) == 32 and len(public) == 32 and len(signature) == 64
        assert len(message) == fields["length"], (len(message), fields["length"])
        out.append((secret, public, message, signature))
    assert len(out) == 5, len(out)
    return out


def c_array(name, data):
    out = []
    for i in range(0, len(data), 16):
        out.append("    " + ", ".join("0x%02x" % b for b in data[i:i + 16]) + ",")
    return "static const uint8_t %s[%d] = {\n%s\n};\n" % (name, len(data), "\n".join(out))


def c_text(name, data):
    out = []
    for i in range(0, len(data), 76):
        out.append('    "%s"' % data[i:i + 76].decode())
    return "static const char %s[] =\n%s;\n" % (name, "\n".join(out))


def main():
    n = unb64url(member("rfc7515.txt", 2252, 2257, "n"))
    e = unb64url(member("rfc7515.txt", 2258, 2258, "e"))
    assert len(n) == 256 and n[0] != 0 and e == b"\x01\x00\x01"
    x = unb64url(member("rfc7515.txt", 2454, 2454, "x"))
    y = unb64url(member("rfc7515.txt", 2455, 2455, "y"))
    assert len(x) == 32 and len(y) == 32
    ed = unb64url(member("rfc8037.txt", 482, 482, "x"))
    assert len(ed) == 32
    private = {name: unb64url(member("rfc7515.txt", first, last, name))
               for name, first, last in (("d", 2259, 2264), ("p", 2265, 2267), ("q", 2268, 2270),
                                         ("dp", 2271, 2273), ("dq", 2274, 2276),
                                         ("qi", 2277, 2279))}
    number = {name: int.from_bytes(value, "big") for name, value in private.items()}
    modulus = int.from_bytes(n, "big")
    assert number["p"] * number["q"] == modulus
    assert number["d"] * 65537 % ((number["p"] - 1) * (number["q"] - 1)) == 1
    assert number["dp"] == number["d"] % (number["p"] - 1)
    assert number["dq"] == number["d"] % (number["q"] - 1)
    assert number["qi"] * number["q"] % number["p"] == 1
    assert len(private["d"]) <= 256 and all(len(private[k]) <= 128 for k in ("p", "q", "dp", "dq", "qi"))
    ec_d = unb64url(member("rfc7515.txt", 2456, 2456, "d"))
    assert len(ec_d) == 32
    examples = [
        ("rfc7515_a2", RS256, bytes([len(e)]) + e + n,
         token("rfc7515.txt", 2364, 2374, "eyJhbGciOiJSUzI1NiJ9", 256)),
        ("rfc7515_a3", ES256, x + y,
         token("rfc7515.txt", 2499, 2505, "eyJhbGciOiJFUzI1NiJ9", 64)),
        ("rfc8037_a4", EDDSA, ed, token("rfc8037.txt", 571, 573, "eyJhbGciOiJFZERTQSJ9", 64)),
    ]
    out = [
        "// Generated by test/gen_jws_rfc_vectors.py; regenerate, never edit.",
        "#ifndef CH_JWS_RFC_VECTORS_H",
        "#define CH_JWS_RFC_VECTORS_H",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        '#include "jws_vectors.h"',
        "",
    ]
    rows = []
    for name, algorithm, key, (text, input_len, sig) in examples:
        out += [c_array(name + "_key", key), c_text(name + "_token", text),
                c_array(name + "_sig", sig)]
        rows.append("    {%d, %s_key, sizeof %s_key, %s_token, sizeof %s_token - 1, %d, %s_sig, "
                    "sizeof %s_sig, 1}," % (algorithm, name, name, name, name, input_len, name, name))
    out += ["// RFC 7515 appendix A.2's RSA private key: each field at its width in a",
            "// ch_rsa_priv, with zero bytes on the left.",
            c_array("rfc7515_a2_n", n), c_array("rfc7515_a2_d", private["d"].rjust(256, b"\x00"))]
    for name, field in (("p", "p"), ("q", "q"), ("dp", "dp"), ("dq", "dq"), ("qi", "qinv")):
        out.append(c_array("rfc7515_a2_" + field, private[name].rjust(128, b"\x00")))
    out += ["// RFC 7515 appendix A.3's P-256 private scalar.", c_array("rfc7515_a3_d", ec_d)]
    ed_rows = []
    for i, (secret, public, message, signature) in enumerate(ed25519_vectors()):
        out += [c_array("rfc8032_secret_%d" % i, secret), c_array("rfc8032_public_%d" % i, public),
                c_array("rfc8032_message_%d" % i, message or b"\x00"),
                c_array("rfc8032_signature_%d" % i, signature)]
        ed_rows.append("    {rfc8032_secret_%d, rfc8032_public_%d, rfc8032_message_%d, %d, "
                    "rfc8032_signature_%d}," % (i, i, i, len(message), i))
    out += ["// RFC 8032 section 7.1's five Ed25519 vectors. The first message is empty,",
            "// and its array holds one byte that is not read.",
            "static const struct {", "    const uint8_t *secret;", "    const uint8_t *public_key;",
            "    const uint8_t *message;", "    size_t message_len;", "    const uint8_t *signature;",
            "} rfc8032_vectors[] = {"] + ed_rows + ["};", ""]
    out += ["// test/jws_vectors.h's rows, for the RFCs' own examples.",
            "static const jws_vector jws_rfc_vectors[] = {"]
    out += rows
    out += ["};", "", "#endif", ""]
    OUT.write_text("\n".join(out))


if __name__ == "__main__":
    main()
