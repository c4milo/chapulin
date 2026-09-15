#!/usr/bin/env python3
"""Regenerates test/webpki_sigalg_vectors.h.

Usage: python3 test/gen_webpki_sigalg_vectors.py

The vectors for test/webpki_spki_test.c and test/webpki_sigalg_test.c:
SubjectPublicKeyInfo DER, the signature AlgorithmIdentifiers a public CA
writes, and signatures over TBS-shaped messages, all from OpenSSL 3 over
the fixed keys under test/webpki_corpus/keys/. The keys are fixed, RSA
PKCS#1 v1.5 is deterministic and ECDSA takes RFC 6979 nonces
(`-sigopt nonce-type:1`), so a run over an unchanged tree reproduces the
header byte for byte.

The exact commands:

  openssl pkey -in <key>.pem -pubout -outform DER        (each SPKI)
  openssl req -new -key <key>.pem -subj /CN=sigalg -<hash> -outform DER
      [-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32]
                                                          (each AlgorithmIdentifier)
  openssl dgst -<hash> -sign <key>.pem [-sigopt nonce-type:1] -out sig msg
  openssl dgst -<hash> -verify pub.pem -signature sig msg

The AlgorithmIdentifier comes out of the certification request's
signatureAlgorithm field, which is the same type a certificate carries
(RFC 2986 section 4.2). The request itself is discarded.

msg is a TBS-shaped message: a SEQUENCE header then content bytes, the
bytes webpki_verify hashes for a certificate whose cert->tbs is that
content. The content lengths are chosen so the three DER length forms
and their edges are all signed: 100 and 127 (short form), 128, 200 and
255 (0x81), 256, 300 and 1000 (0x82).

Two more signed messages sit at the TBS length cap, 3072 and 3073 bytes.
Two signatures are over the wrong end of a digest, which FIPS 186-4
section 6.4 does not use:

  openssl dgst -<hash> -binary msg                        (the digest)
  openssl pkeyutl -sign -inkey <key>.pem -in raw -pkeyopt digest:<hash>
      -pkeyopt nonce-type:1 -out sig
  openssl pkeyutl -verify -pubin -inkey pub.pem -in raw -sigfile sig
      -pkeyopt digest:<hash>

where raw is the rightmost 32 bytes of a SHA-384 digest (P-256), or a
SHA-256 digest with 16 zero bytes on its right (P-384).

Every openssl signature is checked with `openssl dgst -verify` or `openssl
pkeyutl -verify` before it is emitted. The admitted AlgorithmIdentifiers are checked against the
RFC-cited literal bytes below, so the constants webpki_sigalg.c carries
are measured against openssl, never copied on trust.

Four more signatures are forged, for the point (1, 0), which is on
neither curve: one under each curve and each ECDSA hash, over the signed
message of the row with that curve and hash. test/webpki_off_curve.py
states the construction and checks each forgery. The curve parameters
come from `openssl ecparam -name <curve> -param_enc explicit -outform
DER`, and `openssl pkey -pubin` must refuse to load each key.

The negative SPKIs are the openssl ones with one field rewritten here,
each named for the one rule it breaks: an exponent of 3, an even
modulus, a 4104-bit modulus (one byte over the 512-byte gate), a missing
and an unneeded pad octet, a compressed point, and each curve's point
under the other curve's identifier. The RSA-1024 SPKI is openssl's own
over the corpus key below the modulus floor.
"""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import webpki_off_curve as off_curve

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "webpki_sigalg_vectors.h"
KEY_DIR = HERE / "webpki_corpus" / "keys"

# label -> (key file, kind)
KEYS = {
    "rsa2048": ("leaf_rsa2048.pem", "rsa"),
    "rsa4096": ("root_gcs_rsa4096.pem", "rsa"),
    "p256": ("leaf_p256.pem", "ec"),
    "p384": ("root_p384.pem", "ec"),
    "rsa1024": ("leaf_rsa1024.pem", "rsa"),
}

# (name, key label, WEBPKI_SIG_* constant, openssl digest, content length).
# Every admitted algorithm under every key that can sign with it; the
# P-256 key with SHA-384 is the digest cut, the P-384 key with SHA-256
# the pad (FIPS 186-4 section 6.4).
SIGNATURES = [
    ("rsa2048_sha256", "rsa2048", "WEBPKI_SIG_RSA_SHA256", "sha256", 300),
    ("rsa2048_sha384", "rsa2048", "WEBPKI_SIG_RSA_SHA384", "sha384", 200),
    ("rsa4096_sha256", "rsa4096", "WEBPKI_SIG_RSA_SHA256", "sha256", 127),
    ("rsa4096_sha384", "rsa4096", "WEBPKI_SIG_RSA_SHA384", "sha384", 128),
    ("p256_sha256", "p256", "WEBPKI_SIG_ECDSA_SHA256", "sha256", 255),
    ("p256_sha384", "p256", "WEBPKI_SIG_ECDSA_SHA384", "sha384", 256),
    ("p384_sha256", "p384", "WEBPKI_SIG_ECDSA_SHA256", "sha256", 100),
    ("p384_sha384", "p384", "WEBPKI_SIG_ECDSA_SHA384", "sha384", 1000),
]

# The TBS length boundary webpki_verify holds: CH_WEBPKI_CERT_MAX (3072)
# is the last length it hashes, 3073 the first it refuses. Both carry a
# valid openssl signature, so the refusal is the cap and nothing else.
CAP_SIGNATURES = [
    ("p256_sha256_cert_max", "p256", "sha256", 3072),
    ("p256_sha256_over_cert_max", "p256", "sha256", 3073),
]

# The admitted AlgorithmIdentifiers as their RFCs spell them, and the
# openssl request that must reproduce each: (name, key label, digest,
# extra openssl arguments, expected DER).
ADMITTED_SIGALGS = [
    # sha256WithRSAEncryption, NULL parameters (RFC 4055 section 5).
    ("rsa_sha256", "rsa2048", "sha256", [], "300d06092a864886f70d01010b0500"),
    # sha384WithRSAEncryption, NULL parameters (RFC 4055 section 5).
    ("rsa_sha384", "rsa2048", "sha384", [], "300d06092a864886f70d01010c0500"),
    # ecdsa-with-SHA256, parameters absent (RFC 5758 section 3.2).
    ("ecdsa_sha256", "p256", "sha256", [], "300a06082a8648ce3d040302"),
    # ecdsa-with-SHA384, parameters absent (RFC 5758 section 3.2).
    ("ecdsa_sha384", "p256", "sha384", [], "300a06082a8648ce3d040303"),
]

# The refused AlgorithmIdentifiers openssl writes: SHA-1 under both
# families and RSASSA-PSS.
REFUSED_SIGALGS = [
    ("rsa_sha1", "rsa2048", "sha1", []),
    ("ecdsa_sha1", "p256", "sha1", []),
    ("rsa_pss_sha256", "rsa2048", "sha256",
     ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"]),
]

# The admitted identifiers' parameter variants no issuer should write:
# ECDSA with a NULL, RSA with the NULL absent. Built here, not by openssl.
ECDSA_SHA256_NULL = "300c06082a8648ce3d0403020500"
RSA_SHA256_ABSENT = "300b06092a864886f70d01010b"

ID_EC_PUBLIC_KEY = bytes.fromhex("2a8648ce3d0201")
PRIME256V1 = bytes.fromhex("2a8648ce3d030107")
SECP384R1 = bytes.fromhex("2b81040022")


def find_openssl():
    ossl = shutil.which("openssl", path="/opt/homebrew/bin:/usr/bin:" + (os.environ.get("PATH") or ""))
    if ossl is None:
        sys.exit("openssl not found")
    version = subprocess.run([ossl, "version"], capture_output=True, text=True).stdout.strip()
    if not version.startswith("OpenSSL 3."):
        sys.exit(f"{ossl} is {version}; the vectors need OpenSSL 3")
    return ossl, version.split(" (")[0]


def sh(*cmd, stdin=None):
    r = subprocess.run(cmd, input=stdin, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"{' '.join(str(c) for c in cmd[:3])} failed: {r.stderr.decode()[:400]}")
    return r.stdout


def der_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def tlv(tag, content):
    return bytes([tag]) + der_len(len(content)) + content


def read_tlv(data, off):
    """Returns (tag, content_off, content_len) for the TLV at off."""
    tag = data[off]
    first = data[off + 1]
    if first < 0x80:
        return tag, off + 2, first
    count = first & 0x7F
    return tag, off + 2 + count, int.from_bytes(data[off + 2 : off + 2 + count], "big")


def children(data):
    """The whole TLVs inside the one SEQUENCE data holds."""
    tag, off, length = read_tlv(data, 0)
    if tag != 0x30 or off + length != len(data):
        sys.exit("not one exact-fill SEQUENCE")
    out = []
    end = off + length
    while off < end:
        _, c_off, c_len = read_tlv(data, off)
        out.append(data[off : c_off + c_len])
        off = c_off + c_len
    return out


def content(whole_tlv):
    _, off, length = read_tlv(whole_tlv, 0)
    return whole_tlv[off : off + length]


def rsa_spki(modulus_content, exponent_tlv):
    """SPKI for rsaEncryption around a modulus INTEGER's content bytes."""
    key = tlv(0x30, tlv(0x02, modulus_content) + exponent_tlv)
    algid = tlv(0x30, tlv(0x06, bytes.fromhex("2a864886f70d010101")) + bytes.fromhex("0500"))
    return tlv(0x30, algid + tlv(0x03, b"\x00" + key))


def ec_spki(curve_oid, point):
    algid = tlv(0x30, tlv(0x06, ID_EC_PUBLIC_KEY) + tlv(0x06, curve_oid))
    return tlv(0x30, algid + tlv(0x03, b"\x00" + point))


def rsa_parts(spki):
    """(modulus INTEGER content, exponent TLV) of an openssl RSA SPKI."""
    _, bits = children(spki)
    key = content(bits)[1:]
    modulus, exponent = children(key)
    return content(modulus), exponent


def ec_point(spki):
    _, bits = children(spki)
    return content(bits)[1:]


def negative_spkis(spki):
    """Each negative SPKI, named for the one rule it breaks."""
    modulus, exponent = rsa_parts(spki["rsa2048"])
    wide_modulus, wide_exponent = rsa_parts(spki["rsa4096"])
    if exponent != bytes.fromhex("0203010001") or modulus[0] != 0 or len(modulus) != 257:
        sys.exit("rsa2048 SPKI shape unexpected")
    if len(wide_modulus) != 513:
        sys.exit("rsa4096 SPKI shape unexpected")
    even = modulus[:-1] + bytes([modulus[-1] & 0xFE])
    # One value byte above the top of the 512-byte gate: prefix a byte
    # with its top bit set, so the pad stays needed and the value odd.
    wide = b"\x00\xc5" + wide_modulus[1:]
    p256_point = ec_point(spki["p256"])
    p384_point = ec_point(spki["p384"])
    compressed = bytes([0x02 | (p256_point[-1] & 1)]) + p256_point[1:33]
    rebuilt = rsa_spki(modulus, exponent)
    if rebuilt != spki["rsa2048"] or ec_spki(PRIME256V1, p256_point) != spki["p256"]:
        sys.exit("the SPKI rebuild does not reproduce openssl's encoding")
    return [
        ("rsa_exponent3", rsa_spki(modulus, bytes.fromhex("020103")),
         "the rsa2048 key with publicExponent 3"),
        ("rsa_even_modulus", rsa_spki(even, exponent),
         "the rsa2048 key with the modulus's low bit cleared"),
        ("rsa4104", rsa_spki(wide, wide_exponent),
         "the rsa4096 modulus with one more value byte, 0xc5, on top: 513 bytes"),
        ("rsa_missing_pad", rsa_spki(modulus[1:], exponent),
         "the rsa2048 modulus INTEGER without its 0x00 pad octet"),
        ("rsa_unneeded_pad", rsa_spki(b"\x00" + modulus, exponent),
         "the rsa2048 modulus INTEGER with a second 0x00 octet"),
        ("p256_compressed", ec_spki(PRIME256V1, compressed),
         "the p256 point in the compressed form, 0x02 or 0x03 then X"),
        ("p256_under_p384", ec_spki(SECP384R1, p256_point),
         "the p256 point under the secp384r1 identifier"),
        ("p384_under_p256", ec_spki(PRIME256V1, p384_point),
         "the p384 point under the prime256v1 identifier"),
    ]


def c_array(name, data, comment):
    lines = [f"// {line}" for line in comment.splitlines()]
    lines.append(f"static const uint8_t {name}[{len(data)}] = {{")
    for i in range(0, len(data), 16):
        chunk = ", ".join(f"0x{b:02x}" for b in data[i : i + 16])
        lines.append(f"    {chunk},")
    lines.append("};")
    return "\n".join(lines) + "\n"


def tbs_content(name, length):
    seed = f"chapulin webpki tbs {name} ".encode()
    return (seed * (length // len(seed) + 1))[:length]


def sign_row(ossl, t, pub, name, label, digest, length):
    """The TBS content and openssl's signature over its signed message."""
    tbs = tbs_content(name, length)
    msg = t / f"{name}.msg"
    msg.write_bytes(tlv(0x30, tbs))
    sig = t / f"{name}.sig"
    cmd = [ossl, "dgst", f"-{digest}", "-sign", str(KEY_DIR / KEYS[label][0])]
    if KEYS[label][1] == "ec":
        cmd += ["-sigopt", "nonce-type:1"]
    sh(*cmd, "-out", str(sig), str(msg))
    sh(ossl, "dgst", f"-{digest}", "-verify", str(pub[label]), "-signature", str(sig), str(msg))
    return [
        c_array(f"webpki_tbs_{name}", tbs,
                f"TBS content, {length} bytes: the signed message is its SEQUENCE\n"
                "header then these bytes."),
        c_array(f"webpki_sig_{name}", sig.read_bytes(),
                f"openssl dgst -{digest} -sign {KEYS[label][0]} over the signed message"),
    ]


def wrong_end_rows(ossl, t, pub):
    """Signatures over the wrong end of a digest, which webpki_verify must
    refuse: the P-256 key over the rightmost 32 bytes of the p256_sha384
    message's SHA-384 digest, and the P-384 key over the p384_sha256
    message's SHA-256 digest with its zeros on the right."""
    out = []
    for name, source, label, digest, raw_digest, shape in WRONG_END_SIGNATURES:
        msg = t / f"{source}.msg"
        full = sh(ossl, "dgst", f"-{digest}", "-binary", str(msg))
        raw = shape(full)
        raw_path = t / f"{name}.raw"
        raw_path.write_bytes(raw)
        sig = t / f"{name}.sig"
        key = str(KEY_DIR / KEYS[label][0])
        sh(ossl, "pkeyutl", "-sign", "-inkey", key, "-in", str(raw_path), "-pkeyopt",
           f"digest:{raw_digest}", "-pkeyopt", "nonce-type:1", "-out", str(sig))
        sh(ossl, "pkeyutl", "-verify", "-pubin", "-inkey", str(pub[label]), "-in", str(raw_path),
           "-sigfile", str(sig), "-pkeyopt", f"digest:{raw_digest}")
        out.append(c_array(f"webpki_sig_{name}", sig.read_bytes(),
                           f"openssl pkeyutl -sign -inkey {KEYS[label][0]} over {shape.__doc__}\n"
                           f"of openssl dgst -{digest} over the webpki_tbs_{source} signed message"))
    return out


def rightmost_32(digest):
    """the rightmost 32 bytes"""
    return digest[-32:]


def zeros_on_the_right(digest):
    """the 32 bytes then 16 zero bytes"""
    return digest + bytes(16)


# (name, source row, key label, message digest, pkeyutl digest length name, shape).
WRONG_END_SIGNATURES = [
    ("p256_sha384_rightmost", "p256_sha384", "p256", "sha384", "sha256", rightmost_32),
    ("p384_sha256_right_padded", "p384_sha256", "p384", "sha256", "sha384", zeros_on_the_right),
]

# The off-curve keys: (label, curve identifier, openssl curve name).
OFF_CURVE_KEYS = [
    ("p256", PRIME256V1, "prime256v1"),
    ("p384", SECP384R1, "secp384r1"),
]

# The forged rows: (name, source row, key label, message digest). The
# source row supplies the signed message.
OFF_CURVE_SIGNATURES = [
    ("p256_sha256_off_curve", "p256_sha256", "p256", "sha256"),
    ("p256_sha384_off_curve", "p256_sha384", "p256", "sha384"),
    ("p384_sha256_off_curve", "p384_sha256", "p384", "sha256"),
    ("p384_sha384_off_curve", "p384_sha384", "p384", "sha384"),
]


def curve_params(ossl, curve):
    """(p, a, b, G, n) from openssl's explicit ECParameters encoding
    (RFC 3279 section 2.3.5): version, fieldID, curve, base, order."""
    fields = children(sh(ossl, "ecparam", "-name", curve, "-param_enc", "explicit",
                         "-outform", "DER"))
    p = int.from_bytes(content(children(fields[1])[1]), "big")
    coefficients = children(fields[2])
    a = int.from_bytes(content(coefficients[0]), "big")
    b = int.from_bytes(content(coefficients[1]), "big")
    base = content(fields[3])
    size = (len(base) - 1) // 2
    g = (int.from_bytes(base[1 : 1 + size], "big"), int.from_bytes(base[1 + size :], "big"))
    return p, a, b, g, int.from_bytes(content(fields[4]), "big")


def der_integer(value):
    return tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def off_curve_rows(ossl, t):
    """The off-curve SPKIs and the signatures forged under them."""
    out = []
    params = {}
    for label, curve_oid, curve in OFF_CURVE_KEYS:
        p, a, b, g, n = curve_params(ossl, curve)
        size = (p.bit_length() + 7) // 8
        key = (1, 0)
        if off_curve.on_curve(key, p, a, b):
            sys.exit(f"(1, 0) is on {curve}")
        spki = ec_spki(curve_oid, b"\x04" + key[0].to_bytes(size, "big") + bytes(size))
        der = t / f"{label}_off_curve.der"
        der.write_bytes(spki)
        loaded = subprocess.run([ossl, "pkey", "-pubin", "-inform", "DER", "-in", str(der),
                                 "-noout"], capture_output=True)
        if loaded.returncode == 0:
            sys.exit(f"openssl loads the {curve} key (1, 0)")
        params[label] = (key, g, p, a, n, size)
        out.append(c_array(f"webpki_spki_{label}_off_curve", spki,
                           f"the point (1, 0) under the {curve} identifier: not on the curve,\n"
                           "and openssl pkey -pubin refuses to load it"))
    for name, source, label, digest in OFF_CURVE_SIGNATURES:
        key, g, p, a, n, size = params[label]
        full = sh(ossl, "dgst", f"-{digest}", "-binary", str(t / f"{source}.msg"))
        # FIPS 186-4 section 6.4: the leftmost min(N, outlen) bits.
        e = int.from_bytes(full[:size], "big") % n
        r, s = off_curve.forge(e, key, g, p, a, n)
        out.append(c_array(f"webpki_sig_{name}", tlv(0x30, der_integer(r) + der_integer(s)),
                           f"forged: satisfies the verification equation under the {label} key\n"
                           f"(1, 0) over the webpki_tbs_{source} signed message's {digest} digest"))
    return out


def sigalg_from_request(ossl, key_file, digest, extra):
    request = sh(ossl, "req", "-new", "-key", str(KEY_DIR / key_file), "-subj", "/CN=sigalg",
                 f"-{digest}", *extra, "-outform", "DER")
    fields = children(request)
    if len(fields) != 3:
        sys.exit("certification request is not three fields")
    return fields[1]


def main():
    ossl, version = find_openssl()
    out = [
        "// SubjectPublicKeyInfo, AlgorithmIdentifier and signature vectors for",
        "// test/webpki_spki_test.c and test/webpki_sigalg_test.c. Generated by",
        "// test/gen_webpki_sigalg_vectors.py, which quotes the openssl commands;",
        f"// regenerate, never edit. Produced with {version}.",
        "#ifndef CH_TEST_WEBPKI_SIGALG_VECTORS_H",
        "#define CH_TEST_WEBPKI_SIGALG_VECTORS_H",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        '#include "webpki.h"',
        "",
        "// clang-format off",
    ]
    with tempfile.TemporaryDirectory() as tmp:
        t = pathlib.Path(tmp)
        spki = {}
        pub = {}
        for label, (key_file, _) in KEYS.items():
            spki[label] = sh(ossl, "pkey", "-in", str(KEY_DIR / key_file), "-pubout", "-outform", "DER")
            pub[label] = t / f"{label}.pub.pem"
            sh(ossl, "pkey", "-in", str(KEY_DIR / key_file), "-pubout", "-out", str(pub[label]))
            out.append(c_array(f"webpki_spki_{label}", spki[label],
                               f"openssl pkey -in {key_file} -pubout -outform DER"))
        for name, der, comment in negative_spkis(spki):
            out.append(c_array(f"webpki_spki_{name}", der, comment))

        for name, label, digest, extra, expected in ADMITTED_SIGALGS:
            der = sigalg_from_request(ossl, KEYS[label][0], digest, extra)
            if der.hex() != expected:
                sys.exit(f"openssl writes {name} as {der.hex()}, not the RFC's {expected}")
            out.append(c_array(f"webpki_sigalg_{name}", der,
                               f"signatureAlgorithm of openssl req -{digest} under {KEYS[label][0]}"))
        for name, label, digest, extra in REFUSED_SIGALGS:
            der = sigalg_from_request(ossl, KEYS[label][0], digest, extra)
            out.append(c_array(f"webpki_sigalg_{name}", der,
                               f"signatureAlgorithm of openssl req -{digest} {' '.join(extra)} "
                               f"under {KEYS[label][0]}".replace("  ", " ")))
        out.append(c_array("webpki_sigalg_ecdsa_sha256_null", bytes.fromhex(ECDSA_SHA256_NULL),
                           "ecdsa-with-SHA256 with a NULL parameter, which RFC 5758 section 3.2 omits"))
        out.append(c_array("webpki_sigalg_rsa_sha256_absent", bytes.fromhex(RSA_SHA256_ABSENT),
                           "sha256WithRSAEncryption with the NULL parameter absent"))

        rows = []
        for name, label, sigalg, digest, length in SIGNATURES:
            out += sign_row(ossl, t, pub, name, label, digest, length)
            rows.append((name, label, sigalg))
        for name, label, digest, length in CAP_SIGNATURES:
            out += sign_row(ossl, t, pub, name, label, digest, length)
        out += wrong_end_rows(ossl, t, pub)
        out += off_curve_rows(ossl, t)

    out.append("// One signature row: the signer's SPKI, the algorithm, the TBS content")
    out.append("// and the signature over its SEQUENCE header and content.")
    out.append("typedef struct {")
    out.append("    const char *name;")
    out.append("    const uint8_t *spki;")
    out.append("    size_t spki_len;")
    out.append("    uint8_t sigalg;")
    out.append("    const uint8_t *tbs;")
    out.append("    size_t tbs_len;")
    out.append("    const uint8_t *sig;")
    out.append("    size_t sig_len;")
    out.append("} webpki_signature_vector;")
    out.append("")
    out.append(f"static const webpki_signature_vector webpki_signature_vectors[{len(rows)}] = {{")
    for name, label, sigalg in rows:
        out.append(f'    {{"{name}", webpki_spki_{label}, sizeof webpki_spki_{label}, {sigalg},')
        out.append(f"     webpki_tbs_{name}, sizeof webpki_tbs_{name}, webpki_sig_{name},")
        out.append(f"     sizeof webpki_sig_{name}}},")
    out.append("};")
    out.append("// clang-format on")
    out.append("")
    out.append("#endif")
    OUT.write_text("\n".join(out) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
