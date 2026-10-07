#!/usr/bin/env python3
"""Regenerates test/rsa_sign_vectors.h, the known answers for rsa_sign.c.

Usage: python3 test/gen_rsa_sign_vectors.py

RSA-PSS signing draws a fresh salt, so the openssl CLI cannot produce a
known answer: two runs over one message give two signatures. This script
fixes the salt instead. It mints a key with OpenSSL 3, encodes EMSA-PSS
(RFC 8017 9.1.1) here in Python over a salt of its own choosing, raises
the encoded message to the private exponent, and writes the result as the
one signature rsa_pss_sign must produce when it is handed that salt.
test/rsa_sign_test.c passes it.

The Python encoder is the second implementation, not the oracle. Every
signature this script emits is checked twice before it lands: openssl
verifies it against the public key under the same PSS parameters, and
the script recovers the encoded message with `openssl pkeyutl
-verifyrecover -pkeyopt rsa_padding_mode:none` and compares it byte for
byte with what the encoder built. A wrong salt length, a wrong mask or a
wrong exponent fails here instead of shipping a vector that agrees with
a matching bug in C.

Four key sizes: RSA-2048, the floor rsa.h admits; RSA-2112, whose primes
are 132 bytes, a length that is no multiple of the 8 bytes of a 64-bit
word; RSA-3072, the top of the device range; and RSA-4096, the top of
the TRUST=webpki range, which test/rsa_sign_test.c signs because it
builds with -DCH_RSA_MODULUS_MAX=512 as bin/rsa_test does.

Each key carries the five integers of the Chinese remainder theorem
beside its modulus and private exponent: the primes p and q, dp = d mod
(p - 1), dq = d mod (q - 1) and qinv = q^-1 mod p, each left-padded to
half the modulus's length, the shape ch_rsa_priv holds them in for a
host object (rsa_sign.h). openssl prints them, and the script checks
each against the definition before it writes it.

The exact commands, per key size:

  openssl genrsa -out key.pem <bits>
  openssl rsa -in key.pem -pubout -out pub.pem
  openssl rsa -in key.pem -noout -modulus            (the modulus)
  openssl rsa -in key.pem -noout -text               (the private exponent,
                                                      and prime1, prime2,
                                                      exponent1, exponent2
                                                      and coefficient)
  openssl dgst -sha256 -verify pub.pem -signature sig
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32
    -sigopt rsa_mgf1_md:sha256 msg
  openssl pkeyutl -verifyrecover -pubin -inkey pub.pem -in sig
    -pkeyopt rsa_padding_mode:none                   (the encoded message)

The keys are fresh on every run, so the committed header changes when it
is regenerated; vectors are regenerate-never-edit snapshots.
"""

import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).parent
OUT = HERE / "rsa_sign_vectors.h"

# (bits, message, salt byte). One message and one salt per key; the salt
# is a constant byte repeated, which no encoder step can produce by
# accident from the digest.
# Each message is exactly 16 bytes, one full row of the emitted array:
# clang-format repacks a row it can fill further, and a short last row
# would come back reflowed and fail make lint-format after every
# regeneration.
KEYS = [
    (2048, b"chapulin rsa2048", 0x5a),
    (2112, b"chapulin rsa2112", 0x69),
    (3072, b"chapulin rsa3072", 0xa5),
    (4096, b"chapulin rsa4096", 0x3c),
]

HLEN = 32
SLEN = 32


def sh(*cmd, stdin=None):
    r = subprocess.run(cmd, input=stdin, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"{cmd[0]} failed: {r.stderr.decode()[:400]}")
    return r.stdout


def c_array(name, data, comment):
    lines = [f"// {line}" for line in comment.splitlines()]
    lines.append(f"static const uint8_t {name}[] = {{")
    for i in range(0, len(data), 16):
        chunk = ", ".join(f"0x{b:02x}" for b in data[i : i + 16])
        lines.append(f"    {chunk},")
    lines.append("};")
    return "\n".join(lines) + "\n"


def text_field(text, name):
    """The big integer openssl prints under `name:` as indented hex."""
    m = re.search(rf"^{name}:\s*\n((?:\s+[0-9a-f:]+\n)+)", text, re.M)
    if m is None:
        sys.exit(f"openssl rsa -text printed no {name}")
    return int(re.sub(r"[^0-9a-f]", "", m.group(1)), 16)


def crt_integers(text, n, d, bits):
    """p, q, dp, dq and qinv as openssl printed them, each checked against
    RFC 8017 3.2's definition and against the shape ch_rsa_priv takes:
    half the modulus's bytes, with the top bit of each prime set."""
    p = text_field(text, "prime1")
    q = text_field(text, "prime2")
    dp = text_field(text, "exponent1")
    dq = text_field(text, "exponent2")
    qinv = text_field(text, "coefficient")
    half = len(n) // 2
    n_int = int.from_bytes(n, "big")
    if p * q != n_int or p.bit_length() != 8 * half or q.bit_length() != 8 * half:
        sys.exit(f"the primes do not have the shape ch_rsa_priv takes at {bits}")
    if dp != d % (p - 1) or dq != d % (q - 1) or qinv * q % p != 1:
        sys.exit(f"a CRT integer does not match its definition at {bits}")
    return [v.to_bytes(half, "big") for v in (p, q, dp, dq, qinv)]


def mgf1(seed, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def pss_encode(msg_hash, salt, em_len):
    """EMSA-PSS-ENCODE with emBits = 8 * em_len - 1, the one case
    rsa_sign.c encodes: every modulus it signs with has its top bit set."""
    h = hashlib.sha256(b"\x00" * 8 + msg_hash + salt).digest()
    db = b"\x00" * (em_len - SLEN - HLEN - 2) + b"\x01" + salt
    masked = bytes(a ^ b for a, b in zip(db, mgf1(h, em_len - HLEN - 1)))
    return bytes([masked[0] & 0x7F]) + masked[1:] + h + b"\xbc"


def main():
    ossl = shutil.which("openssl",
                        path="/opt/homebrew/bin:/usr/bin:" + (os.environ.get("PATH") or ""))
    if ossl is None:
        sys.exit("openssl not found")
    version = sh(ossl, "version").decode().strip().split(" (")[0]

    out = [
        "// RSA-PSS signing known answers: keys, fixed salts and the one",
        "// signature each produces. Generated by",
        "// test/gen_rsa_sign_vectors.py, which quotes the openssl commands;",
        f"// regenerate, never edit. Produced with {version}.",
        "#ifndef CH_TEST_RSA_SIGN_VECTORS_H",
        "#define CH_TEST_RSA_SIGN_VECTORS_H",
        "",
        "#include <stdint.h>",
        "",
    ]
    with tempfile.TemporaryDirectory() as tmp:
        t = pathlib.Path(tmp)
        for bits, message, salt_byte in KEYS:
            key, pub, sig = t / "key.pem", t / "pub.pem", t / "sig"
            msg = t / "msg"
            msg.write_bytes(message)
            sh(ossl, "genrsa", "-out", str(key), str(bits))
            sh(ossl, "rsa", "-in", str(key), "-pubout", "-out", str(pub))
            modulus = sh(ossl, "rsa", "-in", str(key), "-noout", "-modulus")
            n = bytes.fromhex(modulus.decode().split("=")[1].strip())
            if len(n) != bits // 8 or n[0] & 0x80 == 0 or n[-1] & 1 == 0:
                sys.exit(f"modulus shape wrong at {bits}")
            text = sh(ossl, "rsa", "-in", str(key), "-noout", "-text").decode()
            d = text_field(text, "privateExponent")
            p, q, dp, dq, qinv = crt_integers(text, n, d, bits)

            salt = bytes([salt_byte]) * SLEN
            em = pss_encode(hashlib.sha256(message).digest(), salt, len(n))
            s = pow(int.from_bytes(em, "big"), d, int.from_bytes(n, "big"))
            signature = s.to_bytes(len(n), "big")
            sig.write_bytes(signature)

            # First check: openssl accepts the signature under the
            # parameters rsa_pss_rsae_sha256 fixes.
            sh(ossl, "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig),
               "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
               "-sigopt", "rsa_mgf1_md:sha256", str(msg))
            # Second check: the encoded message openssl recovers is the
            # one the encoder above built.
            recovered = sh(ossl, "pkeyutl", "-verifyrecover", "-pubin", "-inkey", str(pub),
                           "-in", str(sig), "-pkeyopt", "rsa_padding_mode:none")
            if recovered != em:
                sys.exit(f"recovered encoded message differs at {bits}")

            name = f"rsa_sign_{bits}"
            out.append(c_array(f"{name}_n", n,
                               f"RSA-{bits} modulus, {len(n)} bytes big-endian."))
            out.append(c_array(f"{name}_d", d.to_bytes(len(n), "big"),
                               f"RSA-{bits} private exponent, left-padded to {len(n)} bytes."))
            half = len(n) // 2
            out.append(c_array(f"{name}_p", p, f"RSA-{bits} first prime, {half} bytes."))
            out.append(c_array(f"{name}_q", q, f"RSA-{bits} second prime, {half} bytes."))
            out.append(c_array(f"{name}_dp", dp,
                               f"RSA-{bits} d mod (p - 1), left-padded to {half} bytes."))
            out.append(c_array(f"{name}_dq", dq,
                               f"RSA-{bits} d mod (q - 1), left-padded to {half} bytes."))
            out.append(c_array(f"{name}_qinv", qinv,
                               f"RSA-{bits} q^-1 mod p, left-padded to {half} bytes."))
            out.append(c_array(f"{name}_msg", message,
                               "The signed message. The test hashes it with the library's"
                               "\nown SHA-256, so no digest is hardcoded here."))
            out.append(c_array(f"{name}_salt", salt,
                               "The salt rsa_pss_sign takes for this vector."))
            out.append(c_array(f"{name}_sig", signature,
                               "The signature rsa_pss_sign must produce over that salt."))
    out.append("#endif")
    OUT.write_text("\n".join(out).replace("\n\n\n", "\n\n") + "\n")
    # clang-format chooses the row length of an array whose last row is
    # short, and RSA-2112's primes are 132 bytes, so the formatter make
    # lint-format runs writes the layout that lint holds.
    fmt = shutil.which("clang-format",
                       path="/opt/homebrew/opt/llvm/bin:" + (os.environ.get("PATH") or ""))
    if fmt is None:
        sys.exit("clang-format not found: the header would fail make lint-format")
    sh(fmt, "-i", str(OUT))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
