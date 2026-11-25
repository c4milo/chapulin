#!/usr/bin/env python3
"""Regenerates test/hash_vectors.h.

Usage: python3 test/gen_hash_vectors.py

The vectors of hash.h's calls (docs/decisions.md 246). The script reads
the published ones out of the RFC texts docs/rfcs/ carries, whose bytes
SHA256SUMS holds, and computes each one again with Python's hashlib and
hmac. It stops if the two differ, so a vector here is the RFC's own and
no value is typed by hand:

- SHA-256, SHA-384 and SHA-512: the rows of RFC 6234 section 8.5's test
  table (rfc6234.txt:5359-5568) whose message is whole bytes, a row with
  no extra bits. Rows 3 and 4 repeat their message 1,000,000 and 10
  times, and the test adds each repeat as one update.
- HMAC-SHA-256, HMAC-SHA-384 and HMAC-SHA-512: the seven test cases of
  RFC 4231 section 4 (rfc4231.txt:175-373). Test case 5 keeps the first
  128 bits of each tag.
- HKDF-SHA-256: the three test cases of RFC 5869 Appendix A
  (rfc5869.txt:516-622). RFC 5869 prints no SHA-384 or SHA-512 case, so
  the script derives two for each of those hashes with its own HKDF over
  Python's hmac, which it first holds to the three printed cases.
- SHA3-256, SHA3-512, SHAKE128 and SHAKE256: no RFC prints them, and
  docs/rfcs carries FIPS 202 no more than FIPS 180-4. hashlib computes
  each digest, over messages whose lengths reach each side of the rates,
  136 and 72 bytes for SHA-3 and 168 and 136 for SHAKE.
"""

import hashlib
import hmac
import pathlib
import re

HERE = pathlib.Path(__file__).parent
RFCS = HERE.parent / "docs" / "rfcs"
OUT = HERE / "hash_vectors.h"

# The algorithm numbers of hash.h.
ALGORITHMS = {"sha256": 1, "sha384": 2, "sha512": 3}
# The lengths the SHA-3 and SHAKE rows hash: each side of every rate.
SPONGE_LENGTHS = [0, 1, 71, 72, 73, 135, 136, 137, 167, 168, 169, 300]
# The bytes a SHAKE row squeezes: more than two blocks of either rate.
SHAKE_OUT_LEN = 400


def rfc_lines(name):
    """The RFC's lines without its page breaks: the form feed, the footer
    and the header lines around it, which fall inside RFC 6234's code."""
    lines = (RFCS / name).read_text().split("\n")
    kept = []
    for line in lines:
        if "\f" in line or re.match(r"^(Eastlake & Hansen|RFC 6234 |Krawczyk & Eronen|RFC 5869 )",
                                    line):
            continue
        kept.append(line)
    return kept


def c_string(text):
    """The bytes of one or more adjacent C string literals."""
    out = bytearray()
    for literal in re.findall(r'"((?:[^"\\]|\\.)*)"', text):
        i = 0
        while i < len(literal):
            if literal.startswith("\\x", i):
                out.append(int(literal[i + 2:i + 4], 16))
                i += 4
            else:
                out.append(ord(literal[i]))
                i += 1
    return bytes(out)


def rfc6234_tests():
    """RFC 6234's test strings, by name, with the names inside resolved."""
    text = "\n".join(rfc_lines("rfc6234.txt"))
    defines = {}
    for name, body in re.findall(r"#define (TEST\w+)\s+((?:.*\\\n)*.*)", text):
        defines[name] = body.replace("\\\n", " ")
    tests = {}

    def resolve(name):
        if name not in tests:
            body = re.sub(r"/\*.*?\*/", "", defines[name])
            parts = re.findall(r'"(?:[^"\\]|\\.)*"(?:\s*"(?:[^"\\]|\\.)*")*|TEST\w+', body)
            tests[name] = b"".join(resolve(p) if p.startswith("TEST") else c_string(p)
                                   for p in parts)
        return tests[name]

    for name in defines:
        resolve(name)
    return tests


def sha2_cases():
    """RFC 6234's rows of whole bytes for the three SHA-2 hashes:
    (algorithm, message, repeat count, digest)."""
    tests = rfc6234_tests()
    text = "\n".join(rfc_lines("rfc6234.txt"))
    table = text[text.index("} hashes[HASHCOUNT] = {"):text.index("} hmachashes[HMACTESTCOUNT] = {")]
    cases = []
    for name, algorithm in (("SHA256", "sha256"), ("SHA384", "sha384"), ("SHA512", "sha512")):
        block = table[table.index('{ "%s", %s,' % (name, name)):]
        block = block[:block.index("_SEED")]
        row = (r"/\* (\d+) \*/ \{ (TEST\w+|\"[^\"]*\"), (?:length\(\w+\)|\d+), (\d+), "
               r"(0x[0-9A-F]+|0), (\d+),\s*((?:\"[0-9A-F]+\"\s*)+)\}")
        rows = re.findall(row, block)
        assert len(rows) == 10, (name, len(rows))
        for number, message, repeat, _, extra_bits, digest in rows:
            if extra_bits != "0":
                continue
            data = tests[message] if message.startswith("TEST") else c_string(message)
            want = bytes.fromhex("".join(re.findall(r'"([0-9A-F]+)"', digest)))
            assert hashlib.new(algorithm, data * int(repeat)).digest() == want, (name, number)
            cases.append((algorithm, data, int(repeat), want))
    assert len(cases) == 21, len(cases)
    return cases


def hmac_cases():
    """RFC 4231 section 4's test cases: (algorithm, key, data, tag)."""
    text = (RFCS / "rfc4231.txt").read_text().split("\n")
    starts = [i for i, line in enumerate(text) if re.match(r"^4\.\d+\.  Test Case \d", line)]
    assert len(starts) == 7, starts
    ends = starts[1:] + [next(i for i, line in enumerate(text) if line.startswith("5.  "))]
    cases = []
    for start, end in zip(starts, ends):
        fields = {}
        current = None
        for line in text[start + 1:end]:
            # Test case 3 prints its key line with no "=" (rfc4231.txt:236).
            m = re.match(r"^\s+(Key|Data|HMAC-SHA-\d+) =?\s+([0-9a-f]+)\b", line)
            if m:
                current = m.group(1)
                fields[current] = m.group(2)
                continue
            m = re.match(r"^\s{10,}([0-9a-f]{2,})(\s|$)", line)
            if m and current:
                fields[current] += m.group(1)
            elif line.strip() and not line.startswith(" " * 10):
                current = None
        key, data = bytes.fromhex(fields["Key"]), bytes.fromhex(fields["Data"])
        for algorithm in ALGORITHMS:
            tag = bytes.fromhex(fields["HMAC-SHA-" + algorithm[3:]])
            assert hmac.new(key, data, algorithm).digest()[:len(tag)] == tag, (start, algorithm)
            cases.append((algorithm, key, data, tag))
    return cases


def hkdf(algorithm, salt, ikm, info, length):
    """RFC 5869 sections 2.2 and 2.3 over Python's hmac."""
    prk = hmac.new(salt, ikm, algorithm).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), algorithm).digest()
        okm += block
        counter += 1
    return prk, okm[:length]


def hkdf_cases():
    """RFC 5869 Appendix A's SHA-256 cases, and two of the script's own
    for SHA-384 and for SHA-512: (algorithm, ikm, salt, info, prk, okm)."""
    text = "\n".join(rfc_lines("rfc5869.txt"))
    cases = []
    for number in (1, 2, 3):
        body = text[text.index("A.%d.  Test Case %d" % (number, number)):]
        body = body[:body.index("A.%d." % (number + 1))]
        assert "Hash = SHA-256" in body, number
        values = {}
        for name in ("IKM", "salt", "info", "PRK", "OKM"):
            m = re.search(r"\b%s\s+= (?:0x)?((?:[0-9a-f]+\s*)*)\(\d+ octets\)" % name, body)
            values[name] = bytes.fromhex("".join(m.group(1).split()))
        length = int(re.search(r"L\s+= (\d+)", body).group(1))
        assert len(values["OKM"]) == length, number
        prk, okm = hkdf("sha256", values["salt"], values["IKM"], values["info"], length)
        assert (prk, okm) == (values["PRK"], values["OKM"]), number
        cases.append(("sha256", values["IKM"], values["salt"], values["info"], prk, okm))
    for algorithm in ("sha384", "sha512"):
        ikm = bytes(range(0x20, 0x20 + 70))
        salt = bytes(range(0x90, 0x90 + 50))
        info = bytes(range(0x30, 0x30 + 40))
        prk, okm = hkdf(algorithm, salt, ikm, info, 200)
        cases.append((algorithm, ikm, salt, info, prk, okm))
        prk, okm = hkdf(algorithm, b"", ikm[:22], b"", 42)
        cases.append((algorithm, ikm[:22], b"", b"", prk, okm))
    return cases


def sponge_message(length):
    """A message of length bytes that no two lengths share a prefix of."""
    return bytes((i * 31 + length) & 0xFF for i in range(length))


def c_bytes(data):
    return ", ".join("0x%02x" % b for b in data) if data else "0"


class Blobs:
    """Each byte string once, as a static array the rows point at."""

    def __init__(self):
        self.lines = []

    def __call__(self, data):
        name = "blob_%d" % len(self.lines)
        self.lines.append("static const uint8_t %s[%d] = {%s};" % (name, max(len(data), 1),
                                                                    c_bytes(data)))
        return name


def main():
    blob = Blobs()
    sha2 = ["    {%d, %s, %d, %d, %s, %d}," % (ALGORITHMS[a], blob(m), len(m), r, blob(d), len(d))
            for a, m, r, d in sha2_cases()]
    macs = ["    {%d, %s, %d, %s, %d, %s, %d}," % (ALGORITHMS[a], blob(k), len(k), blob(m), len(m),
                                                  blob(t), len(t)) for a, k, m, t in hmac_cases()]
    hkdfs = ["    {%d, %s, %d, %s, %d, %s, %d, %s, %d, %s, %d}," % (
        ALGORITHMS[a], blob(i), len(i), blob(s), len(s), blob(n), len(n), blob(p), len(p),
        blob(o), len(o)) for a, i, s, n, p, o in hkdf_cases()]
    sponges = []
    for length in SPONGE_LENGTHS:
        message = sponge_message(length)
        sponges.append("    {%s, %d, %s, %s, %s, %s}," % (
            blob(message), length, blob(hashlib.sha3_256(message).digest()),
            blob(hashlib.sha3_512(message).digest()),
            blob(hashlib.shake_128(message).digest(SHAKE_OUT_LEN)),
            blob(hashlib.shake_256(message).digest(SHAKE_OUT_LEN))))
    lines = ["// Generated by test/gen_hash_vectors.py; do not edit.",
             "#ifndef CH_TEST_HASH_VECTORS_H", "#define CH_TEST_HASH_VECTORS_H", "",
             "#include <stddef.h>", "#include <stdint.h>", ""]
    lines += blob.lines
    lines += ["", "// RFC 6234 section 8.5: message repeated repeat_count times.",
              "static const struct {", "    uint8_t algorithm;", "    const uint8_t *message;",
              "    size_t message_len;", "    size_t repeat_count;", "    const uint8_t *digest;",
              "    size_t digest_len;", "} sha2_vectors[] = {"]
    lines += sha2 + ["};", ""]
    lines += ["// RFC 4231 section 4: tag holds tag_len bytes, the first bytes of the HMAC.",
              "static const struct {", "    uint8_t algorithm;", "    const uint8_t *key;",
              "    size_t key_len;", "    const uint8_t *data;", "    size_t data_len;",
              "    const uint8_t *tag;", "    size_t tag_len;", "} hmac_vectors[] = {"]
    lines += macs + ["};", ""]
    lines += ["// RFC 5869 Appendix A, and the SHA-384 and SHA-512 rows Python derives.",
              "static const struct {", "    uint8_t algorithm;", "    const uint8_t *ikm;",
              "    size_t ikm_len;", "    const uint8_t *salt;", "    size_t salt_len;",
              "    const uint8_t *info;", "    size_t info_len;", "    const uint8_t *prk;",
              "    size_t prk_len;", "    const uint8_t *okm;", "    size_t okm_len;",
              "} hkdf_vectors[] = {"]
    lines += hkdfs + ["};", ""]
    lines += ["// hashlib's SHA3-256, SHA3-512, and SHAKE_OUT_LEN bytes of SHAKE128 and SHAKE256.",
              "#define SHAKE_OUT_LEN %d" % SHAKE_OUT_LEN,
              "static const struct {", "    const uint8_t *message;", "    size_t message_len;",
              "    const uint8_t *sha3_256;", "    const uint8_t *sha3_512;",
              "    const uint8_t *shake128;", "    const uint8_t *shake256;",
              "} sponge_vectors[] = {"]
    lines += sponges + ["};", "", "#endif", ""]
    OUT.write_text("\n".join(lines))
    print("gen_hash_vectors: %d SHA-2 rows, %d HMAC rows, %d HKDF rows, %d sponge rows"
          % (len(sha2), len(macs), len(hkdfs), len(sponges)))


if __name__ == "__main__":
    main()
