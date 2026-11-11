#!/usr/bin/env python3
"""Regenerates test/scram_vectors.h.

Usage: python3 test/gen_scram_vectors.py

The vectors of scram.h's calls (docs/decisions.md 222). The script reads
the published ones out of the RFC texts docs/rfcs/ carries, whose bytes
SHA256SUMS holds, and computes each one again with Python's hashlib and
hmac. It stops if the two differ, so a vector here is the RFC's own and
no value is typed by hand:

- HMAC-SHA-256: the seven test cases of RFC 4231 section 4
  (rfc4231.txt:175-373). Test case 5 keeps the first 128 bits of the tag.
  One more case has an empty key and an empty message, from Python's hmac
  alone.
- PBKDF2-HMAC-SHA-256: the two vectors of RFC 7914 section 11
  (rfc7914.txt:631-643), with 1 and with 80,000 iterations. Two more are
  from Python's hashlib alone: a password of 100 bytes, which HMAC hashes
  first, and the SHA-256 of the longest output scram.h permits.
- SCRAM-SHA-256: the exchange of RFC 7677 section 3
  (rfc7677.txt:122-134). The script writes the four messages, and the
  test computes the ClientProof and the ServerSignature from the password
  with scram.h's calls.
- SHA-256: FIPS 180-4's one-block and two-block examples, the empty
  message and a message of 1,000 bytes, computed with hashlib.

For ch_tls_server_end_point (RFC 5929 section 4.1) the script mints one
self-signed certificate for each signature algorithm with OpenSSL:

  openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.der
    -outform DER -subj /CN=chapulin-test -days 3650 -<hash>
  ... -newkey ec -pkeyopt ec_paramgen_curve:P-256 -<hash>
  ... -newkey rsa:2048 -<hash> -sigopt rsa_padding_mode:pss
    -sigopt rsa_pss_saltlen:<n>
  ... -newkey ed25519

It checks with `openssl asn1parse` that each certificate names the
signature algorithm the row expects, and writes the digest hashlib
computes under the hash RFC 5929 takes for it: SHA-256 in place of MD5
and SHA-1. A row with no digest is a certificate the call refuses:
sha224WithRSAEncryption and Ed25519. The keys are fresh on every run, so
the header changes when it is regenerated; vectors are
regenerate-never-edit snapshots.
"""

import hashlib
import hmac
import pathlib
import re
import subprocess
import tempfile

HERE = pathlib.Path(__file__).parent
RFCS = HERE.parent / "docs" / "rfcs"
OUT = HERE / "scram_vectors.h"

# (name, openssl -newkey arguments, hash flag, the algorithm asn1parse
# prints last, the hash RFC 5929 takes or None for a refusal)
CERTS = [
    ("rsa_sha256", ["rsa:2048"], "sha256", "sha256WithRSAEncryption", "sha256"),
    ("rsa_sha384", ["rsa:2048"], "sha384", "sha384WithRSAEncryption", "sha384"),
    ("rsa_sha512", ["rsa:2048"], "sha512", "sha512WithRSAEncryption", "sha512"),
    ("rsa_sha1", ["rsa:2048"], "sha1", "sha1WithRSAEncryption", "sha256"),
    ("rsa_md5", ["rsa:2048"], "md5", "md5WithRSAEncryption", "sha256"),
    ("rsa_sha224", ["rsa:2048"], "sha224", "sha224WithRSAEncryption", None),
    ("ecdsa_sha256", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"], "sha256", "ecdsa-with-SHA256",
     "sha256"),
    ("ecdsa_sha384", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"], "sha384", "ecdsa-with-SHA384",
     "sha384"),
    ("ecdsa_sha512", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"], "sha512", "ecdsa-with-SHA512",
     "sha512"),
    ("ecdsa_sha1", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"], "sha1", "ecdsa-with-SHA1",
     "sha256"),
    ("pss_sha256", ["rsa:2048", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"],
     "sha256", "rsassaPss", "sha256"),
    ("pss_sha384", ["rsa:2048", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:48"],
     "sha384", "rsassaPss", "sha384"),
    ("pss_sha512", ["rsa:2048", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:64"],
     "sha512", "rsassaPss", "sha512"),
    ("pss_sha1", ["rsa:2048", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:20"],
     "sha1", "rsassaPss", "sha256"),
    ("ed25519", ["ed25519"], None, "ED25519", None),
]


def run(*args):
    return subprocess.run(args, capture_output=True, check=True).stdout


def rfc(name):
    return (RFCS / name).read_text().split("\n")


def hmac_cases():
    """RFC 4231 section 4's test cases: (key, data, HMAC-SHA-256 tag)."""
    text = rfc("rfc4231.txt")
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
        key, data, tag = (bytes.fromhex(fields[k]) for k in ("Key", "Data", "HMAC-SHA-256"))
        assert hmac.new(key, data, hashlib.sha256).digest()[:len(tag)] == tag, start
        assert len(tag) in (16, 32)
        cases.append((key, data, tag))
    cases.append((b"", b"", hmac.new(b"", b"", hashlib.sha256).digest()))
    return cases


def pbkdf2_cases():
    """RFC 7914 section 11's PBKDF2-HMAC-SHA-256 vectors."""
    text = "\n".join(rfc("rfc7914.txt"))
    pattern = (r'PBKDF2-HMAC-SHA-256 \(P="(\w+)", S="(\w+)",\s+c=(\d+), dkLen=(\d+)\) =\n'
               r"((?:   (?:[0-9a-f]{2} ?)+\n)+)")
    cases = []
    for password, salt, count, dk_len, dk in re.findall(pattern, text):
        key = bytes.fromhex("".join(dk.split()))
        assert len(key) == int(dk_len)
        assert hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(count),
                                   len(key)) == key
        cases.append((password.encode(), salt.encode(), int(count), key))
    assert len(cases) == 2, len(cases)
    long_password = bytes(range(1, 101))
    cases.append((long_password, b"salt of a long password", 3,
                  hashlib.pbkdf2_hmac("sha256", long_password, b"salt of a long password", 3, 40)))
    return cases


def scram_example():
    """RFC 7677 section 3's exchange, as the strings a test needs."""
    text = rfc("rfc7677.txt")
    block = " ".join(text[121:134])
    assert "'user' and password 'pencil'" in block
    joined = "".join("".join(line.split()) if not line.startswith("   C:") and
                     not line.startswith("   S:") else "\n" + line.strip()
                     for line in text[125:134])
    messages = [m.split(": ", 1) for m in joined.strip().split("\n")]
    assert [m[0] for m in messages] == ["C", "S", "C", "S"], messages
    client_first, server_first, client_final, server_final = (m[1] for m in messages)
    assert client_first.startswith("n,,")
    bare = client_first[3:]
    without_proof, proof = client_final.rsplit(",p=", 1)
    assert server_final.startswith("v=")
    signature = server_final[2:]
    fields = dict(f.split("=", 1) for f in server_first.split(","))
    return {"password": "pencil", "client_first_bare": bare, "server_first": server_first,
            "client_final_without_proof": without_proof, "salt": fields["s"],
            "iteration_count": int(fields["i"]), "proof": proof, "signature": signature}


def last_algorithm(der_path):
    """The signatureAlgorithm of a certificate, as asn1parse names it."""
    lines = run("openssl", "asn1parse", "-inform", "DER", "-in", der_path).decode().split("\n")
    depth1 = [i for i, line in enumerate(lines) if "d=1 " in line]
    # The Certificate's second field: the lines between the last two
    # depth-1 headers.
    for line in lines[depth1[-2]:depth1[-1]]:
        if "OBJECT" in line:
            return line.rsplit(":", 1)[1].strip()
    raise AssertionError(der_path)


def c_array(name, data):
    out = []
    for i in range(0, len(data), 16):
        out.append("    " + ", ".join("0x%02x" % b for b in data[i:i + 16]) + ",")
    return "static const uint8_t %s[%d] = {\n%s\n};\n" % (name, len(data), "\n".join(out))


def main():
    out = [
        "// Generated by test/gen_scram_vectors.py; regenerate, never edit.",
        "#ifndef CH_SCRAM_VECTORS_H",
        "#define CH_SCRAM_VECTORS_H",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
    ]
    rows = []
    for i, (key, data, tag) in enumerate(hmac_cases()):
        out += [c_array("hmac_key_%d" % i, key or b"\x00"),
                c_array("hmac_data_%d" % i, data or b"\x00"), c_array("hmac_tag_%d" % i, tag)]
        rows.append("    {hmac_key_%d, %d, hmac_data_%d, %d, hmac_tag_%d, sizeof hmac_tag_%d},"
                    % (i, len(key), i, len(data), i, i))
    out += ["// RFC 4231 section 4: tag_len is 16 for test case 5, which keeps the tag's",
            "// first 128 bits, and 32 for the others. The last row has an empty key and",
            "// an empty message, and each array of it holds one byte that is not read.",
            "static const struct {", "    const uint8_t *key;", "    size_t key_len;",
            "    const uint8_t *data;", "    size_t data_len;", "    const uint8_t *tag;",
            "    size_t tag_len;", "} hmac_vectors[] = {"] + rows + ["};", ""]

    rows = []
    for i, (password, salt, count, key) in enumerate(pbkdf2_cases()):
        out += [c_array("pbkdf2_password_%d" % i, password), c_array("pbkdf2_salt_%d" % i, salt),
                c_array("pbkdf2_key_%d" % i, key)]
        rows.append("    {pbkdf2_password_%d, sizeof pbkdf2_password_%d, pbkdf2_salt_%d, "
                    "sizeof pbkdf2_salt_%d, %d, pbkdf2_key_%d, sizeof pbkdf2_key_%d},"
                    % (i, i, i, i, count, i, i))
    out += ["// RFC 7914 section 11's two vectors, and one with a password of 100 bytes.",
            "static const struct {", "    const uint8_t *password;", "    size_t password_len;",
            "    const uint8_t *salt;", "    size_t salt_len;", "    uint32_t iteration_count;",
            "    const uint8_t *key;", "    size_t key_len;",
            "} pbkdf2_vectors[] = {"] + rows + ["};", ""]
    longest = hashlib.pbkdf2_hmac("sha256", b"passwd", b"salt", 1, 65536 * 32)
    out += ["// SHA-256 of the 2,097,152 bytes PBKDF2 writes for the password \"passwd\",",
            "// the salt \"salt\" and 1 iteration: CH_PBKDF2_OUT_LEN_MAX bytes, whose first",
            "// 64 are RFC 7914's first vector.",
            c_array("pbkdf2_longest_digest", hashlib.sha256(longest).digest())]

    scram = scram_example()
    out += ["// RFC 7677 section 3: the password, the three parts of the AuthMessage,",
            "// the salt and the iteration count the server sent, and the base64 of",
            "// the ClientProof and of the ServerSignature."]
    for name in ("password", "client_first_bare", "server_first", "client_final_without_proof",
                 "salt", "proof", "signature"):
        out.append('static const char scram_%s[] = "%s";' % (name, scram[name]))
    out += ["#define SCRAM_ITERATION_COUNT %d" % scram["iteration_count"], ""]

    rows = []
    messages = [b"", b"abc", b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", b"a" * 1000]
    for i, message in enumerate(messages):
        out += [c_array("sha256_message_%d" % i, message or b"\x00"),
                c_array("sha256_digest_%d" % i, hashlib.sha256(message).digest())]
        rows.append("    {sha256_message_%d, %d, sha256_digest_%d}," % (i, len(message), i))
    out += ["// SHA-256 of four messages. The first is empty, and its array holds one",
            "// byte that is not read.",
            "static const struct {", "    const uint8_t *message;", "    size_t message_len;",
            "    const uint8_t *digest;", "} sha256_vectors[] = {"] + rows + ["};", ""]

    rows = []
    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        for name, newkey, digest_flag, algorithm, end_point_hash in CERTS:
            der = str(tmp / (name + ".der"))
            flags = ["-" + digest_flag] if digest_flag else []
            run("openssl", "req", "-x509", "-newkey", newkey[0], *newkey[1:], "-nodes", "-keyout",
                str(tmp / "key.pem"), "-out", der, "-outform", "DER", "-subj", "/CN=chapulin-test",
                "-days", "3650", *flags)
            assert last_algorithm(der) == algorithm, (name, last_algorithm(der))
            cert = pathlib.Path(der).read_bytes()
            out.append(c_array("cert_" + name, cert))
            if end_point_hash is None:
                rows.append('    {"%s", cert_%s, sizeof cert_%s, NULL, 0},' % (name, name, name))
            else:
                digest = hashlib.new(end_point_hash, cert).digest()
                out.append(c_array("end_point_" + name, digest))
                rows.append('    {"%s", cert_%s, sizeof cert_%s, end_point_%s, sizeof end_point_%s},'
                            % (name, name, name, name, name))
    out += ["// RFC 5929 section 4.1: one certificate for each signature algorithm, and",
            "// its tls-server-end-point value. A row with no value is a certificate",
            "// ch_tls_server_end_point refuses.",
            "static const struct {", "    const char *name;", "    const uint8_t *cert;",
            "    size_t cert_len;", "    const uint8_t *end_point;", "    size_t end_point_len;",
            "} end_point_vectors[] = {"] + rows + ["};", "", "#endif", ""]
    OUT.write_text("\n".join(out))


if __name__ == "__main__":
    main()
