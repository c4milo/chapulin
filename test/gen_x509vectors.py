#!/usr/bin/env python3
"""Regenerates test/x509_vectors.h.

Usage: python3 test/gen_x509vectors.py [cert-dir]

With no argument the script mints a fresh own-CA hierarchy into a
temporary directory with OpenSSL 3 and generates from that, so
anyone can regenerate without prior material; the committed header
changes because the keys are fresh, which is fine — vectors are
regenerate-never-edit snapshots. With a cert-dir argument it reads
previously minted files instead. Either way the directory holds the
nine regeneration sources:

  leaf_eku.der           RSA-PSS-signed leaf, KU + EKU + BC present
  leaf_p256_eku.der      ECDSA-signed leaf, KU + EKU + BC present
  leaf_p256_real.der     ECDSA-signed leaf without extendedKeyUsage
  int_rsa.der            RSA-PSS-signed intermediate, CA-signed
  leaf_via_int_rsa.der   RSA-PSS-signed leaf, intermediate-signed
  int_p256.der           ECDSA-signed intermediate, CA-signed
  leaf_via_int_p256.der  ECDSA-signed leaf, intermediate-signed
  ca_modulus.bin         raw big-endian RSA-3072 CA modulus (384 bytes)
  ca_p256_xy.bin         raw uncompressed P-256 CA point, X||Y (64 bytes)

The certificates come from an OpenSSL 3.x own-CA issuance matching
docs/ca.md: a self-signed fleet CA (RSA-3072 signed with PSS,
saltlen 32, MGF1-SHA256; or P-256 with ecdsa-with-SHA256) issuing a
leaf whose extension file requests
"keyUsage = critical, digitalSignature", "extendedKeyUsage =
serverAuth", and "basicConstraints = CA:FALSE". The intermediates
come from the same CA with "basicConstraints = critical, CA:TRUE,
pathlen:0" and "keyUsage = critical, keyCertSign, cRLSign"; each
via-int leaf uses the leaf extension file and the intermediate's
key. ca_modulus.bin is the CA key's modulus from `openssl rsa
-noout -modulus`, hex-decoded; ca_p256_xy.bin is the CA public
point from `openssl ec -pubout -outform DER`, minus the SPKI
wrapper and the 0x04 marker.

Each array is sanity-checked before it is emitted (DER shape, key
sizes, EKU presence or absence), so a wrong input file fails loudly
instead of shipping a misleading vector. The leaf SPKI key bytes are
extracted here so the C test can assert the exact copied-out key.
"""

import os
import pathlib
import sys

OUT = pathlib.Path(__file__).with_name("x509_vectors.h")

EKU_OID = bytes.fromhex("06 03 55 1d 25".replace(" ", ""))

# Extension OID contents (2.5.29.x) and the intermediate's one
# admitted basicConstraints content: CA=TRUE with pathLen 0.
KU_OID_CONTENT = bytes.fromhex("551d0f")
EKU_OID_CONTENT = bytes.fromhex("551d25")
BC_OID_CONTENT = bytes.fromhex("551d13")
BC_CA_PATHLEN0 = bytes.fromhex("30060101ff020100")


LEAF_CNF = """keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
basicConstraints = CA:FALSE
"""
NO_EKU_CNF = """keyUsage = critical, digitalSignature
basicConstraints = CA:FALSE
"""
INT_CNF = """basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
"""


def sh(*cmd, stdin=None):
    import subprocess

    r = subprocess.run(cmd, input=stdin, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"{cmd[0]} failed: {r.stderr.decode()[:400]}")
    return r.stdout


def mint(tmp):
    """Mints the nine sources into tmp with OpenSSL, per docs/ca.md."""
    import shutil

    ossl = shutil.which("openssl", path="/opt/homebrew/bin:/usr/bin:" + (os.environ.get("PATH") or ""))
    if ossl is None:
        sys.exit("openssl not found")
    t = pathlib.Path(tmp)
    (t / "leaf.cnf").write_text(LEAF_CNF)
    (t / "no_eku.cnf").write_text(NO_EKU_CNF)
    (t / "int.cnf").write_text(INT_CNF)
    pss = ["-sha256", "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"]

    def key_rsa(name):
        sh(ossl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
           "-out", str(t / name))

    def key_p256(name):
        sh(ossl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(t / name))

    def issue(key, ca, cakey, cnf, out, sig):
        csr = sh(ossl, "req", "-new", "-key", str(t / key), "-subj", "/CN=vector")
        sh(ossl, "x509", "-req", "-CA", str(t / ca), "-CAkey", str(t / cakey), "-days", "14",
           "-extfile", str(t / cnf), "-out", str(t / out), *sig, stdin=csr)

    def der(pem, out):
        sh(ossl, "x509", "-in", str(t / pem), "-outform", "DER", "-out", str(t / out))

    key_rsa("ca_rsa.key")
    sh(ossl, "req", "-new", "-x509", "-key", str(t / "ca_rsa.key"), "-subj", "/CN=fleet-ca",
       "-days", "3650", "-out", str(t / "ca_rsa.pem"), *pss)
    key_p256("ca_p256.key")
    sh(ossl, "req", "-new", "-x509", "-key", str(t / "ca_p256.key"), "-subj", "/CN=fleet-ca",
       "-days", "3650", "-out", str(t / "ca_p256.pem"))
    for k in ["leaf_rsa.key", "int_rsa.key"]:
        key_rsa(k)
    for k in ["leaf_p256.key", "int_p256.key"]:
        key_p256(k)

    issue("leaf_rsa.key", "ca_rsa.pem", "ca_rsa.key", "leaf.cnf", "leaf_eku.pem", pss)
    issue("leaf_p256.key", "ca_p256.pem", "ca_p256.key", "leaf.cnf", "leaf_p256_eku.pem", [])
    issue("leaf_p256.key", "ca_p256.pem", "ca_p256.key", "no_eku.cnf", "leaf_p256_real.pem", [])
    issue("int_rsa.key", "ca_rsa.pem", "ca_rsa.key", "int.cnf", "int_rsa.pem", pss)
    issue("int_p256.key", "ca_p256.pem", "ca_p256.key", "int.cnf", "int_p256.pem", [])
    issue("leaf_rsa.key", "int_rsa.pem", "int_rsa.key", "leaf.cnf", "leaf_via_int_rsa.pem", pss)
    issue("leaf_p256.key", "int_p256.pem", "int_p256.key", "leaf.cnf", "leaf_via_int_p256.pem", [])
    for pem in ["leaf_eku", "leaf_p256_eku", "leaf_p256_real", "int_rsa", "int_p256",
                "leaf_via_int_rsa", "leaf_via_int_p256"]:
        der(pem + ".pem", pem + ".der")

    modulus = sh(ossl, "rsa", "-in", str(t / "ca_rsa.key"), "-noout", "-modulus")
    (t / "ca_modulus.bin").write_bytes(bytes.fromhex(modulus.decode().split("=")[1].strip()))
    spki = sh(ossl, "ec", "-in", str(t / "ca_p256.key"), "-pubout", "-outform", "DER")
    (t / "ca_p256_xy.bin").write_bytes(spki[-64:])
    return t


def read_tlv(data, off):
    """Returns (tag, content_off, content_len) for the TLV at off."""
    tag = data[off]
    first = data[off + 1]
    if first < 0x80:
        return tag, off + 2, first
    if first == 0x81:
        return tag, off + 3, data[off + 2]
    if first == 0x82:
        return tag, off + 4, (data[off + 2] << 8) | data[off + 3]
    sys.exit(f"offset {off}: length form 0x{first:02x} is out of scope")


def child(data, content_off, content_len, index):
    """Returns the TLV triple of the index-th child of a container."""
    off = content_off
    end = content_off + content_len
    for _ in range(index):
        _, c_off, c_len = read_tlv(data, off)
        off = c_off + c_len
        if off > end:
            sys.exit(f"offset {off}: child walk ran past the container")
    return read_tlv(data, off)


def leaf_spki_key(cert, rsa):
    """Extracts the SPKI key bytes: RSA modulus value or P-256 X||Y."""
    _, cert_off, cert_len = read_tlv(cert, 0)
    if cert[0] != 0x30 or cert_off + cert_len != len(cert):
        sys.exit("certificate is not one exact-fill SEQUENCE")
    tag, tbs_off, tbs_len = read_tlv(cert, cert_off)
    if tag != 0x30:
        sys.exit("TBSCertificate is not a SEQUENCE")
    # TBS field 6 is subjectPublicKeyInfo (after version, serial,
    # sigalg, issuer, validity, subject).
    tag, spki_off, spki_len = child(cert, tbs_off, tbs_len, 6)
    if tag != 0x30:
        sys.exit("subjectPublicKeyInfo is not a SEQUENCE")
    tag, bits_off, bits_len = child(cert, spki_off, spki_len, 1)
    if tag != 0x03 or cert[bits_off] != 0x00:
        sys.exit("SPKI BIT STRING is malformed or has unused bits")
    if not rsa:
        if bits_len != 66 or cert[bits_off + 1] != 0x04:
            sys.exit("P-256 point is not uncompressed 0x04||X||Y")
        return cert[bits_off + 2 : bits_off + 66]
    tag, seq_off, seq_len = read_tlv(cert, bits_off + 1)
    if tag != 0x30:
        sys.exit("RSAPublicKey is not a SEQUENCE")
    tag, mod_off, mod_len = child(cert, seq_off, seq_len, 0)
    if tag != 0x02 or cert[mod_off] != 0x00 or not cert[mod_off + 1] & 0x80:
        sys.exit("RSA modulus INTEGER lacks its one 0x00 pad octet")
    return cert[mod_off + 1 : mod_off + mod_len]


def ext_value(cert, oid_content):
    """Returns the extnValue content of the extension whose extnID
    content matches oid_content, or None when the certificate does
    not carry it."""
    _, cert_off, cert_len = read_tlv(cert, 0)
    _, tbs_off, tbs_len = read_tlv(cert, cert_off)
    # TBS field 7 is the extensions wrapper [3].
    tag, wrap_off, wrap_len = child(cert, tbs_off, tbs_len, 7)
    if tag != 0xA3:
        sys.exit("TBS field 7 is not the [3] extensions wrapper")
    tag, list_off, list_len = read_tlv(cert, wrap_off)
    if tag != 0x30:
        sys.exit("Extensions is not a SEQUENCE")
    off = list_off
    end = list_off + list_len
    while off < end:
        _, ext_off, ext_len = read_tlv(cert, off)
        tag, oid_off, oid_len = read_tlv(cert, ext_off)
        if tag != 0x06:
            sys.exit("extnID is not an OID")
        if cert[oid_off : oid_off + oid_len] == oid_content:
            tag, v_off, v_len = read_tlv(cert, oid_off + oid_len)
            if tag == 0x01:  # critical BOOLEAN
                tag, v_off, v_len = read_tlv(cert, v_off + v_len)
            if tag != 0x04:
                sys.exit("extnValue is not an OCTET STRING")
            return cert[v_off : v_off + v_len]
        off = ext_off + ext_len
    return None


def check_intermediate(cert, name):
    """Checks the intermediate's profile arm: basicConstraints
    CA=TRUE pathLen 0, keyUsage with keyCertSign, no EKU."""
    if ext_value(cert, BC_OID_CONTENT) != BC_CA_PATHLEN0:
        sys.exit(f"{name}: basicConstraints is not CA=TRUE pathLen 0")
    ku = ext_value(cert, KU_OID_CONTENT)
    if ku is None:
        sys.exit(f"{name}: keyUsage extension missing")
    tag, ku_off, ku_len = read_tlv(ku, 0)
    if tag != 0x03 or ku_len < 2 or not ku[ku_off + 1] & 0x04:
        sys.exit(f"{name}: keyUsage lacks keyCertSign")
    if ext_value(cert, EKU_OID_CONTENT) is not None:
        sys.exit(f"{name}: an intermediate must not carry an EKU")


def check_modulus(value, name):
    if len(value) != 384:
        sys.exit(f"{name}: {len(value)} bytes, expected an RSA-3072 modulus")
    if not value[0] & 0x80 or not value[-1] & 1:
        sys.exit(f"{name}: top bit clear or even; not a usable modulus")


def load(directory):
    """Reads, checks, and names every vector. Returns (name, bytes) pairs."""
    src = pathlib.Path(directory)
    leaf_rsa = (src / "leaf_eku.der").read_bytes()
    leaf_p256 = (src / "leaf_p256_eku.der").read_bytes()
    leaf_no_eku = (src / "leaf_p256_real.der").read_bytes()
    int_rsa = (src / "int_rsa.der").read_bytes()
    via_rsa = (src / "leaf_via_int_rsa.der").read_bytes()
    int_p256 = (src / "int_p256.der").read_bytes()
    via_p256 = (src / "leaf_via_int_p256.der").read_bytes()
    ca_modulus = (src / "ca_modulus.bin").read_bytes()
    ca_xy = (src / "ca_p256_xy.bin").read_bytes()

    if EKU_OID not in leaf_rsa or EKU_OID not in leaf_p256:
        sys.exit("a good leaf lacks the extendedKeyUsage OID")
    if EKU_OID in leaf_no_eku:
        sys.exit("leaf_p256_real.der carries an EKU; wrong input file")
    if EKU_OID not in via_rsa or EKU_OID not in via_p256:
        sys.exit("a via-intermediate leaf lacks the extendedKeyUsage OID")
    check_intermediate(int_rsa, "int_rsa.der")
    check_intermediate(int_p256, "int_p256.der")
    rsa_key = leaf_spki_key(leaf_rsa, rsa=True)
    p256_key = leaf_spki_key(leaf_p256, rsa=False)
    leaf_spki_key(leaf_no_eku, rsa=False)  # shape check only
    via_rsa_key = leaf_spki_key(via_rsa, rsa=True)
    via_p256_key = leaf_spki_key(via_p256, rsa=False)
    check_modulus(rsa_key, "leaf_eku.der modulus")
    check_modulus(via_rsa_key, "leaf_via_int_rsa.der modulus")
    check_modulus(ca_modulus, "ca_modulus.bin")
    if len(ca_xy) != 64:
        sys.exit(f"ca_p256_xy.bin: {len(ca_xy)} bytes, expected 64")

    return [
        ("leaf_rsa", leaf_rsa),
        ("leaf_rsa_key", rsa_key),
        ("leaf_p256", leaf_p256),
        ("leaf_p256_key", p256_key),
        ("leaf_p256_no_eku", leaf_no_eku),
        ("int_rsa", int_rsa),
        ("leaf_via_int_rsa", via_rsa),
        ("leaf_via_int_rsa_key", via_rsa_key),
        ("int_p256", int_p256),
        ("leaf_via_int_p256", via_p256),
        ("leaf_via_int_p256_key", via_p256_key),
        ("ca_rsa_modulus", ca_modulus),
        ("ca_p256_xy", ca_xy),
    ]


def emit(vectors):
    lines = [
        "// Certificate test vectors. Generated by test/gen_x509vectors.py",
        "// from the minted own-CA leaves, intermediates, and CA keys the",
        "// script's docstring describes — regenerate with the script, never",
        "// edit by hand. The",
        "// script is also the formatter: the off marker keeps regeneration",
        "// byte-identical under any clang-format version, or none.",
        "#ifndef CH_X509_VECTORS_H",
        "#define CH_X509_VECTORS_H",
        "",
        "#include <stdint.h>",
        "",
        "// clang-format off",
    ]
    for name, data in vectors:
        lines.append(f"static const uint8_t certv_{name}[{len(data)}] = {{")
        for off in range(0, len(data), 16):
            row = ", ".join(f"0x{b:02x}" for b in data[off : off + 16])
            comma = "," if off + 16 < len(data) else ""
            lines.append(f"    {row}{comma}")
        lines.append("};")
        lines.append("")
    lines.append("// clang-format on")
    lines.append("")
    lines.append("#endif")
    return "\n".join(lines) + "\n"


def main():
    if len(sys.argv) > 2:
        sys.exit("usage: gen_x509vectors.py [cert-dir]")
    if len(sys.argv) == 2:
        src = sys.argv[1]
    else:
        import tempfile

        src = mint(tempfile.mkdtemp(prefix="x509vec_"))
    vectors = load(src)
    OUT.write_text(emit(vectors))
    print(f"{OUT}: {len(vectors)} arrays")


if __name__ == "__main__":
    main()
