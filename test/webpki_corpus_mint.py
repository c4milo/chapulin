"""The openssl side of gen_webpki_corpus.py: keys, certificates and the
`openssl verify` oracle.

Minter issues every certificate with `openssl x509 -req` under fixed
dates and a fixed serial. RSA PKCS#1 v1.5 signatures are deterministic by
construction; ECDSA signatures take `-sigopt nonce-type:1`, OpenSSL's
RFC 6979 deterministic nonce, so a run over unchanged keys reproduces
every certificate byte for byte.
"""

import os
import pathlib
import shutil
import subprocess
import sys

KEY_DIR = pathlib.Path(__file__).with_name("webpki_corpus") / "keys"


def find_openssl():
    """OpenSSL 3, which has -not_before, -not_after and nonce-type; the
    LibreSSL at /usr/bin has none of them, so Homebrew's path goes first."""
    ossl = shutil.which("openssl", path="/opt/homebrew/bin:/usr/bin:" + (os.environ.get("PATH") or ""))
    if ossl is None:
        sys.exit("openssl not found")
    version = subprocess.run([ossl, "version"], capture_output=True, text=True).stdout.strip()
    if not version.startswith("OpenSSL 3."):
        sys.exit(f"{ossl} is {version}; the corpus needs OpenSSL 3")
    return ossl, version.split(" (")[0]


def sh(*cmd, stdin=None):
    r = subprocess.run(cmd, input=stdin, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"{' '.join(str(c) for c in cmd[:3])} failed: {r.stderr.decode()[:400]}")
    return r.stdout


def key_path(label):
    return KEY_DIR / f"{label}.pem"


def ensure_keys(ossl, keys):
    """Mints any key file missing under KEY_DIR and says so, because a
    fresh key changes the header. keys maps label -> ("rsa", bits) or
    ("ec", curve)."""
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    for label, (kind, size) in keys.items():
        path = key_path(label)
        if path.exists():
            continue
        if kind == "rsa":
            opts = ["-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{size}"]
        else:
            opts = ["-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{size}"]
        sh(ossl, "genpkey", *opts, "-out", str(path))
        print(f"minted a new key {path}; the header changes")


class Minter:
    """Issues certificates into a temporary directory."""

    def __init__(self, ossl, tmp, keys):
        self.ossl = ossl
        self.tmp = pathlib.Path(tmp)
        self.keys = keys
        self.pem = {}  # label -> PEM path
        self.der = {}  # label -> DER bytes
        self.key_of = {}  # label -> key label

    def issue(self, label, key, subject, issuer, extensions, serial, not_before, not_after, digest):
        """Mints one certificate under the key labelled key. issuer is the
        label of the issuing certificate, or None for a self-signed one.
        extensions is openssl x509v3 config text."""
        csr = sh(self.ossl, "req", "-new", "-key", str(key_path(key)), "-subj", subject)
        ext = self.tmp / f"{label}.cnf"
        ext.write_text(extensions)
        out = self.tmp / f"{label}.pem"
        cmd = [
            self.ossl, "x509", "-req",
            "-not_before", not_before, "-not_after", not_after,
            "-set_serial", str(serial), f"-{digest}",
            "-extfile", str(ext), "-out", str(out),
        ]
        if issuer is None:
            signer = key
            cmd += ["-key", str(key_path(key))]
        else:
            signer = self.key_of[issuer]
            cmd += ["-CA", str(self.pem[issuer]), "-CAkey", str(key_path(signer))]
        if self.keys[signer][0] == "ec":
            cmd += ["-sigopt", "nonce-type:1"]
        sh(*cmd, stdin=csr)
        self.pem[label] = out
        self.key_of[label] = key
        self.der[label] = sh(self.ossl, "x509", "-in", str(out), "-outform", "DER")
        return self.der[label]

    def subject_key_identifier(self, label):
        """The SKID openssl printed for a minted certificate, as colon hex,
        so a second certificate can carry the same one."""
        text = sh(self.ossl, "x509", "-in", str(self.pem[label]), "-noout",
                  "-ext", "subjectKeyIdentifier").decode()
        return text.strip().splitlines()[-1].strip()


def openssl_verify(ossl, tmp, leaf_pem, untrusted_pem, anchors_pem, hostname, now_seconds):
    """Runs the oracle and returns (accepts, reason). reason is "OK" or the
    `error N at D depth lookup: ...` line openssl printed."""
    tmp = pathlib.Path(tmp)
    leaf = tmp / "oracle_leaf.pem"
    leaf.write_text(leaf_pem)
    anchors = tmp / "oracle_anchors.pem"
    anchors.write_text(anchors_pem)
    cmd = [
        ossl, "verify", "-purpose", "sslserver", "-verify_hostname", hostname,
        "-attime", str(now_seconds), "-CAfile", str(anchors),
    ]
    if untrusted_pem:
        untrusted = tmp / "oracle_untrusted.pem"
        untrusted.write_text(untrusted_pem)
        cmd += ["-untrusted", str(untrusted)]
    cmd.append(str(leaf))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode == 0:
        return True, "OK"
    # openssl 3 prints the subject on stdout and the lookup error on stderr.
    for line in (r.stdout + r.stderr).splitlines():
        if line.startswith("error ") and "depth lookup" in line:
            return False, line
    sys.exit(f"openssl verify failed without a lookup error: {r.stdout} {r.stderr[:200]}")
