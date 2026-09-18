#!/usr/bin/env python3
"""Regenerates test/webpki_corpus.h, the chain fixtures for TRUST=webpki.

Usage: python3 test/gen_webpki_corpus.py

Two tables come out, as docs/webpki.md's "Verification" section lays
them out. The minted corpus mirrors the four captured shapes and takes
one rule per negative row; the captures under test/webpki_captures/
carry the real extension bulk. The generator renders both into the
exact RFC 9846 section 4.5.1 Certificate message bytes.

Fixed inputs keep the header stable between runs: the keys under
test/webpki_corpus/keys/ (webpki_corpus_mint.py mints each once, and
the tree keeps them), fixed notBefore and notAfter values, fixed
serials, a fixed now_seconds, and RFC 6979 nonces for ECDSA. The
generator also runs every chain through `openssl verify -purpose
sslserver -verify_hostname` at the row's now_seconds, and the run
fails unless the set of rows where openssl disagrees with this mode is
exactly EXPECTED_DISAGREEMENTS below: the rows docs/webpki.md's "Where
this profile is stricter than OpenSSL" section lists in its table,
plus the three that section records after the table.

The generator runs the openssl CLI and opens no network connection.
"""

import calendar
import pathlib
import sys
import tempfile
import time

import webpki_corpus_der as der
import webpki_corpus_emit as emit
import webpki_corpus_mint as mint

OUT = pathlib.Path(__file__).with_name("webpki_corpus.h")
CAPTURE_DIR = pathlib.Path(__file__).with_name("webpki_captures")

HOST = "s3.example.test"


def epoch(utc_time):
    """Seconds since 1970-01-01T00:00:00Z of a [CC]YYMMDDHHMMSSZ value,
    the form openssl x509 -not_before and -not_after take."""
    return calendar.timegm(time.strptime(utc_time, "%Y%m%d%H%M%SZ"))


# The corpus clock and the leaf's validity. The CA certificates are valid
# over a wider window, so each date row moves only the leaf's verdict.
# One intermediate, int_aws_rsa2048_short, is valid over a window inside
# the leaf's, so a clock at its edges moves only the issuer's verdict.
LEAF_NOT_BEFORE = "20260101000000Z"
LEAF_NOT_AFTER = "20261231235959Z"
CA_NOT_BEFORE = "20250101000000Z"
CA_NOT_AFTER = "20401231235959Z"
SHORT_NOT_BEFORE = "20260301000000Z"
SHORT_NOT_AFTER = "20260930235959Z"
NOW = epoch("20260701000000Z")

# Labels whose validity is not the one their prefix picks.
VALIDITY = {"int_aws_rsa2048_short": (SHORT_NOT_BEFORE, SHORT_NOT_AFTER)}

# When the four captures were taken, in UTC; the row clock for them.
CAPTURE_TIME_UTC = "20260915111915Z"
CAPTURE_TIME = epoch(CAPTURE_TIME_UTC)

# label -> ("rsa", bits) or ("ec", curve). A missing file is minted once.
KEYS = {
    "root_aws_rsa2048": ("rsa", 2048),
    "root_cross_rsa2048": ("rsa", 2048),
    "root_gcs_rsa4096": ("rsa", 4096),
    "root_p384": ("ec", "P-384"),
    "impostor_p384": ("ec", "P-384"),
    "int_aws_rsa2048": ("rsa", 2048),
    "int_aws_rsa2048_v2": ("rsa", 2048),
    "int_gcs_rsa2048": ("rsa", 2048),
    "int_r2_p256": ("ec", "P-256"),
    "int_le1_p384": ("ec", "P-384"),
    "int_le2_p384": ("ec", "P-384"),
    "leaf_rsa2048": ("rsa", 2048),
    "leaf_rsa1024": ("rsa", 1024),
    "leaf_p256": ("ec", "P-256"),
    "leaf_p384": ("ec", "P-384"),
}

SUBJECT = {
    "root_aws_rsa2048": "/C=US/O=Corpus/CN=Corpus AWS Root",
    "root_cross_rsa2048": "/C=US/O=Corpus/CN=Corpus Cross Root",
    "root_gcs_rsa4096": "/C=US/O=Corpus/CN=Corpus GCS Root",
    "root_p384": "/C=US/O=Corpus/CN=Corpus P-384 Root",
    "int_aws_rsa2048": "/C=US/O=Corpus/CN=Corpus AWS Intermediate",
    "int_aws_rsa2048_short": "/C=US/O=Corpus/CN=Corpus AWS Short Intermediate",
    "int_gcs_rsa2048": "/C=US/O=Corpus/CN=Corpus GCS Intermediate",
    "int_r2_p256": "/C=US/O=Corpus/CN=Corpus R2 Intermediate",
    "int_r2_p256_constrained": "/C=US/O=Corpus/CN=Corpus R2 Constrained Intermediate",
    "int_r2_p256_not_ca": "/C=US/O=Corpus/CN=Corpus R2 Non-CA Intermediate",
    "int_r2_p256_alias": "/C=US/O=Corpus/CN=Corpus R2 Intermediate Alias",
    "int_le1_p384": "/C=US/O=Corpus/CN=Corpus LE Intermediate 1",
    "int_le2_p384": "/C=US/O=Corpus/CN=Corpus LE Intermediate 2",
}

ROOT_EXT = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"


def intermediate_ext(path_len, ca="TRUE", extra=""):
    return (
        f"basicConstraints=critical,CA:{ca},pathlen:{path_len}\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "extendedKeyUsage=serverAuth,clientAuth\n" + extra
    )


def leaf_ext(key_usage="digitalSignature", eku="serverAuth,clientAuth", san="DNS:" + HOST, ca="FALSE"):
    lines = [f"basicConstraints=critical,CA:{ca}", f"keyUsage=critical,{key_usage}", f"extendedKeyUsage={eku}"]
    if san:
        lines.append(f"subjectAltName={san}")
    return "\n".join(lines) + "\n"


def impostor_ext(minter):
    """The P-384 root's subjectKeyIdentifier over another key, so openssl
    finds this anchor by name and identifier and fails on the signature,
    the same step this mode fails on."""
    return ROOT_EXT + f"subjectKeyIdentifier={minter.subject_key_identifier('root_p384')}\n"


RSA_LEAF_KU = "digitalSignature,keyEncipherment"
NAME_CONSTRAINTS = "nameConstraints=critical,permitted;DNS:.example.test\n"

# (label, key, subject, issuer label or None, extensions, digest), in
# issuing order. The serial is the position in this list plus one.
CERTS = [
    ("root_aws_rsa2048", "root_aws_rsa2048", SUBJECT["root_aws_rsa2048"], None, ROOT_EXT, "sha256"),
    ("root_cross_rsa2048", "root_cross_rsa2048", SUBJECT["root_cross_rsa2048"], None, ROOT_EXT, "sha256"),
    ("root_gcs_rsa4096", "root_gcs_rsa4096", SUBJECT["root_gcs_rsa4096"], None, ROOT_EXT, "sha256"),
    ("root_p384", "root_p384", SUBJECT["root_p384"], None, ROOT_EXT, "sha384"),
    ("impostor_p384", "impostor_p384", SUBJECT["root_p384"], None, impostor_ext, "sha384"),
    ("root_aws_rsa2048_cross", "root_aws_rsa2048", SUBJECT["root_aws_rsa2048"], "root_cross_rsa2048", ROOT_EXT, "sha256"),
    ("int_aws_rsa2048", "int_aws_rsa2048", SUBJECT["int_aws_rsa2048"], "root_aws_rsa2048", intermediate_ext(0), "sha256"),
    ("int_gcs_rsa2048", "int_gcs_rsa2048", SUBJECT["int_gcs_rsa2048"], "root_gcs_rsa4096", intermediate_ext(0), "sha256"),
    ("int_r2_p256", "int_r2_p256", SUBJECT["int_r2_p256"], "root_p384", intermediate_ext(0), "sha384"),
    ("int_r2_p256_constrained", "int_r2_p256", SUBJECT["int_r2_p256_constrained"], "root_p384",
     intermediate_ext(0, extra=NAME_CONSTRAINTS), "sha384"),
    ("int_r2_p256_not_ca", "int_r2_p256", SUBJECT["int_r2_p256_not_ca"], "root_p384",
     intermediate_ext(0, ca="FALSE"), "sha384"),
    ("int_r2_p256_alias", "int_r2_p256", SUBJECT["int_r2_p256_alias"], "root_p384", intermediate_ext(0), "sha384"),
    ("int_le2_p384", "int_le2_p384", SUBJECT["int_le2_p384"], "root_p384", intermediate_ext(1), "sha384"),
    ("int_le2_p384_pathlen0", "int_le2_p384", SUBJECT["int_le2_p384"], "root_p384", intermediate_ext(0), "sha384"),
    ("int_le1_p384", "int_le1_p384", SUBJECT["int_le1_p384"], "int_le2_p384", intermediate_ext(0), "sha384"),
    ("leaf_aws", "leaf_rsa2048", "/CN=" + HOST, "int_aws_rsa2048", leaf_ext(RSA_LEAF_KU), "sha256"),
    ("leaf_aws_key_encipherment", "leaf_rsa2048", "/CN=" + HOST, "int_aws_rsa2048", leaf_ext("keyEncipherment"), "sha256"),
    ("leaf_aws_sha1", "leaf_rsa2048", "/CN=" + HOST, "int_aws_rsa2048", leaf_ext(RSA_LEAF_KU), "sha1"),
    ("leaf_aws_rsa1024", "leaf_rsa1024", "/CN=" + HOST, "int_aws_rsa2048", leaf_ext(RSA_LEAF_KU), "sha256"),
    ("leaf_gcs", "leaf_p256", "/CN=" + HOST, "int_gcs_rsa2048", leaf_ext(), "sha256"),
    ("leaf_r2", "leaf_p256", "/CN=" + HOST, "int_r2_p256", leaf_ext(), "sha256"),
    ("leaf_le", "leaf_p256", "/CN=" + HOST, "int_le1_p384", leaf_ext(), "sha384"),
    ("leaf_r2_wildcard", "leaf_p256", "/CN=*.example.test", "int_r2_p256", leaf_ext(san="DNS:*.example.test"), "sha256"),
    ("leaf_r2_wildcard_public_suffix", "leaf_p256", "/CN=*.com", "int_r2_p256", leaf_ext(san="DNS:*.com"), "sha256"),
    ("leaf_r2_no_san", "leaf_p256", "/CN=" + HOST, "int_r2_p256", leaf_ext(san=None), "sha256"),
    ("leaf_r2_client_auth", "leaf_p256", "/CN=" + HOST, "int_r2_p256", leaf_ext(eku="clientAuth"), "sha256"),
    ("leaf_r2_ca", "leaf_p256", "/CN=" + HOST, "int_r2_p256", leaf_ext(ca="TRUE"), "sha256"),
    ("leaf_r2_constrained", "leaf_p256", "/CN=" + HOST, "int_r2_p256_constrained", leaf_ext(), "sha256"),
    ("leaf_r2_under_not_ca", "leaf_p256", "/CN=" + HOST, "int_r2_p256_not_ca", leaf_ext(), "sha256"),
    ("leaf_r2_under_alias", "leaf_p256", "/CN=" + HOST, "int_r2_p256_alias", leaf_ext(), "sha256"),
    # Last, so every serial above keeps the value it had. The only P-384
    # leaf key in the corpus: RFC 9846 section 4.5.2 binds that key to
    # ecdsa_secp384r1_sha384, the one CertificateVerify scheme whose
    # signed content this client hashes with SHA-384.
    ("leaf_r2_p384", "leaf_p384", "/CN=" + HOST, "int_r2_p256", leaf_ext(), "sha256"),
    # The intermediate whose validity lies inside the leaf's, and a leaf
    # under it, for the issuer validity rows.
    ("int_aws_rsa2048_short", "int_aws_rsa2048", SUBJECT["int_aws_rsa2048_short"], "root_aws_rsa2048",
     intermediate_ext(0), "sha256"),
    ("leaf_aws_short", "leaf_rsa2048", "/CN=" + HOST, "int_aws_rsa2048_short", leaf_ext(RSA_LEAF_KU), "sha256"),
    # The aws intermediate re-keyed under its own Name: the new key's
    # certificate is signed by the old key, so its subject Name equals its
    # issuer Name, which is what RFC 5280 section 6.1 calls self-issued.
    ("int_aws_rsa2048_rekey", "int_aws_rsa2048_v2", SUBJECT["int_aws_rsa2048"], "int_aws_rsa2048",
     intermediate_ext(0), "sha256"),
    ("leaf_aws_rekey", "leaf_rsa2048", "/CN=" + HOST, "int_aws_rsa2048_rekey", leaf_ext(RSA_LEAF_KU), "sha256"),
]

AWS = ["leaf_aws", "int_aws_rsa2048", "root_aws_rsa2048_cross"]
AWS_SHORT = ["leaf_aws_short", "int_aws_rsa2048_short"]
AWS_REKEY = ["leaf_aws_rekey", "int_aws_rsa2048_rekey", "int_aws_rsa2048"]
R2 = ["leaf_r2", "int_r2_p256"]
LE = ["leaf_le", "int_le1_p384", "int_le2_p384", "root_p384"]


def chain(name, entries, anchors, expected, note, hostname=HOST, now=NOW, anchor_set=None):
    """One table row. anchor_set names the C anchor array; the default is
    the anchor labels joined, which reads well for one or two anchors."""
    return dict(name=name, entries=entries, anchors=anchors, hostname=hostname,
                now=now, expected=expected, note=note, anchor_set=anchor_set or "_".join(anchors))


CHAINS = [
    chain("aws", AWS, ["root_aws_rsa2048"], "ok",
          "aws: RSA-2048 leaf, sha256WithRSA <- RSA-2048 intermediate <- RSA-2048 anchor.\n"
          "Entry 2 is the root cross-signed by the cross root; the walk stops at entry 1\n"
          "and never reads it."),
    chain("gcs", ["leaf_gcs", "int_gcs_rsa2048"], ["root_gcs_rsa4096"], "ok",
          "gcs: P-256 leaf, sha256WithRSA <- RSA-2048 intermediate <- RSA-4096 anchor."),
    chain("r2", R2, ["root_p384"], "ok",
          "r2: P-256 leaf, ecdsa-with-SHA256 <- P-256 intermediate, ecdsa-with-SHA384\n"
          "<- P-384 anchor."),
    chain("letsencrypt", LE, ["root_p384"], "ok",
          "letsencrypt: P-256 leaf, ecdsa-with-SHA384 <- P-384 intermediate 1 <- P-384\n"
          "intermediate 2 <- P-384 anchor. Entry 3 is the anchor's own certificate; the\n"
          "walk stops at entry 2 and never reads it."),
    chain("p384_leaf", ["leaf_r2_p384", "int_r2_p256"], ["root_p384"], "ok",
          "p384_leaf: P-384 leaf, ecdsa-with-SHA256 <- P-256 intermediate, ecdsa-with-SHA384\n"
          "<- P-384 anchor. The r2 shape with the leaf key family the other rows never\n"
          "carry, which is what binds a CertificateVerify to ecdsa_secp384r1_sha384\n"
          "(test/webpki_auth_vectors.h)."),
    chain("wildcard", ["leaf_r2_wildcard", "int_r2_p256"], ["root_p384"], "ok",
          "wildcard: the r2 shape with subjectAltName *.example.test, asked for s3.example.test."),
    chain("not_after_boundary", AWS, ["root_aws_rsa2048"], "ok",
          "not_after_boundary: the aws chain at now_seconds = notAfter, the last valid\n"
          "instant (RFC 5280 section 4.1.2.5).", now=epoch(LEAF_NOT_AFTER)),
    chain("not_before_boundary", AWS, ["root_aws_rsa2048"], "ok",
          "not_before_boundary: the aws chain at now_seconds = notBefore, the first valid instant.",
          now=epoch(LEAF_NOT_BEFORE)),
    chain("expired", AWS, ["root_aws_rsa2048"], "expired",
          "expired: the aws chain at now_seconds = notAfter + 1.", now=epoch(LEAF_NOT_AFTER) + 1),
    chain("not_yet_valid", AWS, ["root_aws_rsa2048"], "not_yet_valid",
          "not_yet_valid: the aws chain at now_seconds = notBefore - 1.", now=epoch(LEAF_NOT_BEFORE) - 1),
    chain("hostname_mismatch", AWS, ["root_aws_rsa2048"], "hostname_mismatch",
          "hostname_mismatch: the aws chain, whose subjectAltName is s3.example.test,\n"
          "asked for other.example.test.", hostname="other.example.test"),
    chain("wildcard_two_labels", ["leaf_r2_wildcard", "int_r2_p256"], ["root_p384"], "wildcard_two_labels",
          "wildcard_two_labels: *.example.test asked for a.b.example.test; a wildcard\n"
          "matches one label.", hostname="a.b.example.test"),
    chain("wildcard_public_suffix", ["leaf_r2_wildcard_public_suffix", "int_r2_p256"], ["root_p384"],
          "wildcard_public_suffix",
          "wildcard_public_suffix: subjectAltName *.com asked for example.com; a pattern\n"
          "with fewer than two labels after the wildcard matches nothing.", hostname="example.com"),
    chain("no_subject_alt_name", ["leaf_r2_no_san", "int_r2_p256"], ["root_p384"], "no_subject_alt_name",
          "no_subject_alt_name: the leaf names s3.example.test in its subject common name\n"
          "only. openssl falls back to the common name; this mode matches dNSName only."),
    chain("key_usage_no_digital_signature",
          ["leaf_aws_key_encipherment", "int_aws_rsa2048", "root_aws_rsa2048_cross"], ["root_aws_rsa2048"],
          "key_usage_no_digital_signature",
          "key_usage_no_digital_signature: keyUsage asserts keyEncipherment alone. openssl\n"
          "admits it for sslserver; TLS 1.3 has no RSA key transport."),
    chain("no_server_auth_eku", ["leaf_r2_client_auth", "int_r2_p256"], ["root_p384"], "no_server_auth_eku",
          "no_server_auth_eku: extendedKeyUsage asserts id-kp-clientAuth alone."),
    chain("leaf_asserts_ca", ["leaf_r2_ca", "int_r2_p256"], ["root_p384"], "leaf_asserts_ca",
          "leaf_asserts_ca: the leaf's basicConstraints asserts CA. openssl reads no\n"
          "basicConstraints on a leaf; this mode refuses it."),
    chain("sha1_signature", ["leaf_aws_sha1", "int_aws_rsa2048", "root_aws_rsa2048_cross"], ["root_aws_rsa2048"],
          "sha1_signature", "sha1_signature: the leaf is signed sha1WithRSAEncryption."),
    chain("rsa_1024_leaf", ["leaf_aws_rsa1024", "int_aws_rsa2048", "root_aws_rsa2048_cross"], ["root_aws_rsa2048"],
          "rsa_1024_leaf", "rsa_1024_leaf: the leaf key is RSA-1024, below the 2048-bit floor."),
    chain("critical_name_constraints", ["leaf_r2_constrained", "int_r2_p256_constrained"], ["root_p384"],
          "critical_name_constraints",
          "critical_name_constraints: the intermediate carries a critical nameConstraints\n"
          "permitting .example.test. openssl honours it; this mode refuses a critical\n"
          "extension it cannot honour."),
    chain("intermediate_not_ca", ["leaf_r2_under_not_ca", "int_r2_p256_not_ca"], ["root_p384"],
          "intermediate_not_ca", "intermediate_not_ca: the intermediate's basicConstraints is critical and CA:FALSE."),
    chain("path_len_exceeded", ["leaf_le", "int_le1_p384", "int_le2_p384_pathlen0", "root_p384"], ["root_p384"],
          "path_len_exceeded",
          "path_len_exceeded: the letsencrypt shape with intermediate 2 at pathLenConstraint\n"
          "0, so intermediate 1 below it is one certificate too many."),
    chain("issuer_name_mismatch", ["leaf_r2_under_alias", "int_r2_p256"], ["root_p384"], "issuer_name_mismatch",
          "issuer_name_mismatch: the leaf's issuer Name is Corpus R2 Intermediate Alias, a\n"
          "second certificate over the intermediate's key. The sent intermediate's key\n"
          "verifies the signature, and its subject Name is not the leaf's issuer Name."),
    chain("issuer_not_after_boundary", AWS_SHORT, ["root_aws_rsa2048"], "ok",
          "issuer_not_after_boundary: the leaf under the short intermediate at now_seconds\n"
          "= the intermediate's notAfter, the last valid instant; the leaf is valid for\n"
          "three more months.", now=epoch(SHORT_NOT_AFTER)),
    chain("issuer_expired", AWS_SHORT, ["root_aws_rsa2048"], "expired",
          "issuer_expired: the same chain at the intermediate's notAfter + 1, inside the\n"
          "leaf's validity.", now=epoch(SHORT_NOT_AFTER) + 1),
    chain("issuer_not_before_boundary", AWS_SHORT, ["root_aws_rsa2048"], "ok",
          "issuer_not_before_boundary: the same chain at the intermediate's notBefore, the\n"
          "first valid instant; the leaf has been valid for two months.",
          now=epoch(SHORT_NOT_BEFORE)),
    chain("issuer_not_yet_valid", AWS_SHORT, ["root_aws_rsa2048"], "not_yet_valid",
          "issuer_not_yet_valid: the same chain at the intermediate's notBefore - 1, inside\n"
          "the leaf's validity.", now=epoch(SHORT_NOT_BEFORE) - 1),
    chain("rekeyed_intermediate", AWS_REKEY, ["root_aws_rsa2048"], "ok",
          "rekeyed_intermediate: the aws leaf under the intermediate's new key, whose\n"
          "certificate is self-issued under the old key, then the old key's certificate at\n"
          "pathLenConstraint 0. RFC 5280 section 6.1.4 (l) does not count the self-issued\n"
          "certificate, so the constraint holds (docs/webpki.md, \"Decisions\")."),
    chain("anchor_key_mismatch", R2, ["impostor_p384"], "anchor_key_mismatch",
          "anchor_key_mismatch: the r2 chain against an anchor carrying the P-384 root's\n"
          "Name over a different key."),
    chain("corrupt_signature", ["leaf_aws_corrupt", "int_aws_rsa2048", "root_aws_rsa2048_cross"],
          ["root_aws_rsa2048"], "corrupt_signature",
          "corrupt_signature: the aws leaf with the last byte of its signature flipped."),
]

# Rows where openssl verify's verdict is not this mode's. Five are
# docs/webpki.md's table, where openssl accepts what this mode refuses.
# That section records the other three after the table. leaf_asserts_ca:
# openssl reads no basicConstraints on a leaf under -purpose sslserver.
# not_after_boundary and issuer_not_after_boundary: openssl's
# X509_cmp_time reports now_seconds equal to notAfter as expired, and RFC
# 5280 section 4.1.2.5 makes notAfter the last valid instant, which
# docs/webpki.md's "Validity" keeps.
EXPECTED_DISAGREEMENTS = {
    "no_subject_alt_name", "key_usage_no_digital_signature", "sha1_signature",
    "rsa_1024_leaf", "critical_name_constraints", "leaf_asserts_ca", "not_after_boundary",
    "issuer_not_after_boundary",
}

CAPTURE_ANCHORS = ["AmazonRootCA1", "SFSRootCAG2", "GTSRootR1", "GTSRootR4", "ISRGRootX2"]

# Cloudflare served r2.cloudflarestorage.com a leaf whose notAfter was
# 2026-09-09T06:59:11Z, six days before the capture, on two handshakes to
# two edges. Its row at the capture time therefore expects "expired", and
# a second row sets the clock inside the leaf's validity so the walk runs
# over the real R2 bulk. test/webpki_captures/README.md records the dates.
R2_VALID_CLOCK_UTC = "20260901000000Z"

# (row name, host, clock, expected). The clock is the capture time unless
# a row says otherwise.
CAPTURE_ROWS = [
    ("s3.amazonaws.com", "s3.amazonaws.com", CAPTURE_TIME_UTC, "ok"),
    ("storage.googleapis.com", "storage.googleapis.com", CAPTURE_TIME_UTC, "ok"),
    ("r2.cloudflarestorage.com", "r2.cloudflarestorage.com", R2_VALID_CLOCK_UTC, "ok"),
    ("r2.cloudflarestorage.com.at_capture", "r2.cloudflarestorage.com", CAPTURE_TIME_UTC, "expired"),
    ("acme-v02.api.letsencrypt.org", "acme-v02.api.letsencrypt.org", CAPTURE_TIME_UTC, "ok"),
]


def mint_all(minter):
    for serial, (label, key, subject, issuer, ext, digest) in enumerate(CERTS, 1):
        if callable(ext):
            ext = ext(minter)
        if label in VALIDITY:
            not_before, not_after = VALIDITY[label]
        elif label.startswith("leaf"):
            not_before, not_after = LEAF_NOT_BEFORE, LEAF_NOT_AFTER
        else:
            not_before, not_after = CA_NOT_BEFORE, CA_NOT_AFTER
        minter.issue(label, key, subject, issuer, ext, serial, not_before, not_after, digest)
    corrupt = bytearray(minter.der["leaf_aws"])
    corrupt[-1] ^= 0x01
    minter.der["leaf_aws_corrupt"] = bytes(corrupt)


def build_rows(ossl, tmp, certs, chains, prefix, anchor_pems):
    """Renders chains over certs (label -> DER) into table rows and the
    byte pools they point at. anchor_pems maps an anchor label to the PEM
    text openssl verify takes for it. Returns (rows, text)."""
    names = emit.Pool(f"{prefix}_name")
    spkis = emit.Pool(f"{prefix}_spki")
    messages = {}
    message_text = []
    anchor_sets = {}
    anchor_text = []
    rows = []
    for c in chains:
        entries = tuple(c["entries"])
        if entries not in messages:
            symbol = f"{prefix}_message_{c['name'].replace('.', '_').replace('-', '_')}"
            messages[entries] = symbol
            ders = [certs[e] for e in entries]
            sizes = ", ".join(f"{len(d)} B" for d in ders)
            message_text.append(f"// Certificate message over {', '.join(entries)} ({sizes}).")
            message_text.append(emit.c_array(symbol, der.certificate_message(ders)))
        anchors = tuple(c["anchors"])
        if anchors not in anchor_sets:
            symbol = f"{prefix}_anchors_{c['anchor_set']}"
            anchor_sets[anchors] = symbol
            members = []
            for a in anchors:
                name = names.add(a, der.subject_name_tlv(certs[a]), f"{a}: subject Name TLV")
                spki = spkis.add(a, der.spki_tlv(certs[a]), f"{a}: subjectPublicKeyInfo TLV")
                members.append((name, spki, a))
            anchor_text.append(emit.anchor_set(symbol, members))
        leaf = der.pem_certificate(certs[entries[0]])
        untrusted = "".join(der.pem_certificate(certs[e]) for e in entries[1:])
        accepts, reason = mint.openssl_verify(
            ossl, tmp, leaf, untrusted, "".join(anchor_pems[a] for a in anchors), c["hostname"], c["now"])
        rows.append(dict(
            name=c["name"], message=messages[entries], anchors=anchor_sets[anchors],
            anchor_count=len(anchors), hostname=c["hostname"], now_seconds=c["now"],
            expected=c["expected"], openssl_accepts=accepts, note=c["note"] + f"\nopenssl: {reason}"))
    text = names.render() + spkis.render() + "\n".join(message_text) + "\n".join(anchor_text)
    return rows, text


def check_oracle(rows):
    disagree = {r["name"] for r in rows if r["openssl_accepts"] != (r["expected"] == "ok")}
    if disagree != EXPECTED_DISAGREEMENTS:
        sys.exit(f"openssl disagrees on {sorted(disagree)}, expected {sorted(EXPECTED_DISAGREEMENTS)}")
    print(f"openssl agrees on {len(rows) - len(disagree)} of {len(rows)} corpus chains; "
          f"disagreements: {', '.join(sorted(disagree))}")


def load_captures():
    """Reads the captured chains and their anchors, prints the measurements
    docs/webpki.md's bounds table is checked against, and returns (certs,
    chains, anchor_pems) in build_rows's shapes."""
    certs = {}
    anchor_pems = {}
    for a in CAPTURE_ANCHORS:
        text = (CAPTURE_DIR / "anchors" / f"{a}.pem").read_text()
        (certs[a],) = der.pem_certificates(text)
        anchor_pems[a] = text
    anchor_names = {der.subject_name_tlv(certs[a]): a for a in CAPTURE_ANCHORS}
    labels = {}
    for host in dict.fromkeys(row[1] for row in CAPTURE_ROWS):
        entries = der.pem_certificates((CAPTURE_DIR / f"{host}.pem").read_text())
        labels[host] = []
        for i, cert in enumerate(entries):
            label = f"{host.replace('.', '_').replace('-', '_')}_{i}"
            certs[label] = cert
            labels[host].append(label)
            anchor = anchor_names.get(der.subject_name_tlv(cert))
            if anchor and der.spki_tlv(cert) != der.spki_tlv(certs[anchor]):
                sys.exit(f"{host} entry {i} names {anchor} over a different key")
        body = len(der.certificate_message(entries)) - 4
        ext_count, ext_tlv = zip(*(der.extension_measurements(c) for c in entries))
        print(f"{host}: {len(entries)} entries, largest entry {max(len(c) for c in entries)} B, "
              f"Certificate body {body} B, largest extension count {max(ext_count)}, "
              f"largest extension TLV {max(ext_tlv)} B")
    chains = []
    for name, host, clock, expected in CAPTURE_ROWS:
        chains.append(chain(name, labels[host], CAPTURE_ANCHORS, expected,
                            f"{name}: the {host} capture of {CAPTURE_TIME_UTC}, {len(labels[host])} entries,\n"
                            f"now_seconds {epoch(clock)} ({clock}); the anchors are the five published roots.",
                            hostname=host, now=epoch(clock), anchor_set="published_roots"))
    return certs, chains, anchor_pems


def main():
    ossl, version = mint.find_openssl()
    mint.ensure_keys(ossl, KEYS)
    print(f"leaf validity {epoch(LEAF_NOT_BEFORE)}..{epoch(LEAF_NOT_AFTER)}, now_seconds {NOW}, "
          f"capture time {CAPTURE_TIME}")
    with tempfile.TemporaryDirectory() as tmp:
        minter = mint.Minter(ossl, tmp, KEYS)
        mint_all(minter)
        anchor_pems = {a: der.pem_certificate(minter.der[a]) for a in ["root_aws_rsa2048", "root_gcs_rsa4096",
                                                                        "root_p384", "impostor_p384"]}
        corpus_rows, corpus_text = build_rows(ossl, tmp, minter.der, CHAINS, "webpki_corpus", anchor_pems)
        check_oracle(corpus_rows)
        certs, chains, anchor_pems = load_captures()
        capture_rows, capture_text = build_rows(ossl, tmp, certs, chains, "webpki_capture", anchor_pems)
    disagree = [r["name"] for r in capture_rows if r["openssl_accepts"] != (r["expected"] == "ok")]
    if disagree:
        sys.exit(f"openssl's verdict on captured rows {disagree} is not the row's expected verdict")
    out = emit.HEADER.format(version=version)
    out += corpus_text + emit.chain_table("webpki_corpus_chains", corpus_rows) + "\n"
    out += capture_text + emit.chain_table("webpki_capture_chains", capture_rows) + "\n"
    out += emit.FOOTER
    OUT.write_text(out)
    positive = sum(1 for r in corpus_rows if r["expected"] == "ok")
    print(f"wrote {OUT}: {len(corpus_rows)} corpus chains ({positive} positive, "
          f"{len(corpus_rows) - positive} negative), {len(capture_rows)} capture rows")


if __name__ == "__main__":
    main()
