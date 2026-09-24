#!/usr/bin/env python3
"""Regenerates test/webpki_auth_vectors.h, the CertificateVerify fixtures
for the TRUST=webpki server authentication flight.

Usage: python3 test/gen_webpki_auth_vectors.py

Each row signs one webpki_corpus_chains row's Certificate message, so
test/webpki_auth_test.c can drive hsa_server_auth (handshake_auth.c)
over a chain that verifies and a CertificateVerify the client must
accept or refuse. The transcript hsa_server_auth hashes before it reads
CertificateVerify is that one message, so the signed content of RFC 9846
section 4.5.2 is fixed here: 64 spaces, the context string, a zero byte,
and SHA-256 of the Certificate message. Each row carries that hash too,
and the test compares it against the hash it computes, so a corpus the
generator no longer matches fails by name instead of as a signature
error.

The generator re-mints the corpus certificates with
gen_webpki_corpus.py's own tables, which is reproducible: RSA PKCS#1
v1.5 is deterministic and the ECDSA signatures take OpenSSL's RFC 6979
nonce. The CertificateVerify signatures reproduce the same way, except
the RSA-PSS ones: the salt is random, so regenerating this header
changes the two rows that carry one. Vectors are regenerate-never-edit
snapshots.

The exact commands per row, over a file holding the 130 signed octets:

  openssl dgst -sha256 -sign leaf.pem -sigopt nonce-type:1       (ECDSA P-256)
  openssl dgst -sha384 -sign leaf.pem -sigopt nonce-type:1       (ECDSA P-384)
  openssl dgst -sha256 -sign leaf.pem -sigopt rsa_padding_mode:pss
    -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256        (RSA-PSS)

Every signature is checked with `openssl dgst -verify` under the leaf's
public key before it is emitted, so a wrong invocation fails here
instead of shipping a misleading vector.

A second table holds the RFC 7250 raw public key flight, one row per
key family: a Certificate message whose one CertificateEntry is the
leaf key's DER SubjectPublicKeyInfo, from

  openssl pkey -in leaf.pem -pubout -outform DER

and the CertificateVerify signature its family's scheme names over that
message's transcript hash, signed and checked the same way.
"""

import hashlib
import pathlib
import sys
import tempfile

import gen_webpki_corpus as corpus
import webpki_corpus_der as der
import webpki_corpus_emit as emit
import webpki_corpus_mint as mint

OUT = pathlib.Path(__file__).with_name("webpki_auth_vectors.h")

# RFC 9846 section 4.3.3's signature schemes, as handshake_message.h
# spells them.
SIGALG_ECDSA_P256_SHA256 = 0x0403
SIGALG_RSA_PSS_RSAE_SHA256 = 0x0804
SIGALG_ECDSA_P384_SHA384 = 0x0503

CONTEXT = b"TLS 1.3, server CertificateVerify"

# (key family, corpus chain, leaf key label). One chain per family, each
# of them a corpus row whose expected verdict is "ok".
SIGNERS = [
    ("rsa", "aws", "leaf_rsa2048"),
    ("p256", "r2", "leaf_p256"),
    ("p384", "p384_leaf", "leaf_p384"),
]


def signed_content(message):
    """The 130 octets of RFC 9846 section 4.5.2 over one Certificate
    message: 64 spaces, the context string, a zero byte, and the
    transcript hash, which is SHA-256 of that message alone."""
    transcript = hashlib.sha256(message).digest()
    return b" " * 64 + CONTEXT + b"\x00" + transcript, transcript


def sign(ossl, tmp, key_label, content, digest, padding):
    """One signature over content. digest is "sha256" or "sha384";
    padding is "pss" for RSA-PSS and None for ECDSA."""
    tmp = pathlib.Path(tmp)
    data = tmp / "signed_content.bin"
    data.write_bytes(content)
    key = mint.key_path(key_label)
    cmd = [ossl, "dgst", f"-{digest}", "-sign", str(key)]
    if padding == "pss":
        cmd += ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
                "-sigopt", "rsa_mgf1_md:sha256"]
    else:
        cmd += ["-sigopt", "nonce-type:1"]  # RFC 6979, so the row reproduces
    sig = mint.sh(*cmd, str(data))
    pub = tmp / f"{key_label}.pub"
    pub.write_bytes(mint.sh(ossl, "pkey", "-in", str(key), "-pubout"))
    sig_file = tmp / "sig.bin"
    sig_file.write_bytes(sig)
    verify = [ossl, "dgst", f"-{digest}", "-verify", str(pub), "-signature", str(sig_file)]
    if padding == "pss":
        verify += ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32",
                   "-sigopt", "rsa_mgf1_md:sha256"]
    mint.sh(*verify, str(data))
    return sig


# (key family, leaf key label, scheme, digest, padding) for the raw
# public key rows, one per key family, in the order the test reads them.
RAW_SIGNERS = [
    ("rsa", "leaf_rsa2048", SIGALG_RSA_PSS_RSAE_SHA256, "sha256", "pss"),
    ("p256", "leaf_p256", SIGALG_ECDSA_P256_SHA256, "sha256", None),
    ("p384", "leaf_p384", SIGALG_ECDSA_P384_SHA384, "sha384", None),
]


def build_raw_rows(ossl, tmp):
    """The raw public key rows: each leaf key's DER SPKI as the one entry
    of a Certificate message, and its family's signature over that
    message's signed content."""
    rows = []
    for family, key, scheme, digest, padding in RAW_SIGNERS:
        spki = mint.sh(ossl, "pkey", "-in", str(mint.key_path(key)), "-pubout", "-outform", "DER")
        message = der.certificate_message([spki])
        content, transcript = signed_content(message)
        sig = sign(ossl, tmp, key, content, digest, padding)
        rows.append(dict(name=family, spki=spki, message=message,
                         transcript=transcript, scheme=scheme, sig=sig))
    return rows


def corrupt(sig):
    """The same signature with its last byte flipped."""
    out = bytearray(sig)
    out[-1] ^= 0x01
    return bytes(out)


def build_rows(ossl, tmp, messages):
    """Every row of the table, in the order test/webpki_auth_test.c
    reads them. messages maps a corpus chain name to its Certificate
    message bytes."""
    content = {}
    transcripts = {}
    good = {}
    for family, chain, key in SIGNERS:
        content[family], transcripts[family] = signed_content(messages[chain])
    # The signature each family's own scheme names, over the hash that
    # scheme names. These three are the rows the client must accept.
    good["rsa"] = sign(ossl, tmp, "leaf_rsa2048", content["rsa"], "sha256", "pss")
    good["p256"] = sign(ossl, tmp, "leaf_p256", content["p256"], "sha256", None)
    good["p384"] = sign(ossl, tmp, "leaf_p384", content["p384"], "sha384", None)
    # The hash the other scheme names, under the same key: valid
    # signatures over content this client never hashes that way.
    other_hash = {
        "p256": sign(ossl, tmp, "leaf_p256", content["p256"], "sha384", None),
        "p384": sign(ossl, tmp, "leaf_p384", content["p384"], "sha256", None),
    }
    rows = []

    def row(name, chain, family, scheme, sig, expected, note):
        rows.append(dict(name=name, chain=chain, transcript=transcripts[family],
                         scheme=scheme, sig=sig, expected=expected, note=note))

    row("rsa_pss", "aws", "rsa", SIGALG_RSA_PSS_RSAE_SHA256, good["rsa"], "ok",
        "rsa_pss: the RSA-2048 leaf signs rsa_pss_rsae_sha256, the one scheme\n"
        "RFC 9846 section 4.3.3 leaves an RSA key.")
    row("p256_sha256", "r2", "p256", SIGALG_ECDSA_P256_SHA256, good["p256"], "ok",
        "p256_sha256: the P-256 leaf signs ecdsa_secp256r1_sha256 over the\n"
        "SHA-256 signed content.")
    row("p384_sha384", "p384_leaf", "p384", SIGALG_ECDSA_P384_SHA384, good["p384"], "ok",
        "p384_sha384: the P-384 leaf signs ecdsa_secp384r1_sha384 over the\n"
        "SHA-384 signed content, the one scheme whose content this client\n"
        "hashes with SHA-384.")
    row("p384_sha256_content", "p384_leaf", "p384", SIGALG_ECDSA_P384_SHA384, other_hash["p384"],
        "bad_signature",
        "p384_sha256_content: the P-384 leaf's valid signature over the\n"
        "SHA-256 signed content, sent under the scheme that names SHA-384.\n"
        "The boundary twin of p384_sha384: a client that hashed the content\n"
        "with SHA-256 here would accept this row and refuse that one.")
    row("p256_sha384_content", "r2", "p256", SIGALG_ECDSA_P256_SHA256, other_hash["p256"],
        "bad_signature",
        "p256_sha384_content: the P-256 leaf's valid signature over the\n"
        "SHA-384 signed content, under the scheme that names SHA-256.")
    row("rsa_corrupt", "aws", "rsa", SIGALG_RSA_PSS_RSAE_SHA256, corrupt(good["rsa"]),
        "bad_signature", "rsa_corrupt: the rsa_pss row with the last signature byte flipped.")
    row("p256_corrupt", "r2", "p256", SIGALG_ECDSA_P256_SHA256, corrupt(good["p256"]),
        "bad_signature", "p256_corrupt: the p256_sha256 row with the last signature byte flipped.")
    row("p384_corrupt", "p384_leaf", "p384", SIGALG_ECDSA_P384_SHA384, corrupt(good["p384"]),
        "bad_signature", "p384_corrupt: the p384_sha384 row with the last signature byte flipped.")
    return rows


HEADER = """\
// CertificateVerify fixtures for the TRUST=webpki server authentication
// flight. Generated by test/gen_webpki_auth_vectors.py over the chains in
// test/webpki_corpus.h; regenerate, never edit. Produced with {version}.
//
// Every row names a webpki_corpus_chains row, whose Certificate message
// is the whole transcript hsa_server_auth (handshake_auth.c) has hashed
// when CertificateVerify arrives. transcript is SHA-256 of that message,
// which test/webpki_auth_test.c recomputes and compares, and the
// signature covers the 130 signed octets of RFC 9846 section 4.5.2 over
// it. expected is the verdict the client must reach: "ok" or
// "bad_signature". The test builds the refusals of the scheme rule
// itself out of the accepted rows, because they need no signature of
// their own.
//
// webpki_raw_vectors holds the RFC 7250 raw public key flight, one row
// per key family: spki is the leaf key's DER SubjectPublicKeyInfo,
// message the Certificate message whose one CertificateEntry it is,
// transcript SHA-256 of that message, and sig the signature the scheme
// names over it. Every row is one the client must accept once a pin
// names spki.
#ifndef CH_TEST_WEBPKI_AUTH_VECTORS_H
#define CH_TEST_WEBPKI_AUTH_VECTORS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {{
    const char *name;
    const char *chain; // the webpki_corpus_chains row this row signs
    uint16_t scheme;   // the CertificateVerify signature scheme code
    const uint8_t *transcript;
    const uint8_t *sig;
    size_t sig_len;
    const char *expected;
}} webpki_auth_vector;

typedef struct {{
    const char *name;
    const uint8_t *spki;
    size_t spki_len;
    const uint8_t *message;
    size_t message_len;
    const uint8_t *transcript;
    uint16_t scheme;
    const uint8_t *sig;
    size_t sig_len;
}} webpki_raw_vector;

// clang-format off
"""

FOOTER = """\
// clang-format on

#endif
"""


def render_raw(rows):
    pool = emit.Pool("webpki_raw")
    table = [f"static const webpki_raw_vector webpki_raw_vectors[{len(rows)}] = {{"]
    for r in rows:
        spki = pool.add(f"spki_{r['name']}", r["spki"], f"{r['name']}: the DER SubjectPublicKeyInfo")
        message = pool.add(f"message_{r['name']}", r["message"],
                           f"{r['name']}: the Certificate message")
        transcript = pool.add(f"transcript_{r['name']}", r["transcript"],
                              f"{r['name']}: SHA-256 of the Certificate message")
        sig = pool.add(f"sig_{r['name']}", r["sig"], f"{r['name']}: the signature")
        table.append("    {")
        table.append(f'        "{r["name"]}", {spki}, sizeof {spki}, {message}, sizeof {message},')
        table.append(f"        {transcript}, 0x{r['scheme']:04x}, {sig}, sizeof {sig},")
        table.append("    },")
    table.append("};")
    return pool.render() + "\n" + "\n".join(table) + "\n"


def render(rows):
    transcripts = emit.Pool("webpki_auth_transcript")
    sigs = emit.Pool("webpki_auth_sig")
    body = []
    table = [f"static const webpki_auth_vector webpki_auth_vectors[{len(rows)}] = {{"]
    for r in rows:
        transcript = transcripts.add(r["chain"], r["transcript"],
                                     f"{r['chain']}: SHA-256 of the Certificate message")
        sig = sigs.add(r["name"], r["sig"], f"{r['name']}: the signature")
        for line in r["note"].splitlines():
            table.append(f"    // {line}")
        table.append("    {")
        table.append(f'        "{r["name"]}", "{r["chain"]}", 0x{r["scheme"]:04x},')
        table.append(f"        {transcript}, {sig}, sizeof {sig},")
        table.append(f'        "{r["expected"]}",')
        table.append("    },")
    table.append("};")
    body.append(transcripts.render())
    body.append(sigs.render())
    body.append("\n".join(table) + "\n")
    return "".join(body)


def main():
    ossl, version = mint.find_openssl()
    mint.ensure_keys(ossl, corpus.KEYS)
    with tempfile.TemporaryDirectory() as tmp:
        minter = mint.Minter(ossl, tmp, corpus.KEYS)
        corpus.mint_all(minter)
        messages = {}
        for c in corpus.CHAINS:
            if c["expected"] == "ok":
                messages[c["name"]] = der.certificate_message([minter.der[e] for e in c["entries"]])
        for _, chain_name, _ in SIGNERS:
            if chain_name not in messages:
                sys.exit(f"{chain_name} is no positive corpus chain")
        rows = build_rows(ossl, tmp, messages)
        raw_rows = build_raw_rows(ossl, tmp)
    OUT.write_text(HEADER.format(version=version) + render(rows) + render_raw(raw_rows) + FOOTER)
    accepted = sum(1 for r in rows if r["expected"] == "ok")
    print(f"wrote {OUT}: {len(rows)} rows ({accepted} accepted, {len(rows) - accepted} refused), "
          f"{len(raw_rows)} raw public key rows")


if __name__ == "__main__":
    main()
