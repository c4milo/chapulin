#!/usr/bin/env python3
"""Regenerates test/rfc8448_vectors.h from the RFC 8448 text.

Usage: python3 test/gen_rfc8448.py [rfc8448.txt]

Without an argument the script downloads the text from
https://www.rfc-editor.org/rfc/rfc8448.txt (the regeneration source).
It writes rfc8448_vectors.h next to itself.

The RFC prints every value as an indented hex block under a label such
as "secret (32 octets):". The parser rebuilds each block and checks the
byte count against the declared octet count, so a parse slip fails
loudly instead of shipping a short array. Two text hazards need care:
page breaks (blank lines plus running headers and footers) fall inside
hex blocks and must not end them, and the section 2 RSA modulus carries
no octet count, so its expected length (128) comes from the extraction
table below instead.
"""

import pathlib
import re
import sys
import urllib.request

URL = "https://www.rfc-editor.org/rfc/rfc8448.txt"
OUT = pathlib.Path(__file__).with_name("rfc8448_vectors.h")

SECTION = re.compile(r"^(\d+)\.  ")
STANZA = re.compile(r"^   \{(?:client|server)\}  (.*)")
# "label (N octets):" at block indent, hex may start on the same line.
LABEL = re.compile(r"^ {3,6}(.+?) \((\d+) octets?\):\s*(.*)$")
# Section 2 private-key fields carry no octet count.
KEYLABEL = re.compile(r"^   (modulus \(public\)):\s*(.*)$")
# A continuation line is nothing but two-digit hex bytes, indented.
HEXLINE = re.compile(r"^ {6,}([0-9a-f]{2}(?: [0-9a-f]{2})*)\s*$")
# Page furniture: the footer, the form feed, and the running header.
# Body text is indented, so column-0 text is never a value.
FURNITURE = re.compile(r"^(Thomson |RFC 8448 |\f)")


class Block:
    def __init__(self, section, stanza, label, want, line):
        self.section = section
        self.stanza = stanza
        self.label = label
        self.want = want  # declared octet count, None for section 2
        self.line = line  # 1-based line of the label, for error messages
        self.data = b""


def parse_blocks(lines):
    """Returns every labeled hex block, in document order."""
    blocks = []
    section = 0
    stanza = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        m = SECTION.match(line)
        if m:
            section = int(m.group(1))
            stanza = ""
        m = STANZA.match(line)
        if m:
            stanza = m.group(1)
        m = LABEL.match(line) or KEYLABEL.match(line)
        if m:
            want = int(m.group(2)) if m.lastindex == 3 else None
            blk = Block(section, stanza, m.group(1), want, i + 1)
            hexed = [] if m.group(m.lastindex) == "(empty)" else [m.group(m.lastindex)]
            # Collect continuation lines. Blank lines and page furniture
            # are skipped only when hex resumes after them, so a page
            # break inside a block does not end it and a block that ends
            # at a page break does not swallow the next one.
            j = i + 1
            while j < len(lines):
                if lines[j].strip() == "" or FURNITURE.match(lines[j]):
                    j += 1
                    continue
                h = HEXLINE.match(lines[j])
                if not h:
                    break
                hexed.append(h.group(1))
                i = j  # consume up to the last hex line
                j += 1
            blk.data = bytes.fromhex(" ".join(hexed).replace(" ", ""))
            if blk.want is not None and len(blk.data) != blk.want:
                sys.exit(
                    f"line {blk.line}: {blk.label!r} declares {blk.want} "
                    f"octets, parsed {len(blk.data)}"
                )
            blocks.append(blk)
        i += 1
    return blocks


# (array name, section, stanza substring, label, occurrence, length).
# occurrence counts matches of (stanza, label) within the section; the
# length is what the C test expects and doubles as the only check for
# the count-less section 2 modulus.
WANT = [
    ("rsa_n", 2, "", "modulus (public)", 0, 128),
    # Section 3: simple 1-RTT.
    ("s3_client_priv", 3, "create an ephemeral x25519", "private key", 0, 32),
    ("s3_client_pub", 3, "create an ephemeral x25519", "public key", 0, 32),
    ("s3_server_priv", 3, "create an ephemeral x25519", "private key", 1, 32),
    ("s3_server_pub", 3, "create an ephemeral x25519", "public key", 1, 32),
    ("s3_client_hello", 3, "construct a ClientHello", "ClientHello", 0, 196),
    ("s3_server_hello", 3, "construct a ServerHello", "ServerHello", 0, 90),
    ("s3_early_secret", 3, 'extract secret "early"', "secret", 0, 32),
    ("s3_ecdhe", 3, 'extract secret "handshake"', "IKM", 0, 32),
    ("s3_hs_secret", 3, 'extract secret "handshake"', "secret", 0, 32),
    ("s3_th_ch_sh", 3, '"tls13 c hs traffic"', "hash", 0, 32),
    ("s3_c_hs_traffic", 3, '"tls13 c hs traffic"', "expanded", 0, 32),
    ("s3_s_hs_traffic", 3, '"tls13 s hs traffic"', "expanded", 0, 32),
    ("s3_master_secret", 3, 'extract secret "master"', "secret", 0, 32),
    ("s3_ee", 3, "construct an EncryptedExtensions", "EncryptedExtensions", 0, 40),
    ("s3_cert", 3, "construct a Certificate handshake", "Certificate", 0, 445),
    ("s3_cv", 3, "construct a CertificateVerify", "CertificateVerify", 0, 136),
    ("s3_server_fin_mac", 3, "calculate finished", "finished", 0, 32),
    ("s3_server_fin_msg", 3, "construct a Finished", "Finished", 0, 36),
    ("s3_th_ch_sf", 3, '"tls13 c ap traffic"', "hash", 0, 32),
    ("s3_c_ap_traffic", 3, '"tls13 c ap traffic"', "expanded", 0, 32),
    ("s3_s_ap_traffic", 3, '"tls13 s ap traffic"', "expanded", 0, 32),
    ("s3_exp_master", 3, '"tls13 exp master"', "expanded", 0, 32),
    ("s3_client_fin_mac", 3, "calculate finished", "finished", 1, 32),
    ("s3_client_fin_msg", 3, "construct a Finished", "Finished", 1, 36),
    ("s3_th_ch_cf", 3, '"tls13 res master"', "hash", 0, 32),
    ("s3_res_master", 3, '"tls13 res master"', "expanded", 0, 32),
    ("s3_ticket_nonce", 3, "generate resumption secret", "hash", 0, 2),
    ("s3_res_psk", 3, "generate resumption secret", "expanded", 0, 32),
    # Section 4: the PSK binder over the section 3 ticket.
    ("s4_early_secret", 4, 'extract secret "early"', "secret", 0, 32),
    ("s4_ch_prefix", 4, "calculate PSK binder", "ClientHello prefix", 0, 477),
    ("s4_binder_hash", 4, "calculate PSK binder", "binder hash", 0, 32),
    ("s4_binder_key", 4, "calculate PSK binder", "PRK", 0, 32),
    ("s4_binder", 4, "calculate PSK binder", "finished", 0, 32),
    # Section 5: HelloRetryRequest. The first "ServerHello" is the HRR.
    ("s5_ch1", 5, "construct a ClientHello", "ClientHello", 0, 180),
    ("s5_hrr", 5, "construct a ServerHello", "ServerHello", 0, 176),
    ("s5_ch2", 5, "construct a ClientHello", "ClientHello", 1, 512),
    ("s5_sh", 5, "construct a ServerHello", "ServerHello", 1, 123),
    ("s5_ecdhe", 5, 'extract secret "handshake"', "IKM", 0, 32),
    ("s5_th_ch_sh", 5, '"tls13 c hs traffic"', "hash", 0, 32),
    ("s5_c_hs_traffic", 5, '"tls13 c hs traffic"', "expanded", 0, 32),
    ("s5_s_hs_traffic", 5, '"tls13 s hs traffic"', "expanded", 0, 32),
]


def pick(blocks, section, stanza, label, occurrence):
    hits = [
        b
        for b in blocks
        if b.section == section and stanza in b.stanza and b.label == label
    ]
    if occurrence >= len(hits):
        sys.exit(
            f"section {section}: {len(hits)} block(s) match "
            f"({stanza!r}, {label!r}), wanted occurrence {occurrence}"
        )
    return hits[occurrence]


def emit(vectors):
    lines = [
        "// RFC 8448 trace vectors. Generated by test/gen_rfc8448.py from",
        "// https://www.rfc-editor.org/rfc/rfc8448.txt — regenerate with the",
        "// script, never edit by hand. The script is also the formatter:",
        "// the off marker keeps regeneration byte-identical under any",
        "// clang-format version, or none.",
        "#ifndef CH_RFC8448_VECTORS_H",
        "#define CH_RFC8448_VECTORS_H",
        "",
        "#include <stdint.h>",
        "",
        "// clang-format off",
    ]
    for name, data in vectors:
        lines.append(f"static const uint8_t rfc8448_{name}[{len(data)}] = {{")
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
    if len(sys.argv) > 1:
        text = pathlib.Path(sys.argv[1]).read_text()
    else:
        with urllib.request.urlopen(URL) as rsp:
            text = rsp.read().decode()
    blocks = parse_blocks(text.splitlines())
    vectors = []
    for name, section, stanza, label, occurrence, length in WANT:
        blk = pick(blocks, section, stanza, label, occurrence)
        if len(blk.data) != length:
            sys.exit(f"line {blk.line}: {name} is {len(blk.data)} bytes, expected {length}")
        vectors.append((name, blk.data))
    OUT.write_text(emit(vectors))
    print(f"{OUT}: {len(vectors)} arrays")


if __name__ == "__main__":
    main()
