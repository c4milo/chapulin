#!/usr/bin/env bash
# Cuts the two DER fields a TRUST=webpki trust anchor carries out of a
# root certificate: its subject Name TLV and its SubjectPublicKeyInfo
# TLV (docs/webpki.md, "Trust anchors").
#
#     examples/webpki-anchor.sh root.pem out
#
# writes out.name and out.spki, the two files examples/webpki_client.c
# and test/tls_client.c read. Nothing here decides anything: openssl
# writes the key, and a short TLV walk copies the Name out of the
# TBSCertificate, where it is the sixth field after version,
# serialNumber, signature, issuer and validity. The client verifies the
# chain; this script only moves bytes.
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 root.pem out" >&2
    exit 2
fi
pem=$1
out=$2

OPENSSL="${OPENSSL:-openssl}"
"$OPENSSL" x509 -in "$pem" -noout -pubkey |
    "$OPENSSL" pkey -pubin -outform DER -out "$out.spki"
"$OPENSSL" x509 -in "$pem" -outform DER -out "$out.der"
python3 - "$out.der" "$out.name" <<'PY'
import sys

data = open(sys.argv[1], "rb").read()


def tlv(b, off):
    """(start, header length, content length) of the TLV at off."""
    n = b[off + 1]
    hdr = 2
    if n & 0x80:
        count = n & 0x7F
        n = int.from_bytes(b[off + 2:off + 2 + count], "big")
        hdr = 2 + count
    return off, hdr, n


# Certificate SEQUENCE, TBSCertificate SEQUENCE, then version [0],
# serialNumber, signature, issuer and validity before subject.
_, h1, _ = tlv(data, 0)
_, h2, _ = tlv(data, h1)
at = h1 + h2
for _ in range(5):
    start, hdr, n = tlv(data, at)
    at = start + hdr + n
start, hdr, n = tlv(data, at)
open(sys.argv[2], "wb").write(data[start:start + hdr + n])
PY
rm -f "$out.der"
