"""DER reading and RFC 9846 section 4.5.1 rendering for gen_webpki_corpus.py.

The reader is the small subset the corpus needs: a TLV walk over one
X.509 certificate that finds the subject Name, the SubjectPublicKeyInfo
and the extensions. It reads, checks shape, and copies bytes out; it
never reaches a verdict. The verifier under test does that.
"""

import base64
import re
import sys

PEM_CERTIFICATE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", re.S
)


def read_tlv(data, off):
    """Returns (tag, content_off, content_len) for the TLV at off."""
    if off + 2 > len(data):
        sys.exit(f"offset {off}: TLV header runs past the end")
    tag = data[off]
    first = data[off + 1]
    if first < 0x80:
        return tag, off + 2, first
    count = first & 0x7F
    if count == 0 or count > 3 or off + 2 + count > len(data):
        sys.exit(f"offset {off}: length form 0x{first:02x} is out of scope")
    length = int.from_bytes(data[off + 2 : off + 2 + count], "big")
    return tag, off + 2 + count, length


def children(data, content_off, content_len):
    """Returns (tag, start, content_off, content_len) for each child TLV
    of the container whose content is [content_off, content_off + len)."""
    off = content_off
    end = content_off + content_len
    out = []
    while off < end:
        tag, c_off, c_len = read_tlv(data, off)
        if c_off + c_len > end:
            sys.exit(f"offset {off}: child runs past its container")
        out.append((tag, off, c_off, c_len))
        off = c_off + c_len
    return out


def tlv_bytes(data, child):
    """The whole TLV, header included, of a children() entry."""
    _, start, c_off, c_len = child
    return data[start : c_off + c_len]


def tbs_fields(cert):
    """The children of TBSCertificate, with the [0] version stripped so
    index 0 is the serial number whatever the version field."""
    tag, cert_off, cert_len = read_tlv(cert, 0)
    if tag != 0x30 or cert_off + cert_len != len(cert):
        sys.exit("certificate is not one exact-fill SEQUENCE")
    tag, tbs_off, tbs_len = read_tlv(cert, cert_off)
    if tag != 0x30:
        sys.exit("TBSCertificate is not a SEQUENCE")
    fields = children(cert, tbs_off, tbs_len)
    if fields and fields[0][0] == 0xA0:
        fields = fields[1:]
    if len(fields) < 6:
        sys.exit("TBSCertificate has fewer than six fields")
    return fields


# TBSCertificate after the version: serialNumber, signature, issuer,
# validity, subject, subjectPublicKeyInfo, then the optional [3] extensions.
FIELD_SUBJECT = 4
FIELD_SPKI = 5


def subject_name_tlv(cert):
    field = tbs_fields(cert)[FIELD_SUBJECT]
    if field[0] != 0x30:
        sys.exit("subject Name is not a SEQUENCE")
    return tlv_bytes(cert, field)


def spki_tlv(cert):
    field = tbs_fields(cert)[FIELD_SPKI]
    if field[0] != 0x30:
        sys.exit("subjectPublicKeyInfo is not a SEQUENCE")
    return tlv_bytes(cert, field)


def extension_measurements(cert):
    """Returns (extension count, largest extension TLV in bytes); (0, 0)
    when the certificate carries no extensions."""
    for field in tbs_fields(cert):
        if field[0] != 0xA3:
            continue
        _, _, wrap_off, _ = field
        tag, list_off, list_len = read_tlv(cert, wrap_off)
        if tag != 0x30:
            sys.exit("Extensions is not a SEQUENCE")
        exts = children(cert, list_off, list_len)
        return len(exts), max(len(tlv_bytes(cert, e)) for e in exts)
    return 0, 0


def certificate_message(entries):
    """The RFC 9846 section 4.5.1 Certificate handshake message: msg_type
    11, a 24-bit length, an empty certificate_request_context, and one
    CertificateEntry per DER certificate with an empty extensions vector."""
    body = b"".join(len(e).to_bytes(3, "big") + e + b"\x00\x00" for e in entries)
    payload = b"\x00" + len(body).to_bytes(3, "big") + body
    return b"\x0b" + len(payload).to_bytes(3, "big") + payload


def pem_certificates(text):
    """Every CERTIFICATE block in text, decoded, in order."""
    return [base64.b64decode(b) for b in PEM_CERTIFICATE.findall(text)]


def pem_certificate(der):
    body = base64.b64encode(der).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"
