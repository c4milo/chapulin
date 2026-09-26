#!/usr/bin/env python3
"""Convert the Wycheproof suites wycheproof_test.c drives into one
generated C header.

Usage: gen_wycheproof.py <wycheproof-checkout> <output.h>

Same pattern as gen_rfc8448.py: every hex block is checked against its
declared length, and the output lands in bin/, never in the tree. Each
suite becomes one data blob plus an index array of offsets, so the
header stays a few symbols instead of thousands.

Skips are encoded, not dropped, so the test binary can report them:
AEAD cases whose nonce size the fixed nonce[12] API cannot express,
HKDF cases outside the library's CH_ASSERT domain (info > 64 bytes,
okm 0 or > 255*32 bytes), HMAC groups whose tag is longer than the 32
bytes hmac_sha256 writes, and RSA PKCS#1 v1.5 groups whose public
exponent is not the fixed 65537. All are findings in chapulin's favor
and the test prints their counts.
"""

import json
import subprocess
import sys
from pathlib import Path


# The AEAD test drives fixed 1024-byte stack buffers; a longer message
# is skipped, not overflowed. Kept in sync with wycheproof_test.c.
WP_AEAD_MSG_MAX = 1024


def bytes_of(hexstr, expect_len=None, what=""):
    b = bytes.fromhex(hexstr)
    if expect_len is not None and len(b) != expect_len:
        raise SystemExit(f"{what}: got {len(b)} bytes, declared {expect_len}")
    return b


# Every non-hex field that reaches the generated C goes through this: the
# vectors track upstream HEAD, so a hostile or malformed value must not be
# interpolated into a struct initializer. Coerce to int and bound it, or
# the run stops. Without this a string tcId could break out of the array
# and inject top-level C that make check then compiles and runs.
def uint_of(v, hi, what):
    if isinstance(v, bool) or not isinstance(v, int):
        raise SystemExit(f"{what}: expected an integer, got {type(v).__name__} {v!r}")
    if v < 0 or v > hi:
        raise SystemExit(f"{what}: {v} out of range 0..{hi}")
    return v


class Blob:
    """One byte pool per suite; tests index into it by offset."""

    def __init__(self):
        self.data = bytearray()

    def add(self, b):
        off = len(self.data)
        self.data += b
        return off


def emit_blob(out, name, blob):
    out.append(f"static const uint8_t {name}[] = {{")
    data = blob.data if blob.data else b"\x00"  # empty arrays are not C
    for i in range(0, len(data), 12):
        out.append("    " + " ".join(f"0x{b:02x}," for b in data[i : i + 12]))
    out.append("};")
    out.append("")


def gen_x25519(d, out):
    blob = Blob()
    rows = []
    for g in d["testGroups"]:
        for t in g["tests"]:
            priv = bytes_of(t["private"], 32, f"x25519 tc{t['tcId']} private")
            pub = bytes_of(t["public"], 32, f"x25519 tc{t['tcId']} public")
            shared = bytes_of(t["shared"], 32, f"x25519 tc{t['tcId']} shared")
            if t["result"] == "valid":
                kind = 0  # must accept and match
            elif "ZeroSharedSecret" in t.get("flags", []):
                kind = 1  # must reject: TLS 1.3 forbids the zero secret
            else:
                kind = 2  # acceptable: either verdict, but a match if accepted
            rows.append((uint_of(t["tcId"], 0xffffffff, "x25519 tcId"), blob.add(priv + pub + shared), kind))
    emit_blob(out, "wp_x25519_data", blob)
    out.append("static const struct { uint32_t tc; uint32_t off; uint8_t kind; } wp_x25519[] = {")
    for tc, off, kind in rows:
        out.append(f"    {{{tc}, {off}, {kind}}},")
    out.append("};")
    out.append("")
    return len(rows)


def gen_aead(d, out):
    blob = Blob()
    rows = []
    skipped = 0
    oversize = 0
    for g in d["testGroups"]:
        if g["keySize"] != 256 or g["ivSize"] != 96 or g["tagSize"] != 128:
            skipped += len(g["tests"])  # key, nonce, or tag size the fixed API cannot express
            continue
        for t in g["tests"]:
            key = bytes_of(t["key"], 32, f"aead tc{t['tcId']} key")
            iv = bytes_of(t["iv"], 12, f"aead tc{t['tcId']} iv")
            tag = bytes_of(t["tag"], 16, f"aead tc{t['tcId']} tag")
            aad = bytes_of(t["aad"])
            msg = bytes_of(t["msg"])
            ct = bytes_of(t["ct"])
            if len(ct) != len(msg):
                raise SystemExit(f"aead tc{t['tcId']}: ct/msg length mismatch")
            if len(msg) > WP_AEAD_MSG_MAX or len(aad) > WP_AEAD_MSG_MAX:
                oversize += 1  # larger than the test's fixed buffers
                continue
            off = blob.add(key + iv + tag + aad + msg + ct)
            rows.append((uint_of(t["tcId"], 0xffffffff, "aead tcId"), off, len(aad), len(msg),
                         1 if t["result"] == "valid" else 0))
    emit_blob(out, "wp_aead_data", blob)
    out.append(
        "static const struct { uint32_t tc; uint32_t off; uint16_t aad_len;"
        " uint16_t msg_len; uint8_t valid; } wp_aead[] = {"
    )
    for tc, off, alen, mlen, valid in rows:
        out.append(f"    {{{tc}, {off}, {alen}, {mlen}, {valid}}},")
    out.append("};")
    out.append("")
    out.append(f"#define WP_AEAD_SKIPPED {skipped} // key/nonce/tag sizes the fixed API cannot express")
    out.append(f"#define WP_AEAD_OVERSIZE {oversize} // messages larger than the test's 1 KB buffers")
    out.append("")
    return len(rows)


# The AES-GCM suite, for gcm.c. Only a -DCH_TRANSPORT_QUIC_NONBLOCKING build
# compiles that file, so the rows below are emitted inside the same guard
# and the other legs of wycheproof_test.c read a header that declares
# nothing for them. INV-26 admits this key in a test: the rule bounds
# which keys a library source may pass to the AEAD, and `test` is
# excluded from the Semgrep rule that holds it.
#
# AEAD_AES_128_GCM is the one profile RFC 9001 fixes, and
# AEAD_AES_256_GCM is TLS_AES_256_GCM_SHA384's, so the 128-bit and the
# 256-bit groups each fill an array of their own and a group with any
# other key, nonce or tag size is counted and skipped rather than
# squeezed into an API that cannot express it. The 256-bit rows sit
# inside CH_AES_256 as well, which aes.h defines for a suite build
# and for a test built with -DCH_AES_256_TEST, because only those builds
# have an AES-256 to run them on.
def gen_aes_gcm(d, out):
    n128 = gen_aes_gcm_size(d, out, 128, "wp_aes_gcm", "WP_AES_GCM")
    n256 = gen_aes_gcm_size(d, out, 256, "wp_aes256_gcm", "WP_AES256_GCM")
    return n128, n256


def gen_aes_gcm_size(d, out, key_bits, name, macro):
    key_len = key_bits // 8
    blob = Blob()
    rows = []
    skipped = 0
    oversize = 0
    for g in d["testGroups"]:
        if g["keySize"] != key_bits or g["ivSize"] != 96 or g["tagSize"] != 128:
            if g["keySize"] == key_bits or (key_bits == 128 and g["keySize"] not in (128, 256)):
                skipped += len(g["tests"])  # key, nonce, or tag size the fixed API cannot express
            continue
        for t in g["tests"]:
            key = bytes_of(t["key"], key_len, f"aes_gcm tc{t['tcId']} key")
            iv = bytes_of(t["iv"], 12, f"aes_gcm tc{t['tcId']} iv")
            tag = bytes_of(t["tag"], 16, f"aes_gcm tc{t['tcId']} tag")
            aad = bytes_of(t["aad"])
            msg = bytes_of(t["msg"])
            ct = bytes_of(t["ct"])
            if len(ct) != len(msg):
                raise SystemExit(f"aes_gcm tc{t['tcId']}: ct/msg length mismatch")
            if len(msg) > WP_AEAD_MSG_MAX or len(aad) > WP_AEAD_MSG_MAX:
                oversize += 1  # larger than the test's fixed buffers
                continue
            off = blob.add(key + iv + tag + aad + msg + ct)
            rows.append((uint_of(t["tcId"], 0xffffffff, "aes_gcm tcId"), off, len(aad), len(msg),
                         1 if t["result"] == "valid" else 0))
    guard = "defined(CH_TRANSPORT_QUIC_NONBLOCKING)" if key_bits == 128 else \
        "defined(CH_TRANSPORT_QUIC_NONBLOCKING) && defined(CH_AES_256)"
    out.append(f"#if {guard}")
    emit_blob(out, f"{name}_data", blob)
    out.append(
        "static const struct { uint32_t tc; uint32_t off; uint16_t aad_len;"
        f" uint16_t msg_len; uint8_t valid; }} {name}[] = {{"
    )
    for tc, off, alen, mlen, valid in rows:
        out.append(f"    {{{tc}, {off}, {alen}, {mlen}, {valid}}},")
    out.append("};")
    out.append("")
    out.append(f"#define {macro}_SKIPPED {skipped} // key/nonce/tag sizes the fixed API cannot express")
    out.append(f"#define {macro}_OVERSIZE {oversize} // messages larger than the test's 1 KB buffers")
    out.append(f"#endif // {guard}")
    out.append("")
    return len(rows)


# The HKDF suites, SHA-256 and SHA-384. hash_len is the hash's output
# length, which fixes both halves of the library's asserted domain below.
# The SHA-384 rows sit inside CH_HASH_SHA384, the define hkdf.h turns
# SHA-384 on with, so a leg that builds without it reads a header that
# declares nothing for them.
def gen_hkdf(d, out, hash_len=32, name="wp_hkdf", macro="WP_HKDF"):
    blob = Blob()
    rows = []
    skipped = 0
    for g in d["testGroups"]:
        for t in g["tests"]:
            ikm, salt, info = bytes_of(t["ikm"]), bytes_of(t["salt"]), bytes_of(t["info"])
            okm = bytes_of(t["okm"], t["size"] if t["result"] == "valid" else None)
            size = t["size"]
            # The library's asserted domain (hkdf.c): 0 < out_len <=
            # 255*hash_len and info_len <= HKDF_INFO_MAX, which hkdf.h
            # derives as 2 + 1 + 6 + HKDF_LABEL_MAX + 1 + HKDF_HASH_MAX
            # and the wycheproof build compiles at the default cap of 12.
            # The SHA-256 rows take a hash length of 32 there, which every
            # build admits, and the SHA-384 rows 48. Outside it, CH_ASSERT
            # faults on purpose instead of proceeding; the test reports
            # the count. Written as the same sum, so a reader can check it
            # against hkdf.h rather than against a number.
            hkdf_info_max = 2 + 1 + 6 + 12 + 1 + hash_len
            if size == 0 or size > 255 * hash_len or len(info) > hkdf_info_max:
                skipped += 1
                continue
            off = blob.add(ikm + salt + info + okm)
            rows.append(
                (uint_of(t["tcId"], 0xffffffff, "hkdf tcId"), off, len(ikm), len(salt), len(info),
                 len(okm), uint_of(size, 255 * hash_len, "hkdf size"),
                 1 if t["result"] == "valid" else 0)
            )
    if hash_len != 32:
        out.append("#ifdef CH_HASH_SHA384")
    emit_blob(out, f"{name}_data", blob)
    out.append(
        "static const struct { uint32_t tc; uint32_t off; uint16_t ikm_len; uint16_t salt_len;"
        f" uint16_t info_len; uint16_t okm_len; uint16_t size; uint8_t valid; }} {name}[] = {{"
    )
    for row in rows:
        out.append("    {" + ", ".join(str(v) for v in row) + "},")
    out.append("};")
    out.append("")
    out.append(f"#define {macro}_SKIPPED {skipped} // outside the library's CH_ASSERT domain")
    if hash_len != 32:
        out.append("#endif // CH_HASH_SHA384")
    out.append("")
    return len(rows)


# The HMAC-SHA-256 suite, for hmac_sha256 called as a MAC: Finished, the
# binders, the QUIC Retry token, the HelloRetryRequest cookie and the
# webpki ticket binding all call it that way. The HKDF suite calls it
# only through extract and expand.
#
# hmac_sha256 asserts nothing about its key or message length (hkdf.c),
# so unlike HKDF no case is skipped for an asserted domain. It always
# writes SHA256_LEN bytes, and a group with a shorter tagSize compares a
# prefix of them. A group whose tag is longer than SHA256_LEN is the one
# the function cannot express. The constant takes sha256.h's name, so a
# reader can check it against the header.
SHA256_LEN = 32


# The HMAC-SHA-384 suite runs the same way through hmac_sha384, whose
# output is SHA384_LEN, inside CH_HASH_SHA384 as the HKDF-SHA-384 rows are.
SHA384_LEN = 48


def gen_hmac(d, out, hash_len=SHA256_LEN, name="wp_hmac", macro="WP_HMAC"):
    blob = Blob()
    rows = []
    skipped = 0
    for g in d["testGroups"]:
        key_bits = uint_of(g["keySize"], 0xffff, "hmac keySize")
        tag_bits = uint_of(g["tagSize"], 0xffff, "hmac tagSize")
        if key_bits % 8 != 0 or tag_bits % 8 != 0:
            raise SystemExit(f"hmac group keySize {key_bits}, tagSize {tag_bits}: not whole bytes")
        if tag_bits > 8 * hash_len:
            skipped += len(g["tests"])  # longer than the hash_len bytes the HMAC writes
            continue
        for t in g["tests"]:
            key = bytes_of(t["key"], key_bits // 8, f"hmac tc{t['tcId']} key")
            msg = bytes_of(t["msg"])
            tag = bytes_of(t["tag"], tag_bits // 8, f"hmac tc{t['tcId']} tag")
            off = blob.add(key + msg + tag)
            rows.append(
                (uint_of(t["tcId"], 0xffffffff, "hmac tcId"), off, len(key), len(msg), len(tag),
                 1 if t["result"] == "valid" else 0)
            )
    if hash_len != SHA256_LEN:
        out.append("#ifdef CH_HASH_SHA384")
    emit_blob(out, f"{name}_data", blob)
    out.append(
        "static const struct { uint32_t tc; uint32_t off; uint16_t key_len; uint16_t msg_len;"
        f" uint8_t tag_len; uint8_t valid; }} {name}[] = {{"
    )
    for row in rows:
        out.append("    {" + ", ".join(str(v) for v in row) + "},")
    out.append("};")
    out.append("")
    out.append(f"#define {macro}_SKIPPED {skipped} // tags longer than the {hash_len} bytes the HMAC writes")
    if hash_len != SHA256_LEN:
        out.append("#endif // CH_HASH_SHA384")
    out.append("")
    return len(rows)


# The P-256 ECDH suite in the "ecpoint" encoding: the peer's public key
# is the SEC 1 point the wire carries, which is what p256_ecdh reads.
# The other secp256r1 ECDH files wrap that point in a SubjectPublicKeyInfo
# or a PEM, and no part of chapulin parses either for a key share.
#
# The private key arrives as a big-endian integer of whatever length it
# needs, so it is left-padded to the fixed 32 bytes the API takes; a
# value that does not fit stops the run. The public key keeps its own
# length, because the compressed and empty encodings are cases the
# 65-byte API refuses by length and the runner counts that way.
def gen_ecdh_p256(d, out):
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    blob = Blob()
    rows = []
    for g in d["testGroups"]:
        if g["curve"] != "secp256r1" or g["encoding"] != "ecpoint":
            raise SystemExit(f"ecdh_p256: group is {g['curve']}/{g['encoding']},"
                             " expected secp256r1/ecpoint")
        for t in g["tests"]:
            priv = bytes.fromhex(t["private"]).lstrip(b"\x00")
            if len(priv) > 32:
                raise SystemExit(f"ecdh_p256 tc{t['tcId']}: private key over 32 bytes")
            if not 1 <= int.from_bytes(priv, "big") < n:
                raise SystemExit(f"ecdh_p256 tc{t['tcId']}: private key outside [1, n-1]")
            priv = priv.rjust(32, b"\x00")
            pub = bytes.fromhex(t["public"])
            shared = bytes_of(t["shared"], None, f"ecdh_p256 tc{t['tcId']} shared")
            if t["result"] == "valid":
                kind = 0  # must accept and match
            elif t["result"] == "invalid":
                kind = 1  # must reject
            else:
                kind = 2  # acceptable: either verdict, but a match if accepted
            if kind != 1 and len(shared) != 32:
                raise SystemExit(f"ecdh_p256 tc{t['tcId']}: shared secret is not 32 bytes")
            off = blob.add(priv + shared.ljust(32, b"\x00") + pub)
            rows.append((uint_of(t["tcId"], 0xffffffff, "ecdh_p256 tcId"), off,
                         uint_of(len(pub), 0xffff, "ecdh_p256 public length"), kind))
    emit_blob(out, "wp_ecdh_p256_data", blob)
    out.append("static const struct { uint32_t tc; uint32_t off; uint16_t pub_len;"
               " uint8_t kind; } wp_ecdh_p256[] = {")
    for row in rows:
        out.append("    {" + ", ".join(str(v) for v in row) + "},")
    out.append("};")
    out.append("")
    return len(rows)


# One ECDSA verify suite. name is the C symbol stem (wp_<name>_data and
# wp_<name>); curve and sha are the values every group must declare, so
# a suite file that changes shape upstream stops the run instead of
# feeding the wrong digest to the wrong verifier; coord_len is the byte
# length of one coordinate, so an uncompressed point is 1 + 2 * coord_len
# bytes and the blob keeps the 2 * coord_len bytes of X||Y after the 0x04.
# The runner hashes msg itself; only sig is stored as the wire carries it.
# "acceptable" is recorded as a rejection: this is a verifier with one
# accepted encoding, so a BER or otherwise lax signature must fail.
def gen_ecdsa(d, out, name, curve, sha, coord_len):
    blob = Blob()
    rows = []
    for g in d["testGroups"]:
        if g["publicKey"]["curve"] != curve or g["sha"] != sha:
            raise SystemExit(f"{name}: group is {g['publicKey']['curve']}/{g['sha']},"
                             f" expected {curve}/{sha}")
        unc = bytes_of(g["publicKey"]["uncompressed"], 1 + 2 * coord_len,
                       f"{name} group public key")
        if unc[0] != 0x04:
            raise SystemExit(f"{name} group public key is not an uncompressed point")
        pub_off = blob.add(unc[1:])
        for t in g["tests"]:
            msg, sig = bytes_of(t["msg"]), bytes_of(t["sig"])
            off = blob.add(msg + sig)
            rows.append(
                (uint_of(t["tcId"], 0xffffffff, f"{name} tcId"), pub_off, off,
                 uint_of(len(msg), 0xffff, f"{name} msg_len"),
                 uint_of(len(sig), 0xffff, f"{name} sig_len"), 1 if t["result"] == "valid" else 0)
            )
    emit_blob(out, f"wp_{name}_data", blob)
    out.append(
        "static const struct { uint32_t tc; uint32_t pub_off; uint32_t off; uint16_t msg_len;"
        f" uint16_t sig_len; uint8_t valid; }} wp_{name}[] = {{"
    )
    for row in rows:
        out.append("    {" + ", ".join(str(v) for v in row) + "},")
    out.append("};")
    out.append("")
    return len(rows)


def gen_rsa(files, out):
    blob = Blob()
    rows = []
    for path in files:
        d = json.load(open(path))
        for g in d["testGroups"]:
            n = bytes_of(g["publicKey"]["modulus"]).lstrip(b"\x00")
            if g["publicKey"]["publicExponent"] != "010001":
                raise SystemExit("rsa group exponent is not 65537")
            n_off = blob.add(n)
            for t in g["tests"]:
                msg, sig = bytes_of(t["msg"]), bytes_of(t["sig"])
                off = blob.add(msg + sig)
                rows.append(
                    (uint_of(t["tcId"], 0xffffffff, "rsa tcId"), n_off, len(n), off,
                     len(msg), len(sig), 1 if t["result"] == "valid" else 0)
                )
    emit_blob(out, "wp_rsa_data", blob)
    out.append(
        "static const struct { uint32_t tc; uint32_t n_off; uint16_t n_len; uint32_t off;"
        " uint16_t msg_len; uint16_t sig_len; uint8_t valid; } wp_rsa[] = {"
    )
    for row in rows:
        out.append("    {" + ", ".join(str(v) for v in row) + "},")
    out.append("};")
    out.append("")
    return len(rows)


# The digest lengths rsa_pkcs1_verify's DigestInfo prefixes name, keyed by
# the hash a v1.5 suite group declares.
RSA_PKCS1_DIGEST_LEN = {"SHA-256": 32, "SHA-384": 48}


# The RSASSA-PKCS1-v1_5 verify suites, several files into one arm. A
# group's key is read from publicKey.modulus and publicKey.publicExponent
# (the schema's hex fields); the modulus is cross-checked against the
# publicKeyAsn DER, which carries the same INTEGER bytes, and its stripped
# length against keySize. rsa_pkcs1_verify fixes e = 65537, so a group with
# another exponent is skipped whole and counted, the way gen_aead counts
# the sizes the AEAD API cannot express. The runner hashes msg with the
# group's hash; digest_len tells it which. "acceptable" is recorded as a
# rejection, as gen_ecdsa does: the one such case per suite is the
# DigestInfo with the AlgorithmIdentifier's NULL parameter missing, and a
# verifier that compares the encoding against one fixed prefix must
# refuse it.
def gen_rsa_pkcs1(files, out):
    blob = Blob()
    rows = []
    skipped = 0
    for path in files:
        d = json.load(open(path))
        for g in d["testGroups"]:
            if g["publicKey"]["publicExponent"] != "010001":
                skipped += len(g["tests"])  # an exponent the fixed e = 65537 verifier refuses
                continue
            modulus_der = bytes_of(g["publicKey"]["modulus"])
            if modulus_der not in bytes_of(g["publicKeyAsn"]):
                raise SystemExit(f"{path.name}: publicKey.modulus is not in publicKeyAsn")
            n = modulus_der.lstrip(b"\x00")
            if len(n) * 8 != g["keySize"]:
                raise SystemExit(f"{path.name}: modulus is {len(n)} bytes, keySize {g['keySize']}")
            if g["sha"] not in RSA_PKCS1_DIGEST_LEN:
                raise SystemExit(f"{path.name}: group hash {g['sha']} has no DigestInfo prefix")
            digest_len = RSA_PKCS1_DIGEST_LEN[g["sha"]]
            n_off = blob.add(n)
            for t in g["tests"]:
                msg, sig = bytes_of(t["msg"]), bytes_of(t["sig"])
                off = blob.add(msg + sig)
                rows.append(
                    (uint_of(t["tcId"], 0xffffffff, "rsa pkcs1 tcId"), n_off, off, len(n),
                     uint_of(len(msg), 0xffff, "rsa pkcs1 msg_len"),
                     uint_of(len(sig), 0xffff, "rsa pkcs1 sig_len"), digest_len,
                     1 if t["result"] == "valid" else 0)
                )
    emit_blob(out, "wp_rsa_pkcs1_data", blob)
    # Fields in size order, widest first, so the row carries no padding.
    out.append(
        "static const struct { uint32_t tc; uint32_t n_off; uint32_t off; uint16_t n_len;"
        " uint16_t msg_len; uint16_t sig_len; uint8_t digest_len; uint8_t valid; }"
        " wp_rsa_pkcs1[] = {"
    )
    for row in rows:
        out.append("    {" + ", ".join(str(v) for v in row) + "},")
    out.append("};")
    out.append("")
    out.append(f"#define WP_RSA_PKCS1_SKIPPED {skipped}"
               " // groups with a public exponent other than 65537")
    out.append("")
    return len(rows)


# How many rows each signing key size contributes. The private
# exponentiation is the most expensive call this binary makes -- one
# RSA-4096 signature is 8,192 Montgomery multiplications of 128 limbs --
# and the same binary runs under qemu on the Cortex-M3 lane, so the suite
# takes a few rows per size rather than every row in the file. The rows
# cover the three sizes rsa_sign.c admits; the cases that vary the
# padding are the verify suites' business, because RSASP1 does not see
# the padding.
RSA_SIGN_ROWS = {2048: 2, 3072: 1, 4096: 1}


# The private exponentiation against third-party vectors.
#
# Wycheproof has no RSA-PSS signing suite, and cannot have one: PSS draws
# a fresh salt, so a signature is not a function of the message alone.
# The RSASSA-PKCS1-v1_5 generation suites carry what rsa_sp1 needs
# anyway -- a private key and a signature that key produced -- because
# RSASP1 is the same primitive under both paddings. The encoded message
# is recovered here as em = sig^e mod n, which is the public
# verification exponentiation over published values, and the row then
# asserts that rsa_sp1 turns that em back into that sig.
#
# Anything rsa_sign.c would refuse is refused here instead, so a skipped
# row is never handed to the C as a silently passing case: a public exponent
# other than 65537, a modulus outside 256..512 bytes or not a multiple
# of 8, a modulus with its top bit clear or its low bit clear, and a
# signature that is not n_len bytes.
def gen_rsa_sign(files, out):
    blob = Blob()
    rows = []
    skipped = 0
    for path in files:
        d = json.load(open(path))
        taken = 0
        want = RSA_SIGN_ROWS[d["testGroups"][0]["keySize"]]
        for g in d["testGroups"]:
            pk = g["privateKey"]
            n = bytes_of(pk["modulus"]).lstrip(b"\x00")
            e = int(pk["publicExponent"], 16)
            priv = bytes_of(pk["privateExponent"]).lstrip(b"\x00")
            if (e != 65537 or len(n) < 256 or len(n) > 512 or len(n) % 8 != 0
                    or not n[0] & 0x80 or not n[-1] & 1 or len(priv) > len(n)):
                skipped += len(g["tests"])
                continue
            n_int = int.from_bytes(n, "big")
            for t in g["tests"]:
                if taken >= want:
                    skipped += 1
                    continue
                sig = bytes_of(t["sig"])
                if len(sig) != len(n) or int.from_bytes(sig, "big") >= n_int:
                    skipped += 1
                    continue
                em = pow(int.from_bytes(sig, "big"), e, n_int).to_bytes(len(n), "big")
                off = blob.add(n + priv.rjust(len(n), b"\x00") + em + sig)
                rows.append((uint_of(t["tcId"], 0xffffffff, "rsa sign tcId"), off,
                             uint_of(len(n), 0xffff, "rsa sign n_len")))
                taken += 1
    emit_blob(out, "wp_rsa_sign_data", blob)
    # Four values of n_len bytes each at off: the modulus, the private
    # exponent left-padded to that length, the encoded message and the
    # signature it must produce.
    out.append(
        "static const struct { uint32_t tc; uint32_t off; uint16_t n_len; } wp_rsa_sign[] = {"
    )
    for row in rows:
        out.append("    {" + ", ".join(str(v) for v in row) + "},")
    out.append("};")
    out.append("")
    out.append(f"#define WP_RSA_SIGN_SKIPPED {skipped}"
               " // rows past the per-size cap, and keys rsa_sign.c refuses")
    out.append("")
    return len(rows)


def gen_mlkem_keygen(d, out):
    blob = Blob()
    rows = []
    for g in d["testGroups"]:
        for t in g["tests"]:
            seed = bytes_of(t["seed"], 64, f"mlkem keygen tc{t['tcId']} seed")
            ek = bytes_of(t["ek"], 1184, f"mlkem keygen tc{t['tcId']} ek")
            dk = bytes_of(t["dk"], 2400, f"mlkem keygen tc{t['tcId']} dk")
            rows.append((uint_of(t["tcId"], 0xffffffff, "mlkem keygen tcId"),
                         blob.add(seed + ek + dk)))
    emit_blob(out, "wp_mlkem_keygen_data", blob)
    out.append("static const struct { uint32_t tc; uint32_t off; } wp_mlkem_keygen[] = {")
    for tc, off in rows:
        out.append(f"    {{{tc}, {off}}},")
    out.append("};")
    out.append("")
    return len(rows)


def gen_mlkem_encaps(d, out):
    blob = Blob()
    rows = []
    skipped = 0
    for g in d["testGroups"]:
        for t in g["tests"]:
            ek = bytes_of(t["ek"])
            if len(ek) != 1184:
                skipped += 1  # an ek length the fixed ek[1184] API cannot express
                continue
            if t["result"] == "valid":
                m = bytes_of(t["m"], 32, f"mlkem encaps tc{t['tcId']} m")
                c = bytes_of(t["c"], 1088, f"mlkem encaps tc{t['tcId']} c")
                k = bytes_of(t["K"], 32, f"mlkem encaps tc{t['tcId']} K")
                rows.append((uint_of(t["tcId"], 0xffffffff, "mlkem encaps tcId"),
                             blob.add(m + ek + c + k), 1))
            else:
                # A correct-length ek the modulus check must reject; m, c
                # and K are absent or empty upstream, so zeros stand in
                # and the test asserts only the nonzero return.
                m = bytes_of(t.get("m", "")).ljust(32, b"\x00")[:32]
                rows.append((uint_of(t["tcId"], 0xffffffff, "mlkem encaps tcId"),
                             blob.add(m + ek + b"\x00" * 1088 + b"\x00" * 32), 0))
    emit_blob(out, "wp_mlkem_encaps_data", blob)
    out.append("static const struct { uint32_t tc; uint32_t off; uint8_t valid; } wp_mlkem_encaps[] = {")
    for tc, off, valid in rows:
        out.append(f"    {{{tc}, {off}, {valid}}},")
    out.append("};")
    out.append("")
    out.append(f"#define WP_MLKEM_ENCAPS_SKIPPED {skipped} // ek lengths the fixed API cannot express")
    out.append("")
    return len(rows)


def gen_mlkem_full(d, out):
    blob = Blob()
    rows = []
    skipped = 0
    for g in d["testGroups"]:
        for t in g["tests"]:
            if t["result"] != "valid":
                skipped += 1  # seed, ek or c of a length the fixed API cannot express
                continue
            seed = bytes_of(t["seed"], 64, f"mlkem tc{t['tcId']} seed")
            ek = bytes_of(t["ek"], 1184, f"mlkem tc{t['tcId']} ek")
            c = bytes_of(t["c"], 1088, f"mlkem tc{t['tcId']} c")
            k = bytes_of(t["K"], 32, f"mlkem tc{t['tcId']} K")
            rows.append((uint_of(t["tcId"], 0xffffffff, "mlkem tcId"),
                         blob.add(seed + ek + c + k)))
    emit_blob(out, "wp_mlkem_data", blob)
    out.append("static const struct { uint32_t tc; uint32_t off; } wp_mlkem[] = {")
    for tc, off in rows:
        out.append(f"    {{{tc}, {off}}},")
    out.append("};")
    out.append("")
    out.append(f"#define WP_MLKEM_SKIPPED {skipped} // input lengths the fixed API cannot express")
    out.append("")
    return len(rows)


def main():
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    v1 = src / "testvectors_v1"
    commit = subprocess.run(
        ["git", "-C", str(src), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()

    out = [
        "// Generated by test/gen_wycheproof.py — do not edit, do not commit.",
        f'#define WYCHEPROOF_COMMIT "{commit}"',
        "#include <stdint.h>",
        "",
    ]
    n_x = gen_x25519(json.load(open(v1 / "x25519_test.json")), out)
    n_d = gen_ecdh_p256(json.load(open(v1 / "ecdh_secp256r1_ecpoint_test.json")), out)
    n_a = gen_aead(json.load(open(v1 / "chacha20_poly1305_test.json")), out)
    n_h = gen_hkdf(json.load(open(v1 / "hkdf_sha256_test.json")), out)
    n_m = gen_hmac(json.load(open(v1 / "hmac_sha256_test.json")), out)
    n_h384 = gen_hkdf(json.load(open(v1 / "hkdf_sha384_test.json")), out, 48, "wp_hkdf384",
                      "WP_HKDF384")
    n_m384 = gen_hmac(json.load(open(v1 / "hmac_sha384_test.json")), out, SHA384_LEN,
                      "wp_hmac384", "WP_HMAC384")
    n_g, n_g256 = gen_aes_gcm(json.load(open(v1 / "aes_gcm_test.json")), out)
    # The four ECDSA arms: the two matched pairs a chain signs with, and
    # the two mismatched digest lengths that exercise the FIPS 186-4
    # section 6.4 rule the runner applies (a short digest is used whole,
    # a long one is cut to the order's length).
    n_e = gen_ecdsa(json.load(open(v1 / "ecdsa_secp256r1_sha256_test.json")), out,
                    "ecdsa_p256_sha256", "secp256r1", "SHA-256", 32)
    n_e384 = gen_ecdsa(json.load(open(v1 / "ecdsa_secp384r1_sha384_test.json")), out,
                       "ecdsa_p384_sha384", "secp384r1", "SHA-384", 48)
    n_e384_256 = gen_ecdsa(json.load(open(v1 / "ecdsa_secp384r1_sha256_test.json")), out,
                           "ecdsa_p384_sha256", "secp384r1", "SHA-256", 48)
    n_e256_512 = gen_ecdsa(json.load(open(v1 / "ecdsa_secp256r1_sha512_test.json")), out,
                           "ecdsa_p256_sha512", "secp256r1", "SHA-512", 32)
    # The RSA suites run up to RSA-4096: the test binary builds with
    # -DCH_RSA_MODULUS_MAX=512, rsa.h's bound in the webpki build.
    n_r = gen_rsa(
        [v1 / "rsa_pss_2048_sha256_mgf1_32_test.json", v1 / "rsa_pss_3072_sha256_mgf1_32_test.json",
         v1 / "rsa_pss_4096_sha256_mgf1_32_test.json"],
        out,
    )
    n_rp = gen_rsa_pkcs1(
        [v1 / "rsa_signature_2048_sha256_test.json", v1 / "rsa_signature_3072_sha256_test.json",
         v1 / "rsa_signature_4096_sha256_test.json", v1 / "rsa_signature_2048_sha384_test.json",
         v1 / "rsa_signature_4096_sha384_test.json"],
        out,
    )
    # The signing suite reads the v1.5 *generation* files, the only ones
    # that carry a private key; gen_rsa_sign says why the padding does
    # not matter and why it caps the rows.
    n_rs = gen_rsa_sign(
        [v1 / "rsa_pkcs1_2048_sig_gen_test.json", v1 / "rsa_pkcs1_3072_sig_gen_test.json",
         v1 / "rsa_pkcs1_4096_sig_gen_test.json"],
        out,
    )
    n_kk = gen_mlkem_keygen(json.load(open(v1 / "mlkem_768_keygen_seed_test.json")), out)
    n_ke = gen_mlkem_encaps(json.load(open(v1 / "mlkem_768_encaps_test.json")), out)
    n_kf = gen_mlkem_full(json.load(open(v1 / "mlkem_768_test.json")), out)
    dst.write_text("\n".join(out) + "\n")
    print(f"wycheproof vectors: x25519 {n_x}, ecdh-p256 {n_d}, aead {n_a}, hkdf {n_h}, hmac {n_m},"
          f" hkdf-sha384 {n_h384}, hmac-sha384 {n_m384},"
          f" aes-128-gcm {n_g}, aes-256-gcm {n_g256},"
          f" ecdsa p256-sha256 {n_e} p384-sha384 {n_e384} p384-sha256 {n_e384_256}"
          f" p256-sha512 {n_e256_512}, rsa-pss {n_r}, rsa-pkcs1 {n_rp}, rsa-sign {n_rs},"
          f" mlkem keygen {n_kk} encaps {n_ke} full {n_kf} (commit {commit[:12]})")


if __name__ == "__main__":
    main()
