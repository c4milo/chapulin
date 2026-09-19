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
okm 0 or > 255*32 bytes), and RSA PKCS#1 v1.5 groups whose public
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


# The AES-GCM suite, for quic_gcm.c. Only a -DCH_TRANSPORT_QUIC build
# compiles that file, so the rows below are emitted inside the same guard
# and the other legs of wycheproof_test.c read a header that declares
# nothing for them. INV-26 admits this key in a test: the rule bounds
# which keys a library source may pass to the AEAD, and `test` is
# excluded from the Semgrep rule that holds it.
#
# AEAD_AES_128_GCM is the one profile RFC 9001 fixes, so a group with any
# other key, nonce or tag size is counted and skipped rather than
# squeezed into an API that cannot express it.
def gen_aes_gcm(d, out):
    blob = Blob()
    rows = []
    skipped = 0
    oversize = 0
    for g in d["testGroups"]:
        if g["keySize"] != 128 or g["ivSize"] != 96 or g["tagSize"] != 128:
            skipped += len(g["tests"])  # key, nonce, or tag size the fixed API cannot express
            continue
        for t in g["tests"]:
            key = bytes_of(t["key"], 16, f"aes_gcm tc{t['tcId']} key")
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
    out.append("#ifdef CH_TRANSPORT_QUIC")
    emit_blob(out, "wp_aes_gcm_data", blob)
    out.append(
        "static const struct { uint32_t tc; uint32_t off; uint16_t aad_len;"
        " uint16_t msg_len; uint8_t valid; } wp_aes_gcm[] = {"
    )
    for tc, off, alen, mlen, valid in rows:
        out.append(f"    {{{tc}, {off}, {alen}, {mlen}, {valid}}},")
    out.append("};")
    out.append("")
    out.append(f"#define WP_AES_GCM_SKIPPED {skipped} // key/nonce/tag sizes the fixed API cannot express")
    out.append(f"#define WP_AES_GCM_OVERSIZE {oversize} // messages larger than the test's 1 KB buffers")
    out.append("#endif // CH_TRANSPORT_QUIC")
    out.append("")
    return len(rows)


def gen_hkdf(d, out):
    blob = Blob()
    rows = []
    skipped = 0
    for g in d["testGroups"]:
        for t in g["tests"]:
            ikm, salt, info = bytes_of(t["ikm"]), bytes_of(t["salt"]), bytes_of(t["info"])
            okm = bytes_of(t["okm"], t["size"] if t["result"] == "valid" else None)
            size = t["size"]
            # The library's asserted domain (hkdf.c): 0 < out_len <=
            # 255*32 and info_len <= 64. Outside it, CH_ASSERT faults on
            # purpose instead of proceeding; the test reports the count.
            if size == 0 or size > 255 * 32 or len(info) > 64:
                skipped += 1
                continue
            off = blob.add(ikm + salt + info + okm)
            rows.append(
                (uint_of(t["tcId"], 0xffffffff, "hkdf tcId"), off, len(ikm), len(salt), len(info),
                 len(okm), uint_of(size, 8160, "hkdf size"), 1 if t["result"] == "valid" else 0)
            )
    emit_blob(out, "wp_hkdf_data", blob)
    out.append(
        "static const struct { uint32_t tc; uint32_t off; uint16_t ikm_len; uint16_t salt_len;"
        " uint16_t info_len; uint16_t okm_len; uint16_t size; uint8_t valid; } wp_hkdf[] = {"
    )
    for row in rows:
        out.append("    {" + ", ".join(str(v) for v in row) + "},")
    out.append("};")
    out.append("")
    out.append(f"#define WP_HKDF_SKIPPED {skipped} // outside the library's CH_ASSERT domain")
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
    n_a = gen_aead(json.load(open(v1 / "chacha20_poly1305_test.json")), out)
    n_h = gen_hkdf(json.load(open(v1 / "hkdf_sha256_test.json")), out)
    n_g = gen_aes_gcm(json.load(open(v1 / "aes_gcm_test.json")), out)
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
    n_kk = gen_mlkem_keygen(json.load(open(v1 / "mlkem_768_keygen_seed_test.json")), out)
    n_ke = gen_mlkem_encaps(json.load(open(v1 / "mlkem_768_encaps_test.json")), out)
    n_kf = gen_mlkem_full(json.load(open(v1 / "mlkem_768_test.json")), out)
    dst.write_text("\n".join(out) + "\n")
    print(f"wycheproof vectors: x25519 {n_x}, aead {n_a}, hkdf {n_h}, aes-gcm {n_g},"
          f" ecdsa p256-sha256 {n_e} p384-sha384 {n_e384} p384-sha256 {n_e384_256}"
          f" p256-sha512 {n_e256_512}, rsa-pss {n_r}, rsa-pkcs1 {n_rp},"
          f" mlkem keygen {n_kk} encaps {n_ke} full {n_kf} (commit {commit[:12]})")


if __name__ == "__main__":
    main()
