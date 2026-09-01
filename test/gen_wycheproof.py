#!/usr/bin/env python3
"""Convert eight Wycheproof suites into one generated C header.

Usage: gen_wycheproof.py <wycheproof-checkout> <output.h>

Same pattern as gen_rfc8448.py: every hex block is checked against its
declared length, and the output lands in bin/, never in the tree. Each
suite becomes one data blob plus an index array of offsets, so the
header stays a few symbols instead of thousands.

Skips are encoded, not dropped, so the test binary can report them:
AEAD cases whose nonce size the fixed nonce[12] API cannot express, and
HKDF cases outside the library's CH_ASSERT domain (info > 64 bytes,
okm 0 or > 255*32 bytes). Both categories are findings in chapulin's
favor and the test prints their counts.
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


def gen_ecdsa(d, out):
    blob = Blob()
    rows = []
    for g in d["testGroups"]:
        unc = bytes_of(g["publicKey"]["uncompressed"], 65, "ecdsa group public key")
        if unc[0] != 0x04:
            raise SystemExit("ecdsa group public key is not an uncompressed point")
        pub_off = blob.add(unc[1:])
        for t in g["tests"]:
            msg, sig = bytes_of(t["msg"]), bytes_of(t["sig"])
            off = blob.add(msg + sig)
            rows.append(
                (uint_of(t["tcId"], 0xffffffff, "ecdsa tcId"), pub_off, off, len(msg),
                 len(sig), 1 if t["result"] == "valid" else 0)
            )
    emit_blob(out, "wp_ecdsa_data", blob)
    out.append(
        "static const struct { uint32_t tc; uint32_t pub_off; uint32_t off; uint16_t msg_len;"
        " uint16_t sig_len; uint8_t valid; } wp_ecdsa[] = {"
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
    n_e = gen_ecdsa(json.load(open(v1 / "ecdsa_secp256r1_sha256_test.json")), out)
    n_r = gen_rsa(
        [v1 / "rsa_pss_2048_sha256_mgf1_32_test.json", v1 / "rsa_pss_3072_sha256_mgf1_32_test.json"],
        out,
    )
    n_kk = gen_mlkem_keygen(json.load(open(v1 / "mlkem_768_keygen_seed_test.json")), out)
    n_ke = gen_mlkem_encaps(json.load(open(v1 / "mlkem_768_encaps_test.json")), out)
    n_kf = gen_mlkem_full(json.load(open(v1 / "mlkem_768_test.json")), out)
    dst.write_text("\n".join(out) + "\n")
    print(f"wycheproof vectors: x25519 {n_x}, aead {n_a}, hkdf {n_h}, ecdsa {n_e}, rsa {n_r},"
          f" mlkem keygen {n_kk} encaps {n_ke} full {n_kf} (commit {commit[:12]})")


if __name__ == "__main__":
    main()
