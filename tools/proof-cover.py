#!/usr/bin/env python3
"""Check that every shipped source is proven with the signed-overflow class on.

.clang-tidy disables bugprone-signed-bitwise, and that disable rests on a claim:
the signed arithmetic in this tree is deliberate, and CBMC proves absence of
signed overflow and UB over unconstrained inputs on every module that holds it.
Nothing enforced the claim, so it could rot three ways -- a new source arrives
with no harness, a launch line drops from the `full` check set to a narrower
one, or one of the hand-audited files gains a signed operand.

This fails when a shipped source is neither compiled by a harness running the
`full` set, nor listed in AUDITED below, nor still a stub carrying the
CH_QUIC_STUB or CH_SRV_STUB marker. Growing AUDITED is deliberate: it means someone read the
file and wrote down what they found. The stub exemption is not a third way to
grow: it holds only while a file has no implementation at all, and it ends on
the commit that deletes that file's last marker.

Run through `make lint-proof-cover`.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Sources with no `full` harness, read by hand instead. Each entry carries what
# the reader established. Re-audit an entry when its file changes shape, and
# delete it once the file gains a harness.
AUDITED = {
    "build.c": (
        "the build record, one const ch_build_info and no function. Every "
        "initializer is a constant expression build.h writes: an integer "
        "constant, a sizeof cast to uint32_t, or CH_BUILD_AXES, an or of "
        "unsigned constants. No operand in the file is signed and nothing "
        "runs at run time, so there is no path for a harness to drive and "
        "no arithmetic for bugprone-signed-bitwise to judge. lib-check links "
        "test/build_test.c against every object it checks and reads each "
        "field back. Delete this entry if the file ever gains a function."
    ),
    "tls.c": (
        "the public calls tls.h declares beside the send path: ch_connect and "
        "the client configuration rules, ch_read, ch_close, ch_export and the "
        "two alert calls. Two bitwise operators in the file, the `& 1` at "
        ":133 and :135 that reads the low bit of a pinned RSA modulus's last "
        "byte: the uint8_t widens to int and holds 0 to 255, so the operand "
        "is never negative and bugprone-signed-bitwise has nothing to say "
        "about it. No shift. No harness runs this file. "
        "proof/writable_len_harness.c included it until ch_write and "
        "ch_writable_len moved to tls_write.c, and drove those two calls "
        "alone; it includes tls_write.c now. bin/unit and the loop tests "
        "test every call left here. Delete this entry when tls.c gets a "
        "harness of its own."
    ),
    "chacha20_vector.c": (
        "a host object's ChaCha20, written in NEON or SSE2 intrinsics, which "
        "CBMC cannot read, so no harness compiles the file. Every bitwise "
        "operator takes unsigned operands: the lane operations run on "
        "uint32x4_t or __m128i values through the intrinsics, load32 shifts "
        "uint32_t values, and the last group's XOR takes two uint8_t bytes, "
        "which widen to int and hold 0 to 255. The SSE2 arm's two (int) "
        "casts hand a uint32_t word to _mm_set1_epi32, a conversion gcc and "
        "clang define as keeping its 32 bits, and no arithmetic runs on the "
        "int. bin/chacha20_equiv_test holds the file to chacha20.c's proven "
        "loop, and bin/unit_host and the Wycheproof host leg run the "
        "published vectors on it. Delete this entry if a harness can ever "
        "compile the file."
    ),
    "chacha20_avx2.c": (
        "a host object's AVX2 ChaCha20 kernel on x86-64, written in AVX2 intrinsics, "
        "which CBMC cannot read, so no harness compiles the file. Every "
        "bitwise operator takes unsigned operands: the lane operations run on "
        "__m256i values through the intrinsics, load32 shifts uint32_t "
        "values, and the last row's XOR takes two uint8_t bytes, which widen "
        "to int and hold 0 to 255. The (int) casts hand a uint32_t word to "
        "_mm256_set1_epi32, a conversion gcc and clang define as keeping its "
        "32 bits, and no arithmetic runs on the int. bin/chacha20_equiv_test "
        "holds the kernel to chacha20.c's proven loop on a CPU with AVX2, and "
        "bin/unit_host and the Wycheproof host leg run the published vectors "
        "on it there, under a ch_cfg.cpu value with CH_CPU_AVX2. Delete this "
        "entry if a harness can ever compile the file."
    ),
    "poly1305_vector.c": (
        "the vector Poly1305 of a host object's native copy, written in NEON or SSE2 intrinsics, "
        "which CBMC cannot read, so no harness compiles the file. Every "
        "bitwise operator takes unsigned operands: the lane operations run on "
        "uint32x2_t, uint64x2_t or __m128i values through the intrinsics, "
        "LIMB_MASK is 0x3ffffffU and HIGH_BIT a uint32_t, and carry_scalar, "
        "multiply_scalar and multiplier_set shift, mask and multiply uint32_t "
        "and uint64_t values, where the constant 5 converts to unsigned. The "
        "SSE2 arm's (int) casts hand _mm_set_epi32 a limb, 5 times a limb, "
        "LIMB_MASK or HIGH_BIT, each below 2^31, and no arithmetic runs on "
        "the int. bin/poly1305_equiv_test holds the file to poly1305.c's "
        "proven loop, and bin/unit_host and the Wycheproof host leg run the "
        "published vectors on it, under a ch_cfg.cpu value with the multiply "
        "bit. Delete this entry if a harness can ever compile the file."
    ),
    "sha256_hw.c": (
        "a host object's SHA-256 on the CPU's SHA-256 instructions, written in "
        "the FEAT_SHA256 and SHA-extension intrinsics, which CBMC cannot read, "
        "so no harness compiles the file. Every bitwise operator takes "
        "unsigned operands: the rounds and the schedule run on uint32x4_t or "
        "__m128i values through the intrinsics, sha256_final_hw shifts a "
        "uint64_t bit count and the uint32_t words of the state, and each "
        "result narrows to uint8_t. The x86-64 arm's byte-order constant is "
        "two long long literals _mm_set_epi64x takes, each positive, and the "
        "shuffle and blend immediates are int constants below 256; no "
        "arithmetic runs on a signed value. The framing adds and subtracts "
        "size_t byte counts that the context's fill, below 64, bounds. "
        "bin/sha2_equiv_test holds the file to sha256.c's proven code, and "
        "bin/unit_host and the Wycheproof host leg run the published vectors "
        "on it, under a ch_cfg.cpu value with the SHA-256 bit. Delete this "
        "entry if a harness can ever compile the file."
    ),
    "sha512_hw.c": (
        "an arm64 host object's SHA-512 and SHA-384 on FEAT_SHA512's "
        "instructions, written in intrinsics CBMC cannot read, so no harness "
        "compiles the file, and with no body on any other target. Every "
        "bitwise operator takes unsigned operands: the rounds and the schedule "
        "run on uint64x2_t values through the intrinsics, finalize shifts the "
        "uint64_t byte count and store_digest the uint64_t words of the state, "
        "and each result narrows to uint8_t. The framing adds and subtracts "
        "size_t byte counts that the context's fill, below 128, bounds, and "
        "the round loop's size_t counters stop at 40. "
        "bin/sha2_equiv_test holds the file to sha512.c's and "
        "sha512_compress.c's proven code on arm64, and bin/sha512_test_host, "
        "bin/hkdf384_test_host and the Wycheproof host leg run the published "
        "vectors on it, under a ch_cfg.cpu value with the SHA-512 bit. Delete "
        "this entry if a harness can ever compile the file."
    ),
    "srv_out.c": (
        "the server's handshake output, one arm per transport. One bitwise "
        "operator in the file: the shift `(uint8_t)(n >> 8)` in "
        "srv_out_plain, which splits a record length into two header bytes "
        "by shifting a size_t right. Its left operand is unsigned, so the "
        "shift is defined and bugprone-signed-bitwise has nothing to say "
        "about it. These lines moved out of srv_flight.c, whose entry "
        "carried this same shift before the split. The refused-send paths "
        "compare int results and assign an alert constant, with no "
        "arithmetic. No harness runs this file: "
        "proof/srv_flight_harness.c covers the handlers that call it and "
        "returns no verdict, which proof/run.sh records. Delete this entry "
        "when srv_out.c gets a harness of its own."
    ),
    "srv_flight.c": (
        "the fifteen flight handlers. Every bitwise operator takes unsigned "
        "operands: `ch->suites`, `ch->groups` and `ch->shares` are uint8_t "
        "bitmasks (srv_parser.h:220-222) tested against uint8_t constants. "
        "The file now holds no shift at all: the one it had went to "
        "srv_out.c with the record writer. No operand is signed. "
        "proof/srv_flight_harness.c covers this file and returns no verdict "
        "with all fifteen handlers in one formula -- no answer in 55 minutes "
        "at --unwind 40, none at 20 or 18 -- which proof/run.sh records along "
        "with the layered split it needs. Delete this entry when that split "
        "gives it a launch line."
    ),
}


# The two forms a stub body's marker takes, and the same pattern the
# Makefile's SRV_STUB_SRCS greps for; QUIC_STUB_SRCS read the other one
# until the TRANSPORT=quic-nonblocking mode was implemented. A file that still
# carries one holds no implementation to prove, so STUBBED below exempts
# it and the exemption ends on the commit that deletes the last marker in
# that file. The two build axes stub independently, which is why there
# are two names and not one. AUDITED would not retire that way: an entry
# there is checked only for presence, so it would outlive its reason.
STUB_MARKER = re.compile(r"(?m)^[ \t]*// CH_(QUIC|SRV)_STUB: ")


def shipped_sources():
    mk = (ROOT / "Makefile").read_text()
    out = set()
    for var in ("SRCS", "LIB_SRCS", "QUIC_SRCS", "SRV_SRCS"):
        m = re.search(rf"^{var} :?=(.*?)(?=\n\S)", mk, re.S | re.M)
        if m:
            out |= {t for t in re.split(r"[\s\\]+", m.group(1)) if t.endswith(".c")}
    # drbg.c and the ML-KEM, SHA-3, SHA-512, P-384, PKCS#1 v1.5, webpki
    # signature-dispatch, webpki certificate, webpki chain-walk, webpki
    # pin, wide X25519 field, wide P-256, vector ChaCha20 and Poly1305
    # sources and SHA-256 and SHA-512 on the CPU's instructions join through
    # build variables or the host test.
    out |= {"drbg.c", "sha3.c", "sha512.c", "sha512_compress.c", "p384.c", "p384_field.c",
            "rsa_pkcs1.c", "webpki_sigalg.c", "webpki_cert.c", "webpki.c", "webpki_pin.c",
            "mlkem.c", "mlkem_poly.c", "x25519_wide.c", "chacha20_vector.c", "chacha20_avx2.c",
            "poly1305_vector.c", "sha256_hw.c", "sha512_hw.c", "p256_wide_field.c",
            "p256_wide_scalar.c", "p256_wide_point.c", "p256_wide_mul.c", "p256_wide_table.c",
            "p256_wide_wipe.c"}
    return {s for s in out if (ROOT / s).exists()}


def stubbed_sources(sources):
    """The shipped sources whose text still carries the stub marker.

    A stub returns the refusal its header documents and writes nothing,
    so it holds no arithmetic to prove absence of overflow over. The
    commit that implements the file deletes its last marker, and this
    set shrinks by itself on that commit, which is the retirement
    docs/quic.md and docs/server.md state for the markers."""
    return {s for s in sources
            if STUB_MARKER.search((ROOT / s).read_text())}


def harness_compiles(name):
    """Sources a harness pulls in: its own #include of a .c, plus its deps."""
    h = ROOT / "proof" / f"{name}_harness.c"
    if not h.exists():
        return set()
    return set(re.findall(r'#include\s+"([^"]+\.c)"', h.read_text()))


def full_covered():
    run = (ROOT / "proof" / "run.sh").read_text()
    covered = set()
    for m in re.finditer(r"^launch\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S*(.*)$", run, re.M):
        _tier, checks, name, rest = m.groups()
        if checks != "full":
            continue
        covered |= harness_compiles(name)
        covered |= {t for t in re.split(r"\s+", rest) if t.endswith(".c")}
    return covered


def main():
    sources = shipped_sources()
    covered = full_covered()
    stubs = stubbed_sources(sources)
    problems = []

    for src in sorted(sources):
        if src in covered:
            if src in AUDITED:
                problems.append(
                    f"{src} now has a full harness, so its AUDITED entry in "
                    f"{Path(__file__).name} is stale. Delete it."
                )
            continue
        if src in stubs:
            continue
        if src not in AUDITED:
            problems.append(
                f"{src} is shipped, no harness runs it under the `full` check "
                f"set, and it is not in AUDITED. Either give it a harness, or "
                f"read it and record what you found in {Path(__file__).name}. "
                f".clang-tidy's bugprone-signed-bitwise entry rests on one of "
                f"those two being true for every shipped source."
            )

    for name in sorted(set(AUDITED) - sources):
        problems.append(f"AUDITED lists {name}, which is not a shipped source. Delete it.")

    if problems:
        for p in problems:
            print(f"lint-proof-cover: {p}")
        return 1

    line = (f"lint-proof-cover: {len(sources - set(AUDITED) - stubs)} shipped "
            f"sources proven with the signed-overflow class on, "
            f"{len(AUDITED)} audited by hand")
    if stubs:
        line += (f", {len(stubs)} still stubs that carry a stub marker "
                 f"and hold no code to prove")
    print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
