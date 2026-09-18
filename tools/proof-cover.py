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
CH_QUIC_STUB marker. Growing AUDITED is deliberate: it means someone read the
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
    "tls.c": (
        "two sites, both `server_pubkey[len - 1] & 1` on a uint8_t array "
        "element, checking that an RSA modulus is odd. No harness compiles "
        "tls.c -- proof/coverage.py reports it, and the README already records "
        "that the connected-phase driver rests on tests rather than a proof."
    ),
}


# The one form a stub body's marker takes, and the same pattern the
# Makefile's QUIC_STUB_SRCS greps for. A file that still carries it
# holds no implementation to prove, so STUBBED below exempts it and the
# exemption ends on the commit that deletes the last marker in that
# file. AUDITED would not retire that way: an entry there is checked
# only for presence, so it would outlive its reason.
STUB_MARKER = re.compile(r"(?m)^[ \t]*// CH_QUIC_STUB: ")


def shipped_sources():
    mk = (ROOT / "Makefile").read_text()
    out = set()
    for var in ("SRCS", "LIB_SRCS", "QUIC_SRCS"):
        m = re.search(rf"^{var} :?=(.*?)(?=\n\S)", mk, re.S | re.M)
        if m:
            out |= {t for t in re.split(r"[\s\\]+", m.group(1)) if t.endswith(".c")}
    # drbg.c and the ML-KEM, SHA-3, SHA-512, P-384, PKCS#1 v1.5, webpki
    # signature-dispatch, webpki certificate and webpki chain-walk sources
    # join through build variables.
    out |= {"drbg.c", "sha3.c", "sha512.c", "sha512_compress.c", "p384.c", "p384_field.c",
            "rsa_pkcs1.c", "webpki_sigalg.c", "webpki_cert.c", "webpki.c", "mlkem.c",
            "mlkem_poly.c"}
    return {s for s in out if (ROOT / s).exists()}


def stubbed_sources(sources):
    """The shipped sources whose text still carries the stub marker.

    A stub returns the refusal its header documents and writes nothing,
    so it holds no arithmetic to prove absence of overflow over. The
    commit that implements the file deletes its last marker, and this
    set shrinks by itself on that commit, which is the retirement
    docs/quic.md states for the marker."""
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
        line += (f", {len(stubs)} still stubs that carry the CH_QUIC_STUB "
                 f"marker and hold no code to prove")
    print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
