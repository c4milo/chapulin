#!/usr/bin/env python3
"""Checks the constants of the wide P-256 files against the curve's definition.

Run from the repository root:

    python3 tools/p256_wide.py check p256_wide_field.c p256_wide_scalar.c p256_wide_point.c

The arguments are the sources the script reads. It takes them so that the
recipe of make lint-p256-wide names them, and it refuses any other list.

Every number here comes from Python's arbitrary-precision integers and from
SEC 2's definition of secp256r1, never from the C under test. The script reads
each constant out of the C source that carries it, recomputes it, and stops
with a message that names the file and the constant when a limb differs:

- p256_wide_field.c: the prime p, 2^512 mod p and 2^256 mod p, and the facts
  its reduction and its inversion rest on: -p^-1 mod 2^64 is 1, (p + 1) / 2^64
  is 2^192 - 2^160 + 2^128 + 2^32, and p - 2 is the run of bits the inversion
  chain writes.
- p256_wide_scalar.c: the group order n, -n^-1 mod 2^64, 2^512 mod n,
  2^256 mod n, and n - 2 as the two limbs the inverse reads four bits at a time
  under the two it writes as runs of ones.
- p256_wide_point.c: the curve coefficient b in the Montgomery domain.

make lint-p256-wide runs it, and make check runs that.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

P = 2**256 - 2**224 + 2**192 + 2**96 - 1
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
R = 2**256
LIMB = 2**64

failures = []


def limbs(value, count=4):
    """value as count little-endian 64-bit limbs."""
    return [(value >> (64 * i)) & (LIMB - 1) for i in range(count)]


def source(name):
    return (ROOT / name).read_text()


def defined(text, name):
    """The value of `#define name UINT64_C(0x...)`, or None."""
    found = re.search(rf"^#define {name} UINT64_C\((0x[0-9a-fA-F]+)\)", text, re.M)
    return int(found.group(1), 16) if found else None


def initialized(text, name):
    """The limbs in the initializer of the object called name: every
    integer literal between its `=` and the `;` that ends it, or None."""
    found = re.search(rf"\b{name}(?:\[\d+\])? = (.*?);", text, re.S)
    if not found:
        return None
    return [int(x, 0) for x in re.findall(r"\b(0x[0-9a-fA-F]+|\d+)\b",
                                          found.group(1).replace("UINT64_C", ""))]


def expect(where, what, got, want):
    if got != want:
        shown = "nothing by that name" if got is None else (
            ", ".join(hex(x) for x in got) if isinstance(got, list) else hex(got))
        wanted = ", ".join(hex(x) for x in want) if isinstance(want, list) else hex(want)
        failures.append(f"{where}: {what} is {shown}, and the curve gives {wanted}")


def check_field():
    name = "p256_wide_field.c"
    text = source(name)
    expect(name, "the prime P0..P3", [defined(text, f"P{i}") for i in range(4)], limbs(P))
    expect(name, "RR, 2^512 mod p", initialized(text, "RR"), limbs(R * R % P))
    expect(name, "p256_wide_fe_one_mont, 2^256 mod p",
           initialized(text, "p256_wide_fe_one_mont"), limbs(R % P))
    # What reduce_round rests on.
    assert (-pow(P, -1, LIMB)) % LIMB == 1, "-p^-1 mod 2^64 is not 1"
    assert (P + 1) % LIMB == 0, "p + 1 is not a multiple of 2^64"
    assert (P + 1) // LIMB == 2**192 - 2**160 + 2**128 + 2**32, "(p + 1) / 2^64 has another form"
    assert limbs(P)[3] == 2**64 - 2**32 + 1, "p's top limb is not 2^64 - 2^32 + 1"
    # What p256_wide_fe_inv's chain writes: 32 ones, 31 zeros, a one, 96
    # zeros, 94 ones, a zero and a one.
    bits = "1" * 32 + "0" * 31 + "1" + "0" * 96 + "1" * 94 + "01"
    assert int(bits, 2) == P - 2, "p - 2 is not the run of bits p256_wide_fe_inv writes"


def check_scalar():
    name = "p256_wide_scalar.c"
    text = source(name)
    expect(name, "the order N0..N3", [defined(text, f"N{i}") for i in range(4)], limbs(N))
    expect(name, "N0_INV, -n^-1 mod 2^64", defined(text, "N0_INV"), (-pow(N, -1, LIMB)) % LIMB)
    expect(name, "RR, 2^512 mod n", initialized(text, "RR"), limbs(R * R % N))
    expect(name, "ONE_MONT, 2^256 mod n", initialized(text, "ONE_MONT"), limbs(R % N))
    expect(name, "EXPONENT_LOW, the low two limbs of n - 2",
           initialized(text, "EXPONENT_LOW"), limbs(N - 2)[:2])
    # What p256_wide_scalar_inverse writes as runs of ones: 32 ones, 32
    # zeros and 64 ones.
    top = int("1" * 32 + "0" * 32 + "1" * 64, 2)
    assert (N - 2) >> 128 == top, "n - 2's top two limbs are not the runs the inverse writes"
    assert 2**255 < N < 2**256, "one conditional subtraction reduces a product only for n > 2^255"


def check_point():
    name = "p256_wide_point.c"
    text = source(name)
    expect(name, "B_MONT, b * 2^256 mod p", initialized(text, "B_MONT"), limbs(B * R % P))
    assert (GY * GY - (GX**3 - 3 * GX + B)) % P == 0, "G is not on the curve"


CHECKED = ["p256_wide_field.c", "p256_wide_scalar.c", "p256_wide_point.c"]


def check(names):
    if names != CHECKED:
        print(f"p256_wide: check reads {' '.join(CHECKED)}, and was handed {' '.join(names)}",
              file=sys.stderr)
        return 2
    check_field()
    check_scalar()
    check_point()
    if failures:
        for line in failures:
            print(f"p256_wide: {line}", file=sys.stderr)
        return 1
    print("p256_wide: every constant of the wide P-256 files is the curve's")
    return 0


def main(argv):
    if argv[1:2] == ["check"]:
        return check(argv[2:])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
