#!/usr/bin/env python3
"""Checks the constants of the wide P-256 files against the curve's definition,
and writes the table of multiples of the generator.

Run from the repository root:

    python3 tools/p256_wide.py check p256_wide_field.h p256_wide_field.c \
        p256_wide_scalar.c p256_wide_point.c
    python3 tools/p256_wide.py table > p256_wide_table.c

check's arguments are the sources the script reads. It takes them so that the
recipe of make lint-p256-wide names them, and it refuses any other list.

Every number here comes from Python's arbitrary-precision integers and from
SEC 2's definition of secp256r1, never from the C under test. check reads
each constant out of the C source that carries it, recomputes it, and stops
with a message that names the file and the constant when a word differs:

- p256_wide_field.h: the prime p, whose words the header's inline addition and
  subtraction read.
- p256_wide_field.c: 2^512 mod p and 2^256 mod p, and the facts its reduction
  and its inversion rest on: -p^-1 mod 2^64 is 1, (p + 1) / 2^64 is
  2^192 - 2^160 + 2^128 + 2^32, and p - 2 is the run of bits the inversion
  chain writes.
- p256_wide_scalar.c: the group order n, -n^-1 mod 2^64, 2^512 mod n,
  2^256 mod n, and n - 2 as the two words the inverse reads four bits at a time
  under the two it writes as runs of ones.
- p256_wide_point.c: the curve coefficient b in the Montgomery domain.

table prints p256_wide_table.c, the 43 by 32 table p256_wide_base_mul reads:
entry [i][j] is (2j + 1) * 2^(6i) * G as an affine point, each coordinate times
2^256 mod p. The points come from the affine group law over Python's integers,
and the script checks each one against the curve's equation before it prints
it. It is also the file's formatter.

make lint-p256-wide runs check and compares the checked-in table with what
table prints, and make check runs that.
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
WORD = 2**64

# The table's shape, which p256_wide_table.h states for the C: one row for
# each six-bit window of a 256-bit scalar, the top one four bits wide, and in
# a row the odd multiples 1, 3, ..., 63.
WINDOW_BITS = 6
WINDOWS = (256 + WINDOW_BITS - 1) // WINDOW_BITS
ENTRIES = 2 ** (WINDOW_BITS - 1)

failures = []


def words(value, count=4):
    """value as count little-endian 64-bit words."""
    return [(value >> (64 * i)) & (WORD - 1) for i in range(count)]


def source(name):
    return (ROOT / name).read_text()


def defined(text, name):
    """The value of `#define name UINT64_C(0x...)`, or None."""
    found = re.search(rf"^#define {name} UINT64_C\((0x[0-9a-fA-F]+)\)", text, re.M)
    return int(found.group(1), 16) if found else None


def initialized(text, name):
    """The words in the initializer of the object called name: every
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


def on_curve(point):
    x, y = point
    return (y * y - (x**3 - 3 * x + B)) % P == 0


def check_field():
    header = "p256_wide_field.h"
    expect(header, "the prime P256_WIDE_P0..P3",
           [defined(source(header), f"P256_WIDE_P{i}") for i in range(4)], words(P))
    name = "p256_wide_field.c"
    text = source(name)
    expect(name, "RR, 2^512 mod p", initialized(text, "RR"), words(R * R % P))
    expect(name, "p256_wide_fe_one_mont, 2^256 mod p",
           initialized(text, "p256_wide_fe_one_mont"), words(R % P))
    # What reduce_round rests on.
    assert (-pow(P, -1, WORD)) % WORD == 1, "-p^-1 mod 2^64 is not 1"
    assert (P + 1) % WORD == 0, "p + 1 is not a multiple of 2^64"
    assert (P + 1) // WORD == 2**192 - 2**160 + 2**128 + 2**32, "(p + 1) / 2^64 has another form"
    assert words(P)[3] == 2**64 - 2**32 + 1, "p's top word is not 2^64 - 2^32 + 1"
    # What p256_wide_fe_inv's chain writes: 32 ones, 31 zeros, a one, 96
    # zeros, 94 ones, a zero and a one.
    bits = "1" * 32 + "0" * 31 + "1" + "0" * 96 + "1" * 94 + "01"
    assert int(bits, 2) == P - 2, "p - 2 is not the run of bits p256_wide_fe_inv writes"


def check_scalar():
    name = "p256_wide_scalar.c"
    text = source(name)
    expect(name, "the order N0..N3", [defined(text, f"N{i}") for i in range(4)], words(N))
    expect(name, "N0_INV, -n^-1 mod 2^64", defined(text, "N0_INV"), (-pow(N, -1, WORD)) % WORD)
    expect(name, "RR, 2^512 mod n", initialized(text, "RR"), words(R * R % N))
    expect(name, "ONE_MONT, 2^256 mod n", initialized(text, "ONE_MONT"), words(R % N))
    expect(name, "EXPONENT_LOW, the low two words of n - 2",
           initialized(text, "EXPONENT_LOW"), words(N - 2)[:2])
    # What p256_wide_scalar_inverse writes as runs of ones: 32 ones, 32
    # zeros and 64 ones.
    top = int("1" * 32 + "0" * 32 + "1" * 64, 2)
    assert (N - 2) >> 128 == top, "n - 2's top two words are not the runs the inverse writes"
    assert 2**255 < N < 2**256, "one conditional subtraction reduces a product only for n > 2^255"


def check_point():
    name = "p256_wide_point.c"
    text = source(name)
    expect(name, "B_MONT, b * 2^256 mod p", initialized(text, "B_MONT"), words(B * R % P))
    assert on_curve((GX, GY)), "G is not on the curve"


CHECKED = ["p256_wide_field.h", "p256_wide_field.c", "p256_wide_scalar.c", "p256_wide_point.c"]


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


def add(a, b):
    """a + b for two finite affine points whose sum is finite: the chord
    for distinct points and the tangent for a point with itself."""
    (x1, y1), (x2, y2) = a, b
    if x1 == x2:
        assert y1 == y2 and y1 != 0, "the table adds no point to its negative"
        slope = (3 * x1 * x1 - 3) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def multiples():
    """The table as Python integers: row i holds (2j + 1) * 2^(6i) * G for j
    from 0 to ENTRIES - 1."""
    rows = []
    base = (GX, GY)
    for _ in range(WINDOWS):
        twice = add(base, base)
        row = [base]
        for _ in range(1, ENTRIES):
            row.append(add(row[-1], twice))
        rows.append(row)
        for _ in range(WINDOW_BITS):
            base = add(base, base)
    assert all(on_curve(point) for row in rows for point in row), "an entry is off the curve"
    return rows


def coordinate(value, indent):
    """One coordinate in the Montgomery domain as an initializer of four
    words, two to a line."""
    literals = [f"UINT64_C(0x{word:016x})" for word in words(value * R % P)]
    return ("{{" + ", ".join(literals[:2]) + ",\n" + " " * (indent + 2) + ", ".join(literals[2:])
            + "}}")


def table():
    out = ["// Generated by tools/p256_wide.py table; regenerate, never edit.\n",
           "//\n",
           "// The multiples of secp256r1's generator G that p256_wide_base_mul adds\n",
           "// (p256_wide_table.h): entry [i][j] is (2j + 1) * 2^(6i) * G as an affine\n",
           "// point, each coordinate times 2^256 mod p, least significant word first.\n",
           "// The script is also the formatter: the off marker below keeps regeneration\n",
           "// byte-identical under any clang-format version, or none. make\n",
           "// lint-p256-wide fails when this file is not what the script prints.\n",
           '#include "p256_wide_table.h"\n',
           "\n",
           "#ifdef CH_CPU_RUNTIME\n",
           "\n",
           "// clang-format off\n",
           "const p256_wide_affine p256_wide_table[P256_WIDE_TABLE_WINDOWS]"
           "[P256_WIDE_TABLE_ENTRIES] = {\n"]
    for i, row in enumerate(multiples()):
        out.append(f"    {{ // 2^{WINDOW_BITS * i} * G times 1, 3, ..., {2 * ENTRIES - 1}\n")
        for x, y in row:
            out.append("        {" + coordinate(x, 9) + ",\n")
            out.append("         " + coordinate(y, 9) + "},\n")
        out.append("    },\n")
    out.append("};\n// clang-format on\n\n#endif // CH_CPU_RUNTIME\n")
    sys.stdout.write("".join(out))
    return 0


def main(argv):
    if argv[1:2] == ["check"]:
        return check(argv[2:])
    if argv[1:] == ["table"]:
        return table()
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
