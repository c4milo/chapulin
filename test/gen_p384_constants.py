#!/usr/bin/env python3
# Prints the P-384 constants the C files embed, in the exact C layout.
# For p384_field.c and p384.c that is 12 little-endian uint32 words per
# number, and for p384_wide_field.c and p384_wide_verify.c, which a host
# object holds, 6 little-endian uint64 words. Both layouts carry the
# Montgomery entry constant r2 = 2^768 mod m, which is one number at
# either width, and the word inverse m0inv = -m^-1 modulo 2^32 or 2^64
# for both moduli. It also prints the two points test/p384_equiv_test.c
# builds the signatures at the edges of x mod n from.
#
# Every curve parameter is read back from openssl before it is printed:
# `openssl ecparam -name secp384r1 -param_enc explicit -text -noout`
# (SEC 2 secp384r1, FIPS 186-4 D.1.2.4). The script exits non-zero if
# the literals below disagree with what openssl prints, so a value in
# the C files is one openssl agreed with.
#
# Run: `python3 test/gen_p384_constants.py`.
import re
import subprocess
import sys

BITS = 384
R = 1 << BITS

# SEC 2 secp384r1.
P = (1 << 384) - (1 << 128) - (1 << 96) + (1 << 32) - 1
N = int("ffffffffffffffffffffffffffffffffffffffffffffffff"
        "c7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)
A = P - 3
B = int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe814112"
        "0314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16)
GX = int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b98"
         "59f741e082542a385502f25dbf55296c3a545e3872760ab7", 16)
GY = int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147c"
         "e9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16)


def openssl_params():
    """The curve parameters as openssl prints them, keyed by field name."""
    text = subprocess.run(
        ["openssl", "ecparam", "-name", "secp384r1", "-param_enc",
         "explicit", "-text", "-noout"],
        check=True, capture_output=True, text=True).stdout
    out = {}
    for name in ("Prime", "A", "B", "Generator (uncompressed)", "Order"):
        match = re.search(re.escape(name) + r":\s*\n((?:\s+[0-9a-f:]+\n)+)",
                          text)
        if match is None:
            sys.exit(f"openssl output lacks {name}")
        digits = "".join(match.group(1).replace(":", "").split())
        out[name] = int(digits, 16)
    return out


def check_against_openssl():
    got = openssl_params()
    generator = got["Generator (uncompressed)"]
    want = {
        "Prime": P, "A": A, "B": B, "Order": N,
        "Generator (uncompressed)": (4 << 768) | (GX << 384) | GY,
    }
    for name, value in want.items():
        if got[name] != value:
            sys.exit(f"{name}: openssl says {got[name]:x}, script says "
                     f"{value:x}")
    assert generator >> 768 == 4
    assert (GY * GY - (GX ** 3 + A * GX + B)) % P == 0, "G is not on the curve"


def words(value, word_bits):
    """value as little-endian words of word_bits bits each."""
    assert 0 <= value < R
    mask = (1 << word_bits) - 1
    return [(value >> (word_bits * i)) & mask
            for i in range(BITS // word_bits)]


def c_array(words, indent, word_bits):
    """The words as a C initializer, 192 bits per line."""
    per_line = 192 // word_bits
    digits = word_bits // 4
    lines = []
    for i in range(0, len(words), per_line):
        lines.append(indent + ", ".join(f"0x{w:0{digits}x}"
                                        for w in words[i:i + per_line]))
    return ",\n".join(lines)


def print_modulus(struct, name, m, word_bits):
    r2 = (R * R) % m
    word = 1 << word_bits
    m0inv = (-pow(m, -1, word)) % word
    assert (m * m0inv) % word == word - 1
    print(f"const {struct} {name} = {{")
    print("    {" + c_array(words(m, word_bits), "     ", word_bits).lstrip()
          + "},")
    print("    {" + c_array(words(r2, word_bits), "     ", word_bits).lstrip()
          + "},")
    print(f"    0x{m0inv:0{word_bits // 4}x},")
    print("};")
    print()


def print_array(word, count, name, value, word_bits):
    print(f"static const {word} {name}[{count}] = {{")
    print(c_array(words(value, word_bits), "    ", word_bits))
    print("};")
    print()


def point_at_or_above(x):
    """The curve point with the smallest x at or above x, and its even y.

    p is 3 modulo 4, so a square's root is its (p + 1) / 4 power.
    """
    while True:
        rhs = (x ** 3 + A * x + B) % P
        y = pow(rhs, (P + 1) // 4, P)
        if (y * y) % P == rhs:
            return x, y if y % 2 == 0 else P - y
        x += 1


def main():
    check_against_openssl()
    print("// p384_field.c")
    print_modulus("p384_modulus", "p384_modp", P, 32)
    print_modulus("p384_modulus", "p384_modn", N, 32)
    print("// p384.c")
    for name, value in (("B", B), ("GX", GX), ("GY", GY)):
        print_array("uint32_t", "P384_WORDS", name, value, 32)
    print("// p384_wide_field.c")
    print_modulus("p384_wide_modulus", "p384_wide_modp", P, 64)
    print_modulus("p384_wide_modulus", "p384_wide_modn", N, 64)
    print("// p384_wide_verify.c")
    for name, value in (("B", B), ("GX", GX), ("GY", GY)):
        print_array("uint64_t", "P384_WIDE_WORDS", name, value, 64)
    # Two points for test/p384_equiv_test.c. One has an x above n, so that
    # x mod n is x - n: an x of n itself is r = 0, which no signature
    # carries, so the search starts one above it. The other has the
    # smallest x there is, so that x + p still fits 48 bytes.
    print("// test/p384_equiv_test.c")
    for name, start in (("LARGE", N + 1), ("SMALL", 0)):
        x, y = point_at_or_above(start)
        assert start <= x < P and (y * y - (x ** 3 + A * x + B)) % P == 0
        print(f"{name}_X = {x:096x}")
        print(f"{name}_Y = {y:096x}")
    print(f"// LARGE_X - n = {point_at_or_above(N + 1)[0] - N}, "
          f"SMALL_X + p < 2^384: {point_at_or_above(0)[0] + P < R}")


if __name__ == "__main__":
    main()
