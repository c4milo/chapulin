#!/usr/bin/env python3
# Prints the P-384 constants p384_field.c and p384.c embed, in the exact
# C layout: 12 little-endian uint32 limbs per number, the Montgomery
# entry constant r2 = 2^768 mod m and the word inverse m0inv = -m^-1
# mod 2^32 for both moduli.
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

LIMBS = 12
LIMB_BITS = 32
R = 1 << (LIMBS * LIMB_BITS)

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


def limbs(value):
    """value as LIMBS little-endian 32-bit words."""
    assert 0 <= value < R
    return [(value >> (LIMB_BITS * i)) & 0xffffffff for i in range(LIMBS)]


def c_array(words, indent):
    """The limbs as a C initializer, six per line, clang-format style."""
    lines = []
    for i in range(0, len(words), 6):
        lines.append(indent + ", ".join(f"0x{w:08x}" for w in words[i:i + 6]))
    return ",\n".join(lines)


def print_modulus(name, m):
    r2 = (R * R) % m
    m0inv = (-pow(m, -1, 1 << LIMB_BITS)) % (1 << LIMB_BITS)
    assert (m * m0inv) % (1 << LIMB_BITS) == (1 << LIMB_BITS) - 1
    print(f"const p384_modulus {name} = {{")
    print("    {" + c_array(limbs(m), "     ").lstrip() + "},")
    print("    {" + c_array(limbs(r2), "     ").lstrip() + "},")
    print(f"    0x{m0inv:08x},")
    print("};")
    print()


def print_array(name, value):
    print(f"static const uint32_t {name}[P384_LIMBS] = {{")
    print(c_array(limbs(value), "    "))
    print("};")
    print()


def main():
    check_against_openssl()
    print("// p384_field.c")
    print_modulus("p384_modp", P)
    print_modulus("p384_modn", N)
    print("// p384.c")
    print_array("B", B)
    print_array("GX", GX)
    print_array("GY", GY)


if __name__ == "__main__":
    main()
