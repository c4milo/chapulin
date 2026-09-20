#!/usr/bin/env python3
"""Prints test/p256_sign_vectors.h: ECDSA P-256 signing and its arithmetic.

Every number here comes from Python's arbitrary-precision integers and from
hashlib's HMAC-SHA-256, not from the C under test, so the vectors are an
independent answer rather than a recording of what p256_sign.c does.

The script also checks three things before it prints anything:

1. Every constant p256_scalar.c and p256_point.c carry is recomputed from the
   curve's definition and compared, so a typo in either place fails here.
2. The complete addition formula p256_point.c writes out is run step for step
   in Python and compared with an affine reference over the cases the formula
   claims to handle: two different points, a point with itself, a point with
   its negative, and either operand at infinity.
3. The RFC 6979 A.2.5 answers for P-256 with SHA-256 are reproduced by the
   generator below, so the generator this script uses as an oracle is itself
   checked against the RFC before it signs anything else.

Usage: python3 test/gen_p256_sign_vectors.py > test/p256_sign_vectors.h
"""

import hashlib
import hmac
import random

P = 2**256 - 2**224 + 2**192 + 2**96 - 1
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
R = 2**256

# The limbs p256_scalar.c carries, repeated here so this script checks them.
C_N = [0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
       0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF]
C_RR = [0xBE79EEA2, 0x83244C95, 0x49BD6FA6, 0x4699799C,
        0x2B6BEC59, 0x2845B239, 0xF3D95620, 0x66E12D94]
C_N0_INV = 0xEE00BC4F
C_N_MINUS_2 = [0xFC63254F, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
               0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF]
C_ONE_MONT = [0x039CDAAF, 0x0C46353D, 0x58E8617B, 0x43190552,
              0x00000000, 0x00000000, 0xFFFFFFFF, 0x00000000]

# The limbs p256_point.c carries, all three in the Montgomery domain.
C_B_MONT = [0x29C4BDDF, 0xD89CDF62, 0x78843090, 0xACF005CD,
            0xF7212ED6, 0xE5A220AB, 0x04874834, 0xDC30061D]
C_GX_MONT = [0x18A9143C, 0x79E730D4, 0x5FEDB601, 0x75BA95FC,
             0x77622510, 0x79FB732B, 0xA53755C6, 0x18905F76]
C_GY_MONT = [0xCE95560A, 0xDDF25357, 0xBA19E45C, 0x8B4AB8E4,
             0xDD21F325, 0xD2E88688, 0x25885D85, 0x8571FF18]
# The Montgomery form of 1 mod p, which p256_point.c repeats inside its
# p256_point_infinity initializer because C cannot name p256_fe_one_mont
# there.
C_FE_ONE_MONT = [0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF,
                 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0x00000000]


def limbs(x):
    return [(x >> (32 * i)) & 0xFFFFFFFF for i in range(8)]


def check_constants():
    assert limbs(N) == C_N, "p256_scalar.c's N is not the P-256 group order"
    assert limbs(R * R % N) == C_RR, "p256_scalar.c's RR is not 2^512 mod n"
    assert (-pow(N, -1, 2**32)) % 2**32 == C_N0_INV, "p256_scalar.c's N0_INV is wrong"
    assert limbs(N - 2) == C_N_MINUS_2, "p256_scalar.c's exponent is not n-2"
    assert limbs(R % N) == C_ONE_MONT, "p256_scalar.c's ONE_MONT is not R mod n"
    assert limbs(B * R % P) == C_B_MONT, "p256_point.c's B_MONT is not b*R mod p"
    assert limbs(GX * R % P) == C_GX_MONT, "p256_point.c's GX_MONT is not G.x*R mod p"
    assert limbs(GY * R % P) == C_GY_MONT, "p256_point.c's GY_MONT is not G.y*R mod p"
    assert limbs(R % P) == C_FE_ONE_MONT, "p256_point.c's infinity Y is not R mod p"
    assert (GY * GY - (GX**3 + A * GX + B)) % P == 0, "G is not on the curve"
    # n is above 2^255, which is why one conditional subtraction reduces any
    # 256-bit value mod n (p256_scalar_reduce).
    assert 2**255 < N < 2**256, "p256_scalar_reduce's single subtraction needs n > 2^255"


# --- affine reference arithmetic, the oracle for the formula check ---

def affine_add(point, other):
    if point is None:
        return other
    if other is None:
        return point
    x1, y1 = point
    x2, y2 = other
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if point == other:
        slope = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return (x3, (slope * (x1 - x3) - y1) % P)


def affine_mul(k, point):
    acc = None
    for bit in bin(k)[2:]:
        acc = affine_add(acc, acc)
        if bit == "1":
            acc = affine_add(acc, point)
    return acc


# --- the formula p256_point_add writes out, step for step ---

def complete_add(p1, p2):
    """Renes-Costello-Batina Algorithm 4 (a = -3), in the paper's order."""
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    t0 = x1 * x2 % P
    t1 = y1 * y2 % P
    t2 = z1 * z2 % P
    t3 = (x1 + y1) % P
    t4 = (x2 + y2) % P
    t3 = t3 * t4 % P
    t4 = (t0 + t1) % P
    t3 = (t3 - t4) % P
    t4 = (y1 + z1) % P
    x3 = (y2 + z2) % P
    t4 = t4 * x3 % P
    x3 = (t1 + t2) % P
    t4 = (t4 - x3) % P
    x3 = (x1 + z1) % P
    y3 = (x2 + z2) % P
    x3 = x3 * y3 % P
    y3 = (t0 + t2) % P
    y3 = (x3 - y3) % P
    z3 = B * t2 % P
    x3 = (y3 - z3) % P
    z3 = (x3 + x3) % P
    x3 = (x3 + z3) % P
    z3 = (t1 - x3) % P
    x3 = (t1 + x3) % P
    y3 = B * y3 % P
    t1 = (t2 + t2) % P
    t2 = (t1 + t2) % P
    y3 = (y3 - t2) % P
    y3 = (y3 - t0) % P
    t1 = (y3 + y3) % P
    y3 = (t1 + y3) % P
    t1 = (t0 + t0) % P
    t0 = (t1 + t0) % P
    t0 = (t0 - t2) % P
    t1 = t4 * y3 % P
    t2 = t0 * y3 % P
    y3 = x3 * z3 % P
    y3 = (y3 + t2) % P
    x3 = t3 * x3 % P
    x3 = (x3 - t1) % P
    z3 = t4 * z3 % P
    t1 = t3 * t0 % P
    z3 = (z3 + t1) % P
    return (x3, y3, z3)


def to_projective(point):
    return (0, 1, 0) if point is None else (point[0], point[1], 1)


def to_affine(point):
    x, y, z = point
    if z % P == 0:
        return None
    inverse = pow(z, -1, P)
    return (x * inverse % P, y * inverse % P)


def check_complete_addition():
    rng = random.Random(20260919)
    generator = (GX, GY)
    cases = 0
    for _ in range(64):
        first = affine_mul(rng.randrange(1, N), generator)
        second = affine_mul(rng.randrange(1, N), generator)
        negated = (first[0], (P - first[1]) % P)
        for left, right in ((first, second), (first, first), (first, negated),
                            (first, None), (None, first), (None, None)):
            want = affine_add(left, right)
            got = to_affine(complete_add(to_projective(left), to_projective(right)))
            assert want == got, f"complete addition disagrees on {left} + {right}"
            cases += 1
    return cases


# --- RFC 6979 §3.2, the deterministic nonce ---

def rfc6979_candidates(priv, msg_hash, count):
    """The first `count` candidates RFC 6979 produces, accepted or not."""
    z = int.from_bytes(msg_hash, "big") % N
    tail = priv.to_bytes(32, "big") + z.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + tail, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + tail, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    out = []
    for _ in range(count):
        v = hmac.new(k, v, hashlib.sha256).digest()
        out.append(int.from_bytes(v, "big"))
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
    return out


def sign(priv, msg_hash):
    """The (r, s) p256_sign.c must produce, by the same rule it follows."""
    z = int.from_bytes(msg_hash, "big") % N
    for nonce in rfc6979_candidates(priv, msg_hash, 4):
        if not 1 <= nonce <= N - 1:
            continue
        point = affine_mul(nonce, (GX, GY))
        r = point[0] % N
        s = pow(nonce, -1, N) * (z + r * priv) % N
        assert r != 0 and s != 0, "the vector reached the 2^-127 retry"
        return r, s
    raise AssertionError("no candidate below the group order in four tries")


def der(r, s):
    def integer(value):
        body = value.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
        if body[0] & 0x80:
            body = b"\x00" + body
        return bytes([0x02, len(body)]) + body

    body = integer(r) + integer(s)
    return bytes([0x30, len(body)]) + body


def check_rfc6979():
    priv = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    for message, want_r, want_s in (
        (b"sample",
         0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
         0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8),
        (b"test",
         0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
         0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083),
    ):
        got = sign(priv, hashlib.sha256(message).digest())
        assert got == (want_r, want_s), f"RFC 6979 A.2.5 disagrees on {message!r}"


# --- printing ---

def bytes_rows(data, indent):
    rows = [", ".join("0x%02x" % b for b in data[i:i + 16]) for i in range(0, len(data), 16)]
    pad = " " * (indent + 1)
    return "{" + (",\n" + pad).join(rows) + "}"


def scalar_case(name, a, b):
    values = (a, b, (a + b) % N, a * b % N, pow(a, -1, N) if a else 0)
    out = [f'    {{"{name}",\n']
    for value in values:
        out.append("     " + bytes_rows(value.to_bytes(32, "big"), 5) + ",\n")
    return "".join(out)[:-2] + "},\n"


def sign_case(name, priv, message):
    msg_hash = hashlib.sha256(message).digest()
    r, s = sign(priv, msg_hash)
    encoded = der(r, s)
    public = affine_mul(priv, (GX, GY))
    out = [f'    {{"{name}", {len(encoded)},\n']
    out.append("     " + bytes_rows(priv.to_bytes(32, "big"), 5) + ",\n")
    out.append("     " + bytes_rows(msg_hash, 5) + ",\n")
    out.append("     " + bytes_rows(
        public[0].to_bytes(32, "big") + public[1].to_bytes(32, "big"), 5) + ",\n")
    out.append("     " + bytes_rows(encoded.ljust(72, b"\x00"), 5) + "},\n")
    return "".join(out)


def main():
    check_constants()
    formula_cases = check_complete_addition()
    check_rfc6979()

    rng = random.Random(6979)
    print("// Generated by test/gen_p256_sign_vectors.py -- do not edit.")
    print("//")
    print("// Scalar arithmetic mod the P-256 group order, and whole ECDSA")
    print("// signatures under the RFC 6979 deterministic nonce. The generator")
    print("// checked every constant p256_scalar.c and p256_point.c carry, ran")
    print("// the complete addition formula against an affine reference on")
    print(f"// {formula_cases} cases, and reproduced the RFC 6979 A.2.5 answers before")
    print("// printing this file.")
    print("#ifndef CH_P256_SIGN_VECTORS_H")
    print("#define CH_P256_SIGN_VECTORS_H")
    print()
    print("#include <stdint.h>")
    print()
    print("// a, b, a+b mod n, a*b mod n, a^-1 mod n.")
    print("typedef struct {")
    print("    const char *name;")
    print("    uint8_t a[32];")
    print("    uint8_t b[32];")
    print("    uint8_t sum[32];")
    print("    uint8_t product[32];")
    print("    uint8_t inverse[32];")
    print("} p256_scalar_vector;")
    print()
    print("static const p256_scalar_vector p256_scalar_vectors[] = {")
    print(scalar_case("one", 1, 1), end="")
    print(scalar_case("n-1", N - 1, N - 1), end="")
    print(scalar_case("n-1 and 1", N - 1, 1), end="")
    print(scalar_case("1 and n-1", 1, N - 1), end="")
    print(scalar_case("halves", N // 2, N // 2 + 1), end="")
    for i in range(12):
        print(scalar_case(f"random {i}", rng.randrange(1, N), rng.randrange(1, N)), end="")
    print("};")
    print()
    print("// A whole signature: the private scalar, the message hash, the")
    print("// public point X||Y, and the DER ECDSA-Sig-Value p256_sign must")
    print("// write byte for byte.")
    print("typedef struct {")
    print("    const char *name;")
    print("    uint8_t sig_len;")
    print("    uint8_t priv[32];")
    print("    uint8_t msg_hash[32];")
    print("    uint8_t pub[64];")
    print("    uint8_t sig[72];")
    print("} p256_sign_vector;")
    print()
    print("static const p256_sign_vector p256_sign_vectors[] = {")
    rfc_key = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    print(sign_case("rfc6979 sample", rfc_key, b"sample"), end="")
    print(sign_case("rfc6979 test", rfc_key, b"test"), end="")
    print(sign_case("key 1", 1, b"smallest key"), end="")
    print(sign_case("key n-1", N - 1, b"largest key"), end="")
    for i in range(10):
        print(sign_case(f"random {i}", rng.randrange(1, N), b"message %d" % i), end="")
    print("};")
    print()
    print("#endif")


if __name__ == "__main__":
    main()
