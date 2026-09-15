"""The off-curve forgery for gen_webpki_sigalg_vectors.py.

The forged signatures verify under the public point (1, 0) when a
verifier skips the curve equation, and under no key on the curve.

- (1, 0) satisfies y^2 = x^3 - 3x + 2, so it is on P-256 or P-384 only
  if that curve's b is 2, and neither curve's is.
- The doubling formula divides by 2y. A point whose y is zero doubles to
  the point at infinity, in these affine formulas and in the Jacobian
  doubling p256.c and p384.c use. So u2*(1, 0) is the point at infinity
  for every even u2.
- ECDSA verification computes w = s^-1, u1 = e*w, u2 = r*w, and accepts
  when x(u1*G + u2*Q) mod n = r. With Q = (1, 0) and u2 even, the sum is
  u1*G.

forge() tries w = 2, 3, ... until u1 = e*w and r = x(u1*G) mod n give an
even u2 = r*w mod n, then returns (r, s = w^-1 mod n). It runs that
verification on the result before it returns, and exits if the
equation does not hold.
"""

import sys


def on_curve(point, p, a, b):
    """True when point satisfies y^2 = x^3 + ax + b mod p."""
    x, y = point
    return (y * y - x * x * x - a * x - b) % p == 0


def point_double(point, p, a):
    """Affine doubling. None is the point at infinity, and so is the
    double of a point whose y is zero, as in p256.c's and p384.c's
    Jacobian doubling."""
    if point is None or point[1] == 0:
        return None
    x, y = point
    slope = (3 * x * x + a) * pow(2 * y, -1, p) % p
    x3 = (slope * slope - 2 * x) % p
    return x3, (slope * (x - x3) - y) % p


def point_add(first, second, p, a):
    """Affine addition with the exceptional cases p256.c's point_add
    spells out: either operand at infinity, equal points, and
    opposite points."""
    if first is None:
        return second
    if second is None:
        return first
    if first[0] == second[0]:
        return point_double(first, p, a) if first[1] == second[1] else None
    slope = (second[1] - first[1]) * pow(second[0] - first[0], -1, p) % p
    x3 = (slope * slope - first[0] - second[0]) % p
    return x3, (slope * (first[0] - x3) - first[1]) % p


def point_mul(k, point, p, a):
    """Left-to-right double-and-add, the order p256.c's point_mul uses."""
    acc = None
    for bit in bin(k)[2:]:
        acc = point_double(acc, p, a)
        if bit == "1":
            acc = point_add(acc, point, p, a)
    return acc


def verifies_without_curve_check(e, r, s, key, g, p, a, n):
    """ECDSA verification of (r, s) over the digest integer e (FIPS 186-4
    section 6.4.2, steps 4 to 8), with no check that key is on the curve."""
    w = pow(s, -1, n)
    total = point_add(point_mul(e * w % n, g, p, a), point_mul(r * w % n, key, p, a), p, a)
    return total is not None and total[0] % n == r


def forge(e, key, g, p, a, n):
    """(r, s) that verifies_without_curve_check accepts under key, a point
    whose y is zero, for the digest integer e."""
    w = 1
    while True:
        w += 1
        base = point_mul(e * w % n, g, p, a)
        if base is None:
            continue
        r = base[0] % n
        if r != 0 and r * w % n % 2 == 0:
            break
    s = pow(w, -1, n)
    if not verifies_without_curve_check(e, r, s, key, g, p, a, n):
        sys.exit("the forged signature does not satisfy the verification equation")
    return r, s
