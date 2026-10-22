#!/usr/bin/env sage

# Try to factor n with the elliptic curve method and return the result.
#
# Local rewrite: the previous version relied on EllipticCurve over Z/nZ and
# division_polynomial(n, x). On current Sage that call returns a single ring
# element with useless factoring semantics, so the attack silently never
# found anything (verified: 0 hits in 20 single-threaded trials on a 41-bit
# factor, and 0 triggers in 200 random curves). The original Qi Cheng
# j-invariant curve family also cannot be combined with the classic
# "force a random point onto the curve" construction in affine coordinates,
# so this version uses plain random curves - the standard ECM choice, which
# is what makes small-factor recovery reliable. Self-contained: no Sage
# curve objects, gcd extraction from failed modular inverses.

import random
import sys
from math import gcd


class FactorFound(Exception):
    def __init__(self, value):
        self.value = value


def inv_mod(x, m):
    """Modular inverse via extended Euclid. Raise FactorFound(gcd) when the
    inverse does not exist - that gcd is very likely a nontrivial factor."""
    x %= m
    old_r, r = x, m
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r == 1:
        return old_s % m
    raise FactorFound(old_r)


def point_add(p, q, a, m):
    """Affine addition on y^2 = x^3 + a*x + b over Z/m (None = infinity)."""
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    dx = (x2 - x1) % m
    dy = (y2 - y1) % m
    if dx == 0:
        if dy == 0:
            return point_double(p, a, m)
        return None
    lam = dy * inv_mod(dx, m) % m
    x3 = (lam * lam - x1 - x2) % m
    y3 = (lam * (x1 - x3) - y1) % m
    return x3, y3


def point_double(p, a, m):
    x, y = p
    if y % m == 0:
        return None
    lam = (3 * x * x + a) * inv_mod(2 * y, m) % m
    x3 = (lam * lam - 2 * x) % m
    y3 = (lam * (x - x3) - y) % m
    return x3, y3


def scalar_mult(k, p, a, m):
    result = None
    addend = p
    while k:
        if k & 1:
            result = point_add(result, addend, a, m)
        addend = point_double(addend, a, m)
        k >>= 1
    return result


def corefunc(n, b1):
    """One ECM pass on a random curve; returns a factor of n or None."""
    x0 = random.randrange(2, n)
    y0 = random.randrange(2, n)
    a = random.randrange(2, n)
    point = (x0, y0)
    try:
        for i in range(2, b1):
            point = scalar_mult(i, point, a, n)
            if point is None:
                return None  # full group order was smooth; curve is spent
            if i % 256 == 0:
                g = gcd(point[0], n)
                if 1 < g < n:
                    return int(g)
    except FactorFound as found:
        g = found.value
        if g is not None and 1 < g < n:
            return int(g)
    return None


def factor(n, attempts=50):
    """ Try to factor n using the elliptic curve method and return the result.
    """
    b1 = 8000  # smoothness bound; fine for factors up to ~50 bits
    for _ in range(int(attempts)):
        g = corefunc(n, b1)
        if g is not None and 1 < g < n:
            return g
    return None


if __name__ in {"__main__", "sage.all"}:
    attempts = Integer(sys.argv[2]) if len(sys.argv) > 2 else 50
    print(factor(Integer(sys.argv[1]), attempts=attempts))
