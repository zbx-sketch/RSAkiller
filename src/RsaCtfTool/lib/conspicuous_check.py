from RsaCtfTool.lib.number_theory import is_prime, gcd, lcm, getpubkeysz, invert


def privatekey_check(N, p, q, d, e):
    ret = False
    txt = ""

    nlen = getpubkeysz(N)
    if not is_prime(p):
        ret = True
        txt += "p IS NOT PROBABLE PRIME\n"
    if not is_prime(q):
        ret = True
        txt += "q IS NOT PROBABLE PRIME\n"
    if gcd(p, e) > 1:
        ret = True
        txt += "p and e ARE NOT RELATIVELY PRIME\n"
    if gcd(q, e) > 1:
        ret = True
        txt += "q and e ARE NOT RELATIVELY PRIME\n"
    if p * q != N:
        ret = True
        txt += "n IS NOT p * q\n"
    if not (abs(p - q) > (2 ** ((nlen >> 1) - 100))):
        ret = True
        txt += "|p - q| IS NOT > 2^(nlen/2 - 100)\n"
    if not (p > 2 ** ((nlen >> 1) - 1)):
        ret = True
        txt += "p IS NOT > 2^(nlen/2 - 1)\n"
    if not (q > 2 ** ((nlen >> 1) - 1)):
        ret = True
        txt += "q IS NOT > 2^(nlen/2 - 1)\n"
    lam = lcm(p - 1, q - 1)
    if not (d > 2 ** (nlen >> 1)):
        ret = True
        txt += "d IS NOT > 2^(nlen/2)\n"
    if not (d < (p - 1) * (q - 1)):
        # Both the lambda-inverse (standard) and the phi-inverse (what
        # this tool emits) stay below phi; only oversized exponents fail.
        ret = True
        txt += "d IS NOT < (p-1)*(q-1)\n"
    unc = (gcd(e - 1, p - 1) + 1) * (gcd(e - 1, q - 1) + 1)
    if unc > 9:
        ret = True
        txt += "The number of unconcealed messages is %d > min\n" % unc
    try:
        inv = invert(e, lam)
    except ZeroDivisionError:
        inv = None
        ret = True
        txt += "e IS NOT INVERTIBLE mod lcm(p-1,q-1)\n"
    if (e * d) % lam != 1:
        # The decryption contract is e*d == 1 (mod lambda); it accepts both
        # the lambda-inverse and the larger phi-inverse as valid d values.
        ret = True
        txt += "d IS NOT e^(-1) mod lcm(p-1,q-1)"
    return (ret, txt)
