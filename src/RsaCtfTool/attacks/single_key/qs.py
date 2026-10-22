#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
from RsaCtfTool.attacks.abstract_attack import AbstractAttack, SAGE_MIN_TIMEOUT
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(max(timeout, SAGE_MIN_TIMEOUT))
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/qs.sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """
        Use sage's internal quadratic sieve method.
        If input is less than 40 digits, i'll fallback to sage factor method.
        """
        privatekey = None
        try:
            sageresult = (
                subprocess.check_output(
                    ["sage", f"{rootpath}/sage/qs.sage", str(publickey.n)],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
                .decode("utf8")
                .rstrip()
            )
            sageresult = sageresult.split("\n")
            for line in sageresult:
                line = line.strip()
                if not line or line.startswith("// ** "):
                    continue
                fields = line.split()
                if len(fields) != 2:
                    continue
                p, q = map(int, fields)
                if p <= 1 or q <= 1 or p * q != publickey.n:
                    continue
                publickey.p, publickey.q = p, q
                privatekey = PrivateKey(
                    p=publickey.p,
                    q=publickey.q,
                    e=int(publickey.e),
                    n=int(publickey.n),
                )
            return (privatekey, None)

        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            ValueError,
        ):
            return (None, None)

    def test(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = RSA.construct((1009 * 1013, 65537)).publickey().exportKey()
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
