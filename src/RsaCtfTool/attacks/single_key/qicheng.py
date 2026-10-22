#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        # The CLI injects its --timeout default (60s) into this constructor.
        # 200 probabilistic ECM attempts need ~11 min; never accept less than
        # 900s so the attempt budget stays meaningful.
        super().__init__(max(timeout, 900))
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/qicheng.sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """Qi Cheng - A New Class of Unsafe Primes"""
        try:
            sageresult = int(
                subprocess.check_output(
                    [
                        "sage",
                        f"{rootpath}/sage/qicheng.sage",
                        str(publickey.n),
                        "200",
                    ],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            return (None, None)

        p = sageresult
        if not (1 < p < publickey.n) or publickey.n % p != 0:
            return (None, None)
        q = publickey.n // p
        priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
        return (priv_key, None)

    def test(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        n = int(
            "1444329727510154393553799612747635457542181563961160832013134005"
            "088873165794135221"
        )
        key_data = RSA.construct((n, 65537)).publickey().exportKey()
        for _ in range(5):
            result = self.attack(PublicKey(key_data), progress=False)
            if result != (None, None):
                return True
        return False
