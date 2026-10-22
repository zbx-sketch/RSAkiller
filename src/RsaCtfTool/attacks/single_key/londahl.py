#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.algos import close_factor


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        # Table plus scan are each b steps (~2s each for a 2048-bit n);
        # 10^6 covers |p - q| up to ~2*10^6 inside the default timeout,
        # while the previous 10^7 default built a >2 GB table and never
        # reached the scan phase before timing out.
        self.londahl_b = 1000000

    def attack(self, publickey, cipher=[], progress=True):
        """Run the Londahl close-prime factorisation attack"""
        factors = close_factor(publickey.n, self.londahl_b, progress)

        if factors is not None:
            p, q = factors
            priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
            return priv_key, None

        return None, None

    def test(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = RSA.construct((1009 * 1013, 65537)).publickey().exportKey()
        self.londahl_b = 100
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
