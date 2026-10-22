#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.exceptions import FactorizationError
from RsaCtfTool.lib.number_theory import gcd
from RsaCtfTool.lib.algos import shor


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run Shor attack with a timeout"""
        try:
            res = shor(publickey.n)
        except FactorizationError:
            return None, None

        # shor() falls through without a result on prime or tiny moduli.
        if res is None:
            return None, None

        p, q = res
        # Degenerate (1, n) / (n, 1) and non-coprime splits (p**k moduli
        # give (p, p**(k-1))) build keys with a wrong phi and a wrong d.
        if p <= 1 or q <= 1 or gcd(p, q) != 1:
            return None, None
        return self.create_private_key_from_pqe(p, q, publickey.e, publickey.n)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCAwDQYJKoZIhvcNAQEBBQADDwAwDAIFCAjGeKUCAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
