#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import williams_pp1


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run attack with Williams' p+1 method"""

        try:
            # williams p+1 attack

            wres = williams_pp1(publickey.n)

            if wres is not None:
                p, q = int(wres[0]), int(wres[1])
                if 1 < p < publickey.n and p * q == publickey.n:
                    publickey.p = p
                    publickey.q = q
                    self.logger.info(
                        f"[+] Williams p+1 found factors: {publickey.p}, {publickey.q}"
                    )

            return self.create_private_key_from_pqe(
                publickey.p, publickey.q, publickey.e, publickey.n
            )
        except TypeError:
            return None, None

    def test(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        # p+1 and q+1 both smooth: the method's designed sweet spot.
        p, q = 601, 401
        key_data = RSA.construct((p * q, 65537)).publickey().exportKey()
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
