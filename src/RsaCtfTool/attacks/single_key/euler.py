# /usr/bin/env python
# code taken from RsaCtfTool.https://maths.dk/teaching/courses/math357-spring2016/projects/factorization.pdf

import logging
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import euler
from RsaCtfTool.lib.number_theory import is_congruent


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.logger = logging.getLogger("global_logger")

    def attack(self, publickey, cipher=[], progress=True):
        """Run attack with Euler method"""
        # Euler attack
        try:
            if is_congruent(publickey.n, 1, 4):
                euler_res = euler(publickey.n)
            else:
                self.logger.error(
                    "[!] Public key modulus must be congruent 1 mod 4 to work with euler method."
                )
                return None, None
        except Exception:
            return None, None
        if euler_res is not None and len(euler_res) == 2:
            p, q = int(euler_res[0]), int(euler_res[1])
            # euler() derives its factors from GCDs that may also come out
            # as 1, n, or values whose product overshoots n (e.g. (45, 45)
            # for n = 225); only a genuine split of n may proceed.
            if 1 < p < publickey.n and 1 < q < publickey.n and p * q == publickey.n:
                publickey.p, publickey.q = p, q

        return self.create_private_key(publickey)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCIwDQYJKoZIhvcNAQEBBQADEQAwDgIHEAABggAEpQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data))
        return result != (None, None)
