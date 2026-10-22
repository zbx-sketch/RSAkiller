#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import subprocess
from collections import Counter

from RsaCtfTool.attacks.abstract_attack import AbstractAttack, SAGE_MIN_TIMEOUT
from RsaCtfTool.lib.utils import rootpath, TimeoutError, terminate_proc_tree
from RsaCtfTool.lib.number_theory import invert, powmod


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(max(timeout, SAGE_MIN_TIMEOUT))
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/ecm2.sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """use elliptic curve method
        only works if the sageworks() function returned True
        """

        try:
            try:
                sage_proc = subprocess.Popen(
                    ["sage", f"{rootpath}/sage/ecm2.sage", str(publickey.n)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    # Own session: os.getpgid(child) then names the child
                    # itself, so the timeout cleanup below cannot escalate
                    # to killing this tool's own process group.
                    start_new_session=True,
                )
                sage_proc.wait(timeout=self.timeout)
                stdout, stderr = sage_proc.communicate()
            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                TimeoutError,
            ):
                terminate_proc_tree(os.getpgid(sage_proc.pid))
                return (None, None)

            # ecm.factor() prints a python list ("[7, 11]") on modern sage
            # and a Factorization string ("7 * 11") on older ones; either
            # way the integer tokens are the prime factors. The helper
            # script prints "0" when the factorization failed.
            sageresults = [int(x) for x in re.findall(rb"\d+", stdout)]

            n_check = 1
            phi = 1
            for fac, exp in Counter(sageresults).items():
                n_check *= fac**exp
                # Euler's totient over p^exp is (p - 1) * p^(exp - 1); a
                # flat product of (fac - 1) miscounts repeated factors.
                phi *= (fac - 1) * fac ** (exp - 1)
            if not sageresults or n_check != publickey.n or phi <= 0:
                return (None, None)

            plain = []
            if cipher is not None and len(cipher) > 0:
                # d depends only on (e, phi); a failure here applies to every
                # ciphertext alike, so compute it once instead of per cipher.
                try:
                    d = invert(publickey.e, phi)
                except ZeroDivisionError:
                    return (None, None)
                for c in cipher:
                    cipher_int = int.from_bytes(c, "big")
                    m = hex(powmod(cipher_int, d, publickey.n))[2::]
                    if len(m) % 2 != 0:
                        m = f"0{m}"
                    plain.append(bytes.fromhex(m))

            return (None, plain)
        except KeyboardInterrupt:
            pass
        return (None, None)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGtMA0GCSqGSIb3DQEBAQUAA4GbADCBlwKBjw+vePt+ocGhwLTa5ONmKUvyhdAX
fU99ZyaGskpxn2DAkPett8hD/3eySSPMgd/y9oXYYsIm/0x5hfs7wLLh/Av5Qx7x
Or5ejGechok7VVoUbw6KTBB1fWy1lC39jFyTa4oZAGCQLf9nJRMYbDGzzrWnDm7K
ynOXWY/6keaIBeg2Xh7VkK5VOl33WjCkSARfAgMBAAE=
-----END PUBLIC KEY-----"""
        cipher = 7102577393434866594929140550804968099111271800384955683330956013020579564684516163830573468073604865935034522944441894535695787080676107364035121171758895218132464499398807752144702697548021940878072503062685829101838944413876346837812265739970980202827485238414586892442822429233004808821082551675699702413952211939387589361654209039260795229
        result = self.attack(
            PublicKey(key_data),
            [cipher.to_bytes((cipher.bit_length() + 7) // 8, "big")],
            progress=False,
        )
        return result != (None, None)
