#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import logging
from RsaCtfTool.attacks.abstract_attack import AbstractAttack, SAGE_MIN_TIMEOUT
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.utils import rootpath
from RsaCtfTool.lib.is_roca_test import is_roca_vulnerable


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(max(timeout, SAGE_MIN_TIMEOUT))
        self.speed = AbstractAttack.speed_enum["slow"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/roca_attack.py"]
        self.logger = logging.getLogger("global_logger")

    def attack(self, publickey, cipher=[], progress=True):
        if is_roca_vulnerable(publickey.n):
            try:
                sageresult = subprocess.check_output(
                    ["sage", f"{rootpath}/sage/roca_attack.py", str(publickey.n)],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )

            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                return (None, None)

            if b"FAIL" not in sageresult and b":" in sageresult:
                sageresult = sageresult.decode("utf-8").strip()
                try:
                    p, q = map(int, sageresult.split(":"))
                except ValueError:
                    # Stray colon-bearing noise on stdout is not a factor pair.
                    return (None, None)
                if p * q != publickey.n:
                    return (None, None)
                priv_key = PrivateKey(
                    int(p), int(q), int(publickey.e), int(publickey.n)
                )
                if priv_key.key is None:
                    return (None, None)
                return (priv_key, None)
            else:
                return (None, None)
        else:
            self.logger.error("[-] This key is not roca, skipping test...")
            return (None, None)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAar8f96eVg1jBUt7IlYJk89ksQxJSdIjC
3e7baDh166JFr7lL6jrkD+9fsqgxFj9nPRYWCkKX/JcceVd5Y81YQwIDAQAB
-----END PUBLIC KEY-----"""
        self.timeout = 120
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
