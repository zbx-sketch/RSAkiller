#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Use YAFU's automatic factorization strategy for the public modulus."""

import logging
import re
import subprocess
import tempfile

from RsaCtfTool.attacks.abstract_attack import AbstractAttack


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.required_binaries = ["yafu"]
        self.speed = AbstractAttack.speed_enum["slow"]
        self.logger = logging.getLogger("global_logger")

    def attack(self, publickey, cipher=None, progress=True):
        """Run YAFU's automatic ``factor(n)`` plan, including large inputs."""
        n = int(publickey.n)
        try:
            with tempfile.TemporaryDirectory(prefix="rsactftool-yafu-") as cwd:
                result = subprocess.run(
                    ["yafu", "-threads", "2"],
                    input=f"factor({n})\n".encode("ascii"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    cwd=cwd,
                    timeout=self.timeout + 5,
                    check=False,
                )
        except (OSError, subprocess.SubprocessError):
            return None, None

        factors = sorted(
            {
                int(value)
                for value in re.findall(
                    rb"^P\d+\s*=\s*(\d+)\s*$",
                    result.stdout,
                    flags=re.MULTILINE | re.IGNORECASE,
                )
            }
        )
        if len(factors) != 2 or factors[0] * factors[1] != n:
            return None, None

        return self.create_private_key_from_pqe(
            factors[0], factors[1], publickey.e, n
        )

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAM7gDElzPMzEU1htubZ8KvfHomChbmwN
ZrJ1fw38h5l1AgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
