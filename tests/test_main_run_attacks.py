from types import SimpleNamespace

import pytest

from RsaCtfTool import main


class _MultiKeyAttack:
    def __init__(self, args):
        self.args = args
        self.decrypted = []
        self.priv_key = None
        self.implemented_attacks = []
        self.single_key_calls = []

    def attack_multiple_keys(self, publickeys, attacks):
        self.decrypted.append(b"plaintext")
        return False

    def has_results(self):
        return bool(self.decrypted)

    def attack_single_key(self, publickey, attacks):
        self.single_key_calls.append(publickey)
        return False


@pytest.mark.parametrize(
    ("private_requested", "expected_single_key_calls"),
    [(False, 0), (True, 2)],
)
def test_multi_key_decryption_skips_redundant_factorization_only_without_private_goal(
    monkeypatch, private_requested, expected_single_key_calls
):
    attack_objects = []

    def attack_factory(args):
        attack = _MultiKeyAttack(args)
        attack_objects.append(attack)
        return attack

    monkeypatch.setattr(main, "RSAAttack", attack_factory)
    args = SimpleNamespace(
        attacks_list=["common_modulus_related_message"],
        publickey=["key-1.pem", "key-2.pem"],
        tests=False,
        decrypt=[b"ciphertext"],
        private=private_requested,
        partial=False,
        cracked=False,
    )

    result = main.run_attacks(args, main.logging.getLogger("test"))

    assert result.cracked is True
    assert len(attack_objects[0].single_key_calls) == expected_single_key_calls
