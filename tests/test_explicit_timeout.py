from types import SimpleNamespace

import pytest

from RsaCtfTool.lib.rsa_attack import RSAAttack


@pytest.mark.parametrize(
    "module_name,multikeys",
    [
        ("ecm", False),
        ("pollard_rho", False),
        ("common_factors", True),
    ],
)
def test_explicit_timeout_caps_constructed_attack(module_name, multikeys):
    args = SimpleNamespace(
        timeout=1,
        attack=[module_name],
        attack_priority=None,
        sendtofdb=False,
        decrypt=None,
        private=False,
    )
    runner = RSAAttack(args)

    runner.load_attacks([module_name], multikeys=multikeys)

    assert runner.implemented_attacks
    assert all(attack.timeout <= 1 for attack in runner.implemented_attacks)


def test_nonpositive_timeout_keeps_existing_attack_semantics():
    args = SimpleNamespace(
        timeout=0,
        attack=["ecm"],
        attack_priority=None,
        sendtofdb=False,
        decrypt=None,
        private=False,
    )
    runner = RSAAttack(args)

    runner.load_attacks(["ecm"])

    assert runner.implemented_attacks[0].timeout == 180
