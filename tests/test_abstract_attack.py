from types import SimpleNamespace

import pytest

from RsaCtfTool.attacks.abstract_attack import AbstractAttack


class FakeAttack(AbstractAttack):
    def attack(self, publickeys, cipher=None, progress=True):
        return "private-key", "plaintext"


@pytest.fixture
def valid_public_key():
    return SimpleNamespace(n=3233, e=17, p=61, q=53)


class TestPrivateKeyHelpers:
    def test_create_private_key_returns_key_for_valid_factors(self, valid_public_key):
        private_key, extra = FakeAttack().create_private_key(valid_public_key)

        assert private_key is not None
        assert private_key.n == 3233
        assert extra is None

    def test_create_private_key_rejects_malformed_values(self, valid_public_key):
        valid_public_key.p = object()

        assert FakeAttack().create_private_key(valid_public_key) == (None, None)

    @pytest.mark.parametrize(
        "p,q,e,n",
        [
            (object(), 53, 17, 3233),
            (61, 53, object(), 3233),
            (61, 53, 17, object()),
        ],
    )
    def test_create_private_key_from_pqe_rejects_malformed_values(self, p, q, e, n):
        assert FakeAttack().create_private_key_from_pqe(p, q, e, n) == (None, None)

    def test_helpers_reject_invalid_factor_split(self, valid_public_key):
        valid_public_key.p = 4
        valid_public_key.q = 6

        assert FakeAttack().create_private_key(valid_public_key) == (None, None)
        assert FakeAttack().create_private_key_from_pqe(4, 6, 17, 3233) == (
            None,
            None,
        )
