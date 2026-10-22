"""Regression tests pinning behaviour fixed during the source audits.

Every test in this file corresponds to a defect that existed before the
sage-compat-and-fixes branch repairs; if any of these fail, a fix has
regressed.
"""
import logging
import random

import pytest

from RsaCtfTool.lib.algos import euler, hart, lehman, mlucas, pollard_rho
from RsaCtfTool.lib.conspicuous_check import privatekey_check
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.number_theory import (
    ilogb,
    inv_mod_pow_of_2,
    is_prime,
    miller_rabin,
)


def rand_semiprime(rng, bits_each):
    while True:
        a = rng.getrandbits(bits_each) | (1 << (bits_each - 1)) | 1
        b = rng.getrandbits(bits_each) | (1 << (bits_each - 1)) | 1
        if a != b and is_prime(a) and is_prime(b):
            return a * b


class TestMlucasChain:
    """mlucas must implement the MSB-first Lucas multiplication chain."""

    def test_multiplication_chain_semantics(self):
        rng = random.Random(2024)

        def V(k, P, mod):
            u, w = 2 % mod, P % mod
            if k == 0:
                return u
            for _ in range(k - 1):
                u, w = w, (P * w - u) % mod
            return w

        for _ in range(50):
            n = 3
            while not is_prime(n) or n < 1000:
                n = rng.getrandbits(40) | 1
            P = rng.randrange(3, n - 1)
            m = rng.randrange(3, 200)
            a = rng.randrange(2, 32)
            assert mlucas(V(m, P, n), a, n) == V(m * a, P, n)


class TestInvModPowOf2:
    @pytest.mark.parametrize(
        "factor,bits,expected", [(3, 8, 171), (5, 12, 3277)]
    )
    def test_known_inverses(self, factor, bits, expected):
        assert inv_mod_pow_of_2(factor, bits) == expected

    def test_round_trip_random(self):
        rng = random.Random(7)
        for _ in range(100):
            bits = rng.randrange(8, 65)
            a = rng.getrandbits(bits) | 1
            assert (a * inv_mod_pow_of_2(a, bits)) % (1 << bits) == 1

    def test_even_factor_rejected(self):
        with pytest.raises(ValueError):
            inv_mod_pow_of_2(4, 8)


class TestPrimalityEdges:
    @pytest.mark.parametrize("n", [2, 3, 5, 7, 11])
    def test_small_primes_true(self, n):
        assert miller_rabin(n) is True

    @pytest.mark.parametrize("n", [1, 4, 9, 15])
    def test_small_composites_false(self, n):
        assert miller_rabin(n) is False

    def test_ilogb_big_int_no_overflow(self):
        assert ilogb(1 << 1100, 2) == 1100
        assert ilogb(1000, 10) == 3


class TestFactoringContracts:
    """Factoring functions return valid splits or None - never garbage."""

    def test_pollard_rho_never_trivial(self):
        rng = random.Random(11)
        for _ in range(10):
            n = rand_semiprime(rng, 16)
            d = pollard_rho(n)
            assert d is None or 1 < int(d) < n and n % int(d) == 0

    def test_lehman_valid_or_none(self):
        rng = random.Random(13)
        for _ in range(10):
            n = rand_semiprime(rng, 14)
            r = lehman(n)
            assert r is None or (
                len(r) == 2 and int(r[0]) * int(r[1]) == n and 1 < int(r[0]) < n
            )

    def test_hart_valid_split(self):
        rng = random.Random(17)
        for _ in range(6):
            n = rand_semiprime(rng, 15)
            r = hart(n)
            assert isinstance(r, tuple) and int(r[0]) * int(r[1]) == n

    def test_williams_pp1_splits_smooth_plus_one(self):
        # p+1 and q+1 both smooth: the method's designed sweet spot,
        # exercising the corrected Lucas chain end-to-end.
        p, q = 601, 401          # p+1=602=2*7*43, q+1=402=2*3*67
        from RsaCtfTool.lib.algos import williams_pp1

        r = williams_pp1(p * q, max_v=80)
        assert isinstance(r, tuple) and int(r[0]) * int(r[1]) == p * q

    def test_euler_textbook_example(self):
        assert tuple(map(int, euler(1000009))) == (293, 3413)


class TestConspicuousCheck:
    def test_all_violations_reported(self):
        # p=4, q=6 composite; e=14 shares factor 2 with both; 4*6 != 15 ...
        ret, txt = privatekey_check(15, 4, 6, 3, 14)
        assert ret is True
        for needle in (
            "p IS NOT PROBABLE PRIME",
            "q IS NOT PROBABLE PRIME",
            "p and e ARE NOT RELATIVELY PRIME",
            "q and e ARE NOT RELATIVELY PRIME",
            "n IS NOT p * q",
        ):
            assert needle in txt, f"violation lost from report: {needle}"


class TestGeneratePQContract:
    def test_derives_missing_prime(self):
        from RsaCtfTool.lib.keys_wrapper import generate_pq_from_n_and_p_or_q

        assert generate_pq_from_n_and_p_or_q(15, 3, None) == (3, 5)
        assert generate_pq_from_n_and_p_or_q(15, None, 5) == (3, 5)

    def test_rejects_non_dividing_prime(self):
        from RsaCtfTool.lib.keys_wrapper import generate_pq_from_n_and_p_or_q

        with pytest.raises(ValueError):
            generate_pq_from_n_and_p_or_q(15, 4, None)

    def test_rejects_missing_primes(self):
        from RsaCtfTool.lib.keys_wrapper import generate_pq_from_n_and_p_or_q

        with pytest.raises(ValueError):
            generate_pq_from_n_and_p_or_q(15, None, None)


class TestSameNHugeE:
    """The multi-key common-modulus attack must handle gcd(e1,e2) > 1."""

    def _keys_and_ciphers(self, m, e1, e2):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        p, q = 1009, 30071              # lcm(p-1,q-1) coprime to 15
        n = p * q
        k1 = RSA.construct((n, e1)).publickey().exportKey()
        k2 = RSA.construct((n, e2)).publickey().exportKey()
        pubs = [PublicKey(k1), PublicKey(k2)]
        c1 = pow(m, e1, n)
        c2 = pow(m, e2, n)
        ciphers = [
            c1.to_bytes((c1.bit_length() + 7) // 8, "big"),
            c2.to_bytes((c2.bit_length() + 7) // 8, "big"),
        ]
        return pubs, ciphers

    def test_shared_factor_small_message_recovered(self):
        from RsaCtfTool.attacks.multi_keys.same_n_huge_e import Attack

        m = 31                          # m^5 < n
        pubs, ciphers = self._keys_and_ciphers(m, 5, 15)
        _, plaintext = Attack(timeout=30).attack(pubs, ciphers)
        assert plaintext is not None
        assert int.from_bytes(plaintext, "big") == m

    def test_shared_factor_large_message_fails_cleanly(self):
        from RsaCtfTool.attacks.multi_keys.same_n_huge_e import Attack

        m_big = pow(7, 40, 1009 * 30071) * 3      # m^5 >> n
        pubs, ciphers = self._keys_and_ciphers(m_big, 5, 15)
        _, plains = Attack(timeout=30).attack(pubs, ciphers)
        assert plains is None or all(p is None for p in plains)


class TestSageHelperScriptPreflight:
    """Every attack that shells out to a sage helper script must declare
    it in required_scripts so a missing script is caught by can_run()."""

    SAGE_SUBPROCESS_ATTACKS = {
        "ecm": "sage/ecm.sage",
        "ecm2": "sage/ecm2.sage",
        "qs": "sage/qs.sage",
        "boneh_durfee": "sage/boneh_durfee.sage",
        "smallfraction": "sage/smallfraction.sage",
        "small_crt_exp": "sage/small_crt_exp.sage",
        "binary_polynomial_factoring": "sage/binary_polynomial_factoring.sage",
        "partial_d": "sage/partial_d.sage",
        "lattice": "sage/lattice.sage",
        "qicheng": "sage/qicheng.sage",
        "roca": "sage/roca_attack.py",
    }

    def test_scripts_declared_and_present(self):
        import importlib
        import os
        from RsaCtfTool.attacks.abstract_attack import _ROOTPATH

        for module_name, script in self.SAGE_SUBPROCESS_ATTACKS.items():
            module = importlib.import_module(
                f"RsaCtfTool.attacks.single_key.{module_name}"
            )
            attack = module.Attack(timeout=1)
            assert script in attack.required_scripts, module_name
            assert os.path.isfile(os.path.join(_ROOTPATH, script)), script


class TestWolframAlphaPreflight:
    def test_api_key_enables_only_with_package(self, monkeypatch):
        # wolframalpha is a Python library: with an API key set, can_run
        # follows whether the module is importable, not any PATH binary.
        import importlib.util
        from RsaCtfTool.attacks.single_key.wolframalpha import Attack

        monkeypatch.setenv("WA_API_KEY", "dummy-key")
        package_present = importlib.util.find_spec("wolframalpha") is not None
        assert Attack().can_run() is package_present

    def test_missing_api_key_disables(self, monkeypatch):
        from RsaCtfTool.attacks.single_key.wolframalpha import Attack

        monkeypatch.delenv("WA_API_KEY", raising=False)
        assert Attack().can_run() is False


class TestFifthAuditRegressions:
    """Fixes from the fifth audit pass (2026-09)."""

    def test_conspicuous_accepts_phi_inverse(self):
        # The tool emits d = e^-1 mod phi; lambda | phi so it also
        # satisfies e*d == 1 (mod lambda). This used to be a false flag.
        p, q, e = 61, 53, 17
        d = pow(e, -1, (p - 1) * (q - 1))
        _, txt = privatekey_check(p * q, p, q, d, e)
        assert "d IS NOT e^(-1)" not in txt
        assert "d IS NOT < " not in txt

    def test_conspicuous_accepts_lambda_inverse(self):
        # Standard implementations emit d = e^-1 mod lambda.
        from math import lcm as _lcm

        p, q, e = 61, 53, 17
        d = pow(e, -1, _lcm(p - 1, q - 1))
        _, txt = privatekey_check(p * q, p, q, d, e)
        assert "d IS NOT e^(-1)" not in txt

    def test_conspicuous_still_rejects_wrong_d(self):
        p, q, e = 61, 53, 17
        _, txt = privatekey_check(p * q, p, q, 12345, e)
        assert "d IS NOT e^(-1)" in txt

    def test_fermat_prime_modulus_returns_none(self):
        from RsaCtfTool.lib.algos import fermat

        assert fermat(101) is None

    def test_lehmer_machine_prime_modulus_returns_none(self):
        from RsaCtfTool.lib.algos import lehmer_machine

        assert lehmer_machine(101) is None

    def test_kraitchik_prime_modulus_returns_none(self):
        from RsaCtfTool.lib.algos import kraitchik

        assert kraitchik(101) is None

    def test_fermat_composite_still_factors(self):
        from RsaCtfTool.lib.algos import fermat

        p, q = 101, 103
        assert tuple(sorted(fermat(p * q))) == (p, q)

    def test_private_key_non_coprime_e_is_inert_not_fatal(self):
        # gcd(e, phi) != 1 used to raise ZeroDivisionError out of the
        # constructor; the key must come out simply unusable instead.
        priv = PrivateKey(p=5, q=7, e=4, n=35)
        assert priv.d is None
        assert priv.key is None

    def test_timeout_nonpositive_disables_timer(self):
        import time as _time

        from RsaCtfTool.lib.utils import timeout as _timeout

        with _timeout(0):
            _time.sleep(0.2)  # must not fire an instant timeout

    def test_timeout_restores_sigterm_handler(self):
        import signal as _signal

        from RsaCtfTool.lib.utils import timeout as _timeout

        before = _signal.getsignal(_signal.SIGTERM)
        with _timeout(30):
            pass
        assert _signal.getsignal(_signal.SIGTERM) is before

    def test_fib_fallback_matches_definition(self):
        from RsaCtfTool.lib.number_theory import _fib

        assert [_fib(i) for i in range(8)] == [0, 1, 1, 2, 3, 5, 8, 13]

    def test_invmod_fallback_raises_without_inverse(self):
        from RsaCtfTool.lib.number_theory import _invmod

        with pytest.raises(ZeroDivisionError):
            _invmod(4, 100)

    def test_decrypt_emits_one_result_per_cipher(self, small_rsa_key):
        # OAEP fails on raw-RSA ciphertexts, so exactly the textbook
        # result is returned (the old code appended duplicates).
        key = small_rsa_key
        priv = PrivateKey(p=key["p"], q=key["q"], e=key["e"], n=key["n"])
        cipher_int = pow(42, key["e"], key["n"])
        cb = cipher_int.to_bytes((cipher_int.bit_length() + 7) // 8, "big")
        out = priv.decrypt([cb])
        assert len(out) == 1
        assert int.from_bytes(out[0], "big") == 42

    def test_decrypt_unusable_key_returns_ciphertext(self):
        priv = PrivateKey(p=5, q=7, e=4, n=35)
        assert priv.decrypt([b"\x01\x02"]) == [b"\x01\x02"]

    def test_reject_unusable_priv_key_drops_shell_objects(self):
        from RsaCtfTool.lib.rsa_attack import RSAAttack

        ra = object.__new__(RSAAttack)
        ra.priv_key = PrivateKey(p=5, q=7, e=4, n=35)
        ra._reject_unusable_priv_key()
        assert ra.priv_key is None

    def test_reject_unusable_priv_key_keeps_d_only_keys(self):
        # Keys with a bare d but no p/q (nonRSA output) stay usable.
        from RsaCtfTool.lib.rsa_attack import RSAAttack

        ra = object.__new__(RSAAttack)
        ra.priv_key = PrivateKey(n=1009 * 1013, e=65537, d=12345)
        ra._reject_unusable_priv_key()
        assert ra.priv_key is not None

    def test_cube_root_rejects_non_perfect_root(self):
        from types import SimpleNamespace

        from RsaCtfTool.attacks.single_key.cube_root import Attack

        priv, plain = Attack().attack(SimpleNamespace(e=3), [b"\x30\x39"])
        assert priv is None
        assert plain is None

    def test_cube_root_accepts_perfect_cube(self):
        from types import SimpleNamespace

        from RsaCtfTool.attacks.single_key.cube_root import Attack

        m = 42
        cb = (m**3).to_bytes(((m**3).bit_length() + 7) // 8, "big")
        priv, plain = Attack().attack(SimpleNamespace(e=3), [cb])
        assert plain == [bytes([42])]

    def test_common_modulus_filters_none_results(self):
        from types import SimpleNamespace

        from RsaCtfTool.attacks.multi_keys.common_modulus_related_message import (
            Attack,
        )

        k1 = SimpleNamespace(n=15, e=7)
        k2 = SimpleNamespace(n=35, e=5)  # different modulus -> every pair None
        priv, plains = Attack().attack([k1, k2], [b"\x01", b"\x02"])
        assert priv is None
        assert plains is None

    def test_factordb_rejects_multiprime_factor_list(self, monkeypatch):
        from types import SimpleNamespace

        from RsaCtfTool.attacks.single_key import factordb as factordb_attack

        monkeypatch.setattr(factordb_attack, "getfdb", lambda n: [3, 5, 7])
        priv, plain = factordb_attack.Attack().attack(SimpleNamespace(n=105, e=7))
        assert priv is None
        assert plain is None


class TestFifthAuditPerformanceFixes:
    """Performance-only fixes from the fifth audit; results must stay
    equivalent (or, for smallq, match its documented q < 100000 bound)."""

    def test_fermat_number_gcd_modular_equivalence(self):
        # gcd(F_x, n) == gcd(2^(2^x) mod n + 1, n) - the identity the
        # attack now relies on instead of building the full Fermat number.
        from RsaCtfTool.lib.number_theory import gcd, powmod

        rng = random.Random(99)
        n = rand_semiprime(rng, 64)
        for x in range(2, 13):
            f = (1 << (1 << x)) + 1
            assert gcd(f, n) == gcd(powmod(2, 1 << x, n) + 1, n)

    def test_close_factor_hits_close_primes(self):
        from RsaCtfTool.lib.algos import close_factor
        from RsaCtfTool.lib.number_theory import next_prime

        base = 1 << 128
        p = int(next_prime(base - 10**5))
        q = int(next_prime(base + 10**5))
        r = close_factor(p * q, 2 * 10**5, progress=False)
        assert r is not None
        assert sorted(r) == sorted([p, q])

    def test_load_system_consts_is_cached(self):
        from RsaCtfTool.lib.system_primes import load_system_consts

        first = load_system_consts()
        assert first is load_system_consts()

    def test_smallq_finds_factor_below_bound(self):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey
        from RsaCtfTool.attacks.single_key.smallq import Attack

        key_data = RSA.construct((54311 * 1009, 65537)).publickey().exportKey()
        priv, _ = Attack().attack(PublicKey(key_data), progress=False)
        assert priv is not None


class TestFifthAuditFollowups:
    """Degenerate-result handling pinned right after the fifth audit."""

    def test_comfact_cn_cipher_multiple_of_n_misses_cleanly(self):
        # gcd(n, c) == n used to build a bogus (1, n) "key" and leave
        # publickey.p/q polluted for the remaining attacks.
        from RsaCtfTool.attacks.single_key.comfact_cn import Attack
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        n = 101 * 113
        pub = PublicKey(RSA.construct((n, 17)).publickey().exportKey())
        priv, _ = Attack(timeout=10).attack(
            pub, cipher=[(2 * n).to_bytes(3, "big")], progress=False
        )
        assert priv is None
        assert pub.p is None and pub.q is None

    def test_comfact_cn_real_shared_factor_still_recovers(self):
        from RsaCtfTool.attacks.single_key.comfact_cn import Attack
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        n = 101 * 113
        pub = PublicKey(RSA.construct((n, 17)).publickey().exportKey())
        priv, _ = Attack(timeout=10).attack(
            pub, cipher=[(101 * 7).to_bytes(3, "big")], progress=False
        )
        assert priv is not None and priv.key is not None
        assert sorted([priv.p, priv.q]) == [101, 113]

    def test_classical_shor_prime_power_modulus_misses_cleanly(self):
        # n = p**k gives a non-coprime split; the resulting wrong-phi key
        # used to be returned as a success carrying a wrong d.
        from RsaCtfTool.attacks.single_key.classical_shor import Attack
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        pub = PublicKey(RSA.construct((27, 5)).publickey().exportKey())
        assert Attack(timeout=10).attack(pub, progress=False) == (None, None)

    def test_classical_shor_semiprime_still_recovers(self):
        from RsaCtfTool.attacks.single_key.classical_shor import Attack
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        pub = PublicKey(RSA.construct((77, 13)).publickey().exportKey())
        priv, _ = Attack(timeout=10).attack(pub, progress=False)
        assert priv is not None and priv.key is not None
        assert sorted([priv.p, priv.q]) == [7, 11]

    def test_boneh_durfee_inconsistent_sage_output_misses_cleanly(
        self, monkeypatch
    ):
        # A positive but inconsistent d from the lattice script used to
        # escape as a ValueError out of RSA.construct.
        import subprocess

        from RsaCtfTool.attacks.single_key.boneh_durfee import Attack
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: b"12345")
        pub = PublicKey(RSA.construct((101 * 113, 17)).publickey().exportKey())
        assert Attack(timeout=10).attack(pub, progress=False) == (None, None)

    def test_tiny_modulus_short_circuits_single_key_mode(self):
        from types import SimpleNamespace

        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey
        from RsaCtfTool.lib.rsa_attack import RSAAttack

        attackobj = RSAAttack(SimpleNamespace(decrypt=None, attack=[]))
        pub = PublicKey(
            RSA.construct((35, 3)).publickey().exportKey(), filename="tiny"
        )
        pub.n = 1  # hand-crafted degenerate modulus
        assert attackobj.attack_single_key(pub) is True
        assert attackobj.priv_key is None
class _FakeSageProc:
    """Minimal subprocess.Popen stand-in for sage-backed attacks."""

    def __init__(self, stdout):
        self._stdout = stdout
        self.pid = 0  # terminate_proc_tree is never reached on this path

    def wait(self, timeout=None):
        return 0

    def communicate(self):
        return self._stdout, b""


class TestSixthAuditGroupB:
    """sage-output parsing and degenerate-factor handling in ecm/ecm2/euler."""

    @staticmethod
    def _pub(n, e):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        return PublicKey(RSA.construct((n, e)).publickey().exportKey())

    def test_euler_degenerate_gcd_pair_misses_cleanly(self):
        # euler(225) returns (45, 45) whose product overshoots n; this used
        # to build a key object with key=None but a valid-looking d.
        from RsaCtfTool.attacks.single_key.euler import Attack

        pub = self._pub(225, 7)
        assert Attack(timeout=10).attack(pub, progress=False) == (None, None)
        assert pub.p is None and pub.q is None

    def test_euler_1mod4_semiprime_still_recovers(self):
        from RsaCtfTool.attacks.single_key.euler import Attack

        pub = self._pub(65, 7)
        priv, _ = Attack(timeout=10).attack(pub, progress=False)
        assert priv is not None and priv.key is not None
        assert sorted([priv.p, priv.q]) == [5, 13]

    def test_ecm2_modern_sage_list_output_parses(self, monkeypatch):
        # ecm.factor() prints "[7, 11]" on modern sage; the old parser only
        # stripped parentheses and died on the square brackets.
        import subprocess

        from RsaCtfTool.attacks.single_key.ecm2 import Attack

        monkeypatch.setattr(
            subprocess, "Popen", lambda *a, **k: _FakeSageProc(b"[7, 11]")
        )
        pub = self._pub(77, 13)
        cipher = pow(42, 13, 77).to_bytes(1, "big")
        _, plain = Attack(timeout=10).attack(pub, [cipher], progress=False)
        assert plain == [bytes([42])]

    def test_ecm2_repeated_factors_compute_correct_phi(self, monkeypatch):
        # n = 7**2: a flat product of (fac - 1) gives phi = 36 instead of
        # the correct 42, silently decrypting to garbage.
        import subprocess

        from RsaCtfTool.attacks.single_key.ecm2 import Attack

        monkeypatch.setattr(
            subprocess, "Popen", lambda *a, **k: _FakeSageProc(b"[7, 7]")
        )
        pub = self._pub(49, 5)
        cipher = pow(3, 5, 49).to_bytes(1, "big")
        _, plain = Attack(timeout=10).attack(pub, [cipher], progress=False)
        assert plain == [bytes([3])]

    def test_ecm2_sage_failure_output_misses_cleanly(self, monkeypatch):
        import subprocess

        from RsaCtfTool.attacks.single_key.ecm2 import Attack

        monkeypatch.setattr(
            subprocess, "Popen", lambda *a, **k: _FakeSageProc(b"0")
        )
        pub = self._pub(77, 13)
        assert Attack(timeout=10).attack(pub, [bytes([14])], progress=False) == (
            None,
            None,
        )

    def test_ecm_empty_sage_stdout_misses_cleanly(self, monkeypatch):
        # A sage binary that dies before printing anything used to raise
        # ValueError out of int(stdout).
        import subprocess

        from RsaCtfTool.attacks.single_key.ecm import Attack

        monkeypatch.setattr(
            subprocess, "Popen", lambda *a, **k: _FakeSageProc(b"")
        )
        pub = self._pub(77, 13)
        assert Attack(timeout=10).attack(pub, progress=False) == (None, None)

    def test_ecm_prime_echo_rejected(self, monkeypatch):
        # ecm.find_factor may echo n itself for prime input; that used to
        # build a bogus (p, q) = (n, 1) key.
        import subprocess

        from RsaCtfTool.attacks.single_key.ecm import Attack

        monkeypatch.setattr(
            subprocess, "Popen", lambda *a, **k: _FakeSageProc(b"77")
        )
        pub = self._pub(77, 13)
        assert Attack(timeout=10).attack(pub, progress=False) == (None, None)
        assert pub.p is None and pub.q is None

    def test_ecm_real_factor_still_recovers(self, monkeypatch):
        import subprocess

        from RsaCtfTool.attacks.single_key.ecm import Attack

        monkeypatch.setattr(
            subprocess, "Popen", lambda *a, **k: _FakeSageProc(bytes([55, 10]))
        )
        pub = self._pub(77, 13)
        priv, _ = Attack(timeout=10).attack(pub, progress=False)
        assert priv is not None and priv.key is not None
        assert sorted([priv.p, priv.q]) == [7, 11]
class TestNonRSAInvertGuard:
    """nonRSA must miss cleanly when e shares a factor with phi."""

    @staticmethod
    def _pub(n, e):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        return PublicKey(RSA.construct((n, e)).publickey().exportKey())

    def test_prime_n_noninvertible_e_misses_cleanly(self):
        # gcd(3, phi(7)=6) = 3: invmod raised ZeroDivisionError instead of
        # returning (None, None).
        from RsaCtfTool.attacks.single_key.nonRSA import Attack

        assert Attack(timeout=10).attack(self._pub(7, 3), progress=False) == (
            None,
            None,
        )

    def test_prime_power_n_noninvertible_e_misses_cleanly(self):
        # n = 7**2, phi = 42, gcd(3, 42) = 3. (n = 27, e = 3 would need a
        # public key whose exponent shares a factor with n, which
        # RSA.construct refuses to serialize.)
        from RsaCtfTool.attacks.single_key.nonRSA import Attack

        assert Attack(timeout=10).attack(self._pub(49, 3), progress=False) == (
            None,
            None,
        )

    def test_prime_power_n_invertible_e_still_recovers(self):
        # phi(49) = 42, d = 5^-1 mod 42 = 17.
        from RsaCtfTool.attacks.single_key.nonRSA import Attack

        priv, _ = Attack(timeout=10).attack(self._pub(49, 5), progress=False)
        assert priv is not None and priv.d == 17
class TestPollardStrassenCoverage:
    """pollard_strassen must reach sqrt(n) and its attack layer must not
    crash when the algorithm finds nothing."""

    def test_scan_reaches_sqrt_n(self):
        # With floor(n**0.25) blocks the scan stopped at c*c < sqrt(n) and
        # missed the smallest factor of most small semiprimes.
        from RsaCtfTool.lib.algos import pollard_strassen

        for n, want in [
            (77, (7, 11)),
            (15, (3, 5)),
            (35, (5, 7)),
            (143, (11, 13)),
            (221, (13, 17)),
        ]:
            r = pollard_strassen(n)
            assert r is not None and sorted(map(int, r)) == sorted(want), n

    def test_attack_layer_recovers_semiprime(self):
        # The None return used to escape as a TypeError from tuple unpack.
        from RsaCtfTool.attacks.single_key.pollard_strassen import Attack
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        pub = PublicKey(RSA.construct((77, 13)).publickey().exportKey())
        priv, _ = Attack(timeout=10).attack(pub, progress=False)
        assert priv is not None and priv.key is not None
        assert sorted([priv.p, priv.q]) == [7, 11]
class TestPartialQMissingComponents:
    def test_component_built_private_key_misses_cleanly(self):
        # Component-built PrivateKey objects have no dp/dq/di attributes;
        # the attack used to die on AttributeError instead of missing.
        from RsaCtfTool.attacks.single_key.partial_q import Attack
        from RsaCtfTool.lib.keys_wrapper import PrivateKey

        pk = PrivateKey(n=77, e=13, d=37)
        assert Attack(timeout=10).attack(pk, progress=False) == (None, None)
class TestRocaSiqsHardening:
    @staticmethod
    def _pub(n, e):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        return PublicKey(RSA.construct((n, e)).publickey().exportKey())

    def test_roca_colon_noise_misses_cleanly(self, monkeypatch):
        # Colon-bearing non-numeric stdout used to escape as ValueError.
        import subprocess

        monkeypatch.setattr(
            "RsaCtfTool.attacks.single_key.roca.is_roca_vulnerable",
            lambda n: True,
        )
        monkeypatch.setattr(
            subprocess, "check_output", lambda *a, **k: b"WARN: ing"
        )
        from RsaCtfTool.attacks.single_key.roca import Attack

        assert Attack(timeout=10).attack(self._pub(77, 13), progress=False) == (
            None,
            None,
        )

    def test_roca_mismatched_factors_rejected(self, monkeypatch):
        import subprocess

        monkeypatch.setattr(
            "RsaCtfTool.attacks.single_key.roca.is_roca_vulnerable",
            lambda n: True,
        )
        monkeypatch.setattr(
            subprocess, "check_output", lambda *a, **k: b"7:13"
        )
        from RsaCtfTool.attacks.single_key.roca import Attack

        assert Attack(timeout=10).attack(self._pub(77, 13), progress=False) == (
            None,
            None,
        )

    def test_roca_valid_factors_still_recover(self, monkeypatch):
        import subprocess

        monkeypatch.setattr(
            "RsaCtfTool.attacks.single_key.roca.is_roca_vulnerable",
            lambda n: True,
        )
        monkeypatch.setattr(
            subprocess, "check_output", lambda *a, **k: b"7:11"
        )
        from RsaCtfTool.attacks.single_key.roca import Attack

        priv, _ = Attack(timeout=10).attack(self._pub(77, 13), progress=False)
        assert priv is not None and priv.key is not None
        assert sorted([priv.p, priv.q]) == [7, 11]

    def test_siqs_yafu_crash_misses_cleanly(self, monkeypatch):
        # A crashing/timing-out yafu used to raise out of attack().
        import subprocess

        def boom(*a, **k):
            raise subprocess.CalledProcessError(1, "yafu")

        monkeypatch.setattr(subprocess, "check_output", boom)
        from RsaCtfTool.attacks.single_key.siqs import Attack

        assert Attack(timeout=10).attack(self._pub(77, 13), progress=False) == (
            None,
            None,
        )
class TestSmallfractionParsing:
    @staticmethod
    def _pub(n, e):
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        return PublicKey(RSA.construct((n, e)).publickey().exportKey())

    def test_empty_sage_stdout_misses_cleanly(self, monkeypatch):
        # int(b"") used to raise ValueError out of attack().
        import subprocess

        from RsaCtfTool.attacks.single_key.smallfraction import Attack

        monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: b"")
        pub = self._pub(77, 13)
        assert Attack(timeout=10).attack(pub, progress=False) == (None, None)

    def test_prime_echo_rejected(self, monkeypatch):
        # A sage result equal to n itself used to build a bogus (n, 1) key.
        import subprocess

        from RsaCtfTool.attacks.single_key.smallfraction import Attack

        monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: b"77")
        pub = self._pub(77, 13)
        assert Attack(timeout=10).attack(pub, progress=False) == (None, None)
        assert pub.p is None and pub.q is None

    def test_real_factor_still_recovers(self, monkeypatch):
        import subprocess

        from RsaCtfTool.attacks.single_key.smallfraction import Attack

        monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: b"7")
        pub = self._pub(77, 13)
        priv, _ = Attack(timeout=10).attack(pub, progress=False)
        assert priv is not None and priv.key is not None
        assert sorted([priv.p, priv.q]) == [7, 11]
class TestCommonModulusRelatedMessage:
    def test_wrapped_m_to_the_g_returns_none(self):
        # gcd(e1, e2) = 3 and m**3 >= n: the truncated cube root used to be
        # returned as if it were the plaintext.
        from RsaCtfTool.lib.number_theory import common_modulus_related_message

        n = 1009 * 1013
        m = 1000
        assert (
            common_modulus_related_message(3, 6, n, pow(m, 3, n), pow(m, 6, n))
            is None
        )

    def test_small_message_still_recovers(self):
        # m**3 < n: the exact cube root is the plaintext.
        from RsaCtfTool.lib.number_theory import common_modulus_related_message

        n = 1009 * 1013
        m = 100  # m**3 = 1e6 < n
        assert (
            common_modulus_related_message(3, 6, n, pow(m, 3, n), pow(m, 6, n))
            == m
        )

    def test_coprime_exponents_unaffected(self):
        from RsaCtfTool.lib.number_theory import common_modulus_related_message

        n = 1009 * 1013
        m = 42
        assert (
            common_modulus_related_message(5, 7, n, pow(m, 5, n), pow(m, 7, n))
            == m
        )
class TestIdrsaPubDisector:
    @staticmethod
    def _line(*fields):
        import base64
        import struct

        blob = b"".join(struct.pack(">I", len(f)) + f for f in fields)
        return "ssh-rsa " + base64.standard_b64encode(blob).decode()

    def test_truncated_blob_misses_cleanly(self):
        # Fewer than the ssh-rsa algo/e/n triple used to raise IndexError.
        from RsaCtfTool.lib.idrsa_pub_disector import disect_idrsa_pub

        assert disect_idrsa_pub(self._line(b"ssh-rsa", b"")) == (None, None)

    def test_invalid_base64_misses_cleanly(self):
        from RsaCtfTool.lib.idrsa_pub_disector import disect_idrsa_pub

        assert disect_idrsa_pub("ssh-rsa !!!not-base64!!!") == (None, None)

    def test_valid_key_still_parses(self):
        from RsaCtfTool.lib.idrsa_pub_disector import disect_idrsa_pub

        line = self._line(b"ssh-rsa", bytes([1, 0, 1]), bytes([0, 199]))
        assert disect_idrsa_pub(line) == (199, 65537)


class TestCryptoWrapperAll:
    def test_dunder_all_is_strings(self):
        # Object-valued __all__ breaks "from crypto_wrapper import *".
        import RsaCtfTool.lib.crypto_wrapper as cw

        assert all(isinstance(name, str) for name in cw.__all__)
        assert set(cw.__all__) == {
            "RSA",
            "PKCS1_OAEP",
            "number",
            "long_to_bytes",
            "bytes_to_long",
        }
class TestBase64DecryptInput:
    def test_str_base64_actually_decodes(self):
        # b64encode returns bytes, so the round-trip check against a str
        # input never matched and base64 strings passed through undecoded.
        from RsaCtfTool.lib.utils import get_base64_value

        assert get_base64_value("aGVsbG8=") == b"hello"

    def test_bytes_input_unchanged(self):
        from RsaCtfTool.lib.utils import get_base64_value

        assert get_base64_value(b"aGVsbG8=") == b"hello"

    def test_non_base64_passes_through(self):
        from RsaCtfTool.lib.utils import get_base64_value

        assert get_base64_value("zzz!!!") == b"zzz!!!"

    def test_handle_decrypt_input_base64_path(self):
        # --decrypt aGVsbG8= used to crash in n2s with a TypeError because
        # the undecoded string (or decoded bytes) is not an int.
        from types import SimpleNamespace

        from RsaCtfTool.main import _handle_decrypt_input

        args = SimpleNamespace(decrypt="aGVsbG8=", decryptfile=None)
        out = _handle_decrypt_input(args, None)
        assert out.decrypt == [b"hello"]

    def test_handle_decrypt_input_numeric_path(self):
        from types import SimpleNamespace

        from RsaCtfTool.main import _handle_decrypt_input

        args = SimpleNamespace(decrypt="0x2a", decryptfile=None)
        out = _handle_decrypt_input(args, None)
        assert out.decrypt == [bytes([42])]


class TestDumpkeyExtGuard:
    def test_ext_with_d_only_key_does_not_crash(self):
        # p/q are None on d-only keys (e.g. nonRSA output); the dp/dq math
        # used to raise TypeError.
        import logging
        from types import SimpleNamespace

        from RsaCtfTool.lib.keys_wrapper import PrivateKey
        from RsaCtfTool.lib.utils import _print_dumpkey_private

        pk = PrivateKey(n=49, e=5, d=17)
        _print_dumpkey_private(
            SimpleNamespace(ext=True), [pk], logging.getLogger("global_logger")
        )

    def test_ext_with_square_modulus_does_not_crash(self):
        # p == q has no CRT inverse; invmod used to raise ZeroDivisionError.
        import logging
        from types import SimpleNamespace

        from RsaCtfTool.lib.keys_wrapper import PrivateKey
        from RsaCtfTool.lib.utils import _print_dumpkey_private

        pk = PrivateKey(p=7, q=7, e=5, n=49)
        _print_dumpkey_private(
            SimpleNamespace(ext=True), [pk], logging.getLogger("global_logger")
        )
class TestProvidedPrimesValidation:
    @staticmethod
    def _attackobj(**kw):
        from types import SimpleNamespace

        from RsaCtfTool.lib.rsa_attack import RSAAttack

        defaults = dict(
            decrypt=None, attack=[], p=None, q=None, n=77, e=13,
            show_modulus=False,
        )
        defaults.update(kw)
        args = SimpleNamespace(**defaults)
        return RSAAttack(args), args

    def test_non_divisor_p_is_ignored(self):
        # --p 3 --n 77 used to floor-divide into q = 25, skip every attack,
        # and report a "success" whose private key prints as an empty blob.
        attackobj, args = self._attackobj(p=3)
        attackobj._handle_provided_primes()
        assert args.p is None and args.q is None
        assert attackobj.need_run is True

    def test_valid_p_still_derives_q(self):
        attackobj, args = self._attackobj(p=7)
        attackobj._handle_provided_primes()
        assert args.q == 11
        assert attackobj.need_run is False

    def test_mismatched_pq_pair_is_ignored(self):
        attackobj, args = self._attackobj(p=7, q=13)
        attackobj._handle_provided_primes()
        assert args.p is None and args.q is None
        assert attackobj.need_run is True


class TestSixthAuditFixes:
    def test_execute_single_attack_rejects_shell_key_without_run(self):
        # p*q == n but gcd(e, phi) != 1: the --p/--q fast path builds an
        # inert shell key that used to be reported as "Attack success".
        from types import SimpleNamespace

        from RsaCtfTool.lib.rsa_attack import RSAAttack

        ra = object.__new__(RSAAttack)
        ra.args = SimpleNamespace(p=5, q=7, e=4, n=35, private=True, decrypt=None)
        ra.logger = logging.getLogger("global_logger")
        ra.need_run = False
        ra.priv_key = None
        ra.decrypted = []
        module = SimpleNamespace(can_run=lambda: True, get_name=lambda: "stub")

        assert ra._execute_single_attack(module) is False
        assert ra.priv_key is None

    def test_williams_pp1_terminates_on_hard_modulus(self):
        # The stage-1 bound must stop the prime walk; the previous
        # isqrt(n) bound made a 510-bit modulus burn the whole timeout.
        from RsaCtfTool.lib.algos import williams_pp1
        from RsaCtfTool.lib.number_theory import next_prime

        n = int(next_prime(2 ** 255)) * int(next_prime(2 ** 255))
        assert williams_pp1(n) is None


class TestStrongPseudoprimeOrientation:
    """strong_pseudoprime must accept nontrivial roots in either orientation.

    The old check `1 < p < q` silently discarded every root where
    gcd(prev-1, N) exceeded gcd(prev+1, N); for 561 that was all roots
    from the first 14 prime bases.
    """

    def test_carmichael_561_factors(self):
        from RsaCtfTool.lib.algos import strong_pseudoprime

        r = strong_pseudoprime(561)
        assert r is not None
        p, q = r
        assert p * q == 561 and 1 < p < q

    def test_first_base_root_is_not_wasted(self):
        # Base 2 yields a nontrivial sqrt of 1 mod 561 with gcd(prev-1, N)
        # larger than gcd(prev+1, N); the fixed code returns on that root
        # without ever advancing to the next prime base.
        import RsaCtfTool.lib.algos as algos

        def boom(_):
            raise RuntimeError("advanced past base 2")

        original = algos.next_prime
        algos.next_prime = boom
        try:
            r = algos.strong_pseudoprime(561)
        finally:
            algos.next_prime = original
        assert r is not None and r[0] * r[1] == 561

    def test_two_prime_modulus(self):
        from RsaCtfTool.lib.algos import strong_pseudoprime

        r = strong_pseudoprime(13 * 31)
        assert r is not None and r[0] * r[1] == 13 * 31

    def test_prime_returns_none(self):
        from RsaCtfTool.lib.algos import strong_pseudoprime

        assert strong_pseudoprime(17) is None


class TestSixthAuditRegressions:
    """Fixes from the sixth audit pass (2026-09)."""

    def test_williams_pp1_wrapper_returns_key(self):
        # algos.williams_pp1 returns a (p, q) tuple; the wrapper used to
        # treat it as a single factor and always reported a miss.
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PublicKey
        from RsaCtfTool.attacks.single_key.williams_pp1 import Attack

        p, q, e = 601, 401, 65537
        pub = PublicKey(RSA.construct((p * q, e)).publickey().exportKey())
        priv, _ = Attack().attack(pub, progress=False)
        assert priv is not None
        assert {int(priv.p), int(priv.q)} == {p, q}

    def test_private_key_from_file_str_and_decrypt(self, tmp_path):
        # A PrivateKey loaded from a file used to keep a cryptography
        # object that crashed __str__; decrypt must keep working too.
        from RsaCtfTool.lib.crypto_wrapper import RSA
        from RsaCtfTool.lib.keys_wrapper import PrivateKey

        p, q, e = 61, 53, 17
        n = p * q
        d = pow(e, -1, (p - 1) * (q - 1))
        key = RSA.construct((n, e, d))
        keyfile = tmp_path / "priv.pem"
        keyfile.write_bytes(key.exportKey())

        priv = PrivateKey(filename=str(keyfile))
        pem = str(priv)
        assert "BEGIN" in pem and "PRIVATE KEY" in pem

        m = 42
        c = pow(m, e, n)
        decrypted = priv.decrypt([c.to_bytes((c.bit_length() + 7) // 8, "big")])
        assert decrypted and int.from_bytes(decrypted[0], "big") == m

    def test_chinese_remainder_rejects_non_coprime_moduli(self):
        # gmpy invert() returns 0 for non-invertible elements, which used
        # to silently produce a wrong residue.
        import pytest as _pytest
        from RsaCtfTool.lib.number_theory import chinese_remainder

        with _pytest.raises(ValueError):
            chinese_remainder([3, 3], [2, 1])

    def test_pollard_p_1_smooth(self):
        # Single-base accumulation must still factor p-1 smooth moduli.
        from RsaCtfTool.lib.algos import pollard_P_1

        p, q = 101, 151
        r = pollard_P_1(p * q, progress=False)
        assert r is not None
        assert {int(r[0]), int(r[1])} == {p, q}
