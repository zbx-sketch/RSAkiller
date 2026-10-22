import hashlib
from pathlib import Path

import pytest
from RsaCtfTool.ctf_solver import extract_material, parse_challenge, solve_text

FIXTURES = Path(__file__).parent / "fixtures" / "rsa_notes"


# SHA-256 of each expected recovered plaintext.  Regression data intentionally does not store
# answer strings; every fixture has answer text redacted and must be solved from RSA parameters.
NOTE_CASES = [
    ("rsa4.md", "147ed7c0df1a8930f1d378da5a21caf4662fc79a57487b8f754cb54cb58891e3"),
    ("rsa5.md", "2b1b696b0f63837efb57bd6af2292d87338b27ca45ce0de2ba6f58dad976c133"),
    ("rsa9.md", "3fcf0dd20484b0aa063ee52fe5ce3e3bf6c84060c954e8991eaf507884126b19"),
    ("rsa_roll.md", "857c56c87b2101026ce4791b614ab3c7cab4f4cea137e286a5bf660d86fb9627"),
    ("rsa_no_e.md", "20be4608be2638f7ecb62060b6f3c741bb4282b99e294e38bd3b3f3d42ac6d63"),
    (
        "rsa_dp_leak.md",
        "cd7211cf5aa3cc6960a3d0b9722b516f2a90f568b9ec23939e0051afba3fdcf0",
    ),
    (
        "rsa_shared_prime.md",
        "cafe23d80723887dda753a34a3a9b754c9afaf6c0202cd9258bdcb0e22024b53",
    ),
    (
        "rsa_common_modulus.md",
        "7707b7d71ead68188f38e9e8c745ada0b6b9185d59e715ea074753cdd429344f",
    ),
    (
        "rsa_direct_root.md",
        "65ede44759c4a66f71d96a4f66f8e9a962ae709a5a5dcc577bbd026821a8a287",
    ),
    (
        "rsa_plain_m.md",
        "6039770233a93a83c62975a45715dac9b143cce1fac8198622a762c276249878",
    ),
    ("baby_rsa.md", "2fc1658b806ca72ac402de0085075c8ebb81baa5a8151b3dea3b261f7f9b0de9"),
    (
        "child_rsa.md",
        "7b2c0f112e24ba766fbf6262bc1c6898ca11671434e57dbd07c48e4645841f43",
    ),
    ("same_mod.md", "f8cbba220daffefdbc78070ef7b695b4d029ce775bc20f61eb1d878e4f352847"),
]


@pytest.mark.parametrize(("filename", "expected_sha256"), NOTE_CASES)
def test_uploaded_rsa_note_cases_are_solved_from_redacted_fixtures(
    filename, expected_sha256
):
    challenge = (FIXTURES / filename).read_text(encoding="utf-8")
    assert "[REDACTED_FLAG]" in challenge or filename == "rsa_plain_m.md"
    report = solve_text(challenge, timeout=90)
    candidate_hashes = {
        hashlib.sha256(candidate.text.encode()).hexdigest()
        for solution in report.solutions
        for candidate in solution.candidates
    }
    assert expected_sha256 in candidate_hashes, (
        filename,
        report.warnings,
        candidate_hashes,
    )
    assert any(
        "True" in item
        for solution in report.solutions
        for item in solution.verification
    )


def test_parser_rejects_truncated_arithmetic_assignments_and_does_not_solve_them():
    challenge = "n = 101 * 113" + chr(10) + "e = 1 << 16 | 1" + chr(10) + "c = 8" + chr(10)
    parsed = parse_challenge(challenge)
    material = extract_material(parsed)
    assert not material.n_values
    assert not material.e_values
    assert any("拒绝解析非字面量赋值" in warning for warning in parsed.warnings)
    assert not solve_text(challenge, timeout=2).solutions


@pytest.mark.parametrize(
    "line",
    [
        "n = 101 * 113",
        "e = 1 << 16 | 1",
        "c = 123 + 456",
        "n = (101 * 113)",
    ],
)
def test_parser_rejects_expression_assignments_without_prefix_tokens(line):
    parsed = parse_challenge(line + chr(10))
    assert not parsed.tokens
    assert any("拒绝解析非字面量赋值" in warning for warning in parsed.warnings)


def test_parser_source_with_printed_literals_uses_only_printed_values():
    challenge = (
        "n = p * q" + chr(10)
        + "e = 1 << 16 | 1" + chr(10)
        + "c = pow(m, e, n)" + chr(10)
        + "print(f'n = {n}')" + chr(10)
        + "print(f'e = {e}')" + chr(10)
        + "print(f'c = {c}')" + chr(10)
        + "n = 3233" + chr(10)
        + "e = 17" + chr(10)
        + "c = 2790" + chr(10)
    )
    parsed = parse_challenge(challenge)
    material = extract_material(parsed)
    assert [(record.n, record.e, record.c) for record in material.records] == [
        (3233, 17, 2790)
    ]
    assert not any("拒绝解析非字面量赋值" in warning for warning in parsed.warnings)


def test_parser_accepts_literal_assignments_with_comments():
    challenge = "n = 3233 # modulus" + chr(10) + "e = 17 # exponent" + chr(10) + "c = 2790 # ciphertext" + chr(10)
    material = extract_material(parse_challenge(challenge))
    assert [(record.n, record.e, record.c) for record in material.records] == [
        (3233, 17, 2790)
    ]


def test_parser_normalizes_crlf_for_worker_byte_input():
    challenge = "n = 3233" + chr(13) + chr(10) + "e = 17" + chr(13) + chr(10) + "c = 2790" + chr(13) + chr(10)
    parsed = parse_challenge(challenge)
    assert not parsed.warnings
    material = extract_material(parsed)
    assert [(record.n, record.e, record.c) for record in material.records] == [
        (3233, 17, 2790)
    ]


@pytest.mark.parametrize(
    "relative_path",
    [
        "pico/pico2022_smooth.txt",
    ],
)
def test_public_small_and_smooth_factor_paths_are_recovered(relative_path):
    path = Path(__file__).parent / "fixtures" / "public_rsa" / relative_path
    report = solve_text(path.read_text(encoding="utf-8"), timeout=180)
    assert report.solutions, (relative_path, report.attempted, report.warnings)
    assert any("True" in item for solution in report.solutions for item in solution.verification)


def test_parser_accepts_python2_long_suffix_and_never_executes_source(tmp_path):
    marker = tmp_path / "must-not-exist"
    text = f"""n = 0x21L\ne = 3L\nc = 8L\n__import__("pathlib").Path({str(marker)!r}).write_text("bad")"""
    parsed = parse_challenge(text)
    material = extract_material(parsed)
    assert material.n_values == [33]
    assert material.e_values == [3]
    assert material.c_values == [8]
    assert not marker.exists()


def test_standalone_ciphertexts_preserve_repeated_characters():
    parsed = parse_challenge("{3233, 17}\n2790\n2790\n")
    material = extract_material(parsed)
    assert [record.c for record in material.records] == [2790, 2790]


def _candidate_texts(report):
    return {
        candidate.text
        for solution in report.solutions
        for candidate in solution.candidates
    }


def test_prime_square_uses_phi_of_prime_power_and_requires_true_closure():
    n = 101**2
    e = 3
    message = 42
    challenge = f"n = {n}\ne = {e}\nc = {pow(message, e, n)}\n"
    report = solve_text(challenge, timeout=10)
    assert any(solution.attack == "prime_power_modulus" for solution in report.solutions)
    assert "*" in _candidate_texts(report)  # bytes(42) is the one-byte plaintext
    assert all(
        "False" not in item
        for solution in report.solutions
        for item in solution.verification
    )


def test_identity_prime_and_wiener_paths_are_automatic():
    identity = solve_text("n = 101\ne = 1\nc = 77\n", timeout=10)
    assert any(solution.attack == "identity_exponent_e1" for solution in identity.solutions)

    p, q, d = 1009, 1013, 5
    n = p * q
    phi = (p - 1) * (q - 1)
    e = pow(d, -1, phi)
    c = pow(42, e, n)
    report = solve_text(f"n={n}\ne={e}\nc={c}\n", timeout=10)
    assert any(solution.attack == "wiener_small_private_exponent" for solution in report.solutions)


def test_labeled_private_key_and_friend_exponent_chain_is_parsed_without_exec():
    p, q = 101, 113
    n = p * q
    phi = (p - 1) * (q - 1)
    base_e = 17
    base_d = pow(base_e, -1, phi)
    friend_exponents = (3, 13)
    message = 42
    ciphertext = pow(message, friend_exponents[0] * friend_exponents[1], n)
    challenge = (
        f"e = {base_e}\n"
        f"My private key: ({n}, {base_d})\n"
        f"My Friend's public keys: [({n}, {friend_exponents[0]}), ({n}, {friend_exponents[1]})]\n"
        f"Encrypted flag: {ciphertext}\n"
    )
    report = solve_text(challenge, timeout=10)
    assert any(
        solution.attack == "same_modulus_exponent_chain_known_d"
        for solution in report.solutions
    )


def test_trailing_null_padding_low_exponent_is_recovered():
    n = (1 << 100) + 159
    e = 3
    message = b"ABC"
    padded = int.from_bytes(message + b"\x00" * 5, "big")
    challenge = (
        f"FLAG = b'???'\n"
        f"def pad(flag): return flag + b'\\x00' * (8 - len(flag))\n"
        f"n = {n}\ne = {e}\nc = {pow(padded, e, n)}\n"
    )
    report = solve_text(challenge, timeout=10)
    assert any(
        solution.attack == "trailing_null_padding_low_exponent"
        for solution in report.solutions
    )
    assert "ABC" in _candidate_texts(report)
