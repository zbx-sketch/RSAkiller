import hashlib
import json
from pathlib import Path
import pytest
from RsaCtfTool.ctf_solver import solve_text
ROOT = Path(__file__).parent / "fixtures" / "public_rsa"
MANIFEST = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
@pytest.mark.parametrize("case", [case for case in MANIFEST["cases"] if case.get("split") == "verified"], ids=lambda case: case["id"])
def test_public_offline_case(case):
    path = ROOT / case.get("subdir", "cryptohack") / case["file"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == case["input_sha256"]
    report = solve_text(path.read_text(encoding="utf-8"), timeout=case["timeout_s"])
    hashes = {hashlib.sha256(c.text.encode()).hexdigest() for s in report.solutions for c in s.candidates}
    assert case["expected_sha256"] in hashes, (case["id"], report.attempted, report.warnings)
    if case.get("attack"):
        assert case["attack"] in {s.attack for s in report.solutions}
    assert report.solutions
    assert all(s.verification for s in report.solutions)
    assert all("False" not in item for s in report.solutions for item in s.verification)
