import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace as NS
import time

from RsaCtfTool.benchmark import assess_report, run_case, run_benchmark


def fixture_case(tmp_path, **updates):
    data = b'n = 55\ne = 3\nc = 8\n'
    (tmp_path / 'input.txt').write_bytes(data)
    case = dict(id='toy', split='development', family='toy', file='input.txt', subdir='.',
                timeout_s=3, input_sha256=hashlib.sha256(data).hexdigest(),
                expected_sha256=hashlib.sha256(b'2').hexdigest(), attack=None)
    case.update(updates)
    return case


def test_real_worker_hash_math_and_sanitization(tmp_path):
    case = fixture_case(tmp_path)
    result = run_case(case, tmp_path)
    assert result['status'] == 'passed', result
    assert result['mathematical_checks_passed']
    assert not {'plaintext', 'keys', 'solutions', 'warnings'} & result.keys()


def test_input_tamper_stops_worker(tmp_path):
    case = fixture_case(tmp_path)
    (tmp_path / 'input.txt').write_text('changed')
    result = run_case(case, tmp_path, command=['does-not-exist'])
    assert result['status'] == 'input_hash_mismatch'


def test_hard_timeout_kills_detached_descendant(tmp_path):
    pidfile = tmp_path / 'pid'
    script = tmp_path / 'slow.py'
    script.write_text('import subprocess,sys,time\nfrom pathlib import Path\n'
                      'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"],start_new_session=True)\n'
                      f'Path({str(pidfile)!r}).write_text(str(p.pid))\n'
                      'time.sleep(60)\n')
    start = time.monotonic()
    result = run_case(fixture_case(tmp_path, timeout_s=0.5), tmp_path, [sys.executable, str(script)])
    assert result['status'] == 'timeout'
    assert time.monotonic() - start < 3
    pid = int(pidfile.read_text())
    stat = Path('/proc') / str(pid) / 'stat'
    assert not stat.exists() or stat.read_text().rsplit(')', 1)[1].split()[0] == 'Z'


def test_checks_cannot_be_combined_across_solutions(tmp_path):
    case = fixture_case(tmp_path, attack='right')
    report = NS(solutions=[NS(attack='wrong', candidates=[NS(text='2')], verification=['eq: True']),
                           NS(attack='right', candidates=[NS(text='garbage')], verification=['eq: True'])], warnings=[])
    assert assess_report(report, case)['status'] == 'failed'
    report.solutions[0].attack = 'right'
    report.solutions[0].verification = ['eq: False']
    assert assess_report(report, case)['status'] == 'failed'


def test_dependency_and_solver_timeout_are_distinct(tmp_path):
    case = fixture_case(tmp_path)
    assert assess_report(NS(solutions=[], warnings=['No module named sage']), case)['status'] == 'dependency_missing'
    assert assess_report(NS(solutions=[], warnings=['时间预算耗尽']), case)['status'] == 'timeout'
    assert assess_report(NS(solutions=[], warnings=[]), case)['status'] == 'failed'


def test_manifest_default_includes_failed_development(tmp_path):
    good = fixture_case(tmp_path)
    bad = dict(good, id='verified-bad', split='verified', expected_sha256='0'*64)
    manifest = tmp_path / 'manifest.json'
    manifest.write_text(json.dumps({'cases': [good, bad]}))
    output = tmp_path / 'result.json'
    result = run_benchmark(manifest, output)
    assert result['selection'] == 'all_manifest_cases'
    assert result['summary']['total'] == result['summary']['completed'] == 2
    assert [case['status'] for case in result['cases']] == ['passed', 'failed']
    assert json.loads(output.read_text()) == result
