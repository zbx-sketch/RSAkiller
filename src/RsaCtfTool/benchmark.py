"""All-manifest offline benchmark. Run: python -m RsaCtfTool.benchmark.

Only hashes, booleans, counts and fixed diagnostic codes leave case workers.
Every manifest entry runs, including development entries. Time budgets include
interpreter startup. Solver output and exception messages are never serialized.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time

DEFAULT_MANIFEST = Path(__file__).resolve().parents[2] / 'tests/fixtures/public_rsa/manifest.json'


def assess_report(report, case):
    """Check the answer and closure on the SAME solution, never across solutions."""
    matching = []
    for solution in report.solutions:
        answer_ok = any(hashlib.sha256(c.text.encode('utf-8')).hexdigest() == case['expected_sha256'] for c in solution.candidates)
        attack_ok = not case.get('attack') or solution.attack == case['attack']
        checks = solution.verification
        # All advertised mathematical equalities must be explicit positive checks.
        math_ok = bool(checks) and all(re.search(r'(?:^|[：:]\s*)True\b', item) and not re.search(r'\bFalse\b', item) for item in checks)
        matching.append((answer_ok, attack_ok, math_ok))
    passed = any(all(item) for item in matching)
    warnings = ' '.join(report.warnings).lower()
    dependencies = any(word in warnings for word in ('modulenotfounderror', 'no module named', 'not installed', 'not found', 'unavailable', '未安装', '不可用'))
    exhausted = any(word in warnings for word in ('timeout', 'timed out', '超时', '预算耗尽', '时间预算'))
    status = 'passed' if passed else 'dependency_missing' if dependencies else 'timeout' if exhausted else 'failed'
    reason = ('checks_passed' if passed else 'dependency_warning' if dependencies else
              'solver_deadline' if exhausted else 'answer_hash_mismatch' if not any(x[0] for x in matching) else
              'attack_mismatch' if not any(x[0] and x[1] for x in matching) else 'mathematical_check_failed')
    return {'status': status, 'reason': reason,
            'answer_hash_match': any(x[0] for x in matching),
            'attack_match': any(x[0] and x[1] for x in matching),
            'mathematical_checks_passed': any(x[0] and x[2] for x in matching),
            'solution_count': len(matching), 'dependency_warning': dependencies,
            'solver_timeout_warning': exhausted}


def _worker(request_path, result_path):
    request = json.loads(Path(request_path).read_text())
    case = request['case']
    try:
        data = Path(request['input']).read_bytes()
        if hashlib.sha256(data).hexdigest() != case['input_sha256']:
            result = {'status': 'input_hash_mismatch', 'reason': 'input_hash_mismatch'}
        else:
            from RsaCtfTool.ctf_solver import solve_text
            result = assess_report(solve_text(data.decode('utf-8'), timeout=case['timeout_s']), case)
    except (ImportError, ModuleNotFoundError):
        result = {'status': 'dependency_missing', 'reason': 'import_error'}
    except FileNotFoundError:
        result = {'status': 'dependency_missing', 'reason': 'file_not_found'}
    except Exception:
        result = {'status': 'error', 'reason': 'worker_exception'}
    Path(result_path).write_text(json.dumps(result), encoding='utf-8')


def _kill_tree(process):
    # Descendant solver subprocesses may create their own sessions. Snapshot /proc
    # ancestry as well as terminating the worker's process group.
    descendants = set()
    if sys.platform.startswith('linux'):
        parents = {}
        for entry in Path('/proc').iterdir():
            if entry.name.isdigit():
                try:
                    tail = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
                    parents[int(entry.name)] = int(tail[1])
                except (OSError, ValueError, IndexError):
                    pass
        pending = {process.pid}
        while pending:
            children = {pid for pid, ppid in parents.items() if ppid in pending} - descendants
            descendants.update(children)
            pending = children
    for pid in descendants:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_case(case, root, command=None):
    started = time.monotonic()
    result = {key: case.get(key) for key in ('id', 'split', 'family', 'timeout_s', 'input_sha256', 'expected_sha256')}
    path = (Path(root) / case.get('subdir', 'cryptohack') / case['file']).resolve()
    try:
        actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        result.update(status='input_error', reason='input_unreadable', elapsed_s=round(time.monotonic()-started, 3))
        return result
    result['input_hash_match'] = actual_hash == case['input_sha256']
    if not result['input_hash_match']:
        result.update(status='input_hash_mismatch', reason='input_hash_mismatch', elapsed_s=round(time.monotonic()-started, 3))
        return result
    with tempfile.TemporaryDirectory(prefix='rsa-benchmark-') as temporary:
        request = Path(temporary) / 'request.json'
        output = Path(temporary) / 'result.json'
        request.write_text(json.dumps({'case': case, 'input': str(path)}))
        env = os.environ.copy()
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1]) + os.pathsep + env.get('PYTHONPATH', '')
        args = command or [sys.executable, '-m', 'RsaCtfTool.benchmark', '--worker', str(request), str(output)]
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True, cwd=temporary, env=env)
        try:
            process.wait(timeout=max(0.001, float(case['timeout_s']) - (time.monotonic()-started)))
        except subprocess.TimeoutExpired:
            _kill_tree(process)
            result.update(status='timeout', reason='wallclock_deadline')
        else:
            _kill_tree(process)  # reap any surviving descendants on normal exit too
            try:
                payload = json.loads(output.read_text())
                allowed = {'status', 'reason', 'answer_hash_match', 'attack_match', 'mathematical_checks_passed', 'solution_count', 'dependency_warning', 'solver_timeout_warning'}
                if process.returncode != 0 or not isinstance(payload, dict) or set(payload) - allowed:
                    raise ValueError('invalid worker result')
                result.update(payload)
            except (OSError, ValueError, TypeError):
                result.update(status='error', reason='worker_exit_or_invalid_result')
    result['elapsed_s'] = round(time.monotonic() - started, 3)
    return result


def run_benchmark(manifest=DEFAULT_MANIFEST, output=None):
    manifest = Path(manifest)
    frozen = manifest.read_bytes()
    document = json.loads(frozen)
    cases = document['cases']
    if len({case['id'] for case in cases}) != len(cases):
        raise ValueError('duplicate case IDs')
    for case in cases:
        if not math.isfinite(float(case['timeout_s'])) or float(case['timeout_s']) <= 0:
            raise ValueError('invalid timeout')
    result = {'schema_version': 1, 'started_at': datetime.now(timezone.utc).isoformat(),
              'manifest_sha256': hashlib.sha256(frozen).hexdigest(), 'selection': 'all_manifest_cases',
              'environment': {'python_version': sys.version.split()[0],
                              'sage_on_path': bool(shutil.which('sage')),
                              'yafu_available': bool(shutil.which('yafu') or (Path.home() / '.local/bin/yafu').is_file()),
                              'solver_sha256': hashlib.sha256(Path(__file__).with_name('ctf_solver.py').read_bytes()).hexdigest()},
              'cases': []}
    for case in cases:
        entry = run_case(case, manifest.parent)
        result['cases'].append(entry)
        result['summary'] = {'total': len(cases), 'completed': len(result['cases']),
                             'status_counts': dict(Counter(x['status'] for x in result['cases']))}
        if output:
            target = Path(output)
            target.parent.mkdir(parents=True, exist_ok=True)
            staging = target.with_suffix(target.suffix + '.tmp')
            staging.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
            staging.replace(target)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument('--output', type=Path, default=Path('docs/public_benchmark_results.json'))
    parser.add_argument('--worker', nargs=2, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        _worker(*args.worker)
        return
    result = run_benchmark(args.manifest, args.output)
    print(json.dumps(result['summary']))


if __name__ == '__main__':
    main()
