"""A small, local-only browser interface for RsaCtfTool."""

import argparse
import base64
import binascii
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

MAX_REQUEST_BYTES = 3 * 1024 * 1024
MAX_UPLOAD_BYTES = 1024 * 1024
MAX_CHALLENGE_CHARS = 1_000_000
MAX_OUTPUT_CHARS = 1_000_000
DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 3600
MAX_PARALLEL_WORKERS = 10
EXTERNAL_ATTACKS = {"factordb", "wolframalpha"}
ATTACKS_REQUIRING_EXTRA_INPUT = {
    "dp_leak",
    "franklin_reiter",
    "partial_p",
    "stereotyped_message",
}
# Multi-key attacks are loaded by the CLI when multiple public keys are
# generated from a comma-separated ``-e`` value.  The web form currently has
# one modulus field, so expose only the common-modulus attack that works with
# that layout; attacks that require unrelated moduli or a different key/cipher
# mapping remain CLI-only until the UI has dedicated key rows.
MULTI_KEY_ATTACKS = {"common_modulus_related_message"}
# Multi-key modules are intentionally kept out of the custom picker until
# the UI grows separate key rows.  ``all`` still loads them through the CLI,
# so the priority analyser knows about these internal names as well.
ALL_MULTI_KEY_ATTACKS = {
    "common_modulus_related_message",
    "common_factors",
    "hastads",
    "same_n_huge_e",
}

# The command line runner historically orders attack instances by their
# coarse ``speed`` value.  That is a useful fallback, but it does not account
# for clues supplied with a challenge (for example a small exponent or a
# leaked dp).  ``recommend_attack_priority`` returns a short, deterministic
# list of attacks that should run before that fallback order.  The list is
# deliberately advisory: unsupported/missing attacks are ignored by the
# runner and all other attacks still run afterwards.
def _integer_hint(value):
    """Parse a form integer for heuristics without changing validation."""
    if value is None or not str(value).strip():
        return None
    try:
        text = str(value).strip()
        return int(text, 0 if text.lower().startswith("0x") else 10)
    except (TypeError, ValueError):
        return None


def recommend_attack_priority(payload, selected=None):
    """Return attack names ordered by clues present in a web request.

    This function only controls execution order.  It never removes an attack
    selected by ``local``/``all`` and it tolerates incomplete form input while
    a user is still editing fields.  ``selected`` may be the concrete attack
    list (for local mode); when omitted, all discovered names are considered.
    """
    if not isinstance(payload, dict):
        return []
    available = set(selected or discover_attacks())
    if selected is None:
        available.update(ALL_MULTI_KEY_ATTACKS)
    ranked = []

    def add(*names):
        for name in names:
            if name in available and name not in ranked:
                ranked.append(name)

    exponents = []
    raw_e = payload.get("e")
    if raw_e is not None:
        for value in str(raw_e).split(","):
            parsed = _integer_hint(value)
            if parsed is not None:
                exponents.append(parsed)
    ciphers = [part.strip() for part in str(payload.get("ciphertext", "")).split(",")
               if part.strip()]

    # Explicit leak/known-message parameters are the strongest clues and are
    # cheap to check before generic factorisation methods.
    if payload.get("dp") or payload.get("dq"):
        add("dp_leak")
    if payload.get("p_high") and payload.get("p_unknown_bits"):
        add("partial_p")
    if payload.get("fr_a") and payload.get("fr_b"):
        add("franklin_reiter")
    if payload.get("sm_len") and (payload.get("sm_prefix") or payload.get("sm_suffix")):
        add("stereotyped_message")

    # Multiple exponents/ciphertexts under one modulus indicate multi-key
    # attacks.  Common modulus is the direct match; small, equal exponents
    # also make Hastad's broadcast attack worth trying.
    if len(exponents) > 1 and len(ciphers) > 1:
        add("common_modulus_related_message")
        if exponents and len(set(exponents)) == 1:
            add("hastads")
        add("common_factors", "same_n_huge_e")

    if exponents:
        small_exponents = [e for e in exponents if 1 < e <= 5]
        if small_exponents:
            add("cube_root")
            if any(e == 3 for e in small_exponents):
                add("hastads")
        if any(e in (3, 5, 7) for e in exponents):
            add("wiener", "boneh_durfee")
        if any(e == 65537 for e in exponents):
            # These are inexpensive checks commonly useful with the standard
            # exponent, while keeping the generic factorisation fallback.
            add("roca", "wiener")

    # Fast structural checks are useful for every modulus and should precede
    # long SIQS/ECM/Sage jobs when no stronger clue was provided.
    add("nonRSA", "fermat", "pollard_p_1", "pollard_rho", "brent", "wiener")
    return ranked

# Human-readable labels shown by the browser picker.  Keep the attack id as
# the option value: it is the stable name understood by the CLI and the
# attack loader.  The Chinese labels are deliberately kept in one place so
# new modules can be added without coupling presentation text to validation.
ATTACK_LABELS = {
    "binary_polynomial_factoring": "二进制多项式分解",
    "boneh_durfee": "Boneh-Durfee 小私钥攻击",
    "brent": "Brent 因子分解",
    "classical_shor": "经典 Shor 算法",
    "comfact_cn": "密文共同因子",
    "compositorial_pm1_gcd": "合数阶乘 p−1 最大公因数",
    "cube_root": "整数立方根（低指数）",
    "dixon": "Dixon 因子分解",
    "dp_leak": "dp 泄漏攻击",
    "ecm": "椭圆曲线因子分解",
    "ecm2": "椭圆曲线因子分解（增强版）",
    "euler": "Euler 因子分解",
    "factor_2PN": "2pN 因子分解",
    "factordb": "FactorDB 在线分解",
    "factorial_pm1_gcd": "阶乘 p−1 最大公因数",
    "fermat_numbers_gcd": "费马数最大公因数",
    "fermat": "费马因子分解",
    "fibonacci_gcd": "斐波那契数最大公因数",
    "franklin_reiter": "Franklin-Reiter 相关消息",
    "hart": "Hart 因子分解",
    "highandlowbitsequal": "p 高低位相等",
    "kraitchik": "Kraitchik 因子分解",
    "lattice": "格攻击",
    "lehman": "Lehman 因子分解",
    "lehmer": "Lehmer 因子分解",
    "londahl": "Londahl 因子分解",
    "lucas_gcd": "Lucas 数最大公因数",
    "mersenne_pm1_gcd": "Mersenne p−1 最大公因数",
    "mersenne_primes": "梅森素数分解",
    "multiple_base_inversion_gcd": "多基逆元最大公因数",
    "neca": "NECA 因子分解",
    "nonRSA": "非标准 RSA 检测",
    "noveltyprimes": "特殊构造素数",
    "partial_d": "部分 d 泄漏",
    "partial_p": "部分 p 泄漏",
    "partial_q": "部分 q 泄漏",
    "pastctfprimes": "历届 CTF 素数",
    "pisano_period": "Pisano 周期",
    "pollard_p_1": "Pollard p−1",
    "pollard_rho": "Pollard rho",
    "pollard_strassen": "Pollard-Strassen",
    "prime_base_collision": "素数基碰撞",
    "primorial_pm1_gcd": "Primorial p−1 最大公因数",
    "qicheng": "Qi Cheng 不安全素数",
    "qs": "二次筛（QS）",
    "quadratic_sieve": "二次筛",
    "rapid7primes": "Rapid7 特殊素数",
    "roca": "ROCA 弱密钥",
    "short_pad": "短填充相关消息",
    "siqs": "自初始化二次筛（SIQS）",
    "small_crt_exp": "小 CRT 指数",
    "smallfraction": "小分数攻击",
    "smallq": "小 q 因子",
    "SQUFOF": "SQUFOF 平方筛",
    "stereotyped_message": "固定格式消息（Coppersmith）",
    "strong_pseudoprime": "强伪素数",
    "system_primes_gcd": "系统素数最大公因数",
    "wiener": "Wiener 小 d",
    "williams_pp1": "Williams p+1",
    "wolframalpha": "WolframAlpha 在线分解",
    "XYXZ": "(X^Y)(X^Z) 结构",
    "z3_solver": "Z3 约束求解",
    "common_factors": "多密钥共同因子",
    "common_modulus_related_message": "RSA 共模相关消息",
    "hastads": "Håstad 广播攻击",
    "same_n_huge_e": "同模数大指数",
}

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "src"


class RequestError(ValueError):
    """An invalid or unsafe request from the browser."""


def discover_attacks():
    attacks_dir = Path(__file__).resolve().parent / "attacks" / "single_key"
    attacks = {
        path.stem
        for path in attacks_dir.glob("*.py")
        if path.name != "__init__.py" and path.stem != "nullattack"
    }
    attacks.update(MULTI_KEY_ATTACKS)
    return sorted(attacks)


def all_attacks():
    """Return every attack accepted by the CLI, including multi-key modules."""
    attacks = set(discover_attacks())
    multi_dir = Path(__file__).resolve().parent / "attacks" / "multi_keys"
    attacks.update(
        path.stem
        for path in multi_dir.glob("*.py")
        if path.name != "__init__.py" and path.stem != "nullattack"
    )
    return sorted(attacks)


def local_attacks(payload=None):
    """Return local attacks, adding parameterized methods when inputs exist.

    With no payload this preserves the original broad list used by the API
    and older callers.  A web request that supplies a dp/p prefix/known
    message clue can safely opt its corresponding local attack back in.
    """
    excluded = EXTERNAL_ATTACKS | ATTACKS_REQUIRING_EXTRA_INPUT
    selected = [attack for attack in discover_attacks() if attack not in excluded]
    if isinstance(payload, dict):
        parameterized = set()
        if payload.get("dp") or payload.get("dq"):
            parameterized.add("dp_leak")
        if payload.get("p_high") and payload.get("p_unknown_bits"):
            parameterized.add("partial_p")
        if payload.get("fr_a") and payload.get("fr_b"):
            parameterized.add("franklin_reiter")
        if payload.get("sm_len") and (
            payload.get("sm_prefix") or payload.get("sm_suffix")
        ):
            parameterized.add("stereotyped_message")
        selected.extend(
            attack for attack in discover_attacks()
            if attack in parameterized and attack not in selected
        )
    return selected


def _upload_bytes(upload, label):
    if upload is None:
        return None
    if not isinstance(upload, dict):
        raise RequestError("上传文件格式无效。")
    encoded = upload.get("data", "")
    if not isinstance(encoded, str) or len(encoded) > ((MAX_UPLOAD_BYTES + 2) // 3) * 4:
        raise RequestError("上传文件超过 1 MiB 限制。")
    try:
        content = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise RequestError("上传文件编码无效。")
    if not content:
        raise RequestError("所选文件为空。")
    if len(content) > MAX_UPLOAD_BYTES:
        raise RequestError("上传文件超过 1 MiB 限制。")
    return content


def _numeric_value(value, label, required=False):
    if value is None or not str(value).strip():
        if required:
            raise RequestError(f"请填写 RSA {label}。")
        return None
    value = str(value).strip()
    if not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", value):
        raise RequestError(f"{label} 请输入十进制整数或 0x 开头的十六进制整数。")
    if value[:2].lower() == "0x":
        value = "0x" + value[2:]
    return value


def _numeric_values(value, label, required=False):
    """Validate one or more comma-separated numeric values.

    The CLI accepts ``-e 17,65537`` and turns it into multiple public keys
    sharing the same modulus.  Keep the browser validation strict while
    preserving the exact comma-separated representation expected by argparse.
    """
    if value is None or not str(value).strip():
        if required:
            raise RequestError(f"请填写 RSA {label}。")
        return None
    parts = [part.strip() for part in str(value).split(",")]
    if any(not part for part in parts):
        raise RequestError(f"{label} 中的每个整数之间请使用英文逗号分隔。")
    normalized = [_numeric_value(part, label, required=True) for part in parts]
    return ",".join(normalized)


def _add_numeric_option(command, payload, field, option, label):
    value = _numeric_value(payload.get(field), label)
    if value is not None:
        if field in ("p_unknown_bits", "sm_len"):
            try:
                parsed_value = int(value)
            except ValueError:
                raise RequestError(f"{label} 必须是十进制整数。")
            if parsed_value < 1:
                raise RequestError(f"{label} 必须大于 0。")
        command.extend([option, value])


def _parallel_workers(payload):
    """Validate the optional browser process count."""
    value = payload.get("parallel_workers", 1) if isinstance(payload, dict) else 1
    try:
        workers = int(value)
    except (TypeError, ValueError):
        raise RequestError("并行攻击数必须是 1 到 10 之间的整数。")
    if not 1 <= workers <= MAX_PARALLEL_WORKERS:
        raise RequestError("并行攻击数必须是 1 到 10 之间的整数。")
    return workers


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _has_plaintext(output):
    """Whether a CLI result contains decoded/decrypted message data."""
    clean = ANSI_ESCAPE_RE.sub("", str(output or ""))
    return bool(
        "Decrypted data :" in clean
        or re.search(r"\butf-8\s*:", clean, re.IGNORECASE)
        or re.search(r"\bHEX\s*:\s*0x[0-9a-f]+", clean, re.IGNORECASE)
    )


def concise_attack_output(output, exit_code=None):
    """Keep the result a user needs and discard noisy CLI progress logs."""
    output = ANSI_ESCAPE_RE.sub("", str(output or ""))
    successes = []
    last_attack = None
    plaintext_attack = None
    plaintexts = []
    hex_values = []
    private_keys = []
    capture_private_key = False
    capture_pem = False
    pem_lines = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        performing = re.search(
            r"Performing\s+(.+?)\s+attack(?:\s+on\s+.+?)?\.?$",
            line,
            re.IGNORECASE,
        )
        if performing:
            last_attack = performing.group(1).strip()

        success = re.search(r"Attack success with (.+?) method", line, re.IGNORECASE)
        if success:
            name = success.group(1).strip()
            if name not in successes:
                successes.append(name)

        if "Private key :" in line:
            capture_private_key = True
            continue
        if capture_private_key:
            if "-----BEGIN " in line:
                capture_pem = True
                pem_lines = [line]
                continue
            if capture_pem:
                pem_lines.append(line)
                if "-----END " in line:
                    private_keys.append("\n".join(pem_lines))
                    capture_pem = False
                    capture_private_key = False
                continue
            # Some private-key renderers print a single-line component rather
            # than PEM.  Avoid collecting arbitrary later status messages.
            if line.startswith(("n:", "e:", "d:", "p:", "q:")):
                private_keys.append(line)
            elif line and not line.startswith("["):
                capture_private_key = False

        utf8_match = re.search(r"\butf-8\s*:\s*(.*)$", line, re.IGNORECASE)
        if utf8_match:
            value = utf8_match.group(1)
            if value and value not in plaintexts:
                plaintexts.append(value)
            if value and plaintext_attack is None:
                plaintext_attack = last_attack

        hex_match = re.search(r"\bHEX\s*:\s*(0x[0-9a-fA-F]+)", line)
        if hex_match and hex_match.group(1) not in hex_values:
            hex_values.append(hex_match.group(1))

    useful = []
    if plaintexts and not successes:
        if plaintext_attack:
            label = ATTACK_LABELS.get(plaintext_attack)
            attack = (
                f"{plaintext_attack}（{label}）" if label else plaintext_attack
            )
            useful.append(f"攻击成功：{attack}（已恢复明文）")
        else:
            useful.append("攻击成功：已恢复明文")
    elif private_keys and not successes:
        useful.append("攻击成功：已恢复私钥")
    useful.extend(f"攻击成功：{name}" for name in successes)
    useful.extend(f"明文：{value}" for value in plaintexts)
    if not plaintexts:
        useful.extend(f"明文（十六进制）：{value}" for value in hex_values)
    useful.extend(f"恢复的私钥：\n{key}" for key in private_keys)
    if useful:
        return "\n\n".join(useful) + "\n"
    if exit_code not in (None, 0):
        return f"未找到可用结果。（退出码 {exit_code}）\n"
    return "未恢复出私钥或明文。\n"


def build_smart_cli_args(payload, challenge_path):
    """Build the shell-free command used by the one-paste challenge analyser."""
    if not isinstance(payload, dict):
        raise RequestError("表单数据无效。")
    challenge_text = payload.get("challenge_text")
    if not isinstance(challenge_text, str) or not challenge_text.strip():
        raise RequestError("请粘贴 RSA 题目文本或源码。")
    if len(challenge_text) > MAX_CHALLENGE_CHARS:
        raise RequestError("题目文本不能超过 1,000,000 个字符。")
    try:
        timeout = int(payload.get("timeout", 120))
    except (TypeError, ValueError):
        raise RequestError("超时必须是整数。")
    if not 1 <= timeout <= MAX_TIMEOUT:
        raise RequestError("超时范围为 1–3600 秒。")
    return [
        sys.executable,
        "-u",
        "-m",
        "RsaCtfTool.ctf_solver",
        "--input",
        str(challenge_path),
        "--timeout",
        str(timeout),
    ]


def build_cli_args(payload, public_key_path=None):
    """Validate browser fields and return a shell-free CLI argument list."""
    if not isinstance(payload, dict):
        raise RequestError("表单数据无效。")

    # The web job runner consumes this value and starts one isolated CLI
    # process per attack.  It is intentionally not passed to the historical
    # CLI, which remains serial and backward compatible.
    _parallel_workers(payload)

    command = [sys.executable, "-m", "RsaCtfTool"]
    mode = payload.get("mode", "recover")
    if mode not in ("recover", "decrypt"):
        raise RequestError("请选择恢复私钥或解密。")

    if public_key_path:
        command.extend(["--publickey", str(public_key_path)])
    else:
        n = _numeric_value(payload.get("n"), "模数 n", required=True)
        e = _numeric_values(payload.get("e"), "公钥指数 e", required=True)
        command.extend(["-n", n, "-e", e])

    try:
        timeout = int(payload.get("timeout", DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        raise RequestError("超时必须是整数。")
    if not 1 <= timeout <= MAX_TIMEOUT:
        raise RequestError("超时范围为 1–3600 秒。")
    command.extend(["--timeout", str(timeout)])

    attack_mode = payload.get("attack_mode", "local")
    if attack_mode == "local":
        selected = local_attacks(payload)
    elif attack_mode == "all":
        selected = ["all"]
    elif attack_mode == "custom":
        selected = payload.get("attacks", [])
        if not isinstance(selected, list) or not selected:
            raise RequestError("请至少选择一种攻击方式。")
        if any(not isinstance(item, str) for item in selected):
            raise RequestError("选择了无效的攻击方式，请刷新页面后重试。")
        if len(selected) != len(set(selected)):
            raise RequestError("攻击方式不能重复选择。")
        allowed = set(discover_attacks())
        if "all" in selected and len(selected) != 1:
            raise RequestError("“全部攻击”不能与其他攻击方式同时选择。")
        if any(item not in allowed | {"all"} for item in selected):
            raise RequestError("选择了无效的攻击方式，请刷新页面后重试。")
    else:
        raise RequestError("攻击方式设置无效。")

    command.extend(["--attack"] + selected)
    # ``all`` is a sentinel, so evaluate recommendations against the full
    # discovered attack set rather than the literal one-item list.
    priority = recommend_attack_priority(
        payload, None if attack_mode == "all" else selected
    )
    if priority:
        command.extend(["--attack-priority", ",".join(priority)])

    if mode == "recover" or payload.get("show_private"):
        command.append("--private")
    if mode == "decrypt":
        ciphertext = payload.get("ciphertext", "")
        if not isinstance(ciphertext, str) or not ciphertext.strip():
            raise RequestError("请输入要解密的密文。")
        if len(ciphertext) > 100_000:
            raise RequestError("密文文本不能超过 100,000 个字符。")
        command.append("--decrypt=" + ciphertext.strip())

    advanced_options = (
        ("fr_a", "--fr-a", "Franklin-Reiter 参数 a"),
        ("fr_b", "--fr-b", "Franklin-Reiter 参数 b"),
        ("p_high", "--p-high", "已知 p 的高位"),
        ("p_unknown_bits", "--p-unknown-bits", "p 的未知低位数"),
        ("dp", "--dp", "泄漏的 dp"),
        ("dq", "--dq", "泄漏的 dq"),
        ("sm_len", "--sm-len", "未知消息长度"),
    )
    for field, option, label in advanced_options:
        _add_numeric_option(command, payload, field, option, label)

    for field, option in (("sm_prefix", "--sm-prefix"), ("sm_suffix", "--sm-suffix")):
        value = payload.get(field)
        if value is not None and str(value):
            if len(str(value)) > 10_000:
                raise RequestError("已知消息前缀或后缀不能超过 10,000 个字符。")
            command.append(option + "=" + str(value))

    command.append("--cleanup")
    return command


def _modulus_bit_length(payload, public_key_path=None):
    """Return the supplied RSA modulus size when it can be read cheaply."""
    value = _integer_hint(payload.get("n")) if isinstance(payload, dict) else None
    if value is not None:
        return value.bit_length()
    if public_key_path:
        try:
            from Crypto.PublicKey import RSA

            return RSA.import_key(Path(public_key_path).read_bytes()).n.bit_length()
        except (ImportError, OSError, ValueError, IndexError, TypeError):
            return None
    return None


def _command_without_attack(command, excluded):
    """Replace the CLI attack selection with its concrete non-excluded names."""
    names = [
        name for name in JobStore._command_attacks(command) if name not in excluded
    ]
    try:
        attack_index = command.index("--attack")
    except ValueError:
        return list(command)
    end = attack_index + 1
    while end < len(command) and not str(command[end]).startswith("--"):
        end += 1
    result = command[:attack_index + 1] + names + command[end:]
    try:
        priority_index = result.index("--attack-priority")
        result[priority_index + 1] = ",".join(
            name
            for name in result[priority_index + 1].split(",")
            if name not in excluded
        )
        if not result[priority_index + 1]:
            del result[priority_index:priority_index + 2]
    except (ValueError, IndexError):
        pass
    return result


class JobStore:
    """Run at most one attack at a time and retain bounded output for polling."""

    def __init__(self):
        self._lock = threading.Lock()
        self._jobs = {}

    def submit(self, payload):
        if not isinstance(payload, dict):
            raise RequestError("表单数据无效。")
        smart_mode = "challenge_text" in payload
        if smart_mode:
            challenge_text = payload.get("challenge_text")
            if payload.get("key_file") or payload.get("n") or payload.get("e"):
                raise RequestError("智能粘贴模式与手动公钥字段不能同时提交。")
            # Full validation is repeated by build_smart_cli_args after the staged path exists.
            if not isinstance(challenge_text, str) or not challenge_text.strip():
                raise RequestError("请粘贴 RSA 题目文本或源码。")
            if len(challenge_text) > MAX_CHALLENGE_CHARS:
                raise RequestError("题目文本不能超过 1,000,000 个字符。")
            upload = None
        else:
            challenge_text = None
            upload = _upload_bytes(payload.get("key_file"), "公钥")
            if upload is not None and (payload.get("n") or payload.get("e")):
                raise RequestError("请只使用公钥文件，或同时填写 n 和 e。")

        with self._lock:
            if any(job["status"] == "running" for job in self._jobs.values()):
                raise RequestError("已有任务正在运行，请等待任务完成后再试。")

        temp_dir = tempfile.mkdtemp(prefix="rsactftool-web-")
        try:
            public_key_path = None
            if smart_mode:
                challenge_path = Path(temp_dir) / "challenge.txt"
                challenge_path.write_text(challenge_text, encoding="utf-8")
                command = build_smart_cli_args(payload, challenge_path)
            else:
                if upload is not None:
                    public_key_path = Path(temp_dir) / "public-key.pem"
                    public_key_path.write_bytes(upload)
                command = build_cli_args(payload, public_key_path)
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

        job_id = uuid.uuid4().hex
        job = {
            "id": job_id,
            "status": "running",
            "output": (
                "正在启动智能分析…\n" if smart_mode else "正在启动 RsaCtfTool…\n"
            ),
            "truncated": False,
            "exit_code": None,
            "started_at": time.time(),
            "finished_at": None,
            "process": None,
            "processes": [],
            "cancel_requested": False,
            "temp_dir": temp_dir,
            "parallel_workers": 1 if smart_mode else _parallel_workers(payload),
            "modulus_bits": (
                None if smart_mode else _modulus_bit_length(payload, public_key_path)
            ),
            "private_requested": False if smart_mode else "--private" in command,
            "smart_mode": smart_mode,
            "timeout": int(payload.get("timeout", 120 if smart_mode else DEFAULT_TIMEOUT)),
            "timed_out": False,
        }
        with self._lock:
            if any(existing["status"] == "running" for existing in self._jobs.values()):
                shutil.rmtree(temp_dir, ignore_errors=True)
                raise RequestError("已有任务正在运行，请等待任务完成后再试。")
            self._prune_finished_jobs()
            self._jobs[job_id] = job

        threading.Thread(
            target=self._run_job,
            args=(job, command),
            name="rsactftool-web-job",
            daemon=True,
        ).start()
        return self.public_view(job)

    def _prune_finished_jobs(self):
        finished = [
            key for key, job in self._jobs.items() if job["status"] != "running"
        ]
        while len(self._jobs) >= 20 and finished:
            del self._jobs[finished.pop(0)]

    @staticmethod
    def _progress_line(line, private_requested=False):
        """Extract one useful live status line from CLI output."""
        clean = ANSI_ESCAPE_RE.sub("", str(line or "")).strip()
        if not clean:
            return None
        if clean.startswith("阶段："):
            return clean
        if private_requested and (
            "Decrypted data :" in clean
            or re.search(r"\butf-8\s*:", clean, re.IGNORECASE)
        ):
            return "已恢复明文；仍在尝试恢复私钥（大模数分解可能很耗时）"
        performing = re.search(
            r"Performing\s+(.+?)\s+attack\.?$", clean, re.IGNORECASE
        )
        if performing:
            attack = performing.group(1).strip()
            label = ATTACK_LABELS.get(attack)
            display_name = f"{attack}（{label}）" if label else attack
            return f"正在尝试攻击：{display_name}"
        success = re.search(
            r"Attack success with (.+?) method", clean, re.IGNORECASE
        )
        if success:
            attack = success.group(1).strip()
            label = ATTACK_LABELS.get(attack)
            display_name = f"{attack}（{label}）" if label else attack
            return f"攻击成功：{display_name}"
        return None

    def _set_live_output(self, job, lines):
        """Publish bounded, de-duplicated progress for browser polling."""
        unique = []
        for line in lines:
            if line and line not in unique:
                unique.append(line)
        text = "\n".join(unique) + ("\n" if unique else "")
        with self._lock:
            if job.get("cancel_requested"):
                return
            job["output"] = text[:MAX_OUTPUT_CHARS]
            job["truncated"] = len(text) > MAX_OUTPUT_CHARS

    def _run_job(self, job, command):
        threading.Thread(
            target=self._watch_job_timeout,
            args=(job,),
            name="rsactftool-web-timeout",
            daemon=True,
        ).start()
        yafu_binary = shutil.which("yafu")
        attack_names = self._command_attacks(command)
        run_yafu_in_background = (
            job.get("private_requested")
            and (job.get("modulus_bits") or 0) >= 512
            and "yafu" in attack_names
            and yafu_binary is not None
        )
        if run_yafu_in_background:
            self._run_with_background_yafu(job, command, yafu_binary)
            return
        if job.get("parallel_workers", 1) > 1:
            self._run_parallel_job(job, command, job["parallel_workers"])
            return

        env = os.environ.copy()
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = str(SOURCE_ROOT) + (
            os.pathsep + existing if existing else ""
        )
        progress_lines = [
            "智能分析正在识别参数、攻击路径与明文编码…"
            if job.get("smart_mode")
            else "已启动 RsaCtfTool，正在尝试攻击…"
        ]
        try:
            process = subprocess.Popen(
                command,
                cwd=str(REPO_ROOT),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                shell=False,
                start_new_session=(os.name != "nt"),
            )
            with self._lock:
                job["process"] = process
                job["started_at"] = time.time()
                cancel_requested = job["cancel_requested"]
            if cancel_requested:
                self._terminate_process(process)
            else:
                self._set_live_output(job, progress_lines)

            raw_output = []
            for line in process.stdout:
                raw_output.append(line)
                progress = self._progress_line(
                    line, private_requested="--private" in command
                )
                if progress and progress not in progress_lines:
                    progress_lines.append(progress)
                    self._set_live_output(job, progress_lines)

            process.wait()
            with self._lock:
                if job["cancel_requested"]:
                    job["exit_code"] = None
                    job["output"] = "用户已停止攻击。\n"
                    job["status"] = "cancelled"
                elif job["timed_out"]:
                    job["exit_code"] = None
                    job["output"] = "任务超过设定时限，已终止。\n"
                    job["status"] = "timeout"
                else:
                    job["exit_code"] = process.returncode
                    complete_output = ANSI_ESCAPE_RE.sub("", "".join(raw_output))
                    if job.get("smart_mode"):
                        job["output"] = complete_output[:MAX_OUTPUT_CHARS]
                        job["truncated"] = len(complete_output) > MAX_OUTPUT_CHARS
                    else:
                        job["output"] = concise_attack_output(
                            complete_output, process.returncode
                        )
                    job["status"] = "finished"
                job["finished_at"] = time.time()
        except Exception as exc:  # noqa: BLE001 - keep workers from getting stuck.
            with self._lock:
                if job["cancel_requested"]:
                    job["status"] = "cancelled"
                    job["output"] = "用户已停止攻击。\n"
                    job["exit_code"] = None
                elif job["timed_out"]:
                    job["status"] = "timeout"
                    job["output"] = "任务超过设定时限，已终止。\n"
                    job["exit_code"] = None
                else:
                    job["status"] = "error"
                    job["output"] = f"启动失败：{exc}\n"
                job["finished_at"] = time.time()
        finally:
            shutil.rmtree(job["temp_dir"], ignore_errors=True)
            with self._lock:
                job["process"] = None

    def _watch_job_timeout(self, job):
        """Enforce wallclock timeout even when a child is silent."""
        while True:
            with self._lock:
                if job["status"] != "running":
                    return
                started_at = job["started_at"]
            if started_at is not None:
                break
            time.sleep(0.01)
        delay = started_at + job["timeout"] - time.time()
        if delay > 0:
            time.sleep(delay)
        with self._lock:
            if job["status"] != "running" or job["cancel_requested"]:
                return
            job["timed_out"] = True
            processes = [job.get("process"), *job.get("processes", [])]
        seen = set()
        for process in processes:
            if process is not None and id(process) not in seen:
                seen.add(id(process))
                self._terminate_process(process)

    def _run_with_background_yafu(self, job, command, yafu_binary):
        """Try YAFU concurrently while the normal attack list keeps running."""
        yafu_command = self._command_for_attack(command, "yafu")
        main_command = _command_without_attack(command, {"yafu"})
        env = os.environ.copy()
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = str(SOURCE_ROOT) + (
            os.pathsep + existing if existing else ""
        )
        # Keep the executable resolvable inside the worker even if its
        # directory was supplied by a launcher-specific PATH setup.
        env["PATH"] = os.path.dirname(yafu_binary) + os.pathsep + env.get("PATH", "")
        progress = [
            "正在后台使用 YAFU 尝试分解大模数，同时继续其他攻击…"
        ]
        process = None
        try:
            try:
                process = subprocess.Popen(
                    yafu_command,
                    cwd=str(REPO_ROOT),
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    shell=False,
                    start_new_session=(os.name != "nt"),
                )
            except OSError:
                self._set_live_output(
                    job, ["YAFU 启动失败，继续尝试其他攻击…"]
                )
                self._run_parallel_job(
                    job,
                    main_command,
                    max(1, job.get("parallel_workers", 1)),
                )
                return
            with self._lock:
                job["process"] = process
                job["processes"] = [process]
                job["started_at"] = time.time()
                cancel_requested = job["cancel_requested"]
            self._set_live_output(job, progress)
            if cancel_requested:
                self._terminate_process(process)
                self._finalize_cancelled(job)
                return

            # The scheduler owns both child processes from here on. Even when
            # the requested batch size is one, YAFU remains concurrent with
            # the next ordinary attack.
            self._run_parallel_job(
                job,
                main_command,
                max(1, job.get("parallel_workers", 1)),
                background_process=process,
                initial_progress=progress,
            )
        except Exception as exc:  # noqa: BLE001
            if process is not None:
                self._terminate_process(process)
            with self._lock:
                if job["cancel_requested"]:
                    job["status"] = "cancelled"
                    job["output"] = "用户已停止攻击。\n"
                    job["exit_code"] = None
                elif job["timed_out"]:
                    job["status"] = "timeout"
                    job["output"] = "任务超过设定时限，已终止。\n"
                    job["exit_code"] = None
                else:
                    job["status"] = "error"
                    job["output"] = f"启动失败：{exc}\n"
                job["finished_at"] = time.time()
        finally:
            shutil.rmtree(job["temp_dir"], ignore_errors=True)
            with self._lock:
                job["process"] = None
                job["processes"] = []

    def _finalize_cancelled(self, job):
        with self._lock:
            job["status"] = "cancelled"
            job["output"] = "用户已停止攻击。\n"
            job["exit_code"] = None
            job["finished_at"] = time.time()

    @staticmethod
    def _command_attacks(command):
        """Expand a CLI command into one command per attack name."""
        try:
            attack_index = command.index("--attack")
        except ValueError:
            return []
        end = attack_index + 1
        while end < len(command) and not str(command[end]).startswith("--"):
            end += 1
        names = command[attack_index + 1 : end]
        if names == ["all"]:
            names = all_attacks()
        else:
            names = [name for name in names if name != "all"]
        try:
            priority_index = command.index("--attack-priority")
            priority = [
                name for name in command[priority_index + 1].split(",") if name
            ]
        except (ValueError, IndexError):
            priority = []
        if priority:
            rank = {name: index for index, name in enumerate(priority)}
            names.sort(key=lambda name: rank.get(name, len(rank)))
        return names

    @staticmethod
    def _command_for_attack(command, attack):
        attack_index = command.index("--attack")
        end = attack_index + 1
        while end < len(command) and not str(command[end]).startswith("--"):
            end += 1
        result = command[: attack_index + 1] + [attack] + command[end:]
        # A priority list referring to the original batch is not useful in a
        # one-attack child process.  Keep the option for logging/compatibility
        # but constrain it to this child.
        try:
            priority_index = result.index("--attack-priority")
            result[priority_index + 1] = attack
        except (ValueError, IndexError):
            pass
        return result

    @staticmethod
    def _terminate_process(process):
        if process is None:
            return
        try:
            if os.name == "nt":
                if process.poll() is not None:
                    return
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                try:
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    process.kill()
            else:
                # Every POSIX child is launched with start_new_session=True,
                # so its PID is also the process-group ID. Signal that group
                # even if the Python parent has already exited: YAFU/Sage
                # descendants may still be running in it.
                process_group = getattr(process, "pid", None)
                if process_group is not None:
                    try:
                        os.killpg(process_group, signal.SIGTERM)
                    except OSError:
                        process_group = None
                if process_group is None and process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=1.5)
                except (OSError, subprocess.TimeoutExpired):
                    if process_group is None:
                        process.kill()
                if process_group is not None:
                    try:
                        os.killpg(process_group, 0)
                    except OSError:
                        pass
                    else:
                        try:
                            os.killpg(process_group, signal.SIGKILL)
                        except OSError:
                            pass
                if process.poll() is None:
                    process.kill()
                try:
                    process.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        except (OSError, subprocess.SubprocessError):
            try:
                process.kill()
            except OSError:
                pass

    @staticmethod
    def _output_is_success(output, private_requested=False):
        lowered = output.lower()
        if private_requested:
            # Several attacks only recover plaintext and still print an
            # attack marker. Keep searching until an actual key is emitted.
            return "private key :" in lowered
        return (
            "attack success with" in lowered
            or "decrypted data :" in lowered
            or "utf-8 :" in lowered
        )

    def _run_parallel_job(
        self, job, command, workers, background_process=None, initial_progress=None
    ):
        """Run attacks in bounded batches of isolated CLI processes.

        Each child has its own key/attack state.  The first child that emits a
        normal RsaCtfTool success marker wins; remaining children in that
        batch are terminated, including their Sage/YAFU descendants.
        """
        attack_names = self._command_attacks(command)
        if len(attack_names) <= 1 and background_process is None:
            # A single selected attack gains nothing from process fan-out.
            with self._lock:
                job["parallel_workers"] = 1
            self._run_job(job, command)
            return

        env = os.environ.copy()
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = str(SOURCE_ROOT) + (
            os.pathsep + existing if existing else ""
        )
        successful = False
        cancelled = False
        last_exit = 1
        private_requested = "--private" in command
        plaintext_outputs = []
        background_pending = background_process is not None
        result_queue = queue.Queue()

        if background_process is not None:
            def collect_background(child=background_process):
                try:
                    output, _ = child.communicate()
                    result_queue.put(("__yafu__", child.returncode, output or ""))
                except Exception as exc:  # pragma: no cover - defensive
                    result_queue.put(("__yafu__", 1, f"\nYAFU 读取失败：{exc}\n"))

            threading.Thread(
                target=collect_background,
                name="rsactftool-web-reader-yafu",
                daemon=True,
            ).start()
        try:
            with self._lock:
                job["started_at"] = time.time()
                job["process"] = background_process
                job["processes"] = [background_process] if background_process else []
            start_lines = list(initial_progress or [])
            start_lines.append(f"已启动并行攻击（每批 {workers} 个进程），正在准备任务…")
            self._set_live_output(job, start_lines)
            for batch_start in range(0, len(attack_names), workers):
                with self._lock:
                    if job["cancel_requested"]:
                        cancelled = True
                        break
                batch = attack_names[batch_start : batch_start + workers]
                batch_status = [
                    f"正在尝试攻击：{name}（{ATTACK_LABELS.get(name, name)}）"
                    for name in batch
                ]
                batch_progress = [
                    *(initial_progress or []),
                    f"并行攻击中（每批 {workers} 个进程）",
                    *batch_status,
                ]
                if plaintext_outputs:
                    batch_progress.extend([
                        "明文已恢复；私钥仍在尝试。",
                        *plaintext_outputs,
                    ])
                self._set_live_output(
                    job, batch_progress
                )
                processes = []
                for attack in batch:
                    with self._lock:
                        if job["cancel_requested"]:
                            cancelled = True
                            break
                    child_command = self._command_for_attack(command, attack)
                    process = subprocess.Popen(
                        child_command,
                        cwd=str(REPO_ROOT),
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        bufsize=1,
                        shell=False,
                        start_new_session=(os.name != "nt"),
                    )
                    processes.append((attack, process))
                    with self._lock:
                        tracked = [child for _, child in processes]
                        if background_process is not None:
                            tracked.insert(0, background_process)
                        job["processes"] = tracked
                        job["process"] = (
                            processes[0][1] if processes else background_process
                        )
                        cancel_after_start = job["cancel_requested"]

                    def collect(name=attack, child=process):
                        try:
                            output, _ = child.communicate()
                            result_queue.put((name, child.returncode, output or ""))
                        except Exception as exc:  # pragma: no cover - defensive
                            result_queue.put((name, 1, f"\n子任务读取失败：{exc}\n"))

                    threading.Thread(
                        target=collect,
                        name=f"rsactftool-web-reader-{attack}",
                        daemon=True,
                    ).start()
                    if cancel_after_start:
                        cancelled = True
                        self._terminate_process(process)
                        break

                remaining = len(processes)
                while remaining or background_pending:
                    if not remaining and not background_pending:
                        break
                    with self._lock:
                        cancel_requested = job["cancel_requested"]
                    if cancel_requested and not cancelled:
                        cancelled = True
                        for _, process in processes:
                            self._terminate_process(process)
                        if background_pending:
                            self._terminate_process(background_process)
                    if not remaining and background_pending:
                        # All attacks in this batch finished. Continue to the
                        # next batch while YAFU remains active; only wait for
                        # YAFU after the regular attack list is exhausted.
                        break
                    try:
                        attack, exit_code, output = result_queue.get(timeout=0.1)
                    except queue.Empty:
                        if time.time() >= job["started_at"] + job["timeout"]:
                            with self._lock:
                                job["timed_out"] = True
                            for _, child in processes:
                                self._terminate_process(child)
                            if background_pending:
                                self._terminate_process(background_process)
                            cancelled = True
                        continue
                    is_background_result = attack == "__yafu__"
                    if is_background_result:
                        background_pending = False
                        attack = "yafu"
                    else:
                        remaining -= 1
                    if exit_code is not None:
                        last_exit = exit_code
                    if self._output_is_success(output, private_requested):
                        successful = True
                        clean_output = concise_attack_output(output, exit_code)
                        if plaintext_outputs:
                            combined = []
                            for value in [*plaintext_outputs, clean_output]:
                                if value and value not in combined:
                                    combined.append(value)
                            clean_output = "\n".join(
                                value.rstrip() for value in combined
                            ) + "\n"
                        with self._lock:
                            job["output"] = clean_output[:MAX_OUTPUT_CHARS]
                            job["truncated"] = len(clean_output) > MAX_OUTPUT_CHARS
                        for other_attack, other_process in processes:
                            if other_attack != attack:
                                self._terminate_process(other_process)
                        if background_pending and attack != "yafu":
                            self._terminate_process(background_process)
                        # Stop any still-running process trees before leaving
                        # the batch. Collector threads are daemons, so a child
                        # that ignores SIGTERM cannot wedge job finalization.
                        for other_attack, other_process in processes:
                            if other_attack != attack:
                                try:
                                    other_process.wait(timeout=2)
                                except (OSError, subprocess.TimeoutExpired):
                                    self._terminate_process(other_process)
                        break
                    if private_requested and _has_plaintext(output):
                        plaintext_result = concise_attack_output(output, exit_code)
                        if plaintext_result not in plaintext_outputs:
                            plaintext_outputs.append(plaintext_result)
                    live_lines = [
                        *(initial_progress or []),
                        f"并行攻击中（每批 {workers} 个进程）",
                        *batch_status,
                    ]
                    if plaintext_outputs:
                        live_lines.extend([
                            "明文已恢复；私钥仍在尝试。",
                            *plaintext_outputs,
                        ])
                    elif attack != "yafu":
                        live_lines.append(f"已完成攻击：{attack}（未找到结果）")
                    self._set_live_output(job, live_lines)
                with self._lock:
                    job["processes"] = (
                        [background_process] if background_pending else []
                    )
                    job["process"] = background_process if background_pending else None
                if successful or cancelled:
                    break
            if not successful and not cancelled and background_pending:
                # Ordinary attacks have all finished. Keep the job cancellable
                # while the background factorization continues.
                waiting_lines = [
                    *(initial_progress or []),
                    "其他攻击已完成，YAFU 仍在后台尝试分解大模数…",
                ]
                if plaintext_outputs:
                    waiting_lines.extend([
                        "明文已恢复；私钥仍在尝试。",
                        *plaintext_outputs,
                    ])
                self._set_live_output(
                    job, waiting_lines
                )
                while background_pending:
                    with self._lock:
                        cancel_requested = job["cancel_requested"]
                    if cancel_requested:
                        cancelled = True
                        self._terminate_process(background_process)
                    try:
                        attack, exit_code, output = result_queue.get(timeout=0.1)
                    except queue.Empty:
                        if time.time() >= job["started_at"] + job["timeout"]:
                            with self._lock:
                                job["timed_out"] = True
                            self._terminate_process(background_process)
                            cancelled = True
                        continue
                    background_pending = False
                    if exit_code is not None:
                        last_exit = exit_code
                    if self._output_is_success(output, private_requested):
                        successful = True
                        clean_output = concise_attack_output(output, exit_code)
                        combined = []
                        for value in [*plaintext_outputs, clean_output]:
                            if value and value not in combined:
                                combined.append(value)
                        with self._lock:
                            job["output"] = "\n".join(
                                value.rstrip() for value in combined
                            ) + "\n"
                            job["output"] = job["output"][:MAX_OUTPUT_CHARS]
                            job["truncated"] = len(job["output"]) > MAX_OUTPUT_CHARS
            with self._lock:
                if job["cancel_requested"]:
                    job["output"] = "用户已停止攻击。\n"
                    job["exit_code"] = None
                    job["status"] = "cancelled"
                elif job["timed_out"]:
                    job["output"] = "任务超过设定时限，已终止。\n"
                    job["exit_code"] = None
                    job["status"] = "timeout"
                elif not successful:
                    job["output"] = (
                        "\n".join(value.rstrip() for value in plaintext_outputs) + "\n"
                        if plaintext_outputs
                        else "未恢复出私钥或明文。\n"
                    )
                    job["exit_code"] = last_exit
                    job["status"] = "finished"
                else:
                    job["exit_code"] = 0
                    job["status"] = "finished"
                job["finished_at"] = time.time()
        except Exception as exc:  # noqa: BLE001
            for _, process in locals().get("processes", []):
                self._terminate_process(process)
            if background_process is not None:
                self._terminate_process(background_process)
            with self._lock:
                if job["cancel_requested"]:
                    job["status"] = "cancelled"
                    job["output"] = "用户已停止攻击。\n"
                    job["exit_code"] = None
                else:
                    job["status"] = "error"
                    job["output"] = f"启动失败：{exc}\n"
                job["finished_at"] = time.time()
        finally:
            with self._lock:
                job["processes"] = []
                job["process"] = None
            shutil.rmtree(job["temp_dir"], ignore_errors=True)

    def get(self, job_id):
        with self._lock:
            job = self._jobs.get(job_id)
            return self.public_view(job) if job else None

    def cancel(self, job_id):
        """Request cancellation and terminate all active attack processes."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            if job["status"] != "running":
                return self.public_view(job)
            job["cancel_requested"] = True
            job["output"] = "正在停止攻击…\n"
            processes = [job.get("process"), *job.get("processes", [])]

        seen = set()
        for process in processes:
            if process is not None and id(process) not in seen:
                seen.add(id(process))
                self._terminate_process(process)
        return self.get(job_id)

    @staticmethod
    def public_view(job):
        return {
            key: job[key]
            for key in (
                "id",
                "status",
                "output",
                "truncated",
                "exit_code",
                "started_at",
                "finished_at",
                "cancel_requested",
            )
        }

    def shutdown(self):
        with self._lock:
            processes = []
            for job in self._jobs.values():
                if job.get("process"):
                    processes.append(job["process"])
                processes.extend(job.get("processes", []))
        for process in processes:
            self._terminate_process(process)


def create_handler(job_store):
    class Handler(BaseHTTPRequestHandler):
        server_version = "RsaCtfToolWeb/1.0"

        def _local_host(self):
            try:
                hostname = urlsplit("//" + self.headers.get("Host", "")).hostname
            except ValueError:
                return False
            return hostname in ("127.0.0.1", "localhost", "::1")

        def _send(self, status, content, content_type):
            data = content if isinstance(content, bytes) else content.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline'; connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'none'",
            )
            self.end_headers()
            self.wfile.write(data)

        def _json(self, status, value):
            self._send(
                status,
                json.dumps(value, ensure_ascii=False),
                "application/json; charset=utf-8",
            )

        def do_GET(self):
            if not self._local_host():
                self._json(403, {"error": "仅接受本机浏览器连接。"})
                return
            path = urlsplit(self.path).path
            if path == "/":
                try:
                    html = (Path(__file__).with_name("web_ui.html")).read_text(
                        encoding="utf-8"
                    )
                except OSError:
                    self._json(500, {"error": "界面文件无法读取。"})
                    return
                self._send(200, html, "text/html; charset=utf-8")
            elif path == "/favicon.ico":
                self._send(204, b"", "image/x-icon")
            elif path == "/api/attacks":
                self._json(
                    200,
                    {
                        "attacks": discover_attacks(),
                        "local_attacks": local_attacks(),
                        "external_attacks": sorted(EXTERNAL_ATTACKS),
                        # Return labels separately so the browser can keep
                        # submitting the canonical English attack ids.
                        "attack_labels": {
                            attack: ATTACK_LABELS.get(attack, attack)
                            for attack in discover_attacks()
                        },
                    },
                )
            elif path.startswith("/api/jobs/"):
                job_id = path.rsplit("/", 1)[-1]
                job = job_store.get(job_id)
                if job is None:
                    self._json(404, {"error": "找不到此任务。"})
                else:
                    self._json(200, job)
            else:
                self._json(404, {"error": "页面不存在。"})

        def do_POST(self):
            if not self._local_host():
                self._json(403, {"error": "仅接受本机浏览器连接。"})
                return
            path = urlsplit(self.path).path
            cancel_match = re.fullmatch(r"/api/jobs/([a-f0-9]+)/cancel", path)
            if cancel_match:
                job = job_store.cancel(cancel_match.group(1))
                if job is None:
                    self._json(404, {"error": "找不到此任务。"})
                else:
                    self._json(200, job)
                return
            if path != "/api/run":
                self._json(404, {"error": "接口不存在。"})
                return
            if self.headers.get_content_type() != "application/json":
                self._json(415, {"error": "请求格式必须为 JSON。"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._json(400, {"error": "请求长度无效。"})
                return
            if length <= 0 or length > MAX_REQUEST_BYTES:
                self._json(413, {"error": "表单总大小不能超过 3 MiB。"})
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                job = job_store.submit(payload)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._json(400, {"error": "表单数据无法解析。"})
                return
            except RequestError as exc:
                self._json(400, {"error": str(exc)})
                return
            self._json(202, job)

        def log_message(self, fmt, *args):
            # Keep key and ciphertext values out of the terminal log.
            return

    return Handler


class LocalThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(
        description="Start the local RsaCtfTool browser interface"
    )
    parser.add_argument(
        "--port", type=int, default=8765, help="local port (0 chooses a free port)"
    )
    parser.add_argument(
        "--no-browser", action="store_true", help="do not open a browser automatically"
    )
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")

    jobs = JobStore()
    server = LocalThreadingHTTPServer(("127.0.0.1", args.port), create_handler(jobs))
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"RsaCtfTool web interface: {url}", flush=True)
    print(
        "The server listens on this computer only. Press Ctrl+C to stop it.", flush=True
    )
    if not args.no_browser:
        webbrowser.open(url, new=2)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping the local web interface.", flush=True)
    finally:
        jobs.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
