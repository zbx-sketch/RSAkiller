"""One-paste RSA CTF analyser used by the local browser workbench.

The parser deliberately accepts only integer literals and simple public-key tuples.  Challenge
text is untrusted: it is never passed to ``eval``/``exec`` and no embedded Python is run.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import math
import re
import shutil
import string
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

MAX_CHALLENGE_CHARS = 1_000_000
MAX_REPORT_INTEGER_DIGITS = 20_000

_NUMBER_LITERAL = r"(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|[0-9][0-9_]*)[lL]?"
_ASSIGNMENT_RE = re.compile(
    rf"(?m)^[ \t]*([A-Za-z][A-Za-z0-9_]*)[ \t]*=[ \t]*(?:\"([^\"\r\n]+)\"|'([^'\r\n]+)'|({_NUMBER_LITERAL}))[ \t]*(?:\#[^\r\n]*)?$"
)
_TUPLE_RE = re.compile(
    rf"(?m)^[ \t]*[{{(][ \t]*({_NUMBER_LITERAL})[ \t]*,[ \t]*({_NUMBER_LITERAL})[ \t]*[}})][ \t]*$"
)
_STANDALONE_RE = re.compile(rf"(?m)^[ \t]*({_NUMBER_LITERAL})[ \t]*$")
_COLON_VALUE_RE = re.compile(
    rf"(?im)^[ \t]*(n|e|c|ct|encrypted[ \t]+flag|encrypted[ \t]+message|ciphertext|cipher|"
    rf"modulus|public[ \t]+exponent|private[ \t]+exponent)[ \t]*:[ \t]*({_NUMBER_LITERAL})[ \t]*$"
)
_PRIVATE_KEY_TUPLE_RE = re.compile(
    rf"(?im)^[ \t]*my[ \t]+private[ \t]+key[ \t]*:[ \t]*\([ \t]*({_NUMBER_LITERAL})[ \t]*,[ \t]*"
    rf"({_NUMBER_LITERAL})[ \t]*\)[ \t]*$"
)
_PUBLIC_PEM_RE = re.compile(
    r"-----BEGIN (?:RSA )?PUBLIC KEY-----[\s\S]+?-----END (?:RSA )?PUBLIC KEY-----"
)
_BARE_HEX_RE = re.compile(r"(?m)^\s*([0-9a-fA-F]{32,})\s*$")
_FLAG_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_]{0,20}\{[^\r\n{}]{1,300}\}")


class SolveTimeout(RuntimeError):
    """The bounded smart-analysis budget was exhausted."""


@dataclass(frozen=True)
class NumberToken:
    name: str
    raw: str
    value: int
    position: int
    quoted: bool = False
    synthetic: bool = False

    @property
    def plain_digits(self) -> str | None:
        value = self.raw.strip().replace("_", "")
        if value.endswith(("L", "l")):
            value = value[:-1]
        return value if value.isdigit() else None

    def value_for_radix(self, radix: int | None) -> int:
        digits = self.plain_digits
        if (
            radix is not None
            and digits is not None
            and len(digits) >= 64
            and self.name.lower().startswith(("n", "c", "message", "cipher"))
            and all(int(ch) < radix for ch in digits)
        ):
            return int(digits, radix)
        return self.value


@dataclass
class ParsedChallenge:
    text: str
    tokens: list[NumberToken]
    standalone: list[int]
    tuple_count: int
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class KeyRecord:
    n: int
    e: int | None
    c: int | None
    label: str


@dataclass
class Material:
    records: list[KeyRecord]
    n_values: list[int]
    e_values: list[int]
    c_values: list[int]
    scalars: dict[str, int]
    radix: int | None = None


@dataclass
class Candidate:
    label: str
    text: str


@dataclass
class Solution:
    attack: str
    plaintext_ints: list[int]
    evidence: list[str]
    verification: list[str]
    plaintext_chunks: list[bytes] = field(default_factory=list)
    factors: tuple[int, ...] | None = None
    private_exponent: int | None = None
    candidates: list[Candidate] = field(default_factory=list)


@dataclass
class SolveReport:
    parsed: ParsedChallenge
    solutions: list[Solution]
    attempted: list[str]
    warnings: list[str]
    elapsed: float

    @property
    def solved(self) -> bool:
        return bool(self.solutions)


class Deadline:
    def __init__(self, seconds: float):
        self.end = time.monotonic() + max(1.0, float(seconds))

    def remaining(self) -> float:
        return max(0.0, self.end - time.monotonic())

    def check(self) -> None:
        if self.remaining() <= 0:
            raise SolveTimeout("智能分析达到时间上限")


def _parse_integer(raw: str) -> int:
    value = raw.strip().replace("_", "")
    if value.endswith(("L", "l")):
        value = value[:-1]
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        return int(value, 16)
    if re.fullmatch(r"0[bB][01]+", value):
        return int(value, 2)
    if re.fullmatch(r"0[oO][0-7]+", value):
        return int(value, 8)
    if value.isdigit():
        return int(value, 10)
    raise ValueError("not a supported integer literal")


def parse_challenge(text: str) -> ParsedChallenge:
    if not isinstance(text, str):
        raise TypeError("challenge text must be a string")
    if len(text) > MAX_CHALLENGE_CHARS:
        raise ValueError("题目文本不能超过 1,000,000 个字符")
    # Normalize copied CRLF/CR challenge text before line-anchored parsing.  Without this,
    # a Windows paste leaves a trailing ``\\r`` before ``$`` and every literal assignment
    # is silently missed by the worker process (which reads bytes rather than text mode).
    # This changes no numeric evidence and keeps the parser platform-independent.
    clean = (
        text.replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\u200b", "")
        .replace("\ufeff", "")
        .replace("\u2060", "")
    )
    tokens: list[NumberToken] = []
    occupied: list[tuple[int, int]] = []
    rejected_assignments: list[str] = []
    for line in clean.splitlines():
        if re.match(r"^[ \t]*[A-Za-z][A-Za-z0-9_]*[ \t]*=", line) and not _ASSIGNMENT_RE.fullmatch(line):
            rejected_assignments.append(line.strip().split("=", 1)[0].strip())
    for match in _ASSIGNMENT_RE.finditer(clean):
        raw = next(group for group in match.groups()[1:] if group is not None)
        try:
            value = _parse_integer(raw)
        except ValueError:
            continue
        quoted = match.group(2) is not None or match.group(3) is not None
        tokens.append(
            NumberToken(match.group(1), raw, value, match.start(), quoted=quoted)
        )
        occupied.append(match.span())

    # A few CTF generators print human-readable labels instead of Python assignments.
    # Only a fixed allow-list is accepted so arbitrary prose cannot become parameters.
    colon_names = {
        "n": "n",
        "e": "e",
        "c": "c",
        "ct": "c",
        "encryptedflag": "c",
        "encryptedmessage": "c",
        "ciphertext": "c",
        "cipher": "c",
        "modulus": "n",
        "publicexponent": "e",
        "privateexponent": "d",
    }
    for match in _COLON_VALUE_RE.finditer(clean):
        if any(start <= match.start() < end for start, end in occupied):
            continue
        raw = match.group(2)
        try:
            value = _parse_integer(raw)
        except ValueError:
            continue
        canonical = colon_names[re.sub(r"\s+", "", match.group(1).lower())]
        tokens.append(NumberToken(canonical, raw, value, match.start(), synthetic=True))
        occupied.append(match.span())

    # Crypto challenges commonly label a tuple as ``My private key: (n, d)``.
    # This is parsed as data only; embedded source remains unexecuted.
    for match in _PRIVATE_KEY_TUPLE_RE.finditer(clean):
        if any(start <= match.start() < end for start, end in occupied):
            continue
        try:
            n_value = _parse_integer(match.group(1))
            d_value = _parse_integer(match.group(2))
        except ValueError:
            continue
        tokens.append(
            NumberToken("n", match.group(1), n_value, match.start(), synthetic=True)
        )
        tokens.append(
            NumberToken("d", match.group(2), d_value, match.start() + 1, synthetic=True)
        )
        occupied.append(match.span())

    pem_count = 0
    for match in _PUBLIC_PEM_RE.finditer(clean):
        try:
            from Crypto.PublicKey import RSA

            key = RSA.import_key(match.group(0).encode("ascii"))
        except (ImportError, ValueError, IndexError):
            continue
        pem_count += 1
        suffix = str(pem_count) if pem_count > 1 else ""
        tokens.append(
            NumberToken(f"n{suffix}", str(int(key.n)), int(key.n), match.start(), synthetic=True)
        )
        tokens.append(
            NumberToken(f"e{suffix}", str(int(key.e)), int(key.e), match.start() + 1, synthetic=True)
        )
        occupied.append(match.span())

    # A raw hexadecimal ciphertext commonly accompanies a pasted PEM key.  Requiring
    # either a PEM block or an explicit ciphertext clue avoids treating arbitrary hashes
    # in prose as RSA data.
    if pem_count or re.search(r"\bcipher(?:text)?\b", clean, re.IGNORECASE):
        hex_index = 0
        for match in _BARE_HEX_RE.finditer(clean):
            if any(start <= match.start() < end for start, end in occupied):
                continue
            raw_hex = match.group(1)
            # Decimal dump lines (notably LCG state transcripts) also satisfy the
            # hexadecimal character class.  Keep them available to standalone parsing;
            # true hex ciphertexts normally contain a-f or are explicitly prefixed.
            if raw_hex.isdigit():
                continue
            if len(raw_hex) % 2:
                continue
            hex_index += 1
            suffix = str(hex_index) if hex_index > 1 else ""
            tokens.append(
                NumberToken(
                    f"c{suffix}",
                    "0x" + raw_hex,
                    int(raw_hex, 16),
                    match.start(),
                    synthetic=True,
                )
            )
            occupied.append(match.span())

    tuple_count = 0
    for match in _TUPLE_RE.finditer(clean):
        try:
            left, right = _parse_integer(match.group(1)), _parse_integer(match.group(2))
        except ValueError:
            continue
        # Public keys commonly appear as {n,e}.  Requiring a clear size difference avoids
        # treating arbitrary coordinate pairs as RSA material.
        large, small = (left, right) if left > right else (right, left)
        if large.bit_length() < 2 * max(2, small.bit_length()):
            continue
        tuple_count += 1
        pos = match.start()
        tokens.append(
            NumberToken(f"n{tuple_count}", str(large), large, pos, synthetic=True)
        )
        tokens.append(
            NumberToken(f"e{tuple_count}", str(small), small, pos + 1, synthetic=True)
        )
        occupied.append(match.span())

    standalone: list[int] = []
    for match in _STANDALONE_RE.finditer(clean):
        if any(start <= match.start() < end for start, end in occupied):
            continue
        try:
            standalone.append(_parse_integer(match.group(1)))
        except ValueError:
            pass

    tokens.sort(key=lambda token: token.position)
    warnings: list[str] = []
    if rejected_assignments:
        # Source generators often contain an arithmetic assignment followed later by the
        # printed literal (e.g. ``n = p*q`` then ``print(f'n = {n}')``).  Keep the strict
        # rejection for names with no usable literal, but do not make a valid pasted output
        # look broken merely because its generator source was included above it.
        accepted_names = {token.name.lower() for token in tokens if not token.synthetic}
        names = ", ".join(
            dict.fromkeys(
                name for name in rejected_assignments if name.lower() not in accepted_names
            )
        )
        if names:
            warnings.append(f"拒绝解析非字面量赋值：{names}。请粘贴计算后的整数参数。")
    if not tokens and not standalone:
        warnings.append("没有识别到受支持的整数参数。")
    return ParsedChallenge(clean, tokens, standalone, tuple_count, warnings)


def _root_tokens(parsed: ParsedChallenge, roots: Iterable[str]) -> list[NumberToken]:
    roots = tuple(root.lower() for root in roots)
    result = []
    for token in parsed.tokens:
        name = token.name.lower()
        if any(re.fullmatch(re.escape(root) + r"\d*", name) for root in roots):
            result.append(token)
    return result


def _suffix(name: str, roots: Iterable[str]) -> str | None:
    lowered = name.lower()
    for root in roots:
        match = re.fullmatch(re.escape(root.lower()) + r"(\d*)", lowered)
        if match:
            return match.group(1)
    return None


def _radix_candidates(parsed: ParsedChallenge) -> list[int | None]:
    relevant = [
        token
        for token in parsed.tokens
        if _suffix(token.name, ("n", "c", "message", "cipher", "ciphertext"))
        is not None
        and token.plain_digits is not None
        and len(token.plain_digits or "") >= 80
    ]
    variants: list[int | None] = [None]
    if len(relevant) < 4:
        return variants
    highest = max(int(ch) for token in relevant for ch in (token.plain_digits or ""))
    # Long strings that use a visibly restricted alphabet are often non-decimal CTF data.
    if highest <= 7:
        variants.extend(range(max(2, highest + 1), 10))
    return variants


def _most_common(values: list[int]) -> int | None:
    if not values:
        return None
    counts = Counter(values)
    best_count = max(counts.values())
    return next(value for value in values if counts[value] == best_count)


def _largest_integer(values: list[int]) -> int | None:
    """Prefer the complete RSA-sized value over truncated examples in write-ups."""
    return max(values, key=lambda value: (value.bit_length(), value), default=None)


def extract_material(parsed: ParsedChallenge, radix: int | None = None) -> Material:
    n_tokens = _root_tokens(parsed, ("n", "modulus"))
    e_tokens = _root_tokens(parsed, ("e",))
    c_tokens = _root_tokens(parsed, ("c", "ct", "cipher", "ciphertext", "message"))
    if not c_tokens:
        # Some challenges intentionally reverse the conventional names and publish m1/m2 as
        # ciphertext.  Only use this fallback when no conventional c token exists.
        c_tokens = _root_tokens(parsed, ("m",))
        c_tokens = [
            token for token in c_tokens if re.fullmatch(r"m\d+", token.name.lower())
        ]

    n_values = [token.value_for_radix(radix) for token in n_tokens]
    e_values = [token.value for token in e_tokens]
    c_values = [token.value_for_radix(radix) for token in c_tokens]

    if not c_values and parsed.standalone and n_values and e_values:
        common_n = _largest_integer(n_values)
        c_values = [
            value for value in parsed.standalone if common_n and 0 <= value < common_n
        ]

    scalar_names = ("p", "q", "d", "dp", "dq", "phi", "x", "p_plus_q")
    scalars: dict[str, int] = {}
    for name in scalar_names:
        values = [token.value for token in parsed.tokens if token.name.lower() == name]
        selected = _most_common(values)
        if selected is not None:
            scalars[name] = selected

    n_by_suffix: dict[str, list[int]] = {}
    e_by_suffix: dict[str, list[int]] = {}
    c_by_suffix: dict[str, list[int]] = {}
    for token in n_tokens:
        suffix = _suffix(token.name, ("n", "modulus"))
        n_by_suffix.setdefault(suffix or "", []).append(token.value_for_radix(radix))
    for token in e_tokens:
        suffix = _suffix(token.name, ("e",))
        e_by_suffix.setdefault(suffix or "", []).append(token.value)
    for token in c_tokens:
        suffix = _suffix(
            token.name, ("c", "ct", "cipher", "ciphertext", "message", "m")
        )
        c_by_suffix.setdefault(suffix or "", []).append(token.value_for_radix(radix))

    records: list[KeyRecord] = []
    indexed_suffixes = sorted(
        {key for key in n_by_suffix | e_by_suffix | c_by_suffix if key},
        key=lambda item: int(item),
    )
    global_n = _largest_integer(n_by_suffix.get("", []))
    global_e = _most_common(e_by_suffix.get("", []))
    global_c = c_by_suffix.get("", [])

    for suffix in indexed_suffixes:
        ns = n_by_suffix.get(suffix) or ([global_n] if global_n is not None else [])
        es = e_by_suffix.get(suffix) or ([global_e] if global_e is not None else [])
        cs = c_by_suffix.get(suffix) or []
        if ns:
            records.append(
                KeyRecord(
                    _largest_integer(ns),
                    _most_common(es) if es else None,
                    _largest_integer(cs) if cs else None,
                    suffix,
                )
            )

    # Keep an explicitly unnumbered n/e/c record even when auxiliary indexed keys are
    # present (for example, one private key plus a list of friends' public keys).
    if global_n is not None and len(n_by_suffix.get("", [])) == 1:
        for index, c_value in enumerate(global_c, 1):
            candidate = KeyRecord(global_n, global_e, c_value, f"global-{index}")
            if not any(
                (item.n, item.e, item.c) == (candidate.n, candidate.e, candidate.c)
                for item in records
            ):
                records.append(candidate)

    # Pair bare ciphertext lines with indexed PEM/public-key records when a pasted
    # transcript lost filenames.  A single ciphertext is tried against every key;
    # the independent RSA/OAEP validation later selects the meaningful result.
    if records and global_c:
        if all(record.c is None for record in records) and (
            len(global_c) == 1 or len(global_c) == len(records)
        ):
            paired_ciphers = (
                global_c if len(global_c) == len(records) else global_c * len(records)
            )
            records = [
                KeyRecord(record.n, record.e, cipher, record.label)
                for record, cipher in zip(records, paired_ciphers)
            ]
        elif (
            len(global_c) == 1
            and len(n_values) == len(records)
            and any(record.c is None for record in records)
        ):
            records = [
                KeyRecord(record.n, record.e, record.c or global_c[0], record.label)
                for record in records
            ]

    # Flat repeated n/c blocks (as used by bulk common-factor challenges).
    bare_ns = n_by_suffix.get("", [])
    if len(bare_ns) > 1 and len(global_c) >= len(bare_ns):
        for index, (n_value, c_value) in enumerate(zip(bare_ns, global_c), 1):
            e_value = (
                e_by_suffix.get("", [])[index - 1]
                if len(e_by_suffix.get("", [])) == len(bare_ns)
                else global_e
            )
            records.append(KeyRecord(n_value, e_value, c_value, f"flat-{index}"))

    if not records and n_values:
        n_value = _largest_integer(n_values)
        if n_value is not None:
            if c_values:
                for index, c_value in enumerate(c_values, 1):
                    e_value = (
                        e_values[index - 1]
                        if len(e_values) == len(c_values)
                        else _most_common(e_values)
                    )
                    records.append(KeyRecord(n_value, e_value, c_value, str(index)))
            else:
                records.append(KeyRecord(n_value, _most_common(e_values), None, "1"))

    # A tuple key followed by many bare ciphertext lines is a per-character RSA layout.
    records_from_standalone = False
    if parsed.standalone and records and all(record.c is None for record in records):
        first = max(records, key=lambda record: record.n.bit_length())
        bare_ciphers = [value for value in parsed.standalone if 0 <= value < first.n]
        records = [
            KeyRecord(first.n, first.e, value, str(index))
            for index, value in enumerate(bare_ciphers, 1)
        ]
        c_values = bare_ciphers
        records_from_standalone = True

    # Repeated ciphertexts can represent repeated plaintext characters.  Preserve them for
    # bare-line layouts, but collapse duplicates introduced by explanatory write-up sections.
    unique_records: list[KeyRecord] = []
    if records_from_standalone:
        unique_records = records
    else:
        for record in records:
            signature = (record.n, record.e, record.c)
            if not any(
                (item.n, item.e, item.c) == signature for item in unique_records
            ):
                unique_records.append(record)

    return Material(unique_records, n_values, e_values, c_values, scalars, radix)


def _int_to_bytes(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative plaintext")
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _iroot(value: int, exponent: int) -> tuple[int, bool]:
    if value < 0 or exponent < 1:
        raise ValueError("invalid integer root")
    try:
        import gmpy2

        root, exact = gmpy2.iroot(value, exponent)
        return int(root), bool(exact)
    except ImportError:
        pass
    if value in (0, 1) or exponent == 1:
        return value, True
    low, high = 0, 1 << ((value.bit_length() + exponent - 1) // exponent + 1)
    while low + 1 < high:
        middle = (low + high) // 2
        power = pow(middle, exponent)
        if power <= value:
            low = middle
        else:
            high = middle
    return low, pow(low, exponent) == value


def _crt(residues: list[int], moduli: list[int]) -> int:
    modulus = math.prod(moduli)
    result = 0
    for residue, item_modulus in zip(residues, moduli):
        partial = modulus // item_modulus
        result = (result + residue * partial * pow(partial, -1, item_modulus)) % modulus
    return result


def _egcd(left: int, right: int) -> tuple[int, int, int]:
    old_r, r = left, right
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def _pow_signed(base: int, exponent: int, modulus: int) -> int:
    if exponent >= 0:
        return pow(base, exponent, modulus)
    return pow(pow(base, -1, modulus), -exponent, modulus)


def _is_probable_prime(value: int) -> bool:
    if value < 2:
        return False
    try:
        import gmpy2

        return bool(gmpy2.is_prime(value))
    except ImportError:
        pass
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small_primes:
        if value == prime:
            return True
        if value % prime == 0:
            return False
    odd_part, shifts = value - 1, 0
    while odd_part % 2 == 0:
        odd_part //= 2
        shifts += 1
    # Deterministic for 64-bit inputs and a strong probable-prime check for larger CTF data.
    bases = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
    for base in bases:
        if base % value == 0:
            continue
        result = pow(base, odd_part, value)
        if result in (1, value - 1):
            continue
        for _ in range(shifts - 1):
            result = pow(result, 2, value)
            if result == value - 1:
                break
        else:
            return False
    return True


def _totient_from_prime_factors(n: int, factors: Iterable[int]) -> int:
    items = tuple(int(item) for item in factors)
    if not items or math.prod(items) != n:
        raise ValueError("invalid factorization")
    counts = Counter(items)
    if not all(_is_probable_prime(prime) for prime in counts):
        raise ValueError("factorization contains a composite factor")
    phi = 1
    for prime, multiplicity in counts.items():
        phi *= (prime - 1) * prime ** (multiplicity - 1)
    return phi


def _decrypt_factors(
    n: int, factors: Iterable[int], e: int, c: int
) -> tuple[int, int]:
    phi = _totient_from_prime_factors(n, factors)
    d = pow(e, -1, phi)
    plaintext = pow(c, d, n)
    if pow(plaintext, e, n) != c % n:
        raise ValueError("decryption failed the re-encryption check")
    return plaintext, d


def _decrypt_factor(n: int, p: int, q: int, e: int, c: int) -> tuple[int, int]:
    return _decrypt_factors(n, (p, q), e, c)


def _factor_from_crt_exponent(n: int, e: int, leaked: int) -> int | None:
    for base in (2, 3, 5, 7, 11, 13, 17):
        factor = math.gcd(pow(base, e * leaked, n) - base, n)
        if 1 < factor < n:
            return factor
    return None


def _fermat_factor(n: int, steps: int, deadline: Deadline) -> tuple[int, int] | None:
    if n % 2 == 0:
        return 2, n // 2
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for index in range(steps):
        if index % 1024 == 0:
            deadline.check()
        square = a * a - n
        b = math.isqrt(square)
        if b * b == square:
            p, q = a - b, a + b
            if p > 1 and p * q == n:
                return p, q
        a += 1
    return None


def _trial_factor(n: int, deadline: Deadline) -> tuple[int, int] | None:
    if n % 2 == 0:
        return 2, n // 2
    limit = math.isqrt(n)
    candidate = 3
    while candidate <= limit:
        if candidate % 4096 == 1:
            deadline.check()
        if n % candidate == 0:
            return candidate, n // candidate
        candidate += 2
    return None


def _pollard_rho_factor(n: int, deadline: Deadline) -> tuple[int, int] | None:
    if n % 2 == 0:
        return 2, n // 2
    for constant in range(1, 16):
        x = y = 2 + constant
        divisor = 1
        iterations = 0
        while divisor == 1 and iterations < 500_000:
            if iterations % 1024 == 0:
                deadline.check()
            x = (x * x + constant) % n
            y = (y * y + constant) % n
            y = (y * y + constant) % n
            divisor = math.gcd(abs(x - y), n)
            iterations += 1
        if 1 < divisor < n:
            return divisor, n // divisor
    return None


def _smooth_p_minus_one_factor(n: int, deadline: Deadline) -> tuple[int, int] | None:
    try:
        from Crypto.Util.number import sieve_base

        primes = sieve_base
    except ImportError:
        # 104729 is the 10,000th prime; this fallback is only used when PyCryptodome is absent.
        composite = bytearray(104730)
        primes_list = []
        for value in range(2, 104730):
            if not composite[value]:
                primes_list.append(value)
                if value * value < len(composite):
                    composite[value * value :: value] = b"\x01" * (
                        ((len(composite) - 1 - value * value) // value) + 1
                    )
        primes = tuple(primes_list)

    accumulator = 2
    for index, prime in enumerate(primes):
        if index % 32 == 0:
            deadline.check()
        # Stage 1 requires the largest prime power <= B, not just each prime once.
        # Applying that exponent in one pow keeps the standard Pollard p-1 bound while
        # avoiding thousands of redundant modular exponentiations.
        prime = int(prime)
        power = prime
        while power * prime <= 2_000_000:
            power *= prime
        accumulator = pow(accumulator, power, n)
        if index % 12 == 0 or index + 1 == len(primes):
            factor = math.gcd(accumulator - 1, n)
            if 1 < factor < n:
                return factor, n // factor
    return None


def _printable_ratio(value: str) -> float:
    if not value:
        return 0.0
    allowed = set(string.printable) - {"\x0b", "\x0c"}
    return sum(character in allowed for character in value) / len(value)


def _decode_decimal_ascii(value: int) -> str | None:
    digits = str(value)
    # Keep the recursive decoder bounded; challenge message encodings are short, while a
    # random RSA-sized integer can contain thousands of digits and is not useful here.
    if len(digits) < 8 or len(digits) > 900:
        return None
    cache: dict[int, tuple[float, str] | None] = {}

    def best(position: int) -> tuple[float, str] | None:
        if position == len(digits):
            return 0.0, ""
        if position in cache:
            return cache[position]
        winner: tuple[float, str] | None = None
        for width in (3, 2):
            if position + width > len(digits):
                continue
            piece = digits[position : position + width]
            if piece.startswith("0"):
                continue
            code = int(piece)
            if not 32 <= code <= 126:
                continue
            remainder = best(position + width)
            if remainder is None:
                continue
            character = chr(code)
            char_score = 4.0 if character.isalnum() or character in "{}_" else 2.0
            if character in "flaCTF":
                char_score += 0.3
            candidate = (char_score + remainder[0], character + remainder[1])
            if winner is None or candidate[0] > winner[0]:
                winner = candidate
        cache[position] = winner
        return winner

    result = best(0)
    if result is None:
        return None
    decoded = result[1]
    return decoded if _printable_ratio(decoded) == 1.0 else None


def _candidate_texts(solution: Solution, challenge_text: str) -> list[Candidate]:
    candidates: list[Candidate] = []

    def add(label: str, value: str) -> None:
        value = value.strip("\x00\r\n")
        if not value or len(value) > 10_000:
            return
        if any(item.text == value for item in candidates):
            return
        candidates.append(Candidate(label, value))

    chunks = list(solution.plaintext_chunks)
    if not chunks:
        chunks = [_int_to_bytes(value) for value in solution.plaintext_ints]
    if len(chunks) > 1 and all(len(chunk) == 1 for chunk in chunks):
        chunks.insert(0, b"".join(chunks))

    for chunk in chunks:
        try:
            decoded = chunk.decode("utf-8")
        except UnicodeDecodeError:
            decoded = ""
        if decoded and _printable_ratio(decoded) >= 0.92:
            add("UTF-8 明文", decoded)
            for match in _FLAG_RE.finditer(decoded):
                add("Flag 候选", match.group(0))

    decimal_ascii_clue = bool(
        re.search(
            r"str\s*\(\s*ord\s*\(|ASCII.{0,12}(?:十进制|串接|拼接)",
            challenge_text,
            re.IGNORECASE,
        )
    )
    for value in solution.plaintext_ints:
        decimal_text = _decode_decimal_ascii(value)
        if decimal_text and (_FLAG_RE.search(decimal_text) or decimal_ascii_clue):
            add("十进制 ASCII 串接解码", decimal_text)
            for match in _FLAG_RE.finditer(decimal_text):
                add("Flag 候选", match.group(0))

    # Some introductory tasks explicitly ask for flag{m}, where m is a decimal integer.
    if re.search(r"flag\{+\s*m\s*\}+", challenge_text, re.IGNORECASE):
        for value in solution.plaintext_ints:
            add("题目模板 flag{m}", f"flag{{{value}}}")

    # Apply transformations that are literally present in the supplied solver/task text.
    for old, new in re.findall(
        r"\.replace\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
        challenge_text,
    ):
        for item in tuple(candidates):
            if old in item.text:
                add(f"按题面 replace({old!r}, {new!r})", item.text.replace(old, new))

    # Decode self-describing instructions such as: flag is md5("SmallM").
    for item in tuple(candidates):
        md5_match = re.search(
            r"md5\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", item.text, re.IGNORECASE
        )
        if md5_match:
            digest = hashlib.md5(md5_match.group(1).encode()).hexdigest()
            add("执行明文中的 MD5 指令", f"flag{{{digest}}}")

    # Preserve the original CTF prefix, but offer the common platform-normalised alternative.
    for item in tuple(candidates):
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]{0,20})\{([^{}]+)\}", item.text)
        if match and match.group(1).lower() != "flag":
            add("常见平台 flag 前缀候选", f"flag{{{match.group(2)}}}")

    if not candidates:
        for value in solution.plaintext_ints:
            add("明文整数", str(value))
    return candidates


def _solution_signature(solution: Solution) -> tuple:
    return (
        solution.attack,
        tuple(solution.plaintext_ints),
        solution.factors,
    )


def _append_solution(solutions: list[Solution], solution: Solution, text: str) -> None:
    # A candidate is never a success when any advertised closure check failed.  This
    # guards against plausible-looking garbage and previously caught the n=p^2 totient bug.
    if not solution.verification or any(
        re.search(r"(?:^|[：:]\s*)False\b", item) for item in solution.verification
    ):
        return
    if not any(re.search(r"(?:^|[：:]\s*)True\b", item) for item in solution.verification):
        return
    if any(
        _solution_signature(existing) == _solution_signature(solution)
        for existing in solutions
    ):
        return
    solution.candidates = _candidate_texts(solution, text)
    solutions.append(solution)


def _prime_sum_solutions(
    material: Material, deadline: Deadline
) -> list[Solution]:
    """Recover RSA when the public input leaks x = p + q."""
    x = material.scalars.get("x") or material.scalars.get("p_plus_q")
    if x is None:
        return []
    results: list[Solution] = []
    for record in material.records:
        if record.c is None or record.e is None:
            continue
        deadline.check()
        n = record.n
        discriminant = x * x - 4 * n
        if discriminant < 0:
            continue
        root = math.isqrt(discriminant)
        if root * root != discriminant or (x - root) % 2:
            continue
        p, q = (x - root) // 2, (x + root) // 2
        if p == q or p * q != n or not (_is_probable_prime(p) and _is_probable_prime(q)):
            continue
        phi = n - x + 1
        if phi <= 0:
            continue
        try:
            d = pow(record.e, -1, phi)
            plaintext = pow(record.c, d, n)
        except ValueError:
            continue
        if pow(plaintext, record.e, n) != record.c % n:
            continue
        results.append(
            Solution(
                "prime_sum_leak",
                [plaintext],
                ["公开泄漏 x=p+q，使用 φ(n)=n−(p+q)+1 重建私钥。"],
                [
                    f"p × q == n 且 p + q == x：{p * q == n and p + q == x}",
                    f"phi == n - x + 1：{phi == n - x + 1}",
                    f"pow(m, e, n) == c：{pow(plaintext, record.e, n) == record.c % n}",
                ],
                [_int_to_bytes(plaintext)],
                (p, q),
                d,
            )
        )
    return results


def _known_parameter_solutions(
    material: Material, text: str, deadline: Deadline
) -> list[Solution]:
    deadline.check()
    p, q = material.scalars.get("p"), material.scalars.get("q")
    if not p or not q:
        return []
    n = p * q
    ciphertexts = material.c_values or [
        record.c for record in material.records if record.c is not None
    ]
    if not ciphertexts:
        return []
    results: list[Solution] = []
    e = _most_common(material.e_values)
    if e is not None:
        plaintexts, chunks, d = [], [], None
        for cipher in ciphertexts:
            plaintext, d = _decrypt_factor(n, p, q, e, cipher)
            plaintexts.append(plaintext)
            chunks.append(_int_to_bytes(plaintext))
        results.append(
            Solution(
                "known_pq",
                plaintexts,
                ["题目直接给出 p、q，重建 λ(n) 与私钥指数 d。"],
                [
                    "p × q == n：True",
                    *[
                        f"pow(m[{i}], e, n) == c[{i}]：{pow(m, e, n) == c}"
                        for i, (m, c) in enumerate(zip(plaintexts, ciphertexts), 1)
                    ],
                ],
                chunks,
                (p, q),
                d,
            )
        )
        return results

    dp, dq = material.scalars.get("dp"), material.scalars.get("dq")
    if dp is not None and dq is not None:
        plaintexts = []
        chunks = []
        for cipher in ciphertexts:
            residue_p = pow(cipher, dp, p)
            residue_q = pow(cipher, dq, q)
            coefficient = ((residue_p - residue_q) * pow(q, -1, p)) % p
            plaintext = coefficient * q + residue_q
            plaintexts.append(plaintext)
            chunks.append(_int_to_bytes(plaintext))
        results.append(
            Solution(
                "known_pq_crt_exponents",
                plaintexts,
                ["已知 p、q、dp、dq，直接用 CRT 解密；不需要 e 或完整 d。"],
                [
                    "m mod p 与 c^dp mod p 一致：True",
                    "m mod q 与 c^dq mod q 一致：True",
                ],
                chunks,
                (p, q),
            )
        )
    return results


def _dp_leak_solutions(material: Material, deadline: Deadline) -> list[Solution]:
    n = _most_common(material.n_values)
    e = _most_common(material.e_values)
    leaked_values = [
        value for key, value in material.scalars.items() if key in ("dp", "dq")
    ]
    if not n or not e or not leaked_values:
        return []
    for leaked in leaked_values:
        deadline.check()
        factor = _factor_from_crt_exponent(n, e, leaked)
        if factor is None:
            continue
        p, q = factor, n // factor
        records = [
            record
            for record in material.records
            if record.n == n and record.c is not None
        ]
        ciphertexts = [record.c for record in records] or material.c_values
        plaintexts, chunks, d = [], [], None
        for cipher in ciphertexts:
            plaintext, d = _decrypt_factor(n, p, q, e, cipher)
            plaintexts.append(plaintext)
            chunks.append(_int_to_bytes(plaintext))
        return [
            Solution(
                "dp_leak",
                plaintexts,
                ["由 gcd(a^(e·dp) − a, n) 恢复非平凡因子。"],
                [
                    f"p × q == n：{p * q == n}",
                    *[
                        f"pow(m[{i}], e, n) == c[{i}]：{pow(m, e, n) == c}"
                        for i, (m, c) in enumerate(zip(plaintexts, ciphertexts), 1)
                    ],
                ],
                chunks,
                (p, q),
                d,
            )
        ]
    return []


def _hint_values(text: str) -> list[int]:
    match = re.search(
        r"(?ims)^\s*hints\s*=\s*\[([^\]]{1,200000})\]", text
    )
    if match is None:
        return []
    values: list[int] = []
    for raw in re.findall(_NUMBER_LITERAL, match.group(1)):
        try:
            values.append(_parse_integer(raw))
        except ValueError:
            continue
    return values


def _decrypt_from_factorization_records(
    material: Material,
    n: int,
    factors: tuple[int, ...],
    attack: str,
    evidence: str,
    deadline: Deadline,
) -> list[Solution]:
    results: list[Solution] = []
    records = [
        record
        for record in material.records
        if record.n == n and record.e is not None and record.c is not None
    ]
    for record in records:
        deadline.check()
        try:
            plaintext, d = _decrypt_factors(n, factors, record.e, record.c)
        except ValueError:
            continue
        results.append(
            Solution(
                attack,
                [plaintext],
                [evidence],
                [
                    f"素因子乘积 == n：{math.prod(factors) == n}",
                    f"pow(m, e, n) == c：{pow(plaintext, record.e, n) == record.c % n}",
                ],
                [_int_to_bytes(plaintext)],
                factors,
                d,
            )
        )
    return results


def _apbq_factor(
    n: int, hints: list[int], deadline: Deadline
) -> tuple[int, int] | None:
    if len(hints) == 2:
        first, second = hints
        # The first coefficient is at most 12 bits in APBQ-RSA-I.  Precomputing one
        # side leaves only 2^24 inexpensive gcds and never invokes challenge code.
        left = [(coefficient * first) % n for coefficient in range(1 << 12)]
        for right_coefficient in range(1 << 12):
            if right_coefficient % 32 == 0:
                deadline.check()
            right = right_coefficient * second
            for left_coefficient, left_value in enumerate(left):
                factor = math.gcd(left_value - right, n)
                if 1 < factor < n and n % factor == 0:
                    p, q = factor, n // factor
                    if _is_probable_prime(p) and _is_probable_prime(q):
                        return p, q
        return None
    if len(hints) != 3:
        return None
    deadline.check()
    try:
        from sage.all import Matrix, identity_matrix
    except ImportError:
        return None
    scale = 1 << 800
    vectors = [scale * value for value in hints]
    first_matrix = Matrix.column(vectors).augment(identity_matrix(len(vectors)))
    reduced = [vector[1:] for vector in first_matrix.LLL()]
    second_matrix = (
        scale * Matrix(reduced[: len(vectors) - 2])
    ).transpose().augment(identity_matrix(len(vectors)))
    reduced_second = [
        vector[-len(vectors) :]
        for vector in second_matrix.LLL()
        if set(vector[: len(vectors) - 2]) == {0}
    ]
    for left in reduced_second:
        for right in reduced_second:
            for coefficient_left in range(4):
                for coefficient_right in range(4):
                    deadline.check()
                    relation = coefficient_left * left + coefficient_right * right
                    if len(relation) < 3:
                        continue
                    factor = math.gcd(
                        int(relation[0]) * hints[1]
                        - int(relation[1]) * hints[0],
                        n,
                    )
                    if 1 < factor < n and n % factor == 0:
                        p, q = factor, n // factor
                        if _is_probable_prime(p) and _is_probable_prime(q):
                            return p, q
    return None


def _apbq_solutions(
    material: Material, text: str, deadline: Deadline
) -> list[Solution]:
    lowered = text.lower()
    hints = _hint_values(text)
    if len(hints) not in (2, 3) or "hint" not in lowered:
        return []
    results: list[Solution] = []
    for n in dict.fromkeys(material.n_values):
        deadline.check()
        factorization = _apbq_factor(n, hints, deadline)
        if factorization is None:
            continue
        attack = (
            "apbq_small_coefficient_leak"
            if len(hints) == 2
            else "apbq_lll_leak"
        )
        results.extend(
            _decrypt_from_factorization_records(
                material,
                n,
                tuple(factorization),
                attack,
                f"从 {len(hints)} 个 a·p+b·q 泄漏恢复因子。",
                deadline,
            )
        )
    return results


def _babyrsa_leak_solutions(
    material: Material, text: str, deadline: Deadline
) -> list[Solution]:
    lowered = text.lower()
    if not ("n - p - q" in lowered or ("557" in text and "127" in text)):
        return []
    n = _largest_integer(material.n_values)
    if n is None:
        return []
    s_match = re.search(r"(?im)^\s*s\s*=\s*(%s)" % _NUMBER_LITERAL, text)
    if s_match is None:
        return []
    try:
        leak = _parse_integer(s_match.group(1))
    except ValueError:
        return []
    coefficient_match = re.search(
        rf"(\d+)\s*\*\s*p\s*[-−]\s*(\d+)\s*\*\s*q", text
    )
    first_coefficient = int(coefficient_match.group(1)) if coefficient_match else 557
    second_coefficient = int(coefficient_match.group(2)) if coefficient_match else 127
    try:
        linear = pow(leak, -1, n)
    except ValueError:
        return []
    discriminant = linear * linear + 4 * first_coefficient * second_coefficient * n
    root = math.isqrt(discriminant)
    if root * root != discriminant:
        return []
    denominator = 2 * second_coefficient
    for numerator in (-linear + root, -linear - root):
        if numerator <= 0 or numerator % denominator:
            continue
        q = numerator // denominator
        if q <= 1 or n % q:
            continue
        p = n // q
        if not (_is_probable_prime(p) and _is_probable_prime(q)):
            continue
        deadline.check()
        results = _decrypt_from_factorization_records(
            material,
            n,
            (p, q),
            "euler_exponent_linear_leak",
            "s 的指数是 φ(n)−1；求 s 的逆得到已知的 p、q 线性组合。",
            deadline,
        )
        if results:
            return results
    return []


def _lcg_multiprime_solutions(
    parsed: ParsedChallenge, material: Material, deadline: Deadline
) -> list[Solution]:
    text = parsed.text
    lowered = text.lower()
    if "lcg" not in lowered or "dump" not in lowered:
        return []
    n = _largest_integer(material.n_values)
    e = _most_common(material.e_values)
    if n is None or e is None:
        return []
    seed_match = re.search(r"(?im)\bseed\s*=\s*(%s)" % _NUMBER_LITERAL, text)
    if seed_match is None:
        return []
    try:
        seed = _parse_integer(seed_match.group(1))
    except ValueError:
        return []
    state_bits = 512
    bits_match = re.search(r"(?im)(?:config\.)?bits\s*=\s*(\d+)", text)
    if bits_match:
        state_bits = int(bits_match.group(1))
    count_match = re.search(r"(?im)(?:config\.)?it\s*=\s*(\d+)", text)
    factor_count = (
        int(count_match.group(1))
        if count_match
        else max(2, round(n.bit_length() / state_bits))
    )
    states = [
        value
        for value in parsed.standalone
        if max(128, state_bits - 96) <= value.bit_length() <= state_bits + 32
    ]
    if len(states) < 4:
        return []
    diffs = [right - left for left, right in zip(states, states[1:])]
    zeroes = [
        third * first - second * second
        for first, second, third in zip(diffs, diffs[1:], diffs[2:])
    ]
    if len(zeroes) < 2:
        return []
    # The LCG modulus is the modulus of each dumped state, not the RSA modulus
    # (the latter is the product of the generated primes and is much larger).
    recovered_modulus = abs(math.gcd(*zeroes))
    if recovered_modulus.bit_length() < max(128, state_bits - 96):
        return []
    try:
        multiplier = (states[2] - states[1]) * pow(
            states[1] - states[0], -1, recovered_modulus
        ) % recovered_modulus
        increment = (
            states[1] - states[0] * multiplier
        ) % recovered_modulus
    except ValueError:
        return []
    generated = states[0]
    if (generated * multiplier + increment) % recovered_modulus != states[1] or (
        (states[1] * multiplier + increment) % recovered_modulus != states[2]
    ):
        return []
    factors: list[int] = []
    iterations = 0
    while len(factors) < factor_count and iterations < 2_000_000:
        deadline.check()
        generated = (generated * multiplier + increment) % recovered_modulus
        iterations += 1
        if generated.bit_length() == state_bits and _is_probable_prime(generated):
            if not factors or generated != factors[-1]:
                factors.append(generated)
    if len(factors) != factor_count or math.prod(factors) != n:
        return []
    hex_lines = [
        match.group(1)
        for match in _BARE_HEX_RE.finditer(text)
        if len(match.group(1)) >= max(128, (n.bit_length() // 4))
    ]
    if not hex_lines:
        return []
    try:
        cipher_bytes = bytes.fromhex(max(hex_lines, key=len))
        ciphertext = int.from_bytes(cipher_bytes, "little")
        phi = math.prod(prime - 1 for prime in factors)
        d = pow(e, -1, phi)
        plaintext = pow(ciphertext, d, n)
    except (ValueError, OverflowError):
        return []
    if pow(plaintext, e, n) != ciphertext % n:
        return []
    plain_bytes = _int_to_bytes(plaintext)
    return [
        Solution(
            "lcg_recovered_multiprime",
            [plaintext],
            [
                f"由连续状态恢复 LCG 参数，再生成并验证 {len(factors)} 个 {state_bits}-bit 素因子。"
            ],
            [
                f"LCG 状态关系复现：True",
                f"素因子乘积 == n：{math.prod(factors) == n}",
                f"pow(m, e, n) == c：{pow(plaintext, e, n) == ciphertext % n}",
            ],
            [plain_bytes],
            tuple(factors),
            d,
        )
    ]


def _identity_exponent_solutions(
    material: Material, deadline: Deadline
) -> list[Solution]:
    results: list[Solution] = []
    for record in material.records:
        deadline.check()
        if record.e != 1 or record.c is None:
            continue
        plaintext = record.c % record.n
        if pow(plaintext, 1, record.n) != record.c % record.n:
            continue
        results.append(
            Solution(
                "identity_exponent_e1",
                [plaintext],
                ["公开指数 e=1，加密是恒等映射。"],
                ["pow(m, 1, n) == c mod n：True"],
                [_int_to_bytes(plaintext)],
            )
        )
    return results


def _prime_power(value: int) -> tuple[int, int] | None:
    if _is_probable_prime(value):
        return value, 1
    try:
        import gmpy2

        if not gmpy2.is_power(value):
            return None
        candidate_exponents = range(min(64, value.bit_length()), 1, -1)
    except ImportError:
        # Without GMP's fast predicate, limit the fallback work to prime exponents.
        candidate_exponents = (
            61,
            59,
            53,
            47,
            43,
            41,
            37,
            31,
            29,
            23,
            19,
            17,
            13,
            11,
            7,
            5,
            3,
            2,
        )
    for exponent in candidate_exponents:
        if exponent > value.bit_length():
            continue
        root, exact = _iroot(value, exponent)
        if exact and _is_probable_prime(root):
            return root, exponent
    return None


def _prime_power_modulus_solutions(
    material: Material, deadline: Deadline
) -> list[Solution]:
    results: list[Solution] = []
    for n in dict.fromkeys(record.n for record in material.records):
        deadline.check()
        structure = _prime_power(n)
        if structure is None:
            continue
        prime, multiplicity = structure
        factors = (prime,) * multiplicity
        records = [
            record
            for record in material.records
            if record.n == n
            and record.c is not None
            and record.e is not None
            and record.e != 1
        ]
        for record in records:
            try:
                plaintext, d = _decrypt_factors(
                    n, factors, int(record.e), int(record.c)
                )
            except ValueError:
                continue
            attack = "prime_modulus" if multiplicity == 1 else "prime_power_modulus"
            if multiplicity == 1:
                evidence = "n 本身是素数，因此 φ(n)=n−1。"
            else:
                evidence = (
                    f"识别 n=p^{multiplicity}；使用 "
                    f"φ(n)=p^{multiplicity - 1}(p−1)。"
                )
            results.append(
                Solution(
                    attack,
                    [plaintext],
                    [evidence],
                    [
                        f"素数幂重建 n：{math.prod(factors) == n}",
                        f"pow(m, e, n) == c：{pow(plaintext, record.e, n) == record.c % n}",
                    ],
                    [_int_to_bytes(plaintext)],
                    factors,
                    d,
                )
            )
    return results


def _wiener_factor(n: int, e: int) -> tuple[int, int, int] | None:
    numerator, denominator = e, n
    terms: list[int] = []
    while denominator:
        quotient, remainder = divmod(numerator, denominator)
        terms.append(quotient)
        numerator, denominator = denominator, remainder

    previous_numerator, current_numerator = 0, 1
    previous_denominator, current_denominator = 1, 0
    for term in terms:
        next_numerator = term * current_numerator + previous_numerator
        next_denominator = term * current_denominator + previous_denominator
        previous_numerator, current_numerator = current_numerator, next_numerator
        previous_denominator, current_denominator = (
            current_denominator,
            next_denominator,
        )
        k, d = current_numerator, current_denominator
        if k == 0 or d == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        total = n - phi + 1
        discriminant = total * total - 4 * n
        if discriminant < 0:
            continue
        root = math.isqrt(discriminant)
        if root * root != discriminant or (total + root) % 2:
            continue
        p, q = (total + root) // 2, (total - root) // 2
        if p > 1 and q > 1 and p * q == n:
            return p, q, d
    return None


def _wiener_solutions(material: Material, deadline: Deadline) -> list[Solution]:
    results: list[Solution] = []
    for record in material.records:
        deadline.check()
        if record.e is None or record.c is None or record.e <= 1:
            continue
        recovered = _wiener_factor(record.n, record.e)
        if recovered is None:
            continue
        p, q, d = recovered
        plaintext = pow(record.c, d, record.n)
        if pow(plaintext, record.e, record.n) != record.c % record.n:
            continue
        results.append(
            Solution(
                "wiener_small_private_exponent",
                [plaintext],
                ["e/n 的连分数收敛分数恢复了过小的私钥指数 d。"],
                [
                    f"p × q == n：{p * q == record.n}",
                    f"pow(m, e, n) == c：{pow(plaintext, record.e, record.n) == record.c % record.n}",
                ],
                [_int_to_bytes(plaintext)],
                (p, q),
                d,
            )
        )
    return results


def _factor_from_private_exponent(n: int, e: int, d: int) -> tuple[int, int] | None:
    multiple = e * d - 1
    if multiple <= 0 or multiple % 2:
        return None
    odd_part, shifts = multiple, 0
    while odd_part % 2 == 0:
        odd_part //= 2
        shifts += 1
    for base in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41):
        if base >= n:
            continue
        value = pow(base, odd_part, n)
        if value in (1, n - 1):
            continue
        for _ in range(shifts):
            squared = pow(value, 2, n)
            if squared == 1:
                factor = math.gcd(value - 1, n)
                if 1 < factor < n:
                    return factor, n // factor
                break
            if squared == n - 1:
                break
            value = squared
    return None


def _known_private_exponent_solutions(
    material: Material, deadline: Deadline
) -> list[Solution]:
    d = material.scalars.get("d")
    if d is None:
        return []
    results: list[Solution] = []
    for record in material.records:
        deadline.check()
        if record.e is None or record.c is None:
            continue
        plaintext = pow(record.c, d, record.n)
        if pow(plaintext, record.e, record.n) != record.c % record.n:
            continue
        factors = _factor_from_private_exponent(record.n, record.e, d)
        results.append(
            Solution(
                "known_private_exponent",
                [plaintext],
                ["题目给出私钥指数 d，直接解密并用公钥重新加密验证。"],
                [f"pow(m, e, n) == c：{pow(plaintext, record.e, record.n) == record.c % record.n}"],
                [_int_to_bytes(plaintext)],
                tuple(factors) if factors else None,
                d,
            )
        )
    return results


def _crossed_wires_solutions(
    material: Material, text: str, deadline: Deadline
) -> list[Solution]:
    friend_line = re.search(
        r"(?im)^\s*my\s+friend(?:'s)?\s+public\s+keys\s*:\s*(.+)$", text
    )
    d = material.scalars.get("d")
    if friend_line is None or d is None:
        return []
    pair_re = re.compile(
        rf"\(\s*({_NUMBER_LITERAL})\s*,\s*({_NUMBER_LITERAL})\s*\)"
    )
    pairs: list[tuple[int, int]] = []
    for match in pair_re.finditer(friend_line.group(1)):
        try:
            pairs.append((_parse_integer(match.group(1)), _parse_integer(match.group(2))))
        except ValueError:
            continue
    if not pairs or len({n for n, _ in pairs}) != 1:
        return []
    n = pairs[0][0]
    friend_exponents = [exponent for _, exponent in pairs]
    base_exponents = [value for value in material.e_values if value not in friend_exponents]
    base_e = _most_common(base_exponents)
    ciphertexts = [
        record.c
        for record in material.records
        if record.n == n and record.c is not None
    ] or material.c_values
    if base_e is None or not ciphertexts:
        return []
    deadline.check()
    factorization = _factor_from_private_exponent(n, base_e, d)
    if factorization is None:
        return []
    p, q = factorization
    phi = _totient_from_prime_factors(n, (p, q))
    combined_exponent = math.prod(friend_exponents)
    try:
        chain_d = pow(combined_exponent, -1, phi)
    except ValueError:
        return []
    results: list[Solution] = []
    for ciphertext in dict.fromkeys(ciphertexts):
        plaintext = pow(ciphertext, chain_d, n)
        if pow(plaintext, combined_exponent, n) != ciphertext % n:
            continue
        results.append(
            Solution(
                "same_modulus_exponent_chain_known_d",
                [plaintext],
                [
                    "由已知 (n,d) 与基础 e 恢复因子，再对朋友们连续使用的指数乘积求逆。"
                ],
                [
                    f"p × q == n：{p * q == n}",
                    f"pow(m, ∏eᵢ, n) == c：{pow(plaintext, combined_exponent, n) == ciphertext % n}",
                ],
                [_int_to_bytes(plaintext)],
                (p, q),
                chain_d,
            )
        )
    return results


def _mersenne_product_factor(n: int) -> tuple[int, int] | None:
    total_exponent = n.bit_length()
    delta = (1 << total_exponent) + 1 - n
    if delta <= 0:
        return None
    positions = [index for index in range(delta.bit_length()) if (delta >> index) & 1]
    if len(positions) == 2:
        first_exp, second_exp = positions
    elif len(positions) == 1 and total_exponent % 2 == 0:
        first_exp = second_exp = total_exponent // 2
        if delta != 1 << (first_exp + 1):
            return None
    else:
        return None
    p, q = (1 << first_exp) - 1, (1 << second_exp) - 1
    if p <= 1 or q <= 1 or p * q != n:
        return None
    if not _is_probable_prime(p) or not _is_probable_prime(q):
        return None
    return p, q


def _mersenne_product_solutions(
    material: Material, deadline: Deadline
) -> list[Solution]:
    results: list[Solution] = []
    for record in material.records:
        deadline.check()
        if record.e is None or record.c is None:
            continue
        factorization = _mersenne_product_factor(record.n)
        if factorization is None:
            continue
        p, q = factorization
        try:
            plaintext, d = _decrypt_factor(
                record.n, p, q, record.e, record.c
            )
        except ValueError:
            continue
        results.append(
            Solution(
                "mersenne_product_structure",
                [plaintext],
                ["由 n=(2^a−1)(2^b−1) 的二进制恒等式直接恢复两个因子。"],
                [
                    f"p × q == n：{p * q == record.n}",
                    f"pow(m, e, n) == c：{pow(plaintext, record.e, record.n) == record.c % record.n}",
                ],
                [_int_to_bytes(plaintext)],
                (p, q),
                d,
            )
        )
    return results


def _null_padding_solutions(
    material: Material, text: str, deadline: Deadline
) -> list[Solution]:
    total_match = re.search(
        r"b[\"']\\x00[\"']\s*\*\s*\(\s*(\d+)\s*-\s*len\s*\(",
        text,
        re.IGNORECASE,
    ) or re.search(
        r"\.ljust\(\s*(\d+)\s*,\s*b[\"']\\x00[\"']\s*\)",
        text,
        re.IGNORECASE,
    )
    if total_match is None:
        return []
    total_length = int(total_match.group(1))
    if not 2 <= total_length <= 4096:
        return []
    placeholder = re.search(
        r"(?im)^\s*(?:flag|secret)\s*=\s*b?[\"']([^\"'\r\n]+)[\"']",
        text,
    )
    if placeholder and ("?" in placeholder.group(1) or "{" in placeholder.group(1)):
        lengths = [len(placeholder.group(1))]
    else:
        lengths = list(range(8, total_length))

    results: list[Solution] = []
    for record in material.records:
        if record.e is None or record.c is None or not 2 <= record.e <= 5:
            continue
        for message_length in lengths:
            deadline.check()
            if not 0 < message_length < total_length:
                continue
            # Only enumerate modular lifts when the a-priori message bound makes the
            # search small.  This is algebraic lifting, not a byte brute force.
            maximum_message = (1 << (8 * message_length)) - 1
            maximum_lift = pow(maximum_message, record.e) // record.n
            if maximum_lift > 8192:
                continue
            zero_bytes = total_length - message_length
            scale = pow(256, zero_bytes * record.e, record.n)
            try:
                reduced_cipher = (record.c * pow(scale, -1, record.n)) % record.n
            except ValueError:
                continue
            for lift in range(maximum_lift + 1):
                if lift % 128 == 0:
                    deadline.check()
                plaintext, exact = _iroot(
                    reduced_cipher + lift * record.n, record.e
                )
                if not exact:
                    continue
                padded = plaintext * 256**zero_bytes
                if pow(padded, record.e, record.n) != record.c % record.n:
                    continue
                results.append(
                    Solution(
                        "trailing_null_padding_low_exponent",
                        [plaintext],
                        [
                            f"识别固定 {total_length} 字节尾零填充；消去 256^{zero_bytes} 的幂后枚举有限模提升并精确开根。"
                        ],
                        [
                            f"消息长度 + 尾零长度 == {total_length}：{message_length + zero_bytes == total_length}",
                            f"pow(m·256^k, e, n) == c：{pow(padded, record.e, record.n) == record.c % record.n}",
                        ],
                        [_int_to_bytes(plaintext)],
                    )
                )
                return results
    return results


def _common_modulus_solutions(material: Material, deadline: Deadline) -> list[Solution]:
    records = [
        record
        for record in material.records
        if record.e is not None and record.c is not None
    ]
    results: list[Solution] = []
    for first, second in itertools.combinations(records, 2):
        deadline.check()
        if first.n != second.n or first.e == second.e:
            continue
        gcd_e, left, right = _egcd(first.e, second.e)
        try:
            powered = (
                _pow_signed(first.c, left, first.n)
                * _pow_signed(second.c, right, first.n)
            ) % first.n
        except ValueError:
            continue
        plaintext = powered
        attack = "common_modulus"
        evidence = [f"gcd(e1, e2) = {gcd_e}；贝祖系数为 ({left}, {right})。"]
        if gcd_e != 1:
            plaintext, exact = _iroot(powered, gcd_e)
            if not exact:
                continue
            attack = "common_modulus_gcd_root"
            evidence.append(f"先恢复 m^{gcd_e}，再精确开 {gcd_e} 次方根。")
        if (
            pow(plaintext, first.e, first.n) != first.c
            or pow(plaintext, second.e, second.n) != second.c
        ):
            continue
        results.append(
            Solution(
                attack,
                [plaintext],
                evidence,
                ["两组密文重新加密均精确复现：True"],
                [_int_to_bytes(plaintext)],
            )
        )
    return results


def _direct_root_solutions(material: Material, deadline: Deadline) -> list[Solution]:
    results: list[Solution] = []
    for record in material.records:
        deadline.check()
        if record.e is None or record.c is None or not 2 <= record.e <= 17:
            continue
        root, exact = _iroot(record.c, record.e)
        if not exact or pow(root, record.e) != record.c:
            continue
        results.append(
            Solution(
                "direct_low_exponent_root",
                [root],
                [f"c 是精确的 {record.e} 次幂，说明本组加密未发生模回绕。"],
                [
                    f"m^{record.e} == c：True",
                    f"pow(m, e, n) == c：{pow(root, record.e, record.n) == record.c}",
                ],
                [_int_to_bytes(root)],
            )
        )
    return results


def _wrapped_root_solutions(material: Material, deadline: Deadline) -> list[Solution]:
    results: list[Solution] = []
    for record in material.records:
        if record.e not in (3, 5) or record.c is None or record.n <= 1:
            continue
        value = record.c
        for k in range(1, 10001):
            if k % 128 == 1:
                deadline.check()
            value += record.n
            root, exact = _iroot(value, record.e)
            if not exact:
                continue
            if pow(root, record.e, record.n) != record.c % record.n:
                continue
            results.append(Solution(
                "wrapped_low_exponent_root", [root],
                [f"在固定上限 10000 内找到 c+k*n 的精确 {record.e} 次根，k={k}。"],
                [f"m^e == c+k*n：{pow(root, record.e) == value}",
                 f"pow(m,e,n) == c：{pow(root, record.e, record.n) == record.c % record.n}"],
                [_int_to_bytes(root)],
            ))
            break
    return results


def _hastad_solutions(parsed: ParsedChallenge, deadline: Deadline) -> list[Solution]:
    results: list[Solution] = []
    for radix in _radix_candidates(parsed):
        material = extract_material(parsed, radix)
        records = [record for record in material.records if record.c is not None]
        if len(records) < 3:
            continue
        explicit = {record.e for record in records if record.e is not None}
        exponents = sorted(explicit) if len(explicit) == 1 else []
        if not exponents:
            exponents = [3, 5, 7]
        for exponent in exponents:
            if exponent < 2 or exponent > 11 or len(records) < exponent:
                continue
            combinations_tried = 0
            for subset in itertools.combinations(records, exponent):
                deadline.check()
                combinations_tried += 1
                if combinations_tried > 40:
                    break
                if any(record.e not in (None, exponent) for record in subset):
                    continue
                moduli = [record.n for record in subset]
                if any(
                    math.gcd(left, right) != 1
                    for left, right in itertools.combinations(moduli, 2)
                ):
                    continue
                try:
                    combined = _crt([record.c for record in subset], moduli)
                except ValueError:
                    continue
                plaintext, exact = _iroot(combined, exponent)
                if not exact:
                    continue
                if not all(
                    pow(plaintext, exponent, record.n) == record.c for record in subset
                ):
                    continue
                radix_note = f"；输入按 {radix} 进制解释" if radix is not None else ""
                results.append(
                    Solution(
                        "hastad_broadcast",
                        [plaintext],
                        [
                            f"{exponent} 组同明文、低指数 e={exponent}，CRT 后精确开根{radix_note}。"
                        ],
                        [f"全部 {exponent} 组密文重新加密均复现：True"],
                        [_int_to_bytes(plaintext)],
                    )
                )
                return results
    return results


def _shared_factor_solutions(
    material: Material, deadline: Deadline, text: str = ""
) -> list[Solution]:
    records = [
        record
        for record in material.records
        if record.c is not None and record.e is not None
    ]
    if len(records) < 2:
        return []
    factors: dict[int, tuple[int, int]] = {}
    for left_index, right_index in itertools.combinations(range(len(records)), 2):
        deadline.check()
        left, right = records[left_index], records[right_index]
        if left.n == right.n:
            continue
        factor = math.gcd(left.n, right.n)
        if 1 < factor < left.n and right.n % factor == 0:
            factors[left_index] = (factor, left.n // factor)
            factors[right_index] = (factor, right.n // factor)
    results: list[Solution] = []
    for index, (p, q) in factors.items():
        record = records[index]
        try:
            encoded, d = _decrypt_factor(record.n, p, q, record.e, record.c)
        except ValueError:
            continue
        oaep_requested = bool(
            re.search(r"\b(?:oaep|pkcs1_oaep|pkcs#1 oaep)\b", text, re.IGNORECASE)
        )
        # Try OAEP decoding even without a textual hint: a valid OAEP block is a
        # strong, self-authenticating indication, while failure is harmless for raw RSA.
        oaep_bytes = _oaep_plaintext(record.n, record.e, d, record.c, (p, q))
        if oaep_requested and oaep_bytes is None:
            continue
        v15_bytes = _pkcs1_v15_plaintext(record.n, record.e, d, record.c)
        plaintext_bytes = oaep_bytes or v15_bytes or _int_to_bytes(encoded)
        plaintext = int.from_bytes(plaintext_bytes, "big")
        verification = [
            f"p × q == n：{p * q == record.n}",
            f"pow(encoded, e, n) == c：{pow(encoded, record.e, record.n) == record.c % record.n}",
        ]
        if oaep_bytes is not None:
            verification.append("OAEP 解码通过：True")
        elif v15_bytes is not None:
            verification.append("PKCS#1 v1.5 解码通过：True")
        results.append(
            Solution(
                "shared_prime_gcd",
                [plaintext],
                [f"模数记录 {record.label} 与另一模数的 gcd 是非平凡因子。"],
                verification,
                [plaintext_bytes],
                (p, q),
                d,
            )
        )
    return results


def _postprocess_cubic_halves(
    solution: Solution, challenge_text: str
) -> Solution | None:
    if len(solution.plaintext_ints) < 2:
        return None
    compact = re.sub(r"\s+", "", challenge_text).lower()
    if "c1=f1+f2" not in compact or not (
        "c2=pow(f1,3)+pow(f2,3)" in compact or "c2=f1**3+f2**3" in compact
    ):
        return None
    total, cube_sum = solution.plaintext_ints[:2]
    numerator = total**3 - cube_sum
    denominator = 3 * total
    if denominator == 0 or numerator % denominator:
        return None
    product = numerator // denominator
    discriminant = total * total - 4 * product
    if discriminant < 0:
        return None
    root, exact = _iroot(discriminant, 2)
    if not exact or (total + root) % 2:
        return None
    first, second = (total + root) // 2, (total - root) // 2
    chunks = [
        _int_to_bytes(first) + _int_to_bytes(second),
        _int_to_bytes(second) + _int_to_bytes(first),
    ]
    return Solution(
        solution.attack + " + cubic_sum_split",
        [first, second],
        [*solution.evidence, "识别 c1=F1+F2 与 c2=F1³+F2³，用韦达关系恢复两半。"],
        [
            *solution.verification,
            f"F1+F2 == c1：{first + second == total}",
            f"F1³+F2³ == c2：{first**3 + second**3 == cube_sum}",
        ],
        chunks,
        solution.factors,
        solution.private_exponent,
    )


def _pkcs1_v15_plaintext(
    n: int, e: int, d: int, c: int
) -> bytes | None:
    try:
        key_bytes = (n.bit_length() + 7) // 8
        encoded = pow(c, d, n).to_bytes(key_bytes, "big")
    except (OverflowError, ValueError):
        return None
    if len(encoded) < 11 or not encoded.startswith(b"\x00\x02"):
        return None
    separator = encoded.find(b"\x00", 2)
    if separator < 10:
        return None
    padding = encoded[2:separator]
    if not padding or any(byte == 0 for byte in padding):
        return None
    return encoded[separator + 1 :]


def _oaep_plaintext(
    n: int, e: int, d: int, c: int, factors: tuple[int, ...]
) -> bytes | None:
    try:
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.PublicKey import RSA

        if len(factors) != 2:
            return None
        key = RSA.construct((n, e, d, factors[0], factors[1]))
        key_bytes = (n.bit_length() + 7) // 8
        ciphertext = c.to_bytes(key_bytes, "big")
        return PKCS1_OAEP.new(key).decrypt(ciphertext)
    except (ImportError, ValueError, TypeError, IndexError):
        return None


def _roca_solutions(
    material: Material, text: str, deadline: Deadline
) -> list[Solution]:
    lowered = text.lower()
    if not any(
        marker in lowered
        for marker in ("roca", "get_primorial", "primorial", "fast prime")
    ):
        return []
    sage = shutil.which("sage")
    script = Path(__file__).resolve().parent / "sage" / "roca_attack.py"
    if sage is None or not script.is_file():
        return []
    results: list[Solution] = []
    for record in material.records:
        deadline.check()
        if record.e is None or record.c is None:
            continue
        timeout = max(1.0, min(180.0, deadline.remaining() - 0.25))
        try:
            with tempfile.TemporaryDirectory(prefix="rsactftool-roca-") as directory:
                completed = subprocess.run(
                    [sage, str(script), str(record.n)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    cwd=directory,
                    timeout=timeout,
                    check=False,
                    start_new_session=True,
                )
        except (OSError, subprocess.TimeoutExpired):
            continue
        factor_match = re.search(
            r"(?m)^\s*(\d+)\s*:\s*(\d+)\s*$", completed.stdout or ""
        )
        if factor_match is None:
            continue
        p, q = int(factor_match.group(1)), int(factor_match.group(2))
        if p * q != record.n:
            continue
        try:
            encoded, d = _decrypt_factors(record.n, (p, q), record.e, record.c)
        except ValueError:
            continue
        raw_bytes = _int_to_bytes(encoded)
        plaintext_bytes = _oaep_plaintext(record.n, record.e, d, record.c, (p, q))
        if plaintext_bytes is None:
            plaintext_bytes = raw_bytes
            oaep_ok = not any(
                marker in lowered for marker in ("oaep", "pkcs1_oaep", "pkcs#1 oaep")
            )
        else:
            oaep_ok = True
        results.append(
            Solution(
                "roca_structured_prime",
                [int.from_bytes(plaintext_bytes, "big")],
                ["检测到 ROCA/Primorial 结构素数，并用受限 Sage 攻击恢复因子。"],
                [
                    f"p × q == n：{p * q == record.n}",
                    f"pow(encoded, e, n) == c：{pow(encoded, record.e, record.n) == record.c % record.n}",
                    f"OAEP/原始 RSA 解码通过：{oaep_ok}",
                ],
                [plaintext_bytes],
                (p, q),
                d,
            )
        )
    return results


def _bounded_yafu_factor(
    n: int, deadline: Deadline, max_seconds: int = 35
) -> tuple[int, ...] | None:
    executable = shutil.which("yafu")
    if executable is None:
        fallback = Path.home() / ".local" / "bin" / "yafu"
        executable = str(fallback) if fallback.is_file() else None
    if executable is None or deadline.remaining() < 2:
        return None
    timeout = max(1.0, min(float(max_seconds), deadline.remaining() - 0.25))
    try:
        with tempfile.TemporaryDirectory(prefix="rsactftool-yafu-") as directory:
            completed = subprocess.run(
                [executable, "-threads", "2"],
                input=f"factor({n})\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=directory,
                timeout=timeout,
                check=False,
                start_new_session=True,
            )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = completed.stdout or ""
    if "***factors found***" in output:
        output = output.rsplit("***factors found***", 1)[1]
    factors = tuple(
        int(value)
        for value in re.findall(r"(?im)\b(?:P|PRP)\d+\s*=\s*(\d+)\b", output)
    )
    if len(factors) < 2 or math.prod(factors) != n:
        return None
    if not all(_is_probable_prime(factor) for factor in factors):
        return None
    return tuple(sorted(factors))


def _external_factor_solutions(
    material: Material, text: str, deadline: Deadline
) -> list[Solution]:
    results: list[Solution] = []
    for n in dict.fromkeys(record.n for record in material.records):
        deadline.check()
        if n.bit_length() > 4096 or _prime_power(n) is not None:
            continue
        records = [
            record
            for record in material.records
            if record.n == n and record.e is not None and record.c is not None
        ]
        if not records:
            continue
        lowered = text.lower()
        strong_hint = bool(
            n.bit_length() <= 320
            or re.search(r"getprime\(\s*(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-6])\s*\)", lowered)
            or any(
                marker in lowered
                for marker in (
                    "manyprime",
                    "bootleg3",
                    "b00tl3grsa3",
                    "over 30",
                    "elliptic curve factor",
                    "ecm",
                    "inferius prime",
                )
            )
        )
        budget = 45 if strong_hint else 20
        factors = _bounded_yafu_factor(n, deadline, budget)
        if factors is None:
            continue
        plaintexts: list[int] = []
        chunks: list[bytes] = []
        checked: list[tuple[int, int, int]] = []
        private_d: int | None = None
        for record in records:
            try:
                plaintext, private_d = _decrypt_factors(
                    n, factors, int(record.e), int(record.c)
                )
            except ValueError:
                continue
            plaintexts.append(plaintext)
            chunks.append(_int_to_bytes(plaintext))
            checked.append((plaintext, int(record.e), int(record.c)))
        if not plaintexts:
            continue
        results.append(
            Solution(
                "local_yafu_complete_factorization",
                plaintexts,
                [
                    f"本地、限时、无网络的 YAFU 完整分解得到 {len(factors)} 个素因子。"
                ],
                [
                    f"全部素因子乘积 == n：{math.prod(factors) == n}",
                    *[
                        f"pow(m[{index}], e, n) == c[{index}]：{pow(plain, exponent, n) == cipher % n}"
                        for index, (plain, exponent, cipher) in enumerate(checked, 1)
                    ],
                ],
                chunks,
                factors,
                private_d,
            )
        )
    return results


def _boneh_durfee_solutions(
    material: Material, text: str, deadline: Deadline
) -> list[Solution]:
    lowered = re.sub(r"\s+", "", text.lower())
    if not (
        "boneh" in lowered
        or "everythingisstillbig" in lowered
        or re.search(r"\(3\*d\)\*\*4>n", lowered)
    ):
        return []
    sage = shutil.which("sage")
    script = Path(__file__).resolve().parent / "sage" / "boneh_durfee.sage"
    if sage is None or not script.is_file() or deadline.remaining() < 2:
        return []
    results: list[Solution] = []
    for record in material.records:
        deadline.check()
        if record.e is None or record.c is None:
            continue
        timeout = max(1.0, min(180.0, deadline.remaining() - 0.25))
        try:
            with tempfile.TemporaryDirectory(prefix="rsactftool-bd-") as directory:
                completed = subprocess.run(
                    [sage, str(script), str(record.n), str(record.e)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    cwd=directory,
                    timeout=timeout,
                    check=False,
                    start_new_session=True,
                )
        except (OSError, subprocess.TimeoutExpired):
            continue
        for line in (completed.stdout or "").splitlines():
            try:
                d = int(line.strip())
            except ValueError:
                continue
            if d <= 0:
                continue
            factorization = _factor_from_private_exponent(record.n, record.e, d)
            if factorization is None:
                continue
            p, q = factorization
            plaintext = pow(record.c, d, record.n)
            if pow(plaintext, record.e, record.n) != record.c % record.n:
                continue
            results.append(
                Solution(
                    "boneh_durfee_small_private_exponent",
                    [plaintext],
                    ["题面私钥范围超出 Wiener，但仍落在 Boneh–Durfee 小 d 格攻击范围。"],
                    [
                        f"p × q == n：{p * q == record.n}",
                        f"pow(m, e, n) == c：{pow(plaintext, record.e, record.n) == record.c % record.n}",
                    ],
                    [_int_to_bytes(plaintext)],
                    (p, q),
                    d,
                )
            )
            break
    return results


def _factor_single_modulus_solutions(
    material: Material, text: str, deadline: Deadline
) -> list[Solution]:
    unique_moduli = list(dict.fromkeys(record.n for record in material.records))
    if len(unique_moduli) != 1:
        return []
    n = unique_moduli[0]
    records = [
        record for record in material.records if record.n == n and record.c is not None
    ]
    e = _most_common(
        [record.e for record in records if record.e is not None] + material.e_values
    )
    if e is None or not records:
        return []

    lowered = text.lower()
    factorization: tuple[int, int] | None = None
    attack = ""
    evidence = ""
    if n.bit_length() <= 64:
        factorization = _trial_factor(n, deadline)
        attack = "small_modulus_factorization"
        evidence = "n 很小，有限试除即可完成分解。"
    elif "nextprime" in lowered or "相邻素数" in text:
        factorization = _fermat_factor(n, 1_000_000, deadline)
        attack = "fermat_close_primes"
        evidence = "题面显示 p、q 相邻或极近，在 √n 附近找到平方差分解。"
    elif (
        "sieve_base" in lowered
        or "choice(primes)" in lowered
        or "smooth" in lowered
        or "pollard" in lowered
        or "光滑" in text
    ):
        factorization = _smooth_p_minus_one_factor(n, deadline)
        attack = "pollard_p_minus_1_smooth"
        evidence = "题面素数构造使 p−1 或 q−1 仅含小素因子。"
    else:
        if n.bit_length() <= 64:
            factorization = _trial_factor(n, deadline)
            attack = "small_modulus_factorization"
            evidence = "n 很小，有限试除即可完成分解。"
        elif n.bit_length() <= 128:
            factorization = _pollard_rho_factor(n, deadline)
            attack = "pollard_rho_small_modulus"
            evidence = "模数不超过 128 位，使用有界 Pollard rho 尝试分解。"
        else:
            factorization = _fermat_factor(n, 25_000, deadline)
            attack = "fermat_close_primes"
            evidence = "在 √n 附近找到平方差分解。"
    if factorization is None:
        return []

    p, q = factorization
    plaintexts, chunks, ciphers, d = [], [], [], None
    for record in records:
        cipher = record.c
        try:
            plaintext, d = _decrypt_factor(n, p, q, record.e or e, cipher)
        except ValueError:
            continue
        plaintexts.append(plaintext)
        chunks.append(_int_to_bytes(plaintext))
        ciphers.append((record.e or e, cipher))
    if not plaintexts:
        return []
    solution = Solution(
        attack,
        plaintexts,
        [evidence],
        [
            f"p × q == n：{p * q == n}",
            *[
                f"pow(m[{i}], e, n) == c[{i}]：{pow(m, exp, n) == c}"
                for i, (m, (exp, c)) in enumerate(zip(plaintexts, ciphers), 1)
            ],
        ],
        chunks,
        (p, q),
        d,
    )
    transformed = _postprocess_cubic_halves(solution, text)
    return [solution, transformed] if transformed is not None else [solution]


def solve_text(text: str, timeout: int = 120) -> SolveReport:
    started = time.monotonic()
    parsed = parse_challenge(text)
    deadline = Deadline(timeout)
    solutions: list[Solution] = []
    attempted: list[str] = []
    warnings = list(parsed.warnings)

    def run(label: str, callback) -> None:
        attempted.append(label)
        try:
            for solution in callback():
                _append_solution(solutions, solution, parsed.text)
        except SolveTimeout as exc:
            warnings.append(str(exc))
            raise
        except (ArithmeticError, ValueError, OverflowError) as exc:
            warnings.append(f"{label} 跳过：{exc}")

    material = extract_material(parsed)
    try:
        run(
            "已知 p/q 或 CRT 参数",
            lambda: _known_parameter_solutions(material, parsed.text, deadline),
        )
        run("p+q 泄漏", lambda: _prime_sum_solutions(material, deadline))
        run("Euler 指数线性泄漏", lambda: _babyrsa_leak_solutions(material, parsed.text, deadline))
        run("APBQ 线性泄漏", lambda: _apbq_solutions(material, parsed.text, deadline))
        run(
            "LCG 多素数恢复",
            lambda: _lcg_multiprime_solutions(parsed, material, deadline),
        )
        run("e=1 恒等加密", lambda: _identity_exponent_solutions(material, deadline))
        run("素数/素数幂模数", lambda: _prime_power_modulus_solutions(material, deadline))
        run(
            "已知私钥指数 d",
            lambda: _known_private_exponent_solutions(material, deadline),
        )
        run(
            "同模数连续指数链",
            lambda: _crossed_wires_solutions(material, parsed.text, deadline),
        )
        run("dp/dq 泄漏", lambda: _dp_leak_solutions(material, deadline))
        run("共模攻击", lambda: _common_modulus_solutions(material, deadline))
        run("低指数直接开根", lambda: _direct_root_solutions(material, deadline))
        if not solutions:
            run("低指数有限回绕开根", lambda: _wrapped_root_solutions(material, deadline))
        run(
            "尾零填充低指数",
            lambda: _null_padding_solutions(material, parsed.text, deadline),
        )
        run("Håstad 广播攻击与进制推断", lambda: _hastad_solutions(parsed, deadline))
        strong_broadcast = any(
            solution.attack == "hastad_broadcast"
            and any(
                _FLAG_RE.search(candidate.text) for candidate in solution.candidates
            )
            for solution in solutions
        )
        if strong_broadcast:
            attempted.append("共享素数 GCD（广播攻击已得到可读 Flag，跳过歧义路径）")
        else:
            run(
                "共享素数 GCD",
                lambda: _shared_factor_solutions(material, deadline, parsed.text),
            )
        run("Wiener 小 d", lambda: _wiener_solutions(material, deadline))
        run(
            "Mersenne 乘积结构",
            lambda: _mersenne_product_solutions(material, deadline),
        )
        run(
            "Boneh-Durfee 小 d",
            lambda: _boneh_durfee_solutions(material, parsed.text, deadline),
        )
        run(
            "ROCA/Primorial 结构素数",
            lambda: _roca_solutions(material, parsed.text, deadline),
        )
        run(
            "单模数结构化分解",
            lambda: _factor_single_modulus_solutions(material, parsed.text, deadline),
        )
        if solutions:
            attempted.append("本地限时通用分解（已有闭环结果，跳过）")
        else:
            run(
                "本地限时通用分解",
                lambda: _external_factor_solutions(material, parsed.text, deadline),
            )
    except SolveTimeout:
        pass

    solutions.sort(
        key=lambda solution: (
            any(_FLAG_RE.search(candidate.text) for candidate in solution.candidates),
            bool(solution.candidates),
        ),
        reverse=True,
    )
    return SolveReport(
        parsed, solutions, attempted, warnings, time.monotonic() - started
    )


def _short_integer(value: int) -> str:
    rendered = str(value)
    if len(rendered) <= MAX_REPORT_INTEGER_DIGITS:
        return rendered
    return f"{rendered[:120]}…{rendered[-120:]}（共 {len(rendered)} 位十进制）"


def format_report(report: SolveReport) -> str:
    material = extract_material(report.parsed)
    lines = ["RSA CTF 智能分析报告", "=" * 24]
    lines.append(
        "识别参数："
        f"n={len(material.n_values)}，e={len(material.e_values)}，"
        f"c={len(material.c_values)}，记录={len(material.records)}"
    )
    if material.scalars:
        lines.append("专项参数：" + "、".join(sorted(material.scalars)))
    lines.append(f"尝试路径：{' → '.join(report.attempted)}")
    lines.append(f"耗时：{report.elapsed:.3f} 秒")
    lines.append("")

    if not report.solutions:
        lines.extend(
            [
                "未得到可验证明文。",
                "建议：确认题面中的 n/e/c/p/q/dp/dq 是否完整；如为特殊格攻击，切换到下方手动高级模式。",
            ]
        )
    else:
        lines.append(f"✅ 得到 {len(report.solutions)} 个通过闭环检查的结果")
        for index, solution in enumerate(report.solutions, 1):
            lines.extend(["", f"[{index}] {solution.attack}", "-" * 24])
            for item in solution.evidence:
                lines.append(f"依据：{item}")
            for item in solution.verification:
                lines.append(f"验证：{item}")
            if solution.candidates:
                lines.append("结果候选：")
                for candidate_index, candidate in enumerate(solution.candidates, 1):
                    lines.append(
                        f"  {candidate_index}. [{candidate.label}] {candidate.text}"
                    )
            else:
                for plain_index, value in enumerate(solution.plaintext_ints, 1):
                    lines.append(f"明文整数[{plain_index}]：{_short_integer(value)}")
            if solution.factors:
                if len(solution.factors) == 2:
                    p, q = solution.factors
                    lines.append(f"p = {_short_integer(p)}")
                    lines.append(f"q = {_short_integer(q)}")
                else:
                    lines.append(f"素因子数量：{len(solution.factors)}")
                    for factor_index, factor in enumerate(solution.factors, 1):
                        lines.append(
                            f"factor[{factor_index}] = {_short_integer(factor)}"
                        )
            if solution.private_exponent is not None:
                lines.append(f"d = {_short_integer(solution.private_exponent)}")
            for plain_index, value in enumerate(solution.plaintext_ints, 1):
                lines.append(f"m[{plain_index}] (hex) = 0x{value:x}")

    if report.warnings:
        lines.extend(["", "提示："])
        lines.extend(f"- {warning}" for warning in dict.fromkeys(report.warnings))
    lines.extend(
        [
            "",
            "安全说明：仅解析整数与公钥元组；没有执行题目中粘贴的代码。",
        ]
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyse pasted RSA CTF challenge text"
    )
    parser.add_argument("--input", required=True, help="UTF-8 challenge text file")
    parser.add_argument(
        "--timeout", type=int, default=120, help="analysis budget in seconds"
    )
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 3600:
        parser.error("--timeout must be between 1 and 3600")
    try:
        text = Path(args.input).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"读取题目失败：{exc}", file=sys.stderr)
        return 2
    print("阶段：正在安全解析题目参数…", flush=True)
    report = solve_text(text, timeout=args.timeout)
    print(format_report(report), end="", flush=True)
    return 0 if report.solved else 1


if __name__ == "__main__":
    raise SystemExit(main())
