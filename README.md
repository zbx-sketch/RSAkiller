# RSAkiller

<div align="center">

[![Test](https://github.com/zbx-sketch/RSAkiller/actions/workflows/test.yml/badge.svg)](https://github.com/RsaCtfTool/RsaCtfTool/actions/workflows/test.yml)
[![Ruff](https://github.com/zbx-sketch/RSAkiller/actions/workflows/lint_python.yml/badge.svg)](https://github.com/RsaCtfTool/RsaCtfTool/actions/workflows/lint_python.yml)

<br>
[![GitHub issues](https://img.shields.io/github/issues/zbx-sketch/RSAkiller.svg)](https://github.com/zbx-sketch/RSAkiller/issues)
[![GitHub forks](https://img.shields.io/github/forks/zbx-sketch/RSAkiller.svg)](https://github.com/zbx-sketch/RSAkiller/network)
[![GitHub stars](https://img.shields.io/github/stars/zbx-sketch/RSAkiller.svg)](https://github.com/zbx-sketch/RSAkiller/stargazers)
[![GitHub license](https://img.shields.io/github/license/zbx-sketch/RSAkiller.svg)](https://github.com/zbx-sketch/RSAkiller)
[![GitHub contributors](https://img.shields.io/github/contributors/zbx-sketch/RSAkiller.svg)](https://github.com/zbx-sketch/RSAkiller/contributors)

</div>

RSA multi-attack tool that decrypts data from weak public keys and recovers private keys.

## Overview

This tool is a utility designed to decrypt data from weak public keys and attempt to recover the corresponding private key. It offers a comprehensive range of attack options for cracking RSA encryption.

RSA security relies on the complexity of integer factorization. This project combines multiple factorization algorithms to enhance decryption capabilities.

> **Note:** This tool is primarily intended for **educational purposes**. Not every key can be broken in a reasonable timeframe. The tool only supports RSA textbook semiprime composite modulus (not multiprimes).

For advanced factorization, consider [msieve](https://github.com/RsaCtfTool/msieve), [yafu](https://github.com/bbuhrow/yafu), or [cado-nfs](https://gitlab.inria.fr/cado-nfs/cado-nfs).

## Usage

```bash
RsaCtfTool --publickey key.pub --private                   # Recover private key
RsaCtfTool --publickey key.pub --decryptfile ciphertext    # Decrypt file
RsaCtfTool --publickey key.pub --attack wiener             # Use specific attack
```

For complete usage, run: `RsaCtfTool --help`

### Browser Interface

RSAkiller also includes a lightweight browser interface that runs on your computer and uses the same attack engine as the CLI:

```bash
pip install -e .
rsactftool-web
# Or: python -m RsaCtfTool.web
```

The interface opens at `http://127.0.0.1:8765` and listens on the local computer only. Its default **Smart paste** workflow accepts an entire challenge statement, source file, or output transcript; it safely extracts numeric RSA parameters without executing pasted code, selects applicable attacks, decodes likely plaintext formats, and reports mathematical verification. The original public-key / `n` / `e` workflow remains available under **Manual advanced**. The recommended manual attack set avoids online factorization services. Choosing **All attacks** can send the modulus to services such as FactorDB; the interface warns before that option is run. Existing `RsaCtfTool` and `rsacrack` CLI commands are unchanged.

The smart analyser is also available from the command line:

```bash
python -m RsaCtfTool.ctf_solver --input challenge.txt --timeout 120
```

中文启动说明见 [`WEB_UI_zh.md`](WEB_UI_zh.md)，随附笔记的逐题回归矩阵见 [`docs/RSA_NOTE_COVERAGE_zh.md`](docs/RSA_NOTE_COVERAGE_zh.md)。

## Installation

### Prerequisites

- Python 3.9+
- [SageMath](https://www.sagemath.org/) (optional but recommended)

### Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Docker

```bash
docker build -t rsakiller .
docker run -it --rm -v $PWD:/data rsakiller <arguments>
```

## Attacks

### Non-Factorization Attacks

- [Wiener's attack](https://en.wikipedia.org/wiki/Wiener%27s_attack)
- [Hastad's attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#H%C3%A5stad's_broadcast_attack) (small public exponent)
- [Boneh-Durfee](https://staff.emu.edu.tr/alexanderchefranov/Documents/CMSE491/Fall2019/BonehIEEETIT2000%20Cryptanalysis%20of%20RSA.pdf) (small private exponent d < n^0.292)
- Same n, huge e
- [Small CRT exponent](https://en.wikipedia.org/wiki/Chinese_remainder_theorem)
- Partial q / Partial d
- dp / dq leak (`--dp` or `--dq`)
- [Lattice reduction](https://en.wikipedia.org/wiki/Lattice_reduction)

### Coppersmith Attacks

Coppersmith's lattice reduction methods solve for small roots of modular polynomials (requires optional SageMath dependency for lattice LLL reduction).

| Attack | Required Flags | Feasibility Limits | Example Command |
|--------|----------------|--------------------|-----------------|
| `stereotyped_message` | `--sm-len` and (`--sm-prefix` or `--sm-suffix`) | $e \le 17$, $X < N^{1/e}$ | `RsaCtfTool --publickey key.pub --decryptfile cipher.bin --attack stereotyped_message --sm-prefix "FLAG:" --sm-len 16` |
| `short_pad` | `--decryptfile c1,c2` | $e \le 5$, $\Delta < N^{1/e^2}$ | `RsaCtfTool --publickey key.pub --decryptfile c1.bin,c2.bin --attack short_pad` |
| `partial_p` | `--p-high` and `--p-unknown-bits` | $\text{unknown\_bits} \le \lfloor N/4 \rfloor + 2$ ($\approx N^{0.25}$) | `RsaCtfTool --publickey key.pub --attack partial_p --p-high 0x1234... --p-unknown-bits 212 --private` |
| `partial_d` | `--key` (partial private key), optional `--d-known-bits` | Low bits of $d$ known | `RsaCtfTool --key key.priv --partial --attack partial_d --d-known-bits 20` |
| `lattice` | `--key` (partial key with approx of $p$) | Approximation of factor $p$ | `RsaCtfTool --key key.priv --partial --attack lattice` |
| `smallfraction` | `--publickey` | $p/q$ close to small fraction $a/b$ | `RsaCtfTool --publickey key.pub --attack smallfraction --private` |

> **Note for text parameters (`--sm-prefix`, `--sm-suffix`):** Values starting with `0x` or `0X` are parsed as hex byte strings, while all other string inputs are parsed as UTF-8 / ASCII text bytes.

### Integer Factorization Methods

| Method | Description |
|--------|-------------|
| [Fermat](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method) | Close p and q |
| [Pollard Rho](https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm) | General factorization |
| [Elliptic Curve (ECM)](https://en.wikipedia.org/wiki/Lenstra_elliptic-curve_factorization) | Smooth numbers |
| [Pollard p-1](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm) | Smooth numbers |
| [Williams p+1](https://en.wikipedia.org/wiki/Williams%27s_p_%2B_1_algorithm) | Smooth numbers |
| [ROCA](https://en.wikipedia.org/wiki/ROCA_vulnerability) | Vulnerable key generation |
| [SQUFOF](https://en.wikipedia.org/wiki/Shanks%27s_square_forms_factorization) | Square forms |
| [Quadratic Sieve](https://en.wikipedia.org/wiki/Quadratic_sieve) | General factorization |
| [Dixon](https://en.wikipedia.org/wiki/Dixon%27s_factorization_method) | Random squares |
| [Factordb](http://factordb.com/) | Online factorization database |
| Common factor attacks | Keys sharing factors |
| GCD attacks | Mersenne, Primorial, Fibonacci, etc. |

### CTF-Specific Methods

- Noveltyprimes
- Past CTF Primes
- Gimmicky Primes
- Non-RSA (b^x form)
- [Z3 Theorem Prover](https://en.wikipedia.org/wiki/Z3_Theorem_Prover)
- [Wolfram Alpha](https://www.wolframalpha.com/)

## Examples

### Recover Private Key

```bash
RsaCtfTool --publickey key.pub --private
```

### Decrypt a File

```bash
RsaCtfTool --publickey key.pub --decryptfile ciphertext
```

### Attack Multiple Keys

```bash
RsaCtfTool --publickey "*.pub" --private
```

### Create Public Key from n and e

```bash
RsaCtfTool --createpub -n 7828374823761928712873... -e 65537
```

### Dump Key Parameters

```bash
RsaCtfTool --dumpkey --key key.pub
RsaCtfTool --dumpkey --ext --key key.pub  # Include CRT parameters
```

### Factor with ECM

```bash
RsaCtfTool --publickey key.pub --ecmdigits 25 --private
```

### Use Specific Attack

```bash
RsaCtfTool --publickey key.pub --attack wiener --private
RsaCtfTool --publickey key.pub --attack factordb --private
```

### Send Results to Factordb

```bash
RsaCtfTool --publickey "*.pub" --private --sendtofdb
```

### Check for ROCA Vulnerability

```bash
RsaCtfTool --isroca --publickey "examples/*.pub"
```

### Convert SSH Key to PEM

```bash
RsaCtfTool --convert_idrsa_pub --publickey ~/.ssh/id_rsa.pub
```

For more examples, run `pytest tests/ --collect-only` to see available tests.

## Testing

Tests use **pytest** and are located in `tests/`.

### Running Tests

```bash
pytest tests/                 # Run all tests
pytest tests/ -m "not slow"   # Skip slow tests
pytest tests/ -v              # Verbose mode
pytest tests/ -k "fermat"     # Run tests matching "fermat"
```

### Test Markers

- `@pytest.mark.slow` - Slow factorization tests
- `@pytest.mark.network` - Tests requiring network (Factordb)
- `@pytest.mark.attack` - Attack integration tests

### Test Files

| File | Description |
|------|-------------|
| `test_number_theory.py` | Number theory functions (gcd, is_prime, phi, etc.) |
| `test_algos.py` | Factorization algorithms (fermat, brent, pollard_rho, etc.) |
| `test_keys_wrapper.py` | PublicKey/PrivateKey classes |
| `test_utils.py` | Utility functions |
| `test_pubkey_decode.py` | RSA public key decoding |
| `test_attacks.py` | Attack integration tests |
| `test_regression.py` | Bug fix regression tests |
| `test_exceptions.py` | Custom exceptions |
| `conftest.py` | pytest configuration and fixtures |

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## License

This fork retains upstream license and copyright notices. Check the headers of each source file and the included [license notices](LICENSE.txt) before reuse; this repository does not relicense upstream code.

## Thanks

<a href="https://github.com/zbx-sketch/RSAkiller/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=zbx-sketch/RSAkiller" />
</a>
