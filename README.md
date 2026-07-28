# Controlled Text Transfer 0.3.0

**Package & Release:** [![PyPI Version](https://img.shields.io/pypi/v/controlled-text-transfer)](https://pypi.org/project/controlled-text-transfer/) [![Python Versions](https://img.shields.io/pypi/pyversions/controlled-text-transfer)](https://pypi.org/project/controlled-text-transfer/) [![PyPI License](https://img.shields.io/pypi/l/controlled-text-transfer)](https://pypi.org/project/controlled-text-transfer/) [![PyPI Downloads](https://img.shields.io/pypi/dm/controlled-text-transfer)](https://pypi.org/project/controlled-text-transfer/)

**Build & Activity:** [![CI](https://img.shields.io/github/actions/workflow/status/dgomez407/ctt/ci.yml?branch=main&label=CI)](https://github.com/dgomez407/ctt/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/actions/workflow/status/dgomez407/ctt/release.yml?label=Release)](https://github.com/dgomez407/ctt/actions/workflows/release.yml) [![codecov](https://codecov.io/gh/dgomez407/ctt/graph/badge.svg?token=4QW3QNLQP1)](https://codecov.io/gh/dgomez407/ctt) [![Last Commit](https://img.shields.io/github/last-commit/dgomez407/ctt)](https://github.com/dgomez407/ctt/commits/main) [![GitHub Repository](https://img.shields.io/badge/github-dgomez407%2Fctt-181717?logo=github)](https://github.com/dgomez407/ctt)

**Quality & Security:** [![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff) [![Code style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![Checked with mypy](https://img.shields.io/badge/types-Mypy%20Strict-blue)](https://mypy-lang.org/) [![Security: Bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit) [![Dependabot](https://img.shields.io/badge/dependabot-active-brightgreen?logo=dependabot)](https://github.com/dgomez407/ctt/network/updates)

**Controlled Text Transfer (`ctt`)** is a security-oriented CLI tool and Python library for transferring files across strict security boundaries—such as Cross-Domain Solutions (CDS), air-gapped networks, or restricted file transfer drops—that only permit plain text (`.txt`) files.

The `ctt` tool validates source files against explicit compliance policies, packages allowed files into a `.txt`-only transfer format (preserving full original paths and metadata in a signed-ready JSON manifest), and restores exact byte-identical originals at the destination.

Python 3.12.13 or newer is required. Earlier 3.12 patch releases omit upstream
security fixes included in 3.12.13.

---

## Core Transfer Workflow

```text
[ Source Directory ]
         │
         ▼
  1. preflight ──────► Audit source directory files against compliance policy (Read-only)
         │
         ▼
  2. prepare ────────► Package allowlisted files into .txt transfer directory or archive
         │
  [ CDS / Restricted Boundary Transfer ]
         │
         ▼
  3. verify ─────────► Check package directory/archive integrity, hashes & signatures
         │
         ▼
  4. restore ────────► Recreate original files byte-for-byte in destination directory
```

1. **`preflight`**: Inspects a directory to test files against policy rules without making changes.
2. **`prepare`**: Converts approved files to `.txt` transfer copies, adds transport BOMs where configured, generates `ctt-manifest.json.txt`, and publishes a signed-ready bundle.
3. **`verify`**: Validates manifest hashes, path boundaries, package structure, and optional digital signatures before unpacking.
4. **`restore`**: Strips `.txt` transfer extensions and BOMs, recreating exact original files atomically at the destination.

---

## Quick Start

Install official releases directly from [PyPI (`controlled-text-transfer`)](https://pypi.org/project/controlled-text-transfer/):

```bash
pip install controlled-text-transfer
```

Run the core 4-step workflow using zero-configuration defaults:

```bash
# 1. Inspect source directory against policy (prints concise summary)
ctt preflight ./source_dir

# 2. Package allowlisted files into a transfer directory
ctt prepare ./source_dir ./transfer_dir

# 3. Verify transfer package directory (or archive)
ctt verify ./transfer_dir

# 4. Restore original files into a new destination directory
ctt restore ./transfer_dir ./restored_dir
```

> **Path Roles & Optional Flags**:
>
> - **Directory Arguments**: `./source_dir` is the input folder containing files; `./transfer_dir` is the output transfer folder (or archive path); `./restored_dir` is the new output folder where original files are recreated.
> - **Zero Required Flags**: `ctt` works out of the box with zero flags using built-in safe defaults (`generic-text-v1` profile, common text allowlists, SHA-256).
> - **`--json`** (`preflight`): Optional flag to output complete machine-readable JSON details instead of a summary text report.
> - **`--strict`** (`prepare`): Optional flag to fail closed and create nothing if any single candidate file is rejected.
> - **`--policy PATH`**: Optional flag to load custom YAML rules (e.g. `ctt.yaml`) instead of built-in defaults.

For detailed quickstart guidance, see [README-quickstart.md](./README-quickstart.md).

---

## Command Reference

The `ctt` CLI cleanly separates end-user transfer operations from developer maintenance tools.

### Primary Transfer Commands

| Command | Purpose | Default Usage | Expressive Usage with Options |
| --- | --- | --- | --- |
| `preflight` | Produce a read-only policy compatibility report | `ctt preflight ./source_dir` | `ctt preflight ./source_dir --policy ctt.yaml --json` |
| `prepare` | Package allowlisted files into `.txt` transfer format | `ctt prepare ./source_dir ./transfer_dir` | `ctt prepare ./source_dir ./dist/pkg.zip --policy ctt.yaml --strict --json-report report.json --log-json` |
| `verify` | Verify package integrity, manifest, and signatures | `ctt verify ./transfer_dir` | `ctt verify ./transfer.zip --require-signature --log-json` |
| `restore` | Restore original byte-identical files | `ctt restore ./transfer_dir ./restored_dir` | `ctt restore ./transfer.zip ./restored_dir --dry-run --log-json` |

### Secondary Utility Commands

| Command | Purpose | Default Usage | Expressive Usage with Options |
| --- | --- | --- | --- |
| `diff` | Compare transfer package against source directory | `ctt diff ./transfer_dir ./source_dir` | `ctt diff ./transfer.zip ./source_dir --policy ctt.yaml --json` |
| `self-package` | Package CTT itself into a `.txt`-only self-bootstrapping bundle | `ctt self-package ./ctt-bootstrap.zip` | `ctt self-package ./dist/ctt-bootstrap.tgz --source . --format tgz` |

---

## Practical Command Examples

Here are common operational scenarios showing how to combine additional CLI options:

### 1. Pre-Transfer Audit and Reporting

Evaluate a source directory before transfer:

```bash
# Summary stdout report using built-in policy defaults
ctt preflight ./source_dir

# Machine-readable JSON preflight report using custom policy
ctt preflight ./source_dir --policy ctt.yaml --json > preflight-audit.json
```

### 2. Strict Packaging with Manifest Audit & Audit Logging

Enforce strict validation (fail if any candidate file is rejected), save a preflight report, and output a JSON audit event to stderr:

```bash
# Package into a ZIP archive with strict policy enforcement and audit outputs
ctt prepare ./source_dir ./dist/transfer.zip \
  --policy ctt.yaml \
  --strict \
  --json-report ./preflight.json \
  --log-json
```

### 3. Signature Verification & Dry-Run Restoration

Verify digital signatures and test restoration without writing to disk:

```bash
# Verify transfer package requiring an authenticated digital signature
ctt verify ./transfer.zip --require-signature --log-json

# Dry-run restoration to inspect files without writing output
ctt restore ./transfer.zip ./restored_dir --dry-run

# Perform real atomic restoration with JSON audit logging
ctt restore ./transfer.zip ./restored_dir --require-signature --log-json
```

### 4. Package Comparison (`diff`)

Inspect changes between a transfer package and a live source directory:

```bash
ctt diff ./transfer_dir ./source_dir --policy ctt.yaml --json
```

### 5. Self-Bootstrapping Deployment Package

Package the `ctt` application itself into a standalone `.txt`-only transfer bundle with embedded zero-dependency bootstrapper:

```bash
ctt self-package ./dist/ctt-bootstrap.zip --format zip
```

The embedded bootstrap requires Python 3.12.13 or newer. It bounds manifests, ZIP
input, expanded content, member count and size, compression ratios, and paths; it
rejects links, duplicate or encrypted members, and multiple manifests. Because the
zero-dependency bootstrap has no trusted signer integration, it rejects signed
packages. Use the installed `ctt restore` command to authenticate and restore them.

For complete CLI flag documentation, see the [CLI option reference](./docs/cli.md).

---

## Policy and Compliance

`ctt` uses an explicit policy-driven allowlist:

- **Default Policy (No `--policy` flag required)**: UTF-8 decoding, explicit extension/name allowlists, SHA-256 hashes, and a 10 MiB per-file limit.
- **Custom Policy (`--policy PATH`)**: Load custom rules from a YAML file (e.g. `ctt.yaml`).
- **Ignored Files**: Files matching `.cttignore` or failing allowlist criteria are safely omitted from transfer.
- **`generic-text-v1` Profile**: Enforces file count, aggregate size, path depth, character sets, line lengths, control character checks, and forbidden textual patterns.
- **Hash Support**: SHA-256 (default), SHA-512 (`hash_algorithm: sha512`), and optional BLAKE3 (`uv sync --extra blake3`).

See the [policy reference and examples](./docs/policy.md) for full configuration details.

---

## Security & Integrity

- **Atomic Restoration**: Destinations are staged and validated before publication to prevent partial writes.
- **Traversal Prevention**: Every manifest path is verified against a link-free package root.
- **Digital Signatures**: Detached signature hooks in `controlled_text_transfer.signing` integrate with host GPG/X.509 infrastructure. `ctt` fails closed if a signature is missing when `--require-signature` is specified.
- **Bounded Ingestion**: Immutable receiver ceilings bound manifests, signatures,
  archives, expansion, members, paths, and individual files. Security-sensitive
  reads use stable descriptors and archive extraction streams observed bytes.
- **Authenticated Signer Identity**: Identity-bearing manifests require an exact
  identity returned by the trusted verifier; `key_label` is informational only.

See the [security hardening contract](./docs/security-hardening.md) for exact
binary-unit ceilings, compatibility rules, residual risks, and test evidence.

See [SECURITY.md](./SECURITY.md) for detailed security guidance.

---

## Development & Maintenance

Developer workflow and project maintenance scripts are managed separately from user CLI commands:

```bash
# Environment setup
bash scripts/run.sh setup
uv sync --extra dev

# Run test suite and quality gates
bash scripts/run.sh check
uv run --extra dev pytest

# Generate test coverage and API documentation reports
bash scripts/run.sh report

# Clean generated build and test artifacts
bash scripts/run.sh clean --dry-run
bash scripts/run.sh clean
```

For full details on repository scripts and release workflows, see [Development scripts](./scripts/README.md) and [AGENTS.md](./AGENTS.md).

---

## GitHub automation

GitHub-specific automation enforces the same build, test, security, and
release requirements documented for local development. It uses
least-privilege permissions, immutable action references, and locked Python
dependencies.

- [Workflow definitions](./.github/workflows/README.md)
- [`dependabot.yml`](./.github/dependabot.yml) maintains pinned GitHub Actions
  dependencies.

Releases use PyPI Trusted Publishing through `.github/workflows/release.yml`. Configure a pending GitHub publisher for project `controlled-text-transfer`, owner `dgomez407`, repository `ctt`, workflow `release.yml`, and environment `pypi`. After quality gates pass, push a version tag such as `v0.1.0` from a commit contained in `main`. The workflow verifies that the tagged commit belongs to `origin/main`, the tag, package version, README, and changelog agree; reruns the locked quality gates; validates the wheel and source distribution; and publishes them without a stored API token.

---

## Documentation Index

- [Documentation index](./docs/README.md)
- [Operations runbook](./docs/operations.md)
- [Policy reference and examples](./docs/policy.md)
- [Complete CLI option reference](./docs/cli.md)
- [CLI and library API](./docs/api.md)
- [Security guidance](./SECURITY.md)
- [Architecture Decision Records](./docs/decisions/README.md)
- [Changelog](./CHANGELOG.md)
- [Contributor and agent guidelines](./AGENTS.md)
- [Repository-specific agent guidance](./AGENTS-project.md)
- [Gemini agent entry point](./GEMINI.md)

### Repository Map

- [GitHub workflow details](./.github/workflows/README.md)
- [Development scripts](./scripts/README.md)
- [Source code](./src/README.md)
- [Test suite](./tests/README.md)
