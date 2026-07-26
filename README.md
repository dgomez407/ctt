# Controlled Text Transfer 0.1.0

[![PyPI Version](https://img.shields.io/pypi/v/controlled-text-transfer)](https://pypi.org/project/controlled-text-transfer/)
[![GitHub Repo](https://img.shields.io/badge/GitHub-dgomez407%2Fctt-blue?logo=github)](https://github.com/dgomez407/ctt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)

Controlled Text Transfer (`ctt`) prepares an allowlisted set of text files for
a controlled transfer that accepts only `.txt` names. It appends `.txt`,
preserves content and paths in a signed-ready JSON manifest, adds an optional
UTF-8 BOM only to transfer copies, and restores byte-identical originals.
Python 3.12 or newer is required.

For the shortest path to running the application, see
[README-quickstart.md](README-quickstart.md).

## Documentation

- [Documentation index](docs/README.md)
- [Operations runbook](docs/operations.md)
- [Policy reference and examples](docs/policy.md)
- [Complete CLI option reference](docs/cli.md)
- [CLI and library API](docs/api.md)
- [Security guidance](SECURITY.md)
- [Architecture Decision Records](docs/decisions/README.md)
- [Changelog](CHANGELOG.md)
- [Contributor and agent guidelines](AGENTS.md)
- [Repository-specific agent guidance](AGENTS-project.md)
- [Gemini agent entry point](GEMINI.md)

## Repository Map

- [GitHub workflow details](.github/workflows/README.md)
- [Development scripts](scripts/README.md)
- [Source code](src/README.md)
- [Test suite](tests/README.md)

## GitHub automation

GitHub-specific automation enforces the same build, test, security, and
release requirements documented for local development. It uses
least-privilege permissions, immutable action references, and locked Python
dependencies.

- [Workflow definitions](.github/workflows/README.md)
- [`dependabot.yml`](.github/dependabot.yml) maintains pinned GitHub Actions
  dependencies.

## Quick start

Install official releases directly from [PyPI (`controlled-text-transfer`)](https://pypi.org/project/controlled-text-transfer/):

```bash
pip install controlled-text-transfer
# Or install from source:
python -m pip install .

ctt prepare ./source ./transfer --policy ctt.yaml
ctt preflight ./source --policy ctt.yaml --json
ctt verify ./transfer
ctt restore ./transfer ./restored
ctt diff ./transfer ./source --json
```

## Commands

| Command | Purpose |
|---|---|
| `uv run ctt preflight SOURCE --json` | Produce a read-only compatibility report |
| `uv run ctt prepare SOURCE TRANSFER --strict` | Build only when every candidate passes |
| `uv run ctt self-package DESTINATION` | Build .txt-only self-bootstrapping CTT transfer bundle |
| `uv run ctt verify TRANSFER` | Verify a directory or supported archive |
| `uv run ctt restore TRANSFER DESTINATION` | Restore verified original files |
| `uv run --extra dev pytest` | Install missing development tools and run all tests |
| `bash scripts/run.sh check` | Run the complete local quality gate |
| `bash scripts/run.sh report` | Generate browsable API, coverage, quality, and security reports |
| `bash scripts/run.sh bootstrap [PATH]` | Package CTT into a .txt-only self-bootstrapping bundle |
| `bash scripts/run.sh release VERSION` | Align version metadata, verify quality, commit, and tag release |
| `bash scripts/run.sh unrelease VERSION` | Remove local tag and reset release commit for a version |

Use `--dry-run` with `prepare` or `restore` to inspect the operation without
writing. Use `--log-json` for machine-readable audit events. Directory format
publishes the requested directory; `zip`, `tar`, and `tgz` publish only the
corresponding archive.

Use `prepare --strict --json-report preflight.json` to publish nothing when a
candidate is rejected while retaining a deterministic compatibility report.
Verification and restoration accept canonical directories and generated
archives directly. Directory verification rejects linked package or payload
paths, and restoration publishes only after its staged output validates.

`diff` is read-only and reports added, removed, modified, and unchanged
allowlisted files when compared with the source directory.

## Architecture

The package keeps transformation, integrity verification, packaging, signing
hooks, and CLI concerns small and separable. The core uses a policy-driven
allowlist and a versioned manifest; archive creation is optional; signing is
delegated to externally managed key infrastructure. See ADR-001 through
ADR-012 for the rationale and rejected alternatives.

## Policy and detection

The default policy uses an explicit extension/name allowlist, UTF-8 decoding, a 10 MiB per-file limit, and SHA-256. Files that are binary, undecodable, ignored by `.cttignore`, oversized, or not allowlisted are reported in the manifest and never copied. `.cttignore` patterns use simple gitignore-like glob matching.

The concrete `generic-text-v1` compatibility profile also checks aggregate
size, file count, path depth and length, filename characters, line endings,
control characters, Unicode policy, line length, prohibited textual patterns,
and the `.txt` transfer extension. See the
[policy reference](docs/policy.md) for every field, default, and example.

SHA-512 is available through `hash_algorithm: sha512`. BLAKE3 is optional
(`uv sync --extra blake3`) and fails closed with a clear message when
unavailable.

## Security notes

The source directory is never modified. Destination directories must not
already exist. Oversized sources are rejected before content reads. Every
manifest path is checked against a link-free package root to prevent traversal
and external reads. Verification hashes transfer bytes before restoration;
restoration validates a staged destination after removing the transport BOM
and publishes it atomically. Do not treat a checksum as authenticity: use a
separately managed digital signature and verify it in the approved environment.

Signing is exposed through a detached-signature hook in
`controlled_text_transfer.signing`;
integrate approved GPG or X.509 tooling outside this package. Never pass
private keys or passphrases through CLI arguments, environment variables, or
manifest content. See [SECURITY.md](SECURITY.md) for the operating guidance.
Archives should be scanned by the CDS and malware controls; renaming or
encoding is not a bypass.

Packages that declare a signature require a trusted verifier by default.
`--allow-unverified-signature` performs explicitly unauthenticated,
integrity-only verification.

## Development

The Bash dispatcher provides memorable shortcuts:

```bash
bash scripts/run.sh setup
bash scripts/run.sh test
bash scripts/run.sh check
bash scripts/run.sh build
bash scripts/run.sh clean --dry-run
```

Run `bash scripts/run.sh help` for the command summary. The underlying commands
remain available directly:

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run black --check .
uv run mypy src
uv run bandit -r src scripts
```

After deleting `.venv`, either run `uv sync --extra dev` before the quality
commands or use `uv run --extra dev pytest` to install the development extra
and run the complete test suite in one step. Plain `uv run pytest` cannot find
pytest in a newly created runtime-only environment. Use
`uv run --extra dev pytest -q` as the equivalent concise-output alternative.

The package is pipx-friendly because it exposes the `ctt` console script.
Build a standalone executable with `pyinstaller ctt.spec`; keep
generated binaries out of source control.

### Clean generated artifacts

Preview the repository-scoped cleanup, then remove reproducible build and test
artifacts:

```bash
bash scripts/run.sh clean --dry-run
bash scripts/run.sh clean
```

The default removes `build/`, `dist/`, tool caches, `.coverage`,
`__pycache__/`, and `*.egg-info/`; it preserves source, configuration,
`uv.lock`, and `.venv`. To remove `.venv` too, run
`bash scripts/run.sh clean --environment`; the dispatcher selects the first
`python` on `PATH` outside the project environment. The action refuses to
delete its active interpreter. It never
cleans uv's shared global cache because that can affect other projects.

## Publishing

Releases use PyPI Trusted Publishing through
`.github/workflows/release.yml`. Configure a pending GitHub publisher for
project `controlled-text-transfer`, owner `dgomez407`, repository `ctt`,
workflow `release.yml`, and environment `pypi`. After the quality gates pass,
push a version tag such as `v0.1.0` from a commit contained in `main`. The
workflow verifies that the tagged commit belongs to `origin/main`, the tag,
package version, README, and changelog agree; reruns the locked quality gates;
validates the wheel and source distribution; and publishes them without a
stored API token.
