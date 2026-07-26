# Repository Guidelines

## Project Structure & Module Organization

Package code is under `src/controlled_text_transfer/`. `core.py` owns policy validation,
preflight, packaging, verification, archive ingestion, and restoration;
`cli.py` defines the command-line interface; and `signing.py` provides
detached-signature integrations. Tests live in `tests/`. User and operator
guidance is in `README.md`, `SECURITY.md`, and `docs/`; durable design
decisions are recorded in `docs/decisions/`. Safe configuration examples are
`ctt.yaml.example` and `.cttignore.example`.

Run all commands from the repository root.

## Build, Test, and Development Commands

- `bash scripts/run.sh test` runs the complete test suite with concise output.
- `bash scripts/run.sh check` runs tests, Ruff, Black, mypy, and Bandit.
- `bash scripts/run.sh report` generates indexed API and quality reports.
- `bash scripts/run.sh build` builds the optional standalone executable.
- `bash scripts/run.sh release <version>` aligns version metadata, verifies quality, commits, and tags a release.
- `bash scripts/run.sh unrelease <version>` removes local tag and resets local release commit.
- `bash scripts/run.sh clean --dry-run` previews repository cleanup.
- `bash scripts/run.sh clean --environment` removes `.venv` with an external Python.
- `bash scripts/run.sh help` lists all dispatcher commands.
- `uv sync --extra dev` installs locked development dependencies.
- `uv run --extra dev pytest` installs missing dev tools and runs all tests.
- `uv run pytest` is valid after `uv sync --extra dev`.
- `uv run ruff check .` checks imports, correctness, upgrades, and security.
- `uv run black --check .` verifies formatting.
- `uv run mypy src` runs strict type checking with unreachable-code detection.
- `uv run bandit -r src scripts -q` scans application and development code for security issues.
- `uv run ctt --help` exercises the local CLI.
- `uv run python scripts/clean.py --dry-run` previews generated-artifact cleanup.
- `uv run python scripts/clean.py` removes repository-local caches and builds.

## Coding Style & Naming Conventions

Support Python 3.12 and newer, use four-space indentation and a 100-character line limit,
and keep Black, Ruff, and strict mypy clean. Use `snake_case` for modules and
functions, `PascalCase` for classes, and `UPPER_SNAKE_CASE` for constants.
Every public Python module, class, method, and function must have a concise
Google-style docstring; Ruff `D` rules enforce this requirement.
Keep untrusted policy, manifest, path, and archive validation fail-closed.

## Testing Guidelines

Use pytest files named `tests/test_*.py` and tests named `test_<behavior>`.
Prefer real filesystem scenarios with `tmp_path`. Every behavior change needs
a regression test covering success and failure; security-sensitive changes
must include malformed or adversarial input. The suite enforces 100% aggregate
statement coverage and omits fully covered modules from its report. Prioritize
observable failure and security behavior over tests written only to execute a
line. Run the complete quality gate before review.

Before completion, build a requirement-to-test matrix from the task, ADRs,
README, API and policy documentation, CLI help, configuration examples, and
security guidance. Every documented behavior, policy field or value, command
path, failure mode, and round-trip workflow must map to an automated test or an
explicit justified exception. Parse documented YAML examples with
`Policy.from_file`, verify documented extras against `pyproject.toml`, and test
statements about which commands consume policy. Coverage percentage alone is
not evidence that this audit is complete.

## Commit & Pull Request Guidelines

Use focused, imperative Conventional Commit subjects, such as
`fix: reject duplicate archive members`. Pull requests should explain intent
and security impact, link relevant issues or ADRs, list verification commands,
and update documentation and `CHANGELOG.md` for public behavior changes.
Use the `documentation-and-adrs` skill when changing public APIs, architecture,
security contracts, or user-facing behavior. Audit the README, API reference,
runbook, security guidance, changelog, examples, and ADR index as applicable.

## Security & Architecture

Never commit keys, passphrases, transfer packages, or generated binaries.
Use the guarded cleanup action instead of broad deletion commands; `.venv`
removal requires `--environment` and a Python interpreter outside `.venv`.
Preserve atomic publication, bounded archive extraction, trusted signer
injection, and post-transfer verification. Read `SECURITY.md` before changing
integrity or signing behavior. Add a sequential ADR instead of deleting or
rewriting an accepted historical decision.
