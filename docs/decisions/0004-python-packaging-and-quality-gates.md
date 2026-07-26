# ADR-004: Use a small Python package with reproducible quality gates

[ADR index](README.md) | [Documentation index](../README.md)

## Status

Accepted

## Date

2026-07-25

## Context

The utility may need to run in restricted environments where a large runtime
stack is undesirable. It also needs a normal Python installation path, a
single-file executable option, and repeatable checks before release.

## Decision

Use a `pyproject.toml` package with a console script, standard-library core
logic, and PyYAML for policy parsing. Support installation through pip/pipx
and standalone builds through PyInstaller. Run pytest with coverage, Ruff,
Black, MyPy, and Bandit in GitHub Actions.

## Alternatives considered

### A larger transfer framework

Rejected because it would add dependencies and operational complexity without
solving the specific reversible text transformation requirement.

### A single script with no package metadata

Rejected because pipx installation, versioning, testing, and PyInstaller
builds are less reliable without a standard package boundary.

### Runtime-only manual testing

Rejected because integrity and security behavior need repeatable automated
regression tests and static analysis.

## Consequences

- The core remains deployable in constrained environments.
- Optional BLAKE3 support does not become a mandatory dependency.
- CI catches formatting, typing, security-lint, and behavioral regressions.
- Release builds should exclude virtual environments, caches, and generated
  binaries from source archives.

## Related implementation

- `pyproject.toml`: packaging and tool configuration.
- `ctt.spec`: PyInstaller build definition.
- `.github/workflows/ci.yml`: automated quality gates.
