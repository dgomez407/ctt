# Changelog

## [Unreleased]

### Added

- `release` and `unrelease` subcommands in `scripts/run.sh` to automate release preflight alignment, metadata validation, quality gates, git tagging, and local rollback operations.
- Offline release snapshot validation helper (`scripts/ctt-release-check.sh`).
- Comprehensive subcommand, flag, and utility reference guide in `scripts/README.md`.
- Architecture Decision Record [ADR-013](docs/decisions/0013-release-alignment-and-rollback-operations.md) for release alignment and unrelease operations.

## [0.1.0] - 2026-07-25

### Added

- `prepare`, `verify`, `restore`, and read-only `diff` commands.
- Strict YAML policies and `.cttignore` filtering; unknown policy fields,
  including `workers`, fail validation.
- UTF-8 validation, optional transfer BOMs, and original BOM restoration.
- Allowlist-based text selection and binary/oversize reporting.
- Deterministic manifest generation.
- SHA-256 and SHA-512 hashing with optional BLAKE3.
- Directory, ZIP, TAR, and TAR.GZ package output.
- Structured JSON audit logging and dry-run modes.
- Detached signing hooks for externally managed GPG/X.509 workflows.
- Named compatibility preflight with deterministic JSON decisions, strict
  policy parsing, content checks, aggregate limits, and strict preparation.
- Guarded repository cleanup with dry-run reporting and optional environment
  removal, including source-checkout operation through an external Python
  interpreter.
- Stable source capture, staged self-verification, and atomic package
  publication; archive formats publish only the requested archive.
- Safe direct verification and restoration of ZIP, TAR, and TAR.GZ packages.
- Enforceable detached manifest signatures using trusted injected signers,
  with trusted verification required by default for signed packages.
- Pytest coverage, Ruff, Black, MyPy, Bandit, GitHub Actions, PyInstaller,
  release-metadata validation, and distribution checks. The suite enforces
  100% application statement coverage, MyPy checks unreachable code, and
  Bandit scans application and development scripts.
- A `scripts/run.sh` development dispatcher with setup, test, check, report,
  build, and guarded cleanup commands. The report command generates indexed
  pydoc, test, coverage, static-analysis, security, dependency, and runtime
  reports.
- Command-scoped CLI options, descriptive built-in help, and executable
  contracts for every advertised option.
- The Controlled Text Transfer identity: distribution
  `controlled-text-transfer`, package `controlled_text_transfer`, command
  `ctt`, policy `ctt.yaml`, ignore file `.cttignore`, and manifest prefix
  `ctt-manifest`.
- Python 3.12 as the minimum supported runtime, including native
  junction-safe filesystem inspection.
- CI using locked dependencies and the canonical quality gate on pushes to
  `dev` and `main` and on pull requests targeting `main`.
- Weekly Dependabot maintenance for commit-SHA-pinned GitHub Actions.
- Publication metadata linking to the `dgomez407/ctt` repository.
- Fail-closed rejection of unsupported package formats before output is
  written.
- Controlled library and CLI errors for malformed manifests.
- Publication documentation, ADRs, security guidance, and configuration
  examples in the source distribution.
- An offline, responsive report dashboard with test and coverage metrics,
  accessible status presentation, formatted raw-output views, and navigation
  from generated API documentation.
- Responsive, navigable pydoc pages with readable signatures and docstrings,
  mobile layouts, preserved API anchors, and print styling.
- Fail-closed pydoc link post-processing that preserves generated application
  targets and renders unavailable local targets as code.
- Complete pydoc coverage for `__main__` and unambiguous
  dashboard/package/module breadcrumbs with full module titles.
- Security guidance, operational runbook, API reference, and ADRs.

### Changed

### Fixed

### Security

- Reject path traversal, symlink payload files, unexpected payload files, and
  existing restore destinations.
- Reject secret-bearing signing command arguments.
- Reject oversized source files before reading their contents.
- Reject linked package roots, metadata sidecars, payload roots, and payload
  descendants.
- Restrict manifest hashes to SHA-256, SHA-512, or optional BLAKE3 and restored
  modes to ordinary permission bits.
- Restore through verified sibling staging so failures leave no partial
  destination.
- Reject secret-bearing external signer flags in assignment form.
- GitHub Actions use explicit least-privilege permissions and immutable
  dependency references.
- Releases use locked build tools and reject tagged commits that are not
  contained in `origin/main`.
