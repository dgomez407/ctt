# ADR-013: Release alignment, preflight verification, and unrelease operations

[ADR index](README.md) | [Documentation index](../README.md)

## Status

Accepted

## Date

2026-07-26

## Context

Release alignment across `pyproject.toml`, `README.md`, `CHANGELOG.md`, and Git tags previously relied on manual multi-step execution. Manual release preparation creates risks of version mismatches, unverified tagging, or skipped quality gates. Furthermore, developers need a standardized, safe procedure to undo or suspend local release preparation prior to pushing tags to remote publishing pipelines.

## Decision

Automate release alignment, verification, and rollback through `scripts/run.sh`:

1. Provide `scripts/run.sh release <version>` to orchestrate release preparation:
   - Validate `CHANGELOG.md` readiness (`## [<version>] - YYYY-MM-DD`).
   - Bump `pyproject.toml` version via `uv version <version>`.
   - Align line 1 of `README.md` to `# Controlled Text Transfer <version>`.
   - Validate metadata using `scripts/check_release.py v<version>`.
   - Run the complete quality gate (`scripts/run.sh check`).
   - Create release commit `chore(release): prepare v<version>` and annotated tag `v<version>`.
   - Run offline snapshot verification via `scripts/ctt-release-check.sh . v<version> HEAD`.

2. Provide `scripts/run.sh unrelease <version>` to undo local release preparation:
   - Remove local tag `v<version>`.
   - Reset release commit `chore(release): prepare v<version>` (`git reset HEAD~1`) while preserving working tree changes for corrections.
   - Output remote tag deletion commands in case the tag was pushed prematurely.

3. Retain `scripts/ctt-release-check.sh` as an offline, read-only snapshot validator for clean Git refs.

## Alternatives considered

### Automatic Regex Rewriting of CHANGELOG.md
Rejected because human editorial review of changelog sections (`### Added`, `### Fixed`, etc.) is essential for release accuracy.

### Hard Reset on Unrelease
Rejected because hard resetting (`git reset --hard`) discards working directory edits, preventing developers from making last-minute corrections to changelog notes or README text.

## Consequences

- Release metadata is enforced consistently across all repository files and Git tags.
- Quality gates run automatically prior to commit and tag creation.
- Local release preparation can be cleanly undone using `unrelease`.
