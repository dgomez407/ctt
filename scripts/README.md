# Development Scripts

[Repository home](../README.md)

The [`scripts/`](.) directory contains the development dispatcher [`run.sh`](run.sh) and standalone Python and Bash scripts supporting build, testing, quality audits, reporting, release management, and repository cleanup.

---

## Command Quick Reference

All primary operations are dispatched through `bash scripts/run.sh COMMAND [ARGS...]`.

| Command | Usage | Description | Key Flags / Arguments |
| :--- | :--- | :--- | :--- |
| `setup` | `bash scripts/run.sh setup` | Install locked development dependencies | Accepts `uv sync` options |
| `test` | `bash scripts/run.sh test [args]` | Run pytest suite with concise output | Accepts pytest flags/paths (e.g. `-k`) |
| `check` | `bash scripts/run.sh check` | Execute complete 5-stage quality gate | Rejects extra arguments |
| `report` | `bash scripts/run.sh report [flags]` | Generate indexed HTML/JSON quality & API dashboard | `--pydoc-only`, `--output PATH` |
| `build` | `bash scripts/run.sh build [args]` | Build standalone binary via PyInstaller | Accepts PyInstaller options |
| `release` | `bash scripts/run.sh release <version>` | Align version metadata, verify quality, commit, and tag | Target version (e.g. `0.1.1` or `v0.1.1`) |
| `unrelease` | `bash scripts/run.sh unrelease <version>` | Undo local release preparation tag and commit | Target version (e.g. `0.1.1` or `v0.1.1`) |
| `clean` | `bash scripts/run.sh clean [flags]` | Remove build artifacts and caches | `--dry-run`, `--environment` |
| `help` | `bash scripts/run.sh help` | Show CLI usage reference | `-h`, `--help` |

---

## Subcommand Details

### `setup` — Install Development Dependencies
Installs locked development and testing dependencies into the virtual environment via `uv sync --extra dev`.

```bash
bash scripts/run.sh setup
```

### `test` — Run Test Suite
Runs pytest with dev extras and concise test reporting (`pytest -q`). Any additional arguments are passed directly to `pytest`.

```bash
# Run all tests
bash scripts/run.sh test

# Run a specific test file
bash scripts/run.sh test tests/test_release.py

# Filter tests by keyword
bash scripts/run.sh test -k "release"
```

### `check` — Execute Quality Gate
Runs the repository's mandatory 5-stage quality gate in sequence:
1. `pytest` test suite with 100% statement coverage enforcement.
2. `ruff` code linting and import checks.
3. `black` code formatting verification.
4. `mypy` strict type checking (`src/`).
5. `bandit` security scanning (`src/`, `scripts/`).

```bash
bash scripts/run.sh check
```

### `report` — Generate Quality & API Dashboard
Generates a browsable HTML and JSON report dashboard under `reports/index.html` including pydoc API documentation, coverage reports, test results, linting/typing/security metrics, and dependency trees.

```bash
# Generate full quality and API report dashboard
bash scripts/run.sh report

# Generate API documentation only (fast)
bash scripts/run.sh report --pydoc-only

# Write reports to a custom directory
bash scripts/run.sh report --output /path/to/output
```

Generated reports are ignored by Git. Running `bash scripts/run.sh clean` removes the default `reports/` directory. See [ADR-010](../docs/decisions/0010-offline-report-dashboard.md) for rationale.

### `build` — Package Standalone Executable
Uses PyInstaller and `ctt.spec` to build an un-archived standalone application binary under `dist/`.

```bash
bash scripts/run.sh build
```

### `release` — Prepare & Tag a Release
Automates the preflight, version alignment, quality check, commit, and tagging workflow for a new release version:

1. Validates that `CHANGELOG.md` has an entry for `## [<version>] - YYYY-MM-DD`.
2. Bumps `pyproject.toml` version via `uv version <version>`.
3. Updates line 1 of `README.md` to `# Controlled Text Transfer <version>`.
4. Validates metadata using `scripts/check_release.py v<version>`.
5. Runs the full quality gate (`bash scripts/run.sh check`).
6. Creates local commit `chore(release): prepare v<version>` and annotated tag `v<version>`.
7. Runs offline snapshot validation via `scripts/ctt-release-check.sh . v<version> HEAD`.

```bash
bash scripts/run.sh release 0.1.1
```

After local release preparation succeeds, push to GitHub:
```bash
git push origin main
git push origin v0.1.1
```

### `unrelease` — Roll Back Local Release Preparation
Safely undoes local release preparation if last-minute adjustments are needed before pushing:

```bash
bash scripts/run.sh unrelease 0.1.1
```

1. Deletes the local tag `v<version>`.
2. Resets the release commit (`git reset HEAD~1`), preserving modified files staged in your working copy for easy correction.

### `clean` — Remove Artifacts & Caches
Removes generated build artifacts, report directories, bytecode, coverage files, and caches.

```bash
# Preview files to be removed without deleting
bash scripts/run.sh clean --dry-run

# Remove local caches and build outputs
bash scripts/run.sh clean

# Remove virtual environment (.venv) using external Python
bash scripts/run.sh clean --environment
```

---

## Standalone Script Utilities

The underlying Python and Bash scripts in `scripts/` can also be invoked directly:

- **[`check_release.py`](check_release.py)**: Validates repository release metadata.
  ```bash
  uv run python scripts/check_release.py v0.1.0 [--trusted-ref origin/main]
  ```
- **[`ctt-release-check.sh`](ctt-release-check.sh)**: Performs offline snapshot release verification against local Git history.
  ```bash
  bash scripts/ctt-release-check.sh [repository] [tag] [release-ref]
  ```
- **[`clean.py`](clean.py)**: Performs safe artifact cleanup.
  ```bash
  uv run python scripts/clean.py [--dry-run] [--environment]
  ```
- **[`report.py`](report.py)**: Generates the HTML quality report dashboard.
  ```bash
  uv run python scripts/report.py [--pydoc-only] [--output PATH]
  ```
