#!/usr/bin/env bash

set -euo pipefail

repository="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository"

usage_summary() {
    cat <<'EOF'
Usage: bash scripts/run.sh COMMAND [ARGS...]

Commands:
  setup      Install locked development dependencies
  test       Run the complete test suite with concise output
  check      Run tests, linting, formatting, typing, and security checks
  report     Generate pydoc, coverage, test, quality, security, and dependency reports
  build      Build the optional standalone executable
  bootstrap  Build .txt-only self-bootstrapping transfer bundle
  release    Align version, validate metadata, check quality, commit, and tag release
  unrelease  Remove local tag and reset release commit for a version
  clean      Remove generated repository artifacts
  help       Show detailed help and subcommand usage
EOF
}

usage_detailed() {
    usage_summary
    cat <<'EOF'

Check Usage:
  bash scripts/run.sh check (Recommended before opening PRs)

  Runs the full pre-PR quality gate:
  - pytest (enforcing 100% coverage)
  - Ruff (linting)
  - Black (formatting)
  - mypy (strict type checking)
  - Bandit (security scanning)

Bootstrap Usage:
  bash scripts/run.sh bootstrap [output_path]

  Packages CTT into a .txt-only self-bootstrapping bundle containing embedded bootstrap.py.txt
  (default: dist/ctt-bootstrap.zip)

Release Usage:
  bash scripts/run.sh release <version>

  Before running release:
  1. Update CHANGELOG.md to convert [Unreleased] notes into:
     ## [<version>] - YYYY-MM-DD
  2. Execute: bash scripts/run.sh release <version>

  The release command automatically:
  - Validates CHANGELOG.md readiness for <version>
  - Bumps project version in pyproject.toml via uv
  - Updates README.md header title to "# Controlled Text Transfer <version>"
  - Runs scripts/check_release.py validation
  - Runs the full quality gate (pytest, ruff, black, mypy, bandit)
  - Stages modified files and creates git commit "chore(release): prepare v<version>"
  - Creates annotated git tag "v<version>"
  - Executes offline snapshot validation via scripts/ctt-release-check.sh

Unrelease Usage:
  bash scripts/run.sh unrelease <version>

  Undoes a local release preparation:
  - Deletes local tag v<version>
  - Resets the release commit (git reset HEAD~1), preserving staged/working files for edits
EOF
}

default_python() {
    local candidate
    while IFS= read -r candidate; do
        if "$candidate" -c '
import sys
from pathlib import Path

environment = (Path(sys.argv[1]) / ".venv").resolve()
executable = Path(sys.executable).resolve()
raise SystemExit(executable == environment or environment in executable.parents)
' "$repository" 2>/dev/null; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done < <(type -a -p python 2>/dev/null)
    return 1
}

if ((!$#)); then
    usage_summary
    exit 0
fi

command="$1"
shift

case "$command" in
    setup)
        exec uv sync --extra dev "$@"
        ;;
    test)
        exec uv run --extra dev pytest -q "$@"
        ;;
    check)
        if (($#)); then
            printf 'error: check does not accept arguments\n' >&2
            exit 2
        fi
        uv run --extra dev pytest -q
        uv run --extra dev ruff check .
        uv run --extra dev black --check .
        uv run --extra dev mypy src
        uv run --extra dev bandit -r src scripts -q
        ;;
    report)
        if python="$(default_python)"; then
            exec "$python" scripts/report.py "$@"
        fi
        exec uv run --extra dev python scripts/report.py "$@"
        ;;
    build)
        exec uv run --extra dev pyinstaller "$@" ctt.spec
        ;;
    release)
        if ((!$#)); then
            printf 'error: release requires a version target (e.g. 0.1.1 or v0.1.1)\n' >&2
            exit 2
        fi
        version="${1#v}"
        shift
        if (($#)); then
            printf 'error: release accepts at most one version argument\n' >&2
            exit 2
        fi
        tag="v$version"

        python_cmd="$(default_python 2>/dev/null || echo "python")"

        printf '==> Validating CHANGELOG.md for release %s...\n' "$version"
        "$python_cmd" -c '
import re, sys
from pathlib import Path
version = sys.argv[1]
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
pattern = rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$"
if not re.search(pattern, changelog, re.MULTILINE):
    sys.exit(f"CHANGELOG.md must contain heading ## [{version}] - YYYY-MM-DD")
' "$version" || {
            printf 'error: CHANGELOG.md is not ready for version %s.\n' "$version" >&2
            printf 'Please update CHANGELOG.md with a heading "## [%s] - YYYY-MM-DD" and empty "[Unreleased]" section.\n' "$version" >&2
            exit 2
        }

        printf '==> Bumping version in pyproject.toml to %s...\n' "$version"
        uv version "$version"

        printf '==> Updating README.md header for %s...\n' "$version"
        "$python_cmd" -c '
import sys
from pathlib import Path
version = sys.argv[1]
readme_path = Path("README.md")
lines = readme_path.read_text(encoding="utf-8").splitlines()
if lines:
    lines[0] = f"# Controlled Text Transfer {version}"
readme_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
' "$version"

        printf '==> Running check_release.py %s...\n' "$tag"
        uv run python scripts/check_release.py "$tag"

        printf '==> Running quality gate (tests, Ruff, Black, mypy, Bandit)...\n'
        uv run --extra dev pytest -q
        uv run --extra dev ruff check .
        uv run --extra dev black --check .
        uv run --extra dev mypy src
        uv run --extra dev bandit -r src scripts -q

        printf '==> Staging release files and creating commit/tag for %s...\n' "$tag"
        git add pyproject.toml README.md CHANGELOG.md
        git commit -m "chore(release): prepare $tag"
        git tag -a "$tag" -m "Release $tag"

        printf '==> Running offline release check...\n'
        bash scripts/ctt-release-check.sh . "$tag" HEAD

        printf '\nRelease %s successfully prepared and tagged locally!\n' "$tag"
        printf 'To complete publication, push main and tag online:\n'
        printf '  git push origin main\n'
        printf '  git push origin %s\n' "$tag"
        ;;
    unrelease)
        if ((!$#)); then
            printf 'error: unrelease requires a version target (e.g. 0.1.1 or v0.1.1)\n' >&2
            exit 2
        fi
        version="${1#v}"
        shift
        if (($#)); then
            printf 'error: unrelease accepts at most one version argument\n' >&2
            exit 2
        fi
        tag="v$version"

        if git tag -l "$tag" | grep -q "^$tag$"; then
            printf '==> Deleting local tag %s...\n' "$tag"
            git tag -d "$tag"
        else
            printf '==> Local tag %s does not exist; skipping tag deletion.\n' "$tag"
        fi

        current_msg="$(git log -1 --pretty=%s 2>/dev/null || true)"
        if [[ "$current_msg" == "chore(release): prepare $tag" ]]; then
            printf '==> Undoing release commit chore(release): prepare %s...\n' "$tag"
            git reset HEAD~1
        else
            printf '==> Current HEAD commit is not "chore(release): prepare %s". Skipping commit reset.\n' "$tag"
        fi

        printf '\nUnreleased %s locally.\n' "$tag"
        printf 'If the tag was already pushed to remote origin, remove it with:\n'
        printf '  git push origin :refs/tags/%s\n' "$tag"
        ;;
    bootstrap)
        output_path="${1:-dist/ctt-bootstrap.zip}"
        if (($# > 1)); then
            printf 'error: bootstrap accepts at most one output_path argument\n' >&2
            exit 2
        fi
        mkdir -p "$(dirname "$output_path")"
        exec uv run ctt self-package "$output_path"
        ;;
    clean)
        if python="$(default_python)"; then
            exec "$python" scripts/clean.py "$@"
        fi
        exec uv run python scripts/clean.py "$@"
        ;;
    help|-h|--help)
        usage_detailed
        ;;
    *)
        printf 'error: unknown command: %s\n' "$command" >&2
        usage_summary >&2
        exit 2
        ;;
esac
