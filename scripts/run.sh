#!/usr/bin/env bash

set -euo pipefail

repository="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository"

usage() {
    cat <<'EOF'
Usage: bash scripts/run.sh COMMAND [ARGS...]

Commands:
  setup    Install locked development dependencies
  test     Run the complete test suite with concise output
  check    Run tests, linting, formatting, typing, and security checks
  report   Generate pydoc, coverage, test, quality, security, and dependency reports
  build    Build the optional standalone executable
  clean    Remove generated repository artifacts
  help     Show this help
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

command="${1:-help}"
if (($#)); then
    shift
fi

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
    clean)
        if python="$(default_python)"; then
            exec "$python" scripts/clean.py "$@"
        fi
        exec uv run python scripts/clean.py "$@"
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        printf 'error: unknown command: %s\n' "$command" >&2
        usage >&2
        exit 2
        ;;
esac
