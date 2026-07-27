#!/usr/bin/env bash
#
# Offline Controlled Text Transfer release preflight.
#
# PyPI publishing is triggered only by pushing a v* tag. The repository's
# release validator then requires all of the following to agree:
#   1. tag:                v<project version>
#   2. pyproject.toml:     project.version
#   3. README.md:          "# Controlled Text Transfer <version>"
#   4. CHANGELOG.md:       one dated heading for <version>
#   5. CHANGELOG.md:       an empty Unreleased section
#   6. Git history:        the release commit is contained in origin/main
#
# This script validates an exact Git ref using only local Git data. It extracts
# that committed snapshot into a temporary directory, runs the repository's
# authoritative validator there, and removes the temporary files on exit. It
# does not fetch, commit, tag, push, build, or publish anything. Because it is
# offline, origin/main means the last remote state fetched locally. Its purpose is 
# to catch version, README, changelog, tag, and branch-alignment errors before 
# an irreversible PyPI upload. 
#
# Usage:
#   bash ctt-release-check.sh [repository] [tag] [release-ref]
#
# Examples:
#   bash ctt-release-check.sh
#   bash ctt-release-check.sh ~/code/i/ctt
#   bash ctt-release-check.sh ~/code/i/ctt v0.1.1
#   bash ctt-release-check.sh ~/code/i/ctt v0.1.1 origin/main
#
# A README-only GitHub update needs no version change and no tag. Run this
# helper only when preparing or auditing a release.

set -euo pipefail

repository="${1:-.}"
requested_tag="${2:-}"
release_ref="${3:-origin/main}"

if [[ "$release_ref" == -* ]]; then
    printf 'error: release ref must not start with a dash\n' >&2
    exit 2
fi

if [[ ! -d "$repository" ]]; then
    printf 'error: repository directory does not exist: %s\n' "$repository" >&2
    exit 2
fi

repository="$(cd "$repository" && pwd)"

if command -v python >/dev/null 2>&1; then
    python_command="python"
elif command -v python3 >/dev/null 2>&1; then
    python_command="python3"
else
    printf 'error: Python 3.12 or newer is required\n' >&2
    exit 2
fi

if ! git -C "$repository" rev-parse --verify --quiet "origin/main^{commit}" >/dev/null; then
    printf 'error: local origin/main is unavailable; fetch it while online first\n' >&2
    exit 2
fi

if ! git -C "$repository" rev-parse --verify --quiet "$release_ref^{commit}" >/dev/null; then
    printf 'error: release ref is unavailable locally: %s\n' "$release_ref" >&2
    exit 2
fi

if [[ "$release_ref" != "HEAD" ]] && ! git -C "$repository" merge-base --is-ancestor "$release_ref" origin/main; then
    printf 'error: %s is not contained in the local origin/main reference\n' \
        "$release_ref" >&2
    exit 2
fi

snapshot="$(
    "$python_command" -c \
        'import tempfile; print(tempfile.mkdtemp(prefix="ctt-release-check-"))'
)"
if command -v cygpath >/dev/null 2>&1; then
    snapshot="$(cygpath -m "$snapshot")"
fi
cleanup() {
    "$python_command" -c \
        'import shutil, sys; shutil.rmtree(sys.argv[1], ignore_errors=True)' \
        "$snapshot"
}
trap cleanup EXIT

git -C "$repository" archive "$release_ref" \
    pyproject.toml README.md CHANGELOG.md scripts/check_release.py |
    tar -xf - -C "$snapshot"

project_version="$(
    "$python_command" -c \
        'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["project"]["version"])' \
        "$snapshot/pyproject.toml"
)"
expected_tag="v$project_version"
release_tag="${requested_tag:-$expected_tag}"
release_commit="$(git -C "$repository" rev-parse "$release_ref^{commit}")"

printf 'Repository:       %s\n' "$repository"
printf 'Release ref:      %s\n' "$release_ref"
printf 'Release commit:   %s\n' "$release_commit"
printf 'Project version:  %s\n' "$project_version"
printf 'Expected tag:     %s\n' "$expected_tag"
printf 'Checked tag:      %s\n' "$release_tag"

if [[ "$release_tag" != "$expected_tag" ]]; then
    printf 'error: tag %s does not match project version %s\n' \
        "$release_tag" "$project_version" >&2
    exit 2
fi

(
    cd "$snapshot"
    "$python_command" scripts/check_release.py "$release_tag"
)

printf '\nOffline release validation passed.\n'
printf 'No tag was created and nothing was uploaded.\n'
printf 'Before publishing, fetch origin/main online and repeat this check.\n'
