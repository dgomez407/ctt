"""Validate repository metadata before building a tagged release."""

from __future__ import annotations

import argparse
import re
import subprocess  # nosec B404
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ReleaseCheckError(ValueError):
    """Report inconsistent release metadata without exposing a traceback."""


def _project_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        version = tomllib.load(stream)["project"]["version"]
    if not isinstance(version, str):
        raise ReleaseCheckError("project version must be a string")
    return version


def require_trusted_ref(repository: Path, trusted_ref: str) -> None:
    """Require the checked-out release commit to be contained in a trusted ref."""
    # The trusted CI ref is passed in a fixed argument vector; shell execution stays disabled.
    result = subprocess.run(  # nosec B603 B607
        ["git", "merge-base", "--is-ancestor", "HEAD", "--", trusted_ref],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 1:
        raise ReleaseCheckError(f"release commit is not contained in trusted ref {trusted_ref}")
    if result.returncode != 0:
        raise ReleaseCheckError(f"could not verify trusted ref {trusted_ref}")


def check_release(tag: str) -> str:
    """Return the version after validating its tag and publication documents."""
    version = _project_version()
    expected_tag = f"v{version}"
    if tag != expected_tag:
        raise ReleaseCheckError(f"tag {tag} does not match project version {version}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if not readme.startswith(f"# Controlled Text Transfer {version}\n"):
        raise ReleaseCheckError(f"README title does not identify version {version}")

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release_heading = re.compile(
        rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$",
        re.MULTILINE,
    )
    if len(release_heading.findall(changelog)) != 1:
        raise ReleaseCheckError(f"changelog must contain one dated {version} release")

    unreleased_content = changelog.partition("## [Unreleased]")[2].partition("\n## ")[0]
    unreleased_items = re.sub(r"(?m)^###\s+.*$", "", unreleased_content).strip()
    if unreleased_items:
        raise ReleaseCheckError("changelog has unreleased changes; assign them to the release")

    return version


def main(argv: list[str] | None = None) -> int:
    """Run release validation as a command-line program."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="Git tag expected to match the project version, such as v0.1.0")
    parser.add_argument(
        "--trusted-ref",
        help="Git ref that must contain the checked-out release commit, such as origin/main",
    )
    args = parser.parse_args(argv)
    try:
        version = check_release(args.tag)
        if args.trusted_ref is not None:
            require_trusted_ref(ROOT, args.trusted_ref)
    except (OSError, KeyError, tomllib.TOMLDecodeError, ReleaseCheckError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"release metadata is consistent for v{version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
