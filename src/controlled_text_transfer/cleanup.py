"""Remove reproducible caches and build artifacts from this repository."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

TOP_LEVEL_ARTIFACTS = frozenset(
    {
        "build",
        "dist",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".coverage",
        "coverage.xml",
        "reports",
    }
)
PRUNED_DIRECTORIES = frozenset({".git", ".venv"}) | TOP_LEVEL_ARTIFACTS


class CleanupError(RuntimeError):
    """Report an unsafe or unsuccessful cleanup request."""


@dataclass(frozen=True)
class CleanupResult:
    """Describe the deterministic outcome of a cleanup operation."""

    planned: tuple[Path, ...]
    removed: tuple[Path, ...]


def _sort_paths(paths: set[Path]) -> tuple[Path, ...]:
    return tuple(sorted(paths, key=lambda path: path.as_posix()))


def discover_targets(root: Path, *, include_environment: bool = False) -> tuple[Path, ...]:
    """Return reproducible artifacts below ``root`` without following symlinks."""
    repository = root.resolve(strict=True)
    if not repository.is_dir():
        raise CleanupError(f"repository root is not a directory: {repository}")

    targets = {
        repository / name
        for name in TOP_LEVEL_ARTIFACTS
        if (repository / name).exists() or (repository / name).is_symlink()
    }
    if include_environment:
        environment = repository / ".venv"
        if environment.exists() or environment.is_symlink():
            targets.add(environment)

    for current, directories, _files in os.walk(repository, followlinks=False):
        current_path = Path(current)
        safe_directories: list[str] = []
        for name in directories:
            candidate = current_path / name
            if candidate.is_symlink() or candidate.is_junction():
                if name == "__pycache__" or name.endswith(".egg-info"):
                    targets.add(candidate)
                continue
            if name == "__pycache__" or name.endswith(".egg-info"):
                targets.add(candidate)
                continue
            if current_path == repository and name in PRUNED_DIRECTORIES:
                continue
            safe_directories.append(name)
        directories[:] = safe_directories

    return _sort_paths(targets)


def _assert_safe_target(root: Path, target: Path, *, include_environment: bool) -> None:
    repository = root.resolve(strict=True)
    absolute_target = target.absolute()
    try:
        relative = absolute_target.relative_to(repository)
    except ValueError as exc:
        raise CleanupError(f"cleanup target is outside repository: {target}") from exc
    if len(relative.parts) == 1 and relative.name in TOP_LEVEL_ARTIFACTS:
        return
    if include_environment and relative == Path(".venv"):
        return
    if relative.name == "__pycache__" or relative.name.endswith(".egg-info"):
        return
    raise CleanupError(f"cleanup target is not an approved artifact: {target}")


def _remove_target(target: Path) -> None:
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.is_junction():
        target.rmdir()
    elif target.is_dir():
        shutil.rmtree(target)


def clean_repository(
    root: Path,
    *,
    dry_run: bool = False,
    include_environment: bool = False,
    executable: Path | None = None,
) -> CleanupResult:
    """Remove approved generated artifacts and return the operation result."""
    repository = root.resolve(strict=True)
    targets = discover_targets(repository, include_environment=include_environment)
    environment = repository / ".venv"
    active_executable = (executable or Path(sys.executable)).resolve()
    if include_environment and environment in targets:
        try:
            active_executable.relative_to(environment.resolve())
        except ValueError:
            pass
        else:
            raise CleanupError(
                "refusing to remove the active Python environment; " "run this script with a system Python interpreter"
            )

    for target in targets:
        _assert_safe_target(repository, target, include_environment=include_environment)
    if dry_run:
        return CleanupResult(planned=targets, removed=())

    removed: list[Path] = []
    for target in targets:
        try:
            _remove_target(target)
        except OSError as exc:
            raise CleanupError(f"failed to remove {target}: {exc}") from exc
        removed.append(target)
    return CleanupResult(planned=targets, removed=tuple(removed))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Remove reproducible repository caches and build artifacts.")
    parser.add_argument("--dry-run", action="store_true", help="list targets without deleting")
    parser.add_argument(
        "--environment",
        action="store_true",
        help="also remove .venv; invoke with a Python interpreter outside .venv",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run repository cleanup from the command line."""
    args = _parser().parse_args(argv)
    repository = Path(__file__).resolve().parents[2]
    try:
        result = clean_repository(
            repository,
            dry_run=args.dry_run,
            include_environment=args.environment,
        )
    except CleanupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not result.planned:
        print("No generated artifacts found.")
        return 0
    action = "Would remove" if args.dry_run else "Removed"
    for target in result.planned:
        print(f"{action}: {target.relative_to(repository)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
