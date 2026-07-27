import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from controlled_text_transfer import cleanup
from controlled_text_transfer.cleanup import CleanupError, clean_repository, discover_targets


def test_discover_targets_finds_only_reproducible_repository_artifacts(tmp_path: Path):
    expected = {
        tmp_path / "build",
        tmp_path / "dist",
        tmp_path / ".pytest_cache",
        tmp_path / ".mypy_cache",
        tmp_path / ".ruff_cache",
        tmp_path / ".coverage",
        tmp_path / "reports",
        tmp_path / "src" / "package.egg-info",
        tmp_path / "src" / "package" / "__pycache__",
    }
    for directory in expected - {tmp_path / ".coverage"}:
        directory.mkdir(parents=True)
    (tmp_path / ".coverage").write_text("coverage", encoding="utf-8")
    (tmp_path / "src" / "package" / "module.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("locked", encoding="utf-8")

    assert set(discover_targets(tmp_path)) == expected


def test_clean_repository_dry_run_preserves_every_target(tmp_path: Path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "artifact.txt").write_text("data", encoding="utf-8")

    result = clean_repository(tmp_path, dry_run=True)

    assert result.planned == (tmp_path / "build",)
    assert result.removed == ()
    assert (tmp_path / "build" / "artifact.txt").is_file()


def test_clean_repository_removes_artifacts_and_preserves_source(tmp_path: Path):
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "package.whl").write_text("wheel", encoding="utf-8")
    (tmp_path / "src").mkdir()
    source = tmp_path / "src" / "module.py"
    source.write_text("value = 1\n", encoding="utf-8")

    result = clean_repository(tmp_path)

    assert result.removed == (tmp_path / "dist",)
    assert not (tmp_path / "dist").exists()
    assert source.is_file()


def test_environment_is_removed_only_when_explicitly_requested(tmp_path: Path):
    environment = tmp_path / ".venv"
    environment.mkdir()
    (environment / "marker").write_text("generated", encoding="utf-8")

    clean_repository(tmp_path)
    assert environment.is_dir()

    result = clean_repository(
        tmp_path,
        include_environment=True,
        executable=tmp_path / "system-python",
    )
    assert result.removed == (environment,)
    assert not environment.exists()


def test_clean_repository_refuses_to_remove_its_active_environment(tmp_path: Path):
    executable = tmp_path / ".venv" / "Scripts" / "python.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"")

    with pytest.raises(CleanupError, match="active Python environment"):
        clean_repository(tmp_path, include_environment=True, executable=executable)

    assert (tmp_path / ".venv").is_dir()


def test_discover_targets_does_not_follow_directory_symlinks(tmp_path: Path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    external_cache = outside / "__pycache__"
    external_cache.mkdir()
    link = tmp_path / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    assert external_cache not in discover_targets(tmp_path)


def test_clean_repository_removes_linked_cache_without_following_it(tmp_path: Path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside-cache"
    outside.mkdir()
    marker = outside / "marker"
    marker.write_text("preserve", encoding="utf-8")
    linked_cache = tmp_path / "src" / "__pycache__"
    linked_cache.parent.mkdir()
    try:
        linked_cache.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    result = clean_repository(tmp_path)

    assert result.removed == (linked_cache,)
    assert not linked_cache.exists()
    assert marker.is_file()


def test_discover_targets_does_not_follow_windows_reparse_points(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    linked = tmp_path / "junction"
    linked.mkdir()
    nested_cache = linked / "__pycache__"
    nested_cache.mkdir()
    original = Path.is_junction
    monkeypatch.setattr(
        Path,
        "is_junction",
        lambda path: path == linked or original(path),
    )

    assert nested_cache not in discover_targets(tmp_path)


def test_discover_targets_includes_linked_cache_without_following_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    linked_cache = tmp_path / "src" / "__pycache__"
    linked_cache.mkdir(parents=True)
    original = Path.is_junction
    monkeypatch.setattr(
        Path,
        "is_junction",
        lambda path: path == linked_cache or original(path),
    )

    assert discover_targets(tmp_path) == (linked_cache,)


def test_remove_target_uses_junction_safe_directory_removal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    junction = tmp_path / "junction"
    junction.mkdir()
    monkeypatch.setattr(Path, "is_junction", lambda path: path == junction)

    cleanup._remove_target(junction)

    assert not junction.exists()


def test_clean_repository_removes_top_level_artifact_file(tmp_path: Path):
    coverage_data = tmp_path / ".coverage"
    coverage_data.write_text("coverage", encoding="utf-8")

    result = clean_repository(tmp_path)

    assert result.removed == (coverage_data,)
    assert not coverage_data.exists()


def test_cleanup_wrapper_runs_without_an_installed_package():
    result = subprocess.run(
        [sys.executable, "-S", "scripts/clean.py", "--dry-run"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_discover_targets_rejects_a_file_as_repository_root(tmp_path: Path):
    root = tmp_path / "not-a-directory"
    root.write_text("data", encoding="utf-8")

    with pytest.raises(CleanupError, match="root is not a directory"):
        discover_targets(root)


def test_clean_repository_rejects_a_discovered_target_outside_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    outside = tmp_path.parent / f"{tmp_path.name}-outside-target"
    outside.mkdir(exist_ok=True)
    monkeypatch.setattr(cleanup, "discover_targets", lambda *_args, **_kwargs: (outside,))

    with pytest.raises(CleanupError, match="outside repository"):
        clean_repository(tmp_path)

    assert outside.is_dir()


def test_clean_repository_rejects_an_unapproved_discovered_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.setattr(cleanup, "discover_targets", lambda *_args, **_kwargs: (source,))

    with pytest.raises(CleanupError, match="not an approved artifact"):
        clean_repository(tmp_path)

    assert source.is_dir()


def test_clean_repository_reports_filesystem_removal_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    artifact = tmp_path / "build"
    artifact.mkdir()

    def fail_remove(_target: Path) -> None:
        raise PermissionError("access denied")

    monkeypatch.setattr(cleanup, "_remove_target", fail_remove)

    with pytest.raises(CleanupError, match=r"failed to remove .*access denied"):
        clean_repository(tmp_path)

    assert artifact.is_dir()


def test_cleanup_cli_reports_when_no_artifacts_are_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr(
        cleanup,
        "clean_repository",
        lambda *_args, **_kwargs: cleanup.CleanupResult((), ()),
    )

    assert cleanup.main([]) == 0
    assert capsys.readouterr().out == "No generated artifacts found.\n"


def test_cleanup_cli_prints_dry_run_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    repository = Path(cleanup.__file__).resolve().parents[2]
    target = repository / "build"
    monkeypatch.setattr(
        cleanup,
        "clean_repository",
        lambda *_args, **_kwargs: cleanup.CleanupResult((target,), ()),
    )

    assert cleanup.main(["--dry-run"]) == 0
    assert capsys.readouterr().out == "Would remove: build\n"


def test_cleanup_cli_converts_cleanup_errors_to_exit_status(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    def fail_clean(*_args: object, **_kwargs: object) -> cleanup.CleanupResult:
        raise CleanupError("unsafe request")

    monkeypatch.setattr(cleanup, "clean_repository", fail_clean)

    assert cleanup.main([]) == 1
    assert capsys.readouterr().err == "error: unsafe request\n"


def test_cleanup_module_entry_point_exits_with_main_status(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(sys, "argv", [str(Path(cleanup.__file__)), "--dry-run"])

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(cleanup.__file__, run_name="__main__")

    assert exit_info.value.code == 0
