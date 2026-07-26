import zipfile
from pathlib import Path

import pytest

from controlled_text_transfer.bootstrap import restore_bootstrap
from controlled_text_transfer.cli import main as cli_main
from controlled_text_transfer.core import self_package

ROOT = Path(__file__).resolve().parents[1]


def test_self_package_creates_zip_and_restores_via_bootstrap(tmp_path: Path):
    target_zip = tmp_path / "ctt-bootstrap.zip"
    manifest, created_path = self_package(target_zip, package_format="zip")

    assert created_path == target_zip
    assert created_path.is_file()
    assert len(manifest.files) > 0

    with zipfile.ZipFile(target_zip, "r") as z:
        names = z.namelist()
        for name in names:
            assert name.endswith(".txt") or name.endswith("/")
        assert any(n.endswith("bootstrap.py.txt") for n in names)

    restored_dest = tmp_path / "restored_ctt"
    restore_bootstrap(target_zip, restored_dest)

    assert restored_dest.is_dir()
    assert (restored_dest / "pyproject.toml").is_file()
    assert (restored_dest / "README.md").is_file()
    assert (restored_dest / "src" / "controlled_text_transfer" / "core.py").is_file()
    assert (restored_dest / "src" / "controlled_text_transfer" / "bootstrap.py").is_file()

    # Compare restored bytes with original source
    orig_core = (ROOT / "src" / "controlled_text_transfer" / "core.py").read_bytes()
    rest_core = (restored_dest / "src" / "controlled_text_transfer" / "core.py").read_bytes()
    assert rest_core == orig_core


def test_cli_self_package_subcommand(tmp_path: Path):
    pkg_dir = tmp_path / "self_pkg_dir"
    exit_code = cli_main(["self-package", str(pkg_dir), "--format", "directory"])
    assert exit_code == 0
    assert pkg_dir.is_dir()
    assert (pkg_dir / "ctt-manifest.json.txt").is_file()


def test_self_package_options_and_error_handling(tmp_path: Path):
    from controlled_text_transfer.core import Policy, TransferError

    # Test auto-appending .zip suffix
    no_ext = tmp_path / "bundle_no_ext"
    m, created = self_package(no_ext, package_format="zip")
    assert created == tmp_path / "bundle_no_ext.zip"
    assert created.is_file()

    # Test explicit policy
    custom_policy = Policy(package_format="zip")
    m2, created2 = self_package(tmp_path / "custom.zip", policy=custom_policy)
    assert created2.is_file()

    # Test unsupported package format
    with pytest.raises(TransferError, match="unsupported package format"):
        self_package(tmp_path / "invalid", package_format="invalid")


def test_self_package_fallback_pkg_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    orig_is_file = Path.is_file
    first_check = True

    def mock_is_file(self: Path) -> bool:
        nonlocal first_check
        if self.name == "pyproject.toml" and first_check:
            first_check = False
            return False
        return orig_is_file(self)

    monkeypatch.setattr(Path, "is_file", mock_is_file)
    m, created = self_package(tmp_path / "fallback.zip", package_format="zip")
    assert created.is_file()
