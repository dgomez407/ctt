import sys
import zipfile
from pathlib import Path

import pytest

from controlled_text_transfer.bootstrap import restore_bootstrap
from controlled_text_transfer.cli import main as cli_main
from controlled_text_transfer.core import Policy, TransferError, self_package

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

    # Test tgz format and suffix deduplication when target already ends with .tgz or .tar.gz
    target_tgz = tmp_path / "bundle1.tgz"
    m_tgz, created_tgz = self_package(target_tgz, package_format="tgz")
    assert created_tgz == tmp_path / "bundle1.tgz"
    assert created_tgz.is_file()

    target_targz = tmp_path / "bundle2.tar.gz"
    m_targz, created_targz = self_package(target_targz, package_format="tgz")
    assert created_targz == tmp_path / "bundle2.tgz"
    assert created_targz.is_file()

    # Test explicit policy
    custom_policy = Policy(package_format="zip")
    m2, created2 = self_package(tmp_path / "custom.zip", policy=custom_policy)
    assert created2.is_file()

    # Test unsupported package format
    with pytest.raises(TransferError, match="unsupported package format"):
        self_package(tmp_path / "invalid", package_format="invalid")


def test_self_package_with_explicit_source_and_meipass(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from controlled_text_transfer.core import _find_bootstrap_file

    # Test explicit source parameter
    m, created = self_package(tmp_path / "explicit_src.zip", source=ROOT, package_format="zip")
    assert created.is_file()

    # Test MEIPASS mock
    fake_mei = tmp_path / "mei"
    mei_bootstrap_dir = fake_mei / "controlled_text_transfer"
    mei_bootstrap_dir.mkdir(parents=True)
    fake_bootstrap = mei_bootstrap_dir / "bootstrap.py"
    fake_bootstrap.write_bytes(b"# mei bootstrap\n")

    monkeypatch.setattr(sys, "_MEIPASS", str(fake_mei), raising=False)
    found = _find_bootstrap_file(ROOT)
    assert found == fake_bootstrap


def test_self_package_fallback_resolution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    # Mock cwd to non-repo directory so cwd pyproject.toml check is False
    monkeypatch.chdir(tmp_path)

    # Test parent resolution hit
    m1, created1 = self_package(tmp_path / "fallback1.zip", package_format="zip")
    assert created1.is_file()

    # Mock Path.is_file to test final cwd fallback
    orig_is_file = Path.is_file

    def mock_is_file(self: Path) -> bool:
        if self.name == "pyproject.toml":
            return False
        return orig_is_file(self)

    monkeypatch.setattr(Path, "is_file", mock_is_file)
    m2, created2 = self_package(tmp_path / "fallback2.zip", package_format="zip")
    assert created2.is_file()


def test_find_bootstrap_file_none(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from controlled_text_transfer.core import _find_bootstrap_file

    monkeypatch.setattr(Path, "is_file", lambda self: False)
    assert _find_bootstrap_file(tmp_path) is None


def test_self_package_rejects_non_standard_hash_algorithm(tmp_path: Path):
    invalid_policy = Policy(hash_algorithm="blake3")
    with pytest.raises(TransferError, match="self-package requires standard library hash algorithm"):
        self_package(tmp_path / "blake3_pkg.zip", policy=invalid_policy)
