import hashlib
import json
import sys
import zipfile
from pathlib import Path

import pytest

from controlled_text_transfer.bootstrap import (
    BootstrapError,
    main,
    restore_bootstrap,
)

ROOT = Path(__file__).resolve().parents[1]


def _make_dummy_package(tmp_path: Path) -> tuple[Path, Path]:
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir(parents=True, exist_ok=True)

    file1_bytes = b"# Controlled Text Transfer 0.1.0\n"
    file1_hash = hashlib.sha256(file1_bytes).hexdigest()

    (pkg_dir / "README.md.txt").write_bytes(file1_bytes)

    manifest = {
        "manifest_version": "1.0",
        "hash_algorithm": "sha256",
        "files": [
            {
                "original_path": "README.md",
                "transfer_path": "README.md.txt",
                "status": "allowlisted",
                "transfer_sha256": file1_hash,
                "has_bom": False,
            }
        ],
    }

    (pkg_dir / "ctt-manifest.json.txt").write_bytes(json.dumps(manifest).encode("utf-8"))
    return pkg_dir, tmp_path / "dest"


def test_bootstrap_restores_directory_package(tmp_path: Path):
    pkg_dir, dest = _make_dummy_package(tmp_path)
    result_dest = restore_bootstrap(pkg_dir, dest)

    assert result_dest.is_dir()
    assert (result_dest / "README.md").is_file()
    assert (result_dest / "README.md").read_bytes() == b"# Controlled Text Transfer 0.1.0\n"


def test_bootstrap_restores_zip_package(tmp_path: Path):
    pkg_dir, dest = _make_dummy_package(tmp_path)
    zip_path = tmp_path / "pkg.zip"

    with zipfile.ZipFile(zip_path, "w") as archive:
        for file_path in pkg_dir.rglob("*"):
            if file_path.is_file():
                archive.write(file_path, file_path.relative_to(pkg_dir))

    result_dest = restore_bootstrap(zip_path, dest)
    assert result_dest.is_dir()
    assert (result_dest / "README.md").read_bytes() == b"# Controlled Text Transfer 0.1.0\n"


def test_bootstrap_rejects_missing_package_source(tmp_path: Path):
    with pytest.raises(BootstrapError, match="package source does not exist"):
        restore_bootstrap(tmp_path / "missing", tmp_path / "dest")


def test_bootstrap_rejects_existing_destination(tmp_path: Path):
    pkg_dir, dest = _make_dummy_package(tmp_path)
    dest.mkdir(parents=True, exist_ok=True)
    with pytest.raises(BootstrapError, match="destination directory already exists"):
        restore_bootstrap(pkg_dir, dest)


def test_bootstrap_rejects_tampered_payload_hash(tmp_path: Path):
    pkg_dir, dest = _make_dummy_package(tmp_path)
    # Modify payload file to break hash
    (pkg_dir / "README.md.txt").write_bytes(b"tampered content\n")

    with pytest.raises(BootstrapError, match="integrity check failed"):
        restore_bootstrap(pkg_dir, dest)
    assert not dest.exists()


def test_bootstrap_rejects_path_traversal_attempt(tmp_path: Path):
    pkg_dir = tmp_path / "pkg_traversal"
    pkg_dir.mkdir(parents=True, exist_ok=True)

    file_bytes = b"bad\n"
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    (pkg_dir / "bad.txt").write_bytes(file_bytes)

    manifest = {
        "manifest_version": "1.0",
        "hash_algorithm": "sha256",
        "files": [
            {
                "original_path": "../evil.py",
                "transfer_path": "bad.txt",
                "status": "allowlisted",
                "transfer_sha256": file_hash,
                "has_bom": False,
            }
        ],
    }
    (pkg_dir / "ctt-manifest.json.txt").write_bytes(json.dumps(manifest).encode("utf-8"))

    dest = tmp_path / "dest_traversal"
    with pytest.raises(BootstrapError, match="path traversal rejected"):
        restore_bootstrap(pkg_dir, dest)


def test_bootstrap_hash_file_and_bytes_algorithms(tmp_path: Path):
    from controlled_text_transfer.bootstrap import _hash_bytes, _hash_file

    sample_file = tmp_path / "sample.txt"
    sample_file.write_bytes(b"hello sha512\n")

    h512_file = _hash_file(sample_file, "sha512")
    h512_bytes = _hash_bytes(b"hello sha512\n", "sha512")
    assert h512_file == h512_bytes == hashlib.sha512(b"hello sha512\n").hexdigest()

    with pytest.raises(BootstrapError, match="unsupported hash algorithm"):
        _hash_file(sample_file, "unsupported")

    with pytest.raises(BootstrapError, match="unsupported hash algorithm"):
        _hash_bytes(b"data", "unsupported")


def test_bootstrap_restores_nested_manifest_and_bom(tmp_path: Path):
    nested_dir = tmp_path / "outer" / "inner"
    nested_dir.mkdir(parents=True, exist_ok=True)

    file_bytes = b"bom test content\n"
    file_hash = hashlib.sha256(b"\xef\xbb\xbf" + file_bytes).hexdigest()

    # Payload with transport BOM added
    (nested_dir / "file.txt").write_bytes(b"\xef\xbb\xbf" + file_bytes)

    manifest = {
        "manifest_version": "1.0",
        "hash_algorithm": "sha256",
        "files": [
            {
                "original_path": "file.md",
                "transfer_path": "file.txt",
                "status": "allowlisted",
                "transfer_sha256": file_hash,
                "has_bom": False,
            },
            {
                "original_path": "ignored.bin",
                "transfer_path": "ignored.bin.txt",
                "status": "rejected",
            },
        ],
    }

    # Write manifest with UTF8 BOM prefix
    manifest_bytes = b"\xef\xbb\xbf" + json.dumps(manifest).encode("utf-8")
    (nested_dir / "ctt-manifest.json.txt").write_bytes(manifest_bytes)

    dest = tmp_path / "dest_nested"
    result_dest = restore_bootstrap(tmp_path / "outer", dest)
    assert (result_dest / "file.md").read_bytes() == file_bytes


def test_bootstrap_rejects_corrupt_manifest_json(tmp_path: Path):
    pkg_dir = tmp_path / "corrupt_pkg"
    pkg_dir.mkdir()
    (pkg_dir / "ctt-manifest.json.txt").write_bytes(b"invalid json")

    with pytest.raises(BootstrapError, match="failed to decode manifest JSON"):
        restore_bootstrap(pkg_dir, tmp_path / "dest_corrupt")


def test_bootstrap_rejects_incomplete_manifest_entry(tmp_path: Path):
    pkg_dir = tmp_path / "incomplete_pkg"
    pkg_dir.mkdir()
    manifest = {
        "manifest_version": "1.0",
        "files": [{"status": "allowlisted", "original_path": "a.txt"}],
    }
    (pkg_dir / "ctt-manifest.json.txt").write_bytes(json.dumps(manifest).encode("utf-8"))

    with pytest.raises(BootstrapError, match="incomplete manifest entry"):
        restore_bootstrap(pkg_dir, tmp_path / "dest_inc")


def test_bootstrap_rejects_missing_payload_file(tmp_path: Path):
    pkg_dir = tmp_path / "missing_payload_pkg"
    pkg_dir.mkdir()
    manifest = {
        "manifest_version": "1.0",
        "hash_algorithm": "sha256",
        "files": [
            {
                "original_path": "missing.txt",
                "transfer_path": "missing.txt.txt",
                "status": "allowlisted",
                "transfer_sha256": "abc",
            }
        ],
    }
    (pkg_dir / "ctt-manifest.json.txt").write_bytes(json.dumps(manifest).encode("utf-8"))

    with pytest.raises(BootstrapError, match="missing payload file"):
        restore_bootstrap(pkg_dir, tmp_path / "dest_missing_payload")


def test_bootstrap_zip_missing_manifest_or_member(tmp_path: Path):
    # Zip without manifest
    bad_zip = tmp_path / "no_manifest.zip"
    with zipfile.ZipFile(bad_zip, "w") as z:
        z.writestr("dummy.txt", "content")

    with pytest.raises(BootstrapError, match="ctt-manifest.json.txt not found in ZIP archive"):
        restore_bootstrap(bad_zip, tmp_path / "dest_no_manifest")

    # Zip with missing payload member
    missing_member_zip = tmp_path / "missing_member.zip"
    manifest = {
        "manifest_version": "1.0",
        "hash_algorithm": "sha256",
        "files": [
            {
                "original_path": "file.py",
                "transfer_path": "file.py.txt",
                "status": "allowlisted",
                "transfer_sha256": "abc",
            }
        ],
    }
    with zipfile.ZipFile(missing_member_zip, "w") as z:
        z.writestr("ctt-manifest.json.txt", json.dumps(manifest))

    with pytest.raises(BootstrapError, match="ZIP archive missing member"):
        restore_bootstrap(missing_member_zip, tmp_path / "dest_missing_member")

    # Zip with incomplete manifest entry
    incomplete_member_zip = tmp_path / "incomplete_member.zip"
    manifest_inc = {
        "manifest_version": "1.0",
        "files": [{"status": "allowlisted", "original_path": "a.py"}],
    }
    with zipfile.ZipFile(incomplete_member_zip, "w") as z:
        z.writestr("ctt-manifest.json.txt", json.dumps(manifest_inc))

    with pytest.raises(BootstrapError, match="incomplete manifest entry"):
        restore_bootstrap(incomplete_member_zip, tmp_path / "dest_inc_zip")


def test_bootstrap_zip_integrity_failure_and_sha512(tmp_path: Path):
    zip_sha512 = tmp_path / "sha512.zip"
    file_bytes = b"zip sha512 payload\n"
    file_hash = hashlib.sha512(b"\xef\xbb\xbf" + file_bytes).hexdigest()

    manifest = {
        "manifest_version": "1.0",
        "hash_algorithm": "sha512",
        "files": [
            {
                "original_path": "file.py",
                "transfer_path": "file.py.txt",
                "status": "allowlisted",
                "transfer_sha512": file_hash,
                "has_bom": False,
            },
            {
                "original_path": "ignored.txt",
                "transfer_path": "ignored.txt",
                "status": "rejected",
            },
        ],
    }

    with zipfile.ZipFile(zip_sha512, "w") as z:
        z.writestr("ctt-manifest.json.txt", b"\xef\xbb\xbf" + json.dumps(manifest).encode("utf-8"))
        z.writestr("file.py.txt", b"\xef\xbb\xbf" + file_bytes)

    dest = tmp_path / "dest_sha512"
    result_dest = restore_bootstrap(zip_sha512, dest)
    assert (result_dest / "file.py").read_bytes() == file_bytes

    # Test integrity failure in ZIP
    zip_bad_hash = tmp_path / "bad_hash.zip"
    manifest_bad = dict(manifest)
    manifest_bad["files"] = [
        {
            "original_path": "file.py",
            "transfer_path": "file.py.txt",
            "status": "allowlisted",
            "transfer_sha512": "0000000000000000000000000000000000000000000000000000000000000000",
        }
    ]
    with zipfile.ZipFile(zip_bad_hash, "w") as z:
        z.writestr("ctt-manifest.json.txt", json.dumps(manifest_bad))
        z.writestr("file.py.txt", file_bytes)

    with pytest.raises(BootstrapError, match="integrity check failed"):
        restore_bootstrap(zip_bad_hash, tmp_path / "dest_bad_hash")


def test_bootstrap_invalid_source_file_and_dir_missing_manifest(tmp_path: Path):
    non_zip_file = tmp_path / "not_a_zip.bin"
    non_zip_file.write_bytes(b"not zip content")

    with pytest.raises(BootstrapError, match="invalid package source"):
        restore_bootstrap(non_zip_file, tmp_path / "dest_non_zip")

    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    with pytest.raises(BootstrapError, match="manifest ctt-manifest.json.txt not found in package"):
        restore_bootstrap(empty_dir, tmp_path / "dest_empty_dir")


def test_bootstrap_main_direct_invocation(tmp_path: Path):
    import runpy

    pkg_dir, dest = _make_dummy_package(tmp_path)
    bootstrap_file = ROOT / "src" / "controlled_text_transfer" / "bootstrap.py"

    # Test main via runpy with sys.argv
    old_argv = sys.argv
    try:
        sys.argv = ["bootstrap.py", str(pkg_dir), str(dest)]
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_path(str(bootstrap_file), run_name="__main__")
        assert exc_info.value.code == 0
    finally:
        sys.argv = old_argv


def test_bootstrap_main_error_handling(tmp_path: Path):
    # Call main with invalid package source
    exit_code = main([str(tmp_path / "non_existent"), str(tmp_path / "dest")])
    assert exit_code == 2
