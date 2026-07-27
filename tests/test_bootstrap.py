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


def test_bootstrap_rejects_signed_and_oversized_manifests(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from controlled_text_transfer import bootstrap

    package, destination = _make_dummy_package(tmp_path)
    manifest_path = package / "ctt-manifest.json.txt"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["signature"] = {"algorithm": "test", "key_label": "unverified"}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(BootstrapError, match="cannot authenticate signed packages"):
        restore_bootstrap(package, destination)

    manifest.pop("signature")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(bootstrap, "MAX_MANIFEST_BYTES", 1)
    with pytest.raises(BootstrapError, match="manifest exceeds the security limit"):
        restore_bootstrap(package, destination)


def test_bootstrap_rejects_duplicate_encrypted_and_oversized_zip_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from controlled_text_transfer import bootstrap

    package, _destination = _make_dummy_package(tmp_path)
    manifest = (package / "ctt-manifest.json.txt").read_bytes()
    payload = (package / "README.md.txt").read_bytes()

    duplicate = tmp_path / "duplicate.zip"
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr("ctt-manifest.json.txt", manifest)
            archive.writestr("README.md.txt", payload)
            archive.writestr("README.md.txt", payload)
    with pytest.raises(BootstrapError, match="duplicate ZIP member"):
        restore_bootstrap(duplicate, tmp_path / "duplicate-destination")

    encrypted = tmp_path / "encrypted.zip"
    encrypted_member = zipfile.ZipInfo("README.md.txt")
    encrypted_member.flag_bits |= 0x1
    with zipfile.ZipFile(encrypted, "w") as archive:
        archive.writestr("ctt-manifest.json.txt", manifest)
        archive.writestr(encrypted_member, payload)
    with zipfile.ZipFile(encrypted, "r") as archive:
        archive.getinfo("README.md.txt").flag_bits |= 0x1
        monkeypatch.setattr(bootstrap.zipfile, "ZipFile", lambda *_args, **_kwargs: archive)
        with pytest.raises(BootstrapError, match="encrypted ZIP member"):
            bootstrap._restore_from_zip(encrypted, tmp_path / "encrypted-stage")

    monkeypatch.undo()
    oversized = tmp_path / "oversized.zip"
    with zipfile.ZipFile(oversized, "w") as archive:
        archive.writestr("ctt-manifest.json.txt", manifest)
        archive.writestr("README.md.txt", payload)
    monkeypatch.setattr(bootstrap, "MAX_ZIP_MEMBER_BYTES", 1)
    with pytest.raises(BootstrapError, match="ZIP member exceeds the security limit"):
        restore_bootstrap(oversized, tmp_path / "oversized-destination")


def test_bootstrap_directory_rejects_linked_payload_and_multiple_manifests(tmp_path: Path):
    package, destination = _make_dummy_package(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_bytes((package / "README.md.txt").read_bytes())
    (package / "README.md.txt").unlink()
    try:
        (package / "README.md.txt").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is not permitted")

    with pytest.raises(BootstrapError, match="regular unlinked file"):
        restore_bootstrap(package, destination)

    (package / "README.md.txt").unlink()
    (package / "README.md.txt").write_bytes(outside.read_bytes())
    nested = package / "nested"
    nested.mkdir()
    (nested / "ctt-manifest.json.txt").write_bytes((package / "ctt-manifest.json.txt").read_bytes())
    with pytest.raises(BootstrapError, match="multiple manifests"):
        restore_bootstrap(package, destination)


def test_bootstrap_stable_reader_rejects_metadata_and_read_races(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import io
    import stat
    from types import SimpleNamespace

    from controlled_text_transfer import bootstrap

    missing = tmp_path / "missing.txt"
    with pytest.raises(BootstrapError, match="cannot inspect payload"):
        bootstrap._read_stable(missing, 10, "payload")

    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(BootstrapError, match="regular unlinked file"):
        bootstrap._read_stable(directory, 10, "payload")

    payload = tmp_path / "payload.txt"
    payload.write_bytes(b"ab")
    with pytest.raises(BootstrapError, match="payload exceeds 1 bytes"):
        bootstrap._read_stable(payload, 1, "payload")

    class Stream(io.BytesIO):
        def fileno(self) -> int:
            return 42

    regular = SimpleNamespace(st_mode=stat.S_IFREG, st_dev=1, st_ino=1, st_size=1)
    directory_metadata = SimpleNamespace(st_mode=stat.S_IFDIR, st_dev=1, st_ino=1, st_size=1)
    monkeypatch.setattr(bootstrap.os, "fstat", lambda _fd: directory_metadata)
    monkeypatch.setattr(Path, "open", lambda _self, _mode: Stream(b"x"))
    monkeypatch.setattr(Path, "lstat", lambda _self: regular)
    with pytest.raises(BootstrapError, match="regular unlinked file"):
        bootstrap._read_stable(payload, 10, "payload")

    read_called = False

    class UnexpectedStream(Stream):
        def read(self, size: int = -1) -> bytes:
            nonlocal read_called
            read_called = True
            return super().read(size)

    opened_different = SimpleNamespace(st_mode=stat.S_IFREG, st_dev=1, st_ino=2, st_size=1)
    monkeypatch.setattr(bootstrap.os, "fstat", lambda _fd: opened_different)
    monkeypatch.setattr(Path, "open", lambda _self, _mode: UnexpectedStream(b"x"))
    with pytest.raises(BootstrapError, match="changed before being read"):
        bootstrap._read_stable(payload, 10, "payload")
    assert not read_called
    monkeypatch.setattr(bootstrap.os, "fstat", lambda _fd: regular)
    monkeypatch.setattr(Path, "open", lambda _self, _mode: Stream(b"ab"))
    with pytest.raises(BootstrapError, match="exceeds 1 bytes"):
        bootstrap._read_stable(payload, 1, "payload")

    class BrokenStream(Stream):
        def read(self, _size: int = -1) -> bytes:
            raise OSError("read failed")

    monkeypatch.setattr(Path, "open", lambda _self, _mode: BrokenStream(b"x"))
    with pytest.raises(BootstrapError, match="cannot read payload"):
        bootstrap._read_stable(payload, 10, "payload")

    monkeypatch.setattr(Path, "open", lambda _self, _mode: Stream(b"x"))
    calls = 0

    def disappearing_lstat(_self):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("gone")
        return regular

    monkeypatch.setattr(Path, "lstat", disappearing_lstat)
    with pytest.raises(BootstrapError, match="changed while being read"):
        bootstrap._read_stable(payload, 10, "payload")

    changed = SimpleNamespace(st_mode=stat.S_IFREG, st_dev=1, st_ino=2, st_size=1)
    metadata = iter((regular, changed))
    monkeypatch.setattr(Path, "lstat", lambda _self: next(metadata))
    with pytest.raises(BootstrapError, match="changed while being read"):
        bootstrap._read_stable(payload, 10, "payload")


def test_bootstrap_manifest_path_and_source_boundaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import stat
    from types import SimpleNamespace

    from controlled_text_transfer import bootstrap

    for unsafe in ("", "a" * 181, "a\\b"):
        with pytest.raises(BootstrapError, match="unsafe package path"):
            bootstrap._safe_relative(unsafe)
    with pytest.raises(BootstrapError, match="files list"):
        bootstrap._decode_manifest(b"[]")
    with pytest.raises(BootstrapError, match="files list"):
        bootstrap._decode_manifest(b"{}")
    monkeypatch.setattr(bootstrap, "MAX_ZIP_MEMBERS", 0)
    with pytest.raises(BootstrapError, match="too many file entries"):
        bootstrap._decode_manifest(b'{"files": [{}]}')
    monkeypatch.undo()

    assert bootstrap._hash_file(tmp_path / "sha256.txt", "sha256") if False else True
    sha_file = tmp_path / "sha256.txt"
    sha_file.write_bytes(b"sha256")
    assert bootstrap._hash_file(sha_file, "sha256") == hashlib.sha256(b"sha256").hexdigest()

    package, destination = _make_dummy_package(tmp_path)
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda _self: SimpleNamespace(st_mode=stat.S_IFREG, st_dev=1, st_ino=1, st_size=1, st_reparse_tag=1),
    )
    with pytest.raises(BootstrapError, match="package source must not be a link"):
        restore_bootstrap(package, destination)

    monkeypatch.setattr(
        Path,
        "lstat",
        lambda _self: SimpleNamespace(st_mode=stat.S_IFIFO, st_dev=1, st_ino=1, st_size=0),
    )
    with pytest.raises(BootstrapError, match="invalid package source"):
        restore_bootstrap(package, destination)


def test_bootstrap_manifest_entry_and_directory_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from controlled_text_transfer import bootstrap

    with pytest.raises(BootstrapError, match="unsupported hash algorithm"):
        bootstrap._manifest_entries({"files": [], "hash_algorithm": "md5"})
    with pytest.raises(BootstrapError, match="files list"):
        bootstrap._manifest_entries({})
    with pytest.raises(BootstrapError, match="entries must be objects"):
        bootstrap._manifest_entries({"files": ["bad"]})

    package, destination = _make_dummy_package(tmp_path)
    manifest = json.loads((package / "ctt-manifest.json.txt").read_text(encoding="utf-8"))
    manifest["files"].append(dict(manifest["files"][0]))
    (package / "ctt-manifest.json.txt").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(BootstrapError, match="duplicate restoration path"):
        restore_bootstrap(package, destination)

    package2, destination2 = _make_dummy_package(tmp_path / "count")
    monkeypatch.setattr(bootstrap, "MAX_ZIP_EXPANDED_BYTES", 1)
    with pytest.raises(BootstrapError, match="expanded-size limit"):
        restore_bootstrap(package2, destination2)

    monkeypatch.undo()
    package3, destination3 = _make_dummy_package(tmp_path / "members")
    monkeypatch.setattr(bootstrap, "MAX_ZIP_MEMBERS", 1)
    with pytest.raises(BootstrapError, match="too many files"):
        restore_bootstrap(package3, destination3)


def test_bootstrap_zip_metadata_and_stream_boundaries(monkeypatch: pytest.MonkeyPatch):
    import io
    import stat

    from controlled_text_transfer import bootstrap

    class Archive:
        def __init__(self, members):
            self.members = members

        def infolist(self):
            return self.members

    regular = zipfile.ZipInfo("payload.txt")
    regular.file_size = 1
    regular.compress_size = 1

    monkeypatch.setattr(bootstrap, "MAX_ZIP_MEMBERS", 0)
    with pytest.raises(BootstrapError, match="too many members"):
        bootstrap._validated_zip_members(Archive([regular]))
    monkeypatch.undo()

    special = zipfile.ZipInfo("special.txt")
    special.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(BootstrapError, match="non-regular ZIP member"):
        bootstrap._validated_zip_members(Archive([special]))

    expanded = zipfile.ZipInfo("expanded.txt")
    expanded.file_size = 2
    expanded.compress_size = 2
    monkeypatch.setattr(bootstrap, "MAX_ZIP_EXPANDED_BYTES", 1)
    with pytest.raises(BootstrapError, match="expanded-size limit"):
        bootstrap._validated_zip_members(Archive([expanded]))
    monkeypatch.undo()

    ratio = zipfile.ZipInfo("ratio.txt")
    ratio.file_size = 101
    ratio.compress_size = 1
    with pytest.raises(BootstrapError, match="compression-ratio limit"):
        bootstrap._validated_zip_members(Archive([ratio]))

    class MemberArchive:
        def __init__(self, data: bytes):
            self.data = data

        def open(self, _info, _mode):
            return io.BytesIO(self.data)

    declared = zipfile.ZipInfo("payload.txt")
    declared.file_size = 1
    with pytest.raises(BootstrapError, match="security limit"):
        bootstrap._read_zip_member(MemberArchive(b"ab"), declared, 1)
    declared.file_size = 2
    with pytest.raises(BootstrapError, match="size changed"):
        bootstrap._read_zip_member(MemberArchive(b"a"), declared, 10)


def test_bootstrap_zip_rejects_signature_multiple_manifests_and_duplicate_targets(tmp_path: Path):
    package, _destination = _make_dummy_package(tmp_path)
    manifest_bytes = (package / "ctt-manifest.json.txt").read_bytes()
    payload = (package / "README.md.txt").read_bytes()

    signed = tmp_path / "signed-sidecar.zip"
    with zipfile.ZipFile(signed, "w") as archive:
        archive.writestr("ctt-manifest.json.txt", manifest_bytes)
        archive.writestr("ctt-manifest.sig.txt", b"signature")
    with pytest.raises(BootstrapError, match="cannot authenticate signed packages"):
        restore_bootstrap(signed, tmp_path / "signed-destination")

    multiple = tmp_path / "multiple-manifests.zip"
    with zipfile.ZipFile(multiple, "w") as archive:
        archive.writestr("one/ctt-manifest.json.txt", manifest_bytes)
        archive.writestr("two/ctt-manifest.json.txt", manifest_bytes)
    with pytest.raises(BootstrapError, match="multiple manifests"):
        restore_bootstrap(multiple, tmp_path / "multiple-destination")

    manifest = json.loads(manifest_bytes)
    manifest["files"].append(dict(manifest["files"][0]))
    duplicate = tmp_path / "duplicate-target.zip"
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("ctt-manifest.json.txt", json.dumps(manifest))
        archive.writestr("README.md.txt", payload)
    with pytest.raises(BootstrapError, match="duplicate restoration path"):
        restore_bootstrap(duplicate, tmp_path / "duplicate-target-destination")


def test_bootstrap_directory_rejects_linked_directories_and_signature_sidecars(tmp_path: Path):
    package, destination = _make_dummy_package(tmp_path)
    outside = tmp_path / "outside-directory"
    outside.mkdir()
    linked = package / "linked-directory"
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is not permitted")
    with pytest.raises(BootstrapError, match="regular unlinked files"):
        restore_bootstrap(package, destination)

    linked.unlink()
    (package / "ctt-manifest.sig.txt").write_bytes(b"signature")
    with pytest.raises(BootstrapError, match="cannot authenticate signed packages"):
        restore_bootstrap(package, destination)
