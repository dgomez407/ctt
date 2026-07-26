import json
import shutil
from pathlib import Path

import pytest

from controlled_text_transfer import core
from controlled_text_transfer.core import Manifest, Policy, TransferError, prepare, restore, verify


def _prepare_one_file(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")
    package = tmp_path / "package"
    prepare(source, package, Policy())
    return package


def _rewrite_manifest(package: Path, update: dict[str, object]) -> None:
    manifest_path = package / "ctt-manifest.json.txt"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0].update(update)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def _read_manifest(package: Path) -> dict[str, object]:
    return json.loads((package / "ctt-manifest.json.txt").read_text(encoding="utf-8"))


def _write_manifest(package: Path, manifest: dict[str, object]) -> None:
    (package / "ctt-manifest.json.txt").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "manifest",
    [
        [],
        {"hash_algorithm": "sha256", "files": []},
        {"format_version": 1, "hash_algorithm": "sha256", "files": [], "extra": True},
        {"format_version": 1, "hash_algorithm": "sha256", "files": {}},
        {"format_version": 1, "hash_algorithm": "sha256", "files": [], "skipped": "x"},
        {"format_version": 1, "hash_algorithm": "sha256", "files": [], "signature": []},
        {"format_version": True, "hash_algorithm": "sha256", "files": []},
        {"format_version": 1, "hash_algorithm": 1, "files": []},
    ],
)
def test_verify_rejects_malformed_manifest_top_level(tmp_path: Path, manifest: object):
    package = _prepare_one_file(tmp_path)
    (package / "ctt-manifest.json.txt").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    with pytest.raises(TransferError, match=r"^invalid manifest:"):
        verify(package)


@pytest.mark.parametrize(
    "update",
    [
        {"original_path": 1},
        {"original_size": -1},
        {"transfer_size": True},
        {"bom_added": 1},
        {"mode": "644"},
        {"mode": -1},
        {"mode": 0o1000},
        {"original_hash": "not-a-hex-digest"},
        {"transfer_hash": "0" * 63},
        {"unexpected": "field"},
    ],
)
def test_verify_rejects_malformed_file_records(tmp_path: Path, update: dict[str, object]):
    package = _prepare_one_file(tmp_path)
    _rewrite_manifest(package, update)

    with pytest.raises(TransferError, match=r"^invalid manifest:"):
        verify(package)


@pytest.mark.parametrize("algorithm", ["md5", "sha1", "unknown"])
def test_verify_rejects_unapproved_manifest_hash_algorithms(tmp_path: Path, algorithm: str):
    package = _prepare_one_file(tmp_path)
    manifest = _read_manifest(package)
    manifest["hash_algorithm"] = algorithm
    _write_manifest(package, manifest)

    with pytest.raises(TransferError, match="invalid manifest: unsupported hash algorithm"):
        verify(package)


def test_verify_rejects_invalid_manifest_json(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    (package / "ctt-manifest.json.txt").write_text("{", encoding="utf-8")

    with pytest.raises(TransferError, match=r"^invalid manifest:"):
        verify(package)


def test_verify_rejects_file_record_with_missing_field(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    manifest = _read_manifest(package)
    del manifest["files"][0]["transfer_hash"]
    _write_manifest(package, manifest)

    with pytest.raises(TransferError, match=r"^invalid manifest:"):
        verify(package)


def test_verify_rejects_missing_transfer_file(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    (package / "payload" / "safe.py.txt").unlink()

    with pytest.raises(TransferError, match="missing transfer file"):
        verify(package)


def test_verify_rejects_transfer_path_that_normalizes_outside_payload(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    manifest = package / "ctt-manifest.json.txt"
    _rewrite_manifest(
        package,
        {
            "transfer_path": "payload/../ctt-manifest.json.txt",
            "transfer_hash": __import__("hashlib").sha256(manifest.read_bytes()).hexdigest(),
        },
    )

    with pytest.raises(TransferError, match="outside payload"):
        verify(package)


def test_restore_rejects_original_path_that_escapes_destination(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    _rewrite_manifest(package, {"original_path": "../escaped.py"})

    destination = tmp_path / "restored"
    with pytest.raises(TransferError, match="path escapes root"):
        restore(package, destination)

    assert not (tmp_path / "escaped.py").exists()


def test_restore_rejects_existing_destination(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    destination = tmp_path / "existing"
    destination.mkdir()

    with pytest.raises(FileExistsError):
        restore(package, destination)


def test_restore_dry_run_verifies_without_creating_destination(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    destination = tmp_path / "restored"

    manifest = restore(package, destination, dry_run=True)

    assert [record.original_path for record in manifest.files] == ["safe.py"]
    assert not destination.exists()


def test_verify_rejects_transfer_path_outside_payload_prefix(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    _rewrite_manifest(package, {"transfer_path": "safe.py.txt"})

    with pytest.raises(TransferError, match="outside payload"):
        verify(package)


def test_verify_rejects_unsupported_manifest_version(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    manifest = _read_manifest(package)
    manifest["format_version"] = 999
    _write_manifest(package, manifest)

    with pytest.raises(TransferError, match="unsupported manifest format version"):
        verify(package)


def test_verify_rejects_duplicate_original_paths(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    manifest = _read_manifest(package)
    manifest["files"].append(dict(manifest["files"][0]))
    _write_manifest(package, manifest)

    with pytest.raises(TransferError, match="duplicate original path"):
        verify(package)


def test_verify_rejects_duplicate_transfer_paths(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    manifest = _read_manifest(package)
    duplicate = dict(manifest["files"][0])
    duplicate["original_path"] = "other.py"
    manifest["files"].append(duplicate)
    _write_manifest(package, manifest)

    with pytest.raises(TransferError, match="duplicate transfer path"):
        verify(package)


def test_verify_rejects_transfer_size_mismatch(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    _rewrite_manifest(package, {"transfer_size": 999})

    with pytest.raises(TransferError, match="size mismatch"):
        verify(package)


def test_verify_rejects_symlink_payload_file(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    payload_file = package / "payload" / "safe.py.txt"
    target = tmp_path / "target.py.txt"
    target.write_bytes(payload_file.read_bytes())
    payload_file.unlink()
    try:
        payload_file.symlink_to(target)
    except OSError:
        pytest.skip("creating symlinks is not permitted on this platform")

    with pytest.raises(TransferError, match="symlink transfer file"):
        verify(package)


def test_verify_rejects_symlinked_payload_directory(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    outside = tmp_path / "outside"
    shutil.copytree(package / "payload", outside)
    shutil.rmtree(package / "payload")
    try:
        (package / "payload").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("creating directory symlinks is not permitted on this platform")

    with pytest.raises(TransferError, match="linked package path"):
        verify(package)


def test_verify_rejects_symlinked_package_root(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    linked_package = tmp_path / "linked-package"
    try:
        linked_package.symlink_to(package, target_is_directory=True)
    except OSError:
        pytest.skip("creating directory symlinks is not permitted on this platform")

    with pytest.raises(TransferError, match="linked package path"):
        verify(linked_package)


@pytest.mark.parametrize("sidecar_name", ["ctt-manifest.json.txt", "ctt-manifest.sig"])
def test_verify_rejects_symlinked_metadata_sidecars(tmp_path: Path, sidecar_name: str):
    package = _prepare_one_file(tmp_path)
    sidecar = package / sidecar_name
    outside = tmp_path / sidecar_name
    if sidecar.exists():
        sidecar.replace(outside)
    else:
        outside.write_bytes(b"signature")
    try:
        sidecar.symlink_to(outside)
    except OSError:
        pytest.skip("creating file symlinks is not permitted on this platform")

    with pytest.raises(TransferError, match="linked package path"):
        verify(package)


def test_verify_rejects_symlinked_payload_ancestor(tmp_path: Path):
    source = tmp_path / "source"
    nested = source / "nested"
    nested.mkdir(parents=True)
    (nested / "safe.py").write_text("safe\n", encoding="utf-8")
    package = tmp_path / "package"
    prepare(source, package, Policy())
    outside = tmp_path / "outside"
    shutil.copytree(package / "payload" / "nested", outside)
    shutil.rmtree(package / "payload" / "nested")
    try:
        (package / "payload" / "nested").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("creating directory symlinks is not permitted on this platform")

    with pytest.raises(TransferError, match="linked package path"):
        verify(package)


def test_restore_rejects_reconstructed_original_checksum_mismatch(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    _rewrite_manifest(package, {"original_hash": "0" * 64})
    destination = tmp_path / "restored"

    with pytest.raises(TransferError, match="restored checksum mismatch"):
        restore(package, destination)

    assert not destination.exists()
    assert not list(tmp_path.glob(".restored-*"))


def test_restore_rejects_reconstructed_original_size_mismatch(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    _rewrite_manifest(package, {"original_size": 999})
    destination = tmp_path / "restored"

    with pytest.raises(TransferError, match="restored size mismatch"):
        restore(package, destination)

    assert not destination.exists()


def test_restore_cleans_staging_directory_when_metadata_application_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    package = _prepare_one_file(tmp_path)
    destination = tmp_path / "restored"

    def fail_chmod(_path: Path, _mode: int) -> None:
        raise OSError("simulated chmod failure")

    monkeypatch.setattr("controlled_text_transfer.core.os.chmod", fail_chmod)

    with pytest.raises(OSError, match="simulated chmod failure"):
        restore(package, destination)

    assert not destination.exists()
    assert not list(tmp_path.glob(".restored-*"))


def test_restore_rejects_staged_checksum_mismatch_and_cleans_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    package = _prepare_one_file(tmp_path)
    destination = tmp_path / "restored"
    original_read_bytes = Path.read_bytes

    def corrupt_staged_read(path: Path) -> bytes:
        if any(part.startswith(".restored-") for part in path.parts):
            return b"corrupted after write"
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", corrupt_staged_read)

    with pytest.raises(TransferError, match="staged checksum mismatch"):
        restore(package, destination)

    assert not destination.exists()
    assert not list(tmp_path.glob(".restored-*"))


def test_restore_refuses_destination_created_during_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    package = _prepare_one_file(tmp_path)
    destination = tmp_path / "restored"
    original_chmod = core.os.chmod

    def create_destination(path: Path, mode: int) -> None:
        original_chmod(path, mode)
        destination.mkdir()

    monkeypatch.setattr(core.os, "chmod", create_destination)

    with pytest.raises(FileExistsError):
        restore(package, destination)

    assert destination.is_dir()
    assert not list(tmp_path.glob(".restored-*"))


def test_verify_accepts_empty_manifest_without_payload_directory(tmp_path: Path):
    package = tmp_path / "package"
    package.mkdir()
    Manifest().write(package / "ctt-manifest.json.txt")

    assert verify(package).files == []


def test_verify_directory_rejects_linked_root_when_called_directly(tmp_path: Path):
    package = _prepare_one_file(tmp_path)
    linked_package = tmp_path / "linked-package"
    try:
        linked_package.symlink_to(package, target_is_directory=True)
    except OSError:
        pytest.skip("creating directory symlinks is not permitted on this platform")

    with pytest.raises(TransferError, match="linked package path"):
        core._verify_directory(linked_package)


def test_prepare_detects_source_changes_during_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source"
    source.mkdir()
    source_file = source / "safe.py"
    source_file.write_text("before\n", encoding="utf-8")
    package = tmp_path / "package"
    original_read_bytes = Path.read_bytes

    def read_and_modify(path: Path) -> bytes:
        data = original_read_bytes(path)
        if path == source_file:
            path.write_text("after and a different size\n", encoding="utf-8")
        return data

    monkeypatch.setattr(Path, "read_bytes", read_and_modify)

    with pytest.raises(TransferError, match="source changed during preparation"):
        prepare(source, package, Policy())

    assert not package.exists()


def test_prepare_cleans_staging_output_when_manifest_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")
    package = tmp_path / "package"

    def fail_write(self: Manifest, path: Path) -> None:
        raise OSError("simulated write failure")

    monkeypatch.setattr(Manifest, "write", fail_write)

    with pytest.raises(OSError, match="simulated write failure"):
        prepare(source, package, Policy())

    assert not package.exists()
    assert not list(tmp_path.glob(".package-*"))


def test_prepare_rejects_existing_final_archive(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")
    package = tmp_path / "package"
    archive = package.with_suffix(".zip")
    archive.write_bytes(b"existing")

    with pytest.raises(FileExistsError):
        prepare(source, package, Policy(package_format="zip"))

    assert archive.read_bytes() == b"existing"


def test_prepare_removes_partial_staged_archive_when_packaging_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")
    package = tmp_path / "package"

    def fail_package(
        _transfer: Path,
        _format: str,
        *,
        archive: Path | None = None,
        root_name: str | None = None,
    ) -> Path:
        del root_name
        assert archive is not None
        archive.write_bytes(b"partial")
        raise OSError("simulated packaging failure")

    monkeypatch.setattr(core, "_package", fail_package)

    with pytest.raises(OSError, match="simulated packaging failure"):
        prepare(source, package, Policy(package_format="zip"))

    assert not package.with_suffix(".zip").exists()
    assert not list(tmp_path.glob(".package-*"))


def test_prepare_removes_published_archive_when_stage_cleanup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")
    package = tmp_path / "package"
    original_rmtree = core.shutil.rmtree
    failed_once = False

    def fail_first_stage_cleanup(path: Path) -> None:
        nonlocal failed_once
        if not failed_once and path.name.startswith(".package-"):
            failed_once = True
            raise OSError("simulated stage cleanup failure")
        original_rmtree(path)

    monkeypatch.setattr(core.shutil, "rmtree", fail_first_stage_cleanup)

    with pytest.raises(OSError, match="simulated stage cleanup failure"):
        prepare(source, package, Policy(package_format="zip"))

    assert not package.with_suffix(".zip").exists()
    assert not list(tmp_path.glob(".package-*"))
