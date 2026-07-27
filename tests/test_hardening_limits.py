import io
import json
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from controlled_text_transfer import core, signing
from controlled_text_transfer.core import Manifest, Policy, TransferError, prepare, verify


def _record(**updates):
    record = {
        "original_path": "safe.py",
        "transfer_path": "payload/safe.py.txt",
        "original_hash": "0" * 64,
        "transfer_hash": "0" * 64,
        "original_size": 1,
        "transfer_size": 1,
        "bom_added": False,
        "original_bom": False,
        "mode": 0o644,
    }
    record.update(updates)
    return record


def _manifest(record):
    return {"format_version": 1, "hash_algorithm": "sha256", "files": [record]}


def test_stable_reader_rejects_non_regular_and_unreadable_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(TransferError, match="regular unlinked"):
        core._read_stable_file(directory, 10, "input")

    missing = tmp_path / "missing"
    with pytest.raises(TransferError, match="could not be read safely"):
        core._read_stable_file(missing, 10, "input")


def test_stable_reader_rejects_identity_change_and_observed_overrun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "input"
    path.write_bytes(b"x")
    original_lstat = Path.lstat
    calls = 0

    def changed_lstat(self):
        nonlocal calls
        result = original_lstat(self)
        calls += 1
        if calls == 2:
            return SimpleNamespace(
                st_dev=result.st_dev,
                st_ino=result.st_ino + 1,
                st_mode=result.st_mode,
            )
        return result

    monkeypatch.setattr(Path, "lstat", changed_lstat)
    with pytest.raises(TransferError, match="changed while it was opened"):
        core._read_stable_file(path, 10, "input")

    monkeypatch.setattr(Path, "lstat", original_lstat)
    monkeypatch.setattr(
        core.os,
        "fstat",
        lambda _fd: SimpleNamespace(
            st_dev=path.stat().st_dev,
            st_ino=path.stat().st_ino,
            st_mode=path.stat().st_mode,
            st_size=0,
        ),
    )
    chunks = iter([b"xx", b""])
    monkeypatch.setattr(core.os, "read", lambda _fd, _size: next(chunks))
    with pytest.raises(TransferError, match="exceeds the security limit"):
        core._read_stable_file(path, 1, "input")


def test_manifest_rejects_aggregate_and_individual_size_limits(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(core, "MAX_ARCHIVE_BYTES", 0)
    with pytest.raises(TransferError, match="aggregate size"):
        Manifest.from_dict(_manifest(_record()))

    monkeypatch.setattr(core, "MAX_ARCHIVE_BYTES", 10)
    monkeypatch.setattr(core, "MAX_ARCHIVE_MEMBER_BYTES", 0)
    with pytest.raises(TransferError, match="file size"):
        Manifest.from_dict(_manifest(_record()))


def test_archive_path_and_stream_observed_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    with pytest.raises(TransferError, match="path exceeds security limit"):
        core._archive_parts("x" * 181)

    root = tmp_path / "root"
    root.mkdir()
    core._write_archive_member(root, ("written.txt",), b"ok")
    assert (root / "written.txt").read_bytes() == b"ok"
    assert core._stream_archive_member(
        root, (), io.BytesIO(b""), declared_size=0, expanded_total=3
    ) == (0, 3)

    monkeypatch.setattr(core, "MAX_ARCHIVE_MEMBER_BYTES", 1)
    with pytest.raises(TransferError, match="member size limit"):
        core._stream_archive_member(
            root, ("declared.txt",), io.BytesIO(b""), declared_size=2, expanded_total=0
        )
    with pytest.raises(TransferError, match="member size limit"):
        core._stream_archive_member(
            root, ("observed.txt",), io.BytesIO(b"xx"), declared_size=1, expanded_total=0
        )

    monkeypatch.setattr(core, "MAX_ARCHIVE_MEMBER_BYTES", 10)
    monkeypatch.setattr(core, "MAX_ARCHIVE_BYTES", 0)
    with pytest.raises(TransferError, match="expansion limit"):
        core._stream_archive_member(
            root, ("total.txt",), io.BytesIO(b"x"), declared_size=1, expanded_total=0
        )

    monkeypatch.setattr(core, "MAX_ARCHIVE_BYTES", 10)
    with pytest.raises(TransferError, match="size mismatch"):
        core._stream_archive_member(
            root, ("mismatch.txt",), io.BytesIO(b"x"), declared_size=2, expanded_total=0
        )


def test_identity_validation_and_signing_output_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    with pytest.raises(TransferError, match="invalid manifest signer identity"):
        core._validated_signer_identity("")

    manifest = tmp_path / "manifest"
    manifest.write_bytes(b"manifest")

    class LargeSigner:
        algorithm = "test"

        def sign(self, data):
            return b"x" * 2

        def verify(self, data, signature):
            return True

    monkeypatch.setattr(signing, "MAX_SIGNATURE_BYTES", 1)
    with pytest.raises(ValueError, match="signature exceeds"):
        signing.sign_manifest(manifest, tmp_path / "signature", LargeSigner())


def test_signing_stable_reader_guards(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(ValueError, match="regular unlinked"):
        signing._read_stable(directory, 10, "input")

    path = tmp_path / "input"
    path.write_bytes(b"x")
    original_lstat = Path.lstat
    calls = 0

    def changed_lstat(self):
        nonlocal calls
        result = original_lstat(self)
        calls += 1
        if calls == 2:
            return SimpleNamespace(
                st_dev=result.st_dev,
                st_ino=result.st_ino + 1,
                st_mode=result.st_mode,
            )
        return result

    monkeypatch.setattr(Path, "lstat", changed_lstat)
    with pytest.raises(ValueError, match="changed while it was opened"):
        signing._read_stable(path, 10, "input")

    monkeypatch.setattr(Path, "lstat", original_lstat)
    with pytest.raises(ValueError, match="exceeds the security limit"):
        signing._read_stable(path, 0, "input")

    monkeypatch.setattr(
        signing.os,
        "fstat",
        lambda _fd: SimpleNamespace(
            st_dev=path.stat().st_dev,
            st_ino=path.stat().st_ino,
            st_mode=path.stat().st_mode,
            st_size=0,
        ),
    )
    chunks = iter([b"xx", b""])
    monkeypatch.setattr(signing.os, "read", lambda _fd, _size: next(chunks))
    with pytest.raises(ValueError, match="exceeds the security limit"):
        signing._read_stable(path, 1, "input")


def test_external_signer_rejects_oversized_signing_output(monkeypatch: pytest.MonkeyPatch):
    result = SimpleNamespace(returncode=0, stdout=b"xx", stderr=b"")
    monkeypatch.setattr(signing.subprocess, "run", lambda *args, **kwargs: result)
    monkeypatch.setattr(signing, "MAX_SIGNATURE_BYTES", 1)
    signer = signing.ExternalCommandSigner(["sign"], ["verify"])

    with pytest.raises(RuntimeError, match="output exceeded"):
        signer.sign(b"manifest")


def test_tar_compression_ratio_and_archive_inspection_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    archive = tmp_path / "ratio.tar"
    data = b"x" * 100
    with tarfile.open(archive, "w") as output:
        member = tarfile.TarInfo("payload/file.txt")
        member.size = len(data)
        output.addfile(member, io.BytesIO(data))
    monkeypatch.setattr(core, "MAX_COMPRESSION_RATIO", 0)
    with pytest.raises(TransferError, match="compression ratio limit exceeded"):
        verify(archive)

    original_stat = Path.stat

    def fail_archive_stat(self, *args, **kwargs):
        if self == archive:
            raise OSError("unreadable")
        return original_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fail_archive_stat)
    with pytest.raises(TransferError, match="archive could not be inspected safely"):
        extraction_root = tmp_path / "tar-extraction"
        extraction_root.mkdir()
        core._extract_tar(archive, extraction_root)


class _IdentitySigner:
    algorithm = "test"
    identity = "approved"

    def sign(self, data: bytes) -> bytes:
        return b"signature:" + data

    def verify(self, data: bytes, signature: bytes):
        return signing.SignatureVerification(signature == b"signature:" + data, self.identity)


def test_signer_metadata_and_structured_verification_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")

    class ChangingIdentitySigner(_IdentitySigner):
        accesses = 0

        @property
        def identity(self):
            self.accesses += 1
            return f"identity-{self.accesses}"

    with pytest.raises(TransferError, match="signer metadata changed"):
        prepare(source, tmp_path / "changing", Policy(), signer=ChangingIdentitySigner())

    package = tmp_path / "package"
    prepare(source, package, Policy(), signer=_IdentitySigner())
    manifest_path = package / "ctt-manifest.json.txt"
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["signature"]["unexpected"] = True
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(TransferError, match="invalid manifest signature metadata"):
        verify(package, signer=_IdentitySigner())


def test_signature_read_and_invalid_structured_result_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")
    package = tmp_path / "package"
    prepare(source, package, Policy(), signer=_IdentitySigner())

    monkeypatch.setattr(
        core,
        "verify_manifest_signature",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("unsafe")),
    )
    with pytest.raises(TransferError, match="signature could not be read safely"):
        verify(package, signer=_IdentitySigner())

    monkeypatch.setattr(
        core,
        "verify_manifest_signature",
        lambda *_args, **_kwargs: signing.SignatureVerification(False, None),
    )
    with pytest.raises(TransferError, match="signature verification failed"):
        verify(package, signer=_IdentitySigner())


def test_package_directory_converts_lstat_errors_and_rejects_special_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    archive = tmp_path / "archive.tar"
    archive.write_bytes(b"archive")
    original_lstat = Path.lstat

    def fail_archive_lstat(self, *args, **kwargs):
        if self == archive:
            raise OSError("unreadable")
        return original_lstat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", fail_archive_lstat)
    with pytest.raises(TransferError, match="archive could not be inspected safely"):
        with core._package_directory(archive):
            pass

    monkeypatch.setattr(
        Path,
        "lstat",
        lambda _self: SimpleNamespace(st_mode=0, st_size=0, st_reparse_tag=0),
    )
    with pytest.raises(FileNotFoundError):
        with core._package_directory(archive):
            pass
