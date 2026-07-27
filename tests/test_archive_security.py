import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from controlled_text_transfer import core
from controlled_text_transfer.core import Policy, TransferError, prepare, restore, verify


@pytest.mark.parametrize(
    ("package_format", "suffix"),
    [("zip", ".zip"), ("tar", ".tar"), ("tgz", ".tgz")],
)
def test_verify_and_restore_accept_archives_directly(tmp_path: Path, package_format: str, suffix: str):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")
    package = tmp_path / "package"
    prepare(source, package, Policy(package_format=package_format))
    archive = package.with_suffix(suffix)
    assert not package.exists()

    manifest = verify(archive)
    destination = tmp_path / "restored"
    restore(archive, destination)

    assert manifest.files[0].original_path == "safe.py"
    assert (destination / "safe.py").read_text(encoding="utf-8") == "safe\n"


def test_tgz_with_sha512_verifies_and_restores_original_bytes(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    original = b"sha512 archive round trip\n"
    (source / "safe.py").write_bytes(original)
    package = tmp_path / "package"

    prepared = prepare(
        source,
        package,
        Policy(package_format="tgz", hash_algorithm="sha512"),
    )
    archive = package.with_suffix(".tgz")
    verified = verify(archive)
    destination = tmp_path / "restored"
    restored = restore(archive, destination)

    assert prepared.hash_algorithm == "sha512"
    assert verified.hash_algorithm == "sha512"
    assert restored.hash_algorithm == "sha512"
    assert (destination / "safe.py").read_bytes() == original


def test_verify_rejects_zip_path_traversal(tmp_path: Path):
    archive = tmp_path / "malicious.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("../escaped.txt", "malicious")

    with pytest.raises(TransferError, match="unsafe archive member"):
        verify(archive)

    assert not (tmp_path / "escaped.txt").exists()


def test_archive_member_parser_rejects_backslashes():
    with pytest.raises(TransferError, match="unsafe archive member"):
        core._archive_parts(r"payload\escaped.txt")


def test_verify_rejects_unexpected_zip_members(tmp_path: Path):
    archive = tmp_path / "unexpected.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("unexpected.txt", "data")

    with pytest.raises(TransferError, match="unexpected archive member"):
        verify(archive)


def test_verify_rejects_invalid_archive_data(tmp_path: Path):
    archive = tmp_path / "invalid.zip"
    archive.write_bytes(b"not an archive")

    with pytest.raises(TransferError, match="unsupported archive format"):
        verify(archive)


def test_verify_rejects_tar_links(tmp_path: Path):
    archive = tmp_path / "malicious.tar"
    with tarfile.open(archive, "w") as output:
        member = tarfile.TarInfo("package/payload/link.txt")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../outside"
        output.addfile(member)

    with pytest.raises(TransferError, match="unsupported archive member"):
        verify(archive)


def test_verify_rejects_zip_links(tmp_path: Path):
    archive = tmp_path / "malicious.zip"
    member = zipfile.ZipInfo("payload/link.txt")
    member.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(member, "../../outside")

    with pytest.raises(TransferError, match="unsupported archive member"):
        verify(archive)


def test_verify_accepts_explicit_zip_directory_entries(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.txt").write_text("safe", encoding="utf-8")
    package = tmp_path / "package"
    prepare(source, package, Policy(package_format="zip"))
    archive = package.with_suffix(".zip")
    with zipfile.ZipFile(archive, "a") as output:
        output.mkdir("payload/empty/")

    assert verify(archive).files


def test_verify_rejects_duplicate_archive_members(tmp_path: Path):
    archive = tmp_path / "duplicate.zip"
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("payload/safe.py.txt", "one")
            output.writestr("payload/safe.py.txt", "two")

    with pytest.raises(TransferError, match="duplicate archive member"):
        verify(archive)


def test_verify_rejects_duplicate_tar_members(tmp_path: Path):
    archive = tmp_path / "duplicate.tar"
    with tarfile.open(archive, "w") as output:
        for content in (b"one", b"two"):
            member = tarfile.TarInfo("package/payload/safe.txt")
            member.size = len(content)
            output.addfile(member, io.BytesIO(content))

    with pytest.raises(TransferError, match="duplicate archive member"):
        verify(archive)


def test_verify_rejects_tar_with_multiple_roots(tmp_path: Path):
    archive = tmp_path / "multiple-roots.tar"
    with tarfile.open(archive, "w") as output:
        for name in ("first/payload/a.txt", "second/payload/b.txt"):
            content = b"x"
            member = tarfile.TarInfo(name)
            member.size = len(content)
            output.addfile(member, io.BytesIO(content))

    with pytest.raises(TransferError, match="invalid archive layout"):
        verify(archive)


def test_verify_rejects_archive_expansion_over_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "large.tar"
    with tarfile.open(archive, "w") as output:
        data = b"12345"
        member = tarfile.TarInfo("package/payload/file.txt")
        member.size = len(data)
        output.addfile(member, io.BytesIO(data))

    monkeypatch.setattr("controlled_text_transfer.core.MAX_ARCHIVE_BYTES", 4)

    with pytest.raises(TransferError, match="archive expansion limit exceeded"):
        verify(archive)


def test_verify_rejects_zip_expansion_over_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "large.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("payload/file.txt", "12345")
    monkeypatch.setattr(core, "MAX_ARCHIVE_BYTES", 4)

    with pytest.raises(TransferError, match="archive expansion limit exceeded"):
        verify(archive)


def test_verify_rejects_archive_input_over_security_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "large.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("payload/file.txt", b"x")
    monkeypatch.setattr(core, "MAX_ARCHIVE_INPUT_BYTES", archive.stat().st_size - 1)

    with pytest.raises(TransferError, match="archive input exceeds security limit"):
        verify(archive)


def test_verify_rejects_member_over_individual_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "large.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("payload/file.txt", b"xx")
    monkeypatch.setattr(core, "MAX_ARCHIVE_MEMBER_BYTES", 1)

    with pytest.raises(TransferError, match="archive member size limit exceeded"):
        verify(archive)


def test_verify_rejects_encrypted_zip_member_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "encrypted.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("payload/file.txt", b"x")
    original_infolist = zipfile.ZipFile.infolist

    def encrypted_infolist(self):
        members = original_infolist(self)
        members[0].flag_bits |= 0x1
        return members

    monkeypatch.setattr(zipfile.ZipFile, "infolist", encrypted_infolist)
    with pytest.raises(TransferError, match="encrypted archive member"):
        verify(archive)


def test_verify_rejects_excessive_zip_compression_ratio(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "ratio.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
        output.writestr("payload/file.txt", b"x" * 100)
    monkeypatch.setattr(core, "MAX_COMPRESSION_RATIO", 1)

    with pytest.raises(TransferError, match="compression ratio limit exceeded"):
        verify(archive)


@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_verify_rejects_archives_over_member_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str):
    archive = tmp_path / f"many.{kind}"
    if kind == "zip":
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("payload/one.txt", "one")
    else:
        with tarfile.open(archive, "w") as output:
            data = b"one"
            member = tarfile.TarInfo("package/payload/one.txt")
            member.size = len(data)
            output.addfile(member, io.BytesIO(data))
    monkeypatch.setattr("controlled_text_transfer.core.MAX_ARCHIVE_MEMBERS", 0)

    with pytest.raises(TransferError, match="archive member limit exceeded"):
        verify(archive)


def test_verify_converts_recognized_corrupt_zip_to_transfer_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "corrupt.zip"
    archive.write_bytes(b"not a zip")
    monkeypatch.setattr(core.zipfile, "is_zipfile", lambda _path: True)

    with pytest.raises(TransferError, match="invalid archive"):
        verify(archive)


def test_verify_converts_recognized_corrupt_tar_to_transfer_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "corrupt.tar"
    archive.write_bytes(b"not a tar")
    monkeypatch.setattr(core.tarfile, "is_tarfile", lambda _path: True)

    with pytest.raises(TransferError, match="invalid archive"):
        verify(archive)


def test_verify_rejects_tar_member_without_extractable_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive = tmp_path / "missing-data.tar"
    archive.write_bytes(b"placeholder")
    member = tarfile.TarInfo("package/payload/file.txt")
    member.size = 1

    class FakeTar:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def getmembers(self):
            return [member]

        def extractfile(self, _member):
            return None

    monkeypatch.setattr(core.tarfile, "is_tarfile", lambda _path: True)
    monkeypatch.setattr(core.tarfile, "open", lambda *_args, **_kwargs: FakeTar())

    with pytest.raises(TransferError, match="invalid archive member"):
        verify(archive)


def test_package_helpers_handle_directory_empty_member_and_invalid_format(
    tmp_path: Path,
):
    transfer = tmp_path / "transfer"
    transfer.mkdir()

    assert core._package(transfer, "directory") == transfer
    core._write_archive_member(transfer, (), b"ignored")
    with pytest.raises(TransferError, match="unsupported package format"):
        core._validate_package_format("rar")
