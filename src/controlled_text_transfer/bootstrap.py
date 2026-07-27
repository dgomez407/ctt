"""Zero-dependency bootstrap restoration script for Controlled Text Transfer (CTT).

This script restores byte-identical CTT source files from a .txt-only cross-domain
transfer package on a destination host where CTT is not yet installed.

It uses ONLY Python standard library modules (Python 3.12.13+).

Usage:
    python bootstrap.py.txt PACKAGE_SOURCE DESTINATION
    python -m controlled_text_transfer.bootstrap PACKAGE_SOURCE DESTINATION
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

UTF8_BOM = b"\xef\xbb\xbf"
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ZIP_INPUT_BYTES = 128 * 1024 * 1024
MAX_ZIP_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_ZIP_MEMBERS = 2_000
MAX_ZIP_MEMBER_BYTES = 10 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
MAX_PATH_DEPTH = 16
MAX_PATH_LENGTH = 180
STREAM_BUFFER_BYTES = 64 * 1024


class BootstrapError(ValueError):
    """Report bootstrap restoration failures without a verbose traceback."""


def _metadata_is_link(metadata: os.stat_result) -> bool:
    """Return whether metadata describes a link or Windows reparse point."""
    return stat.S_ISLNK(metadata.st_mode) or bool(getattr(metadata, "st_reparse_tag", 0))


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    """Return the stable filesystem identity represented by metadata."""
    return metadata.st_dev, metadata.st_ino


def _read_stable(path: Path, limit: int, description: str) -> bytes:
    """Read a bounded regular file while rejecting replacement during the read."""
    try:
        before = path.lstat()
    except OSError as error:
        raise BootstrapError(f"cannot inspect {description}: {path}") from error
    if _metadata_is_link(before) or not stat.S_ISREG(before.st_mode):
        raise BootstrapError(f"{description} must be a regular unlinked file: {path}")
    if before.st_size > limit:
        if description == "manifest":
            raise BootstrapError(f"manifest exceeds the security limit of {limit} bytes")
        raise BootstrapError(f"{description} exceeds {limit} bytes: {path}")

    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if _metadata_is_link(opened) or not stat.S_ISREG(opened.st_mode):
                raise BootstrapError(f"{description} must be a regular unlinked file: {path}")
            if _identity(before) != _identity(opened) or before.st_size != opened.st_size:
                raise BootstrapError(f"{description} changed before being read: {path}")
            chunks: list[bytes] = []
            total = 0
            while chunk := stream.read(min(STREAM_BUFFER_BYTES, limit + 1 - total)):
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise BootstrapError(f"{description} exceeds {limit} bytes: {path}")
    except BootstrapError:
        raise
    except OSError as error:
        raise BootstrapError(f"cannot read {description}: {path}") from error

    try:
        after = path.lstat()
    except OSError as error:
        raise BootstrapError(f"{description} changed while being read: {path}") from error
    identities = {_identity(before), _identity(opened), _identity(after)}
    data = b"".join(chunks)
    if (
        len(identities) != 1
        or _metadata_is_link(after)
        or not stat.S_ISREG(after.st_mode)
        or before.st_size != opened.st_size
        or opened.st_size != after.st_size
        or after.st_size != len(data)
    ):
        raise BootstrapError(f"{description} changed while being read: {path}")
    return data


def _safe_relative(value: str) -> PurePosixPath:
    """Validate a portable, bounded relative path from an untrusted manifest."""
    if not isinstance(value, str) or not value or len(value) > MAX_PATH_LENGTH:
        raise BootstrapError(f"unsafe package path: {value!r}")
    if "\\" in value:
        raise BootstrapError(f"unsafe package path: {value}")
    relative = PurePosixPath(value)
    parts = relative.parts
    if (
        relative.is_absolute()
        or len(parts) > MAX_PATH_DEPTH
        or any(part in ("", ".", "..") or ":" in part for part in parts)
    ):
        raise BootstrapError(f"path traversal rejected: {value}")
    return relative


def _decode_manifest(data: bytes) -> dict[str, object]:
    """Decode and minimally validate a bounded manifest."""
    if data.startswith(UTF8_BOM):
        data = data[len(UTF8_BOM) :]
    try:
        manifest = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BootstrapError(f"failed to decode manifest JSON: {error}") from error
    if not isinstance(manifest, dict):
        raise BootstrapError("manifest must be an object containing a files list")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise BootstrapError("manifest must be an object containing a files list")
    if manifest.get("signature") is not None:
        raise BootstrapError("bootstrap cannot authenticate signed packages; use ctt restore")
    if len(files) > MAX_ZIP_MEMBERS:
        raise BootstrapError("manifest contains too many file entries")

    return manifest


def _hash_file(file_path: Path, algorithm: str) -> str:
    """Compute digest hex string for a local file using hashlib."""
    if algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "sha512":
        hasher = hashlib.sha512()
    else:
        raise BootstrapError(f"unsupported hash algorithm: {algorithm}")

    with file_path.open("rb") as stream:
        while chunk := stream.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _hash_bytes(data: bytes, algorithm: str) -> str:
    """Compute digest hex string for in-memory bytes."""
    if algorithm == "sha256":
        return hashlib.sha256(data).hexdigest()
    if algorithm == "sha512":
        return hashlib.sha512(data).hexdigest()
    raise BootstrapError(f"unsupported hash algorithm: {algorithm}")


def _safe_target_path(destination: Path, relative_str: str) -> Path:
    """Resolve target path ensuring link-free traversal prevention."""
    relative = _safe_relative(relative_str)
    return destination.joinpath(*relative.parts)


def restore_bootstrap(package_source: Path, destination: Path) -> Path:
    """Restore CTT package from a directory or ZIP file using zero dependencies."""
    try:
        source_metadata = package_source.lstat()
    except OSError as error:
        raise BootstrapError(f"package source does not exist: {package_source}") from error
    if _metadata_is_link(source_metadata):
        raise BootstrapError(f"package source must not be a link: {package_source}")
    if not (stat.S_ISREG(source_metadata.st_mode) or stat.S_ISDIR(source_metadata.st_mode)):
        raise BootstrapError(f"invalid package source: {package_source}")

    if destination.exists():
        raise BootstrapError(f"destination directory already exists: {destination}")

    staging = destination.parent / f".{destination.name}.staging-{os.getpid()}"
    staging.mkdir(parents=True, exist_ok=False)

    try:
        if stat.S_ISREG(source_metadata.st_mode):
            _restore_from_zip(package_source, staging)
        elif stat.S_ISDIR(source_metadata.st_mode):
            _restore_from_dir(package_source, staging)

        os.replace(staging, destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return destination


def _manifest_entries(manifest: dict[str, object]) -> tuple[str, list[dict[str, object]]]:
    """Return validated restoration entries and their declared hash algorithm."""
    hash_algorithm = manifest.get("hash_algorithm", "sha256")
    if hash_algorithm not in ("sha256", "sha512"):
        raise BootstrapError(f"unsupported hash algorithm: {hash_algorithm}")
    raw_entries = manifest.get("files")
    if not isinstance(raw_entries, list):
        raise BootstrapError("manifest must contain a files list")
    entries: list[dict[str, object]] = []
    for entry in raw_entries:
        if not isinstance(entry, dict):
            raise BootstrapError("manifest file entries must be objects")
        entries.append(entry)
    return hash_algorithm, entries


def _entry_fields(entry: dict[str, object]) -> tuple[str, str, str, bool] | None:
    """Validate and normalize one accepted manifest entry."""
    status = entry.get("status", "allowlisted")
    if status not in ("allowlisted", "accepted"):
        return None
    transfer_path = entry.get("transfer_path")
    original_path = entry.get("original_path")
    expected_hash = (
        entry.get("transfer_hash") or entry.get("transfer_sha256") or entry.get("transfer_sha512")
    )
    if not (
        isinstance(transfer_path, str)
        and transfer_path
        and isinstance(original_path, str)
        and original_path
        and isinstance(expected_hash, str)
        and expected_hash
    ):
        raise BootstrapError(f"incomplete manifest entry: {entry}")
    _safe_relative(transfer_path)
    _safe_relative(original_path)
    original_bom = bool(entry.get("original_bom", False) or entry.get("has_bom", False))
    return transfer_path, original_path, expected_hash, original_bom


def _restore_payload(data: bytes, original_bom: bool, target_file: Path) -> None:
    """Restore one verified payload while preserving its original BOM state."""
    if data.startswith(UTF8_BOM) and not original_bom:
        data = data[len(UTF8_BOM) :]
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_bytes(data)


def _restore_from_dir(package_dir: Path, staging: Path) -> None:
    """Restore a bounded package directory without following filesystem links."""
    manifests: list[Path] = []
    expanded = 0
    visited = 0
    for root, directory_names, file_names in os.walk(package_dir, followlinks=False):
        root_path = Path(root)
        for name in directory_names:
            metadata = (root_path / name).lstat()
            if _metadata_is_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
                raise BootstrapError(f"package entries must be regular unlinked files: {name}")
        for name in file_names:
            visited += 1
            if visited > MAX_ZIP_MEMBERS:
                raise BootstrapError("package directory contains too many files")
            candidate = root_path / name
            metadata = candidate.lstat()
            if _metadata_is_link(metadata) or not stat.S_ISREG(metadata.st_mode):
                raise BootstrapError(f"package entries must be regular unlinked files: {candidate}")
            expanded += metadata.st_size
            if expanded > MAX_ZIP_EXPANDED_BYTES:
                raise BootstrapError("package directory exceeds expanded-size limit")
            if name == "ctt-manifest.sig.txt":
                raise BootstrapError(
                    "bootstrap cannot authenticate signed packages; use ctt restore"
                )
            if name == "ctt-manifest.json.txt":
                manifests.append(candidate)
    if not manifests:
        raise BootstrapError("manifest ctt-manifest.json.txt not found in package")
    if len(manifests) != 1:
        raise BootstrapError("multiple manifests found in package")

    manifest_path = manifests[0]
    package_root = manifest_path.parent
    manifest = _decode_manifest(_read_stable(manifest_path, MAX_MANIFEST_BYTES, "manifest"))
    hash_algorithm, entries = _manifest_entries(manifest)
    restored_paths: set[str] = set()
    for entry in entries:
        fields = _entry_fields(entry)
        if fields is None:
            continue
        transfer_path, original_path, expected_hash, original_bom = fields
        if original_path in restored_paths:
            raise BootstrapError(f"duplicate restoration path: {original_path}")
        restored_paths.add(original_path)
        relative = _safe_relative(transfer_path)
        payload_path = package_root.joinpath(*relative.parts)
        if not payload_path.exists():
            raise BootstrapError(f"missing payload file: {transfer_path}")
        data = _read_stable(payload_path, MAX_ZIP_MEMBER_BYTES, "payload file")
        if _hash_bytes(data, hash_algorithm).lower() != expected_hash.lower():
            raise BootstrapError(f"integrity check failed for {transfer_path}")
        _restore_payload(data, original_bom, _safe_target_path(staging, original_path))


def _validated_zip_members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    """Validate ZIP metadata and return uniquely named regular members."""
    members = archive.infolist()
    if len(members) > MAX_ZIP_MEMBERS:
        raise BootstrapError("ZIP archive contains too many members")
    expanded = 0
    validated: dict[str, zipfile.ZipInfo] = {}
    for info in members:
        normalized = _safe_relative(info.filename).as_posix()
        if normalized in validated:
            raise BootstrapError(f"duplicate ZIP member: {normalized}")
        if info.flag_bits & 0x1:
            raise BootstrapError(f"encrypted ZIP member rejected: {normalized}")
        mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if file_type and file_type not in (stat.S_IFREG, stat.S_IFDIR):
            raise BootstrapError(f"non-regular ZIP member rejected: {normalized}")
        if info.file_size > MAX_ZIP_MEMBER_BYTES:
            raise BootstrapError(
                "ZIP member exceeds the security limit of "
                f"{MAX_ZIP_MEMBER_BYTES} bytes: {normalized}"
            )
        expanded += info.file_size
        if expanded > MAX_ZIP_EXPANDED_BYTES:
            raise BootstrapError("ZIP archive exceeds expanded-size limit")
        if info.file_size and (
            info.compress_size == 0 or info.file_size > info.compress_size * MAX_COMPRESSION_RATIO
        ):
            raise BootstrapError(f"ZIP member exceeds compression-ratio limit: {normalized}")
        validated[normalized] = info
    return validated


def _read_zip_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    """Stream a ZIP member into bounded memory."""
    chunks: list[bytes] = []
    total = 0
    with archive.open(info, "r") as stream:
        while chunk := stream.read(min(STREAM_BUFFER_BYTES, limit + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise BootstrapError(
                    f"ZIP member exceeds the security limit of {limit} bytes: {info.filename}"
                )
    if total != info.file_size:
        raise BootstrapError(f"ZIP member size changed while reading: {info.filename}")
    return b"".join(chunks)


def _restore_from_zip(zip_path: Path, staging: Path) -> None:
    """Restore a bounded ZIP package after validating all member metadata."""
    zip_bytes = _read_stable(zip_path, MAX_ZIP_INPUT_BYTES, "ZIP package")
    try:
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    except (OSError, zipfile.BadZipFile) as error:
        raise BootstrapError(f"invalid package source: {zip_path}") from error
    with archive:
        members = _validated_zip_members(archive)
        signature_names = [
            name for name in members if PurePosixPath(name).name == "ctt-manifest.sig.txt"
        ]
        if signature_names:
            raise BootstrapError("bootstrap cannot authenticate signed packages; use ctt restore")
        manifest_names = [
            name for name in members if PurePosixPath(name).name == "ctt-manifest.json.txt"
        ]
        if not manifest_names:
            raise BootstrapError("ctt-manifest.json.txt not found in ZIP archive")
        if len(manifest_names) != 1:
            raise BootstrapError("multiple manifests found in ZIP archive")
        manifest_name = manifest_names[0]
        manifest_data = _read_zip_member(archive, members[manifest_name], MAX_MANIFEST_BYTES)
        manifest = _decode_manifest(manifest_data)
        hash_algorithm, entries = _manifest_entries(manifest)
        prefix = PurePosixPath(manifest_name).parent
        restored_paths: set[str] = set()
        for entry in entries:
            fields = _entry_fields(entry)
            if fields is None:
                continue
            transfer_path, original_path, expected_hash, original_bom = fields
            if original_path in restored_paths:
                raise BootstrapError(f"duplicate restoration path: {original_path}")
            restored_paths.add(original_path)
            member_name = (prefix / _safe_relative(transfer_path)).as_posix()
            info = members.get(member_name)
            if info is None:
                raise BootstrapError(f"ZIP archive missing member: {member_name}")
            data = _read_zip_member(archive, info, MAX_ZIP_MEMBER_BYTES)
            if _hash_bytes(data, hash_algorithm).lower() != expected_hash.lower():
                raise BootstrapError(f"integrity check failed for {member_name}")
            _restore_payload(data, original_bom, _safe_target_path(staging, original_path))


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for bootstrap restoration."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "package_source", type=Path, help="Path to .txt package directory or ZIP archive"
    )
    parser.add_argument(
        "destination", type=Path, help="Destination directory for restored CTT source"
    )

    args = parser.parse_args(argv)
    try:
        dest = restore_bootstrap(args.package_source, args.destination)
        print(f"Successfully restored CTT source to: {dest}")
        print("\nNext steps on destination host:")
        print(f"  1. Install CTT:   pip install --no-index --find-links {dest} {dest}")
        print("  2. Or run CLI:    python -m controlled_text_transfer.cli --help")
        return 0
    except (BootstrapError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
