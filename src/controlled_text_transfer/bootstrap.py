"""Zero-dependency bootstrap restoration script for Controlled Text Transfer (CTT).

This script restores byte-identical CTT source files from a .txt-only cross-domain
transfer package on a destination host where CTT is not yet installed.

It uses ONLY Python standard library modules (Python 3.12+).

Usage:
    python bootstrap.py.txt PACKAGE_SOURCE DESTINATION
    python -m controlled_text_transfer.bootstrap PACKAGE_SOURCE DESTINATION
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import zipfile
from pathlib import Path

UTF8_BOM = b"\xef\xbb\xbf"


class BootstrapError(ValueError):
    """Report bootstrap restoration failures without a verbose traceback."""


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
    target = (destination / relative_str).resolve()
    dest_resolved = destination.resolve()
    try:
        target.relative_to(dest_resolved)
    except ValueError as error:
        raise BootstrapError(f"path traversal rejected: {relative_str}") from error
    return target


def restore_bootstrap(package_source: Path, destination: Path) -> Path:
    """Restore CTT package from a directory or ZIP file using zero dependencies."""
    if not package_source.exists():
        raise BootstrapError(f"package source does not exist: {package_source}")

    if destination.exists():
        raise BootstrapError(f"destination directory already exists: {destination}")

    staging = destination.parent / f".{destination.name}.staging-{os.getpid()}"
    staging.mkdir(parents=True, exist_ok=False)

    try:
        if package_source.is_file() and zipfile.is_zipfile(package_source):
            _restore_from_zip(package_source, staging)
        elif package_source.is_dir():
            _restore_from_dir(package_source, staging)
        else:
            raise BootstrapError(f"invalid package source: {package_source}")

        os.replace(staging, destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return destination


def _restore_from_dir(package_dir: Path, staging: Path) -> None:
    manifest_path = package_dir / "ctt-manifest.json.txt"
    if not manifest_path.is_file():
        # Fall back to root search
        candidates = list(package_dir.rglob("ctt-manifest.json.txt"))
        if not candidates:
            raise BootstrapError("manifest ctt-manifest.json.txt not found in package")
        manifest_path = candidates[0]
        package_dir = manifest_path.parent

    manifest_bytes = manifest_path.read_bytes()
    if manifest_bytes.startswith(UTF8_BOM):
        manifest_bytes = manifest_bytes[len(UTF8_BOM) :]

    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as error:
        raise BootstrapError(f"failed to decode manifest JSON: {error}") from error

    hash_algorithm = manifest.get("hash_algorithm", "sha256")
    files_manifest = manifest.get("files", [])

    for entry in files_manifest:
        status = entry.get("status", "allowlisted")
        if status not in ("allowlisted", "accepted"):
            continue

        transfer_path_str = entry.get("transfer_path")
        original_path_str = entry.get("original_path")
        expected_hash = (
            entry.get("transfer_hash")
            or entry.get("transfer_sha256")
            or entry.get("transfer_sha512")
        )
        original_bom = entry.get("original_bom", False) or entry.get("has_bom", False)

        if not transfer_path_str or not original_path_str or not expected_hash:
            raise BootstrapError(f"incomplete manifest entry: {entry}")

        payload_path = package_dir / transfer_path_str
        if not payload_path.is_file():
            raise BootstrapError(f"missing payload file: {transfer_path_str}")

        actual_hash = _hash_file(payload_path, hash_algorithm)
        if actual_hash.lower() != expected_hash.lower():
            raise BootstrapError(f"integrity check failed for {transfer_path_str}")

        data = payload_path.read_bytes()
        if data.startswith(UTF8_BOM) and not original_bom:
            data = data[len(UTF8_BOM) :]

        target_file = _safe_target_path(staging, original_path_str)
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_bytes(data)


def _restore_from_zip(zip_path: Path, staging: Path) -> None:
    with zipfile.ZipFile(zip_path, "r") as archive:
        names = archive.namelist()
        manifest_name = next((n for n in names if n.endswith("ctt-manifest.json.txt")), None)
        if not manifest_name:
            raise BootstrapError("ctt-manifest.json.txt not found in ZIP archive")

        prefix = manifest_name[: -len("ctt-manifest.json.txt")]
        manifest_bytes = archive.read(manifest_name)
        if manifest_bytes.startswith(UTF8_BOM):
            manifest_bytes = manifest_bytes[len(UTF8_BOM) :]

        manifest = json.loads(manifest_bytes.decode("utf-8"))
        hash_algorithm = manifest.get("hash_algorithm", "sha256")

        for entry in manifest.get("files", []):
            status = entry.get("status", "allowlisted")
            if status not in ("allowlisted", "accepted"):
                continue

            transfer_path_str = entry.get("transfer_path")
            original_path_str = entry.get("original_path")
            expected_hash = (
                entry.get("transfer_hash")
                or entry.get("transfer_sha256")
                or entry.get("transfer_sha512")
            )
            original_bom = entry.get("original_bom", False) or entry.get("has_bom", False)

            if not transfer_path_str or not original_path_str or not expected_hash:
                raise BootstrapError(f"incomplete manifest entry: {entry}")

            zip_member_name = prefix + transfer_path_str
            try:
                data = archive.read(zip_member_name)
            except KeyError as error:
                raise BootstrapError(f"ZIP archive missing member: {zip_member_name}") from error

            actual_hash = _hash_bytes(data, hash_algorithm)
            if actual_hash.lower() != expected_hash.lower():
                raise BootstrapError(f"integrity check failed for {zip_member_name}")

            if data.startswith(UTF8_BOM) and not original_bom:
                data = data[len(UTF8_BOM) :]

            target_file = _safe_target_path(staging, original_path_str)
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_bytes(data)


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
