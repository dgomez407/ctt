"""Core policy, preflight, packaging, verification, and restoration APIs."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Optional, cast

from .signing import ManifestSigner, sign_manifest, verify_manifest_signature

DEFAULT_EXTENSIONS = {
    ".py",
    ".md",
    ".rst",
    ".txt",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".sh",
    ".ps1",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".css",
    ".html",
    ".xml",
    ".sql",
    ".csv",
}
DEFAULT_NAMES = {
    "Dockerfile",
    "Makefile",
    "LICENSE",
    "NOTICE",
    "README",
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
}
PACKAGE_SUFFIXES = {"zip": ".zip", "tar": ".tar", "tgz": ".tgz"}
PACKAGE_FORMATS = {"directory", *PACKAGE_SUFFIXES}
APPROVED_HASH_ALGORITHMS = frozenset({"sha256", "sha512", "blake3"})
APPROVED_HASH_LENGTHS = frozenset({64, 128})
FILE_RECORD_FIELDS = {
    "original_path",
    "transfer_path",
    "original_hash",
    "transfer_hash",
    "original_size",
    "transfer_size",
    "bom_added",
    "original_bom",
    "mode",
}
MANIFEST_REQUIRED_FIELDS = {"format_version", "hash_algorithm", "files"}
MANIFEST_OPTIONAL_FIELDS = {"skipped", "signature"}
MAX_ARCHIVE_MEMBERS = 10_001
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024


class TransferError(RuntimeError):
    """Report a controlled policy, package, integrity, or security failure."""

    pass


def _policy_error(message: str) -> TransferError:
    return TransferError(f"invalid policy: {message}")


def _policy_int(raw: dict[str, Any], name: str, default: int, *, minimum: int = 1) -> int:
    value = raw.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise _policy_error(f"{name} must be an integer of at least {minimum}")
    return value


def _policy_bool(raw: dict[str, Any], name: str, default: bool) -> bool:
    value = raw.get(name, default)
    if not isinstance(value, bool):
        raise _policy_error(f"{name} must be a boolean")
    return value


def _policy_string(raw: dict[str, Any], name: str, default: str) -> str:
    value = raw.get(name, default)
    if not isinstance(value, str):
        raise _policy_error(f"{name} must be a string")
    return value


def _string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise _policy_error(f"{name} must be a list of strings")
    return value


def digest(data: bytes, algorithm: str = "sha256") -> str:
    """Return a hexadecimal digest using an approved algorithm.

    Raises:
        TransferError: If the algorithm or its optional dependency is unavailable.
    """
    if algorithm not in APPROVED_HASH_ALGORITHMS:
        raise TransferError(f"unsupported hash algorithm: {algorithm}")
    if algorithm == "blake3":
        try:
            import blake3
        except ImportError as exc:
            raise TransferError(
                "blake3 requested but optional dependency is not installed"
            ) from exc
        return cast(str, blake3.blake3(data).hexdigest())
    return hashlib.new(algorithm, data).hexdigest()


@dataclass(frozen=True)
class CDSProfile:
    """Describe immutable compatibility constraints for a named CDS target."""

    name: str
    permitted_transfer_extensions: frozenset[str]
    allow_unicode: bool = True


CDS_PROFILES = {
    profile.name: profile
    for profile in (
        CDSProfile("generic-text-v1", frozenset({".txt"})),
        CDSProfile("ascii-text-v1", frozenset({".txt"}), allow_unicode=False),
    )
}


def get_profile(name: str) -> CDSProfile:
    """Return a registered profile or raise ``TransferError``."""
    try:
        return CDS_PROFILES[name]
    except (KeyError, TypeError) as exc:
        raise _policy_error("unsupported profile") from exc


@dataclass
class Policy:
    """Configure selection, transformation, packaging, and compatibility limits."""

    extensions: set[str] = field(default_factory=lambda: set(DEFAULT_EXTENSIONS))
    names: set[str] = field(default_factory=lambda: set(DEFAULT_NAMES))
    add_bom: bool = True
    hash_algorithm: str = "sha256"
    max_bytes: int = 10 * 1024 * 1024
    package_format: str = "directory"
    ignore_file: str = ".cttignore"
    profile: str = "generic-text-v1"
    max_total_bytes: int = 100 * 1024 * 1024
    max_files: int = 10_000
    max_path_depth: int = 32
    max_path_length: int = 240
    max_filename_length: int = 120
    max_line_length: int = 10_000
    allow_unicode: bool = True
    allow_mixed_line_endings: bool = False
    prohibited_patterns: list[str] = field(default_factory=list)

    def validate(self) -> CDSProfile:
        """Validate every field and hash dependency before source traversal."""
        if not isinstance(self.extensions, set) or any(
            not isinstance(item, str) for item in self.extensions
        ):
            raise _policy_error("extensions must be a set of strings")
        if not isinstance(self.names, set) or any(not isinstance(item, str) for item in self.names):
            raise _policy_error("names must be a set of strings")
        if not isinstance(self.prohibited_patterns, list) or any(
            not isinstance(item, str) for item in self.prohibited_patterns
        ):
            raise _policy_error("prohibited_patterns must be a list of strings")
        if any(
            not isinstance(value, bool)
            for value in (
                self.add_bom,
                self.allow_unicode,
                self.allow_mixed_line_endings,
            )
        ):
            raise _policy_error("boolean fields must contain booleans")
        integer_fields = {
            "max_bytes": self.max_bytes,
            "max_total_bytes": self.max_total_bytes,
            "max_files": self.max_files,
            "max_path_depth": self.max_path_depth,
            "max_path_length": self.max_path_length,
            "max_filename_length": self.max_filename_length,
            "max_line_length": self.max_line_length,
        }
        for name, value in integer_fields.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise _policy_error(f"{name} must be an integer of at least 1")
        if (
            not isinstance(self.hash_algorithm, str)
            or self.hash_algorithm not in APPROVED_HASH_ALGORITHMS
        ):
            raise _policy_error("unsupported hash_algorithm")
        if not isinstance(self.package_format, str) or self.package_format not in PACKAGE_FORMATS:
            raise _policy_error("unsupported package_format")
        if not isinstance(self.ignore_file, str) or not self.ignore_file:
            raise _policy_error("ignore_file must be a non-empty string")
        if not isinstance(self.profile, str):
            raise _policy_error("profile must be a string")
        profile = get_profile(self.profile)
        if ".txt" not in profile.permitted_transfer_extensions:
            raise _policy_error("profile does not permit .txt transfer files")
        digest(b"", self.hash_algorithm)
        return profile

    @classmethod
    def from_file(cls, path: Optional[Path]) -> Policy:
        """Load and validate YAML policy data or return validated defaults."""
        if not path:
            policy = cls()
            policy.validate()
            return policy
        try:
            import yaml

            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except ImportError as exc:
            raise TransferError("YAML policy requires PyYAML") from exc
        except Exception as exc:
            raise _policy_error("malformed YAML") from exc
        raw: dict[str, Any]
        if loaded is None:
            raw = {}
        elif isinstance(loaded, dict):
            raw = cast(dict[str, Any], loaded)
        else:
            raise _policy_error("top level must be an object")
        known = {
            "allowlist",
            "add_bom",
            "hash_algorithm",
            "max_bytes",
            "package_format",
            "ignore_file",
            "profile",
            "max_total_bytes",
            "max_files",
            "max_path_depth",
            "max_path_length",
            "max_filename_length",
            "max_line_length",
            "allow_unicode",
            "allow_mixed_line_endings",
            "prohibited_patterns",
        }
        if set(raw) - known:
            raise _policy_error("unknown field")
        allowlist = raw.get("allowlist", {})
        if not isinstance(allowlist, dict):
            raise _policy_error("allowlist must be an object")
        allowed = cast(dict[str, Any], allowlist)
        if set(allowed) - {"extensions", "names"}:
            raise _policy_error("unknown allowlist field")
        extensions = _string_list(
            allowed.get("extensions", sorted(DEFAULT_EXTENSIONS)),
            "allowlist.extensions",
        )
        names = _string_list(allowed.get("names", sorted(DEFAULT_NAMES)), "allowlist.names")
        hash_algorithm = _policy_string(raw, "hash_algorithm", "sha256")
        if hash_algorithm not in APPROVED_HASH_ALGORITHMS:
            raise _policy_error("unsupported hash_algorithm")
        package_format = _policy_string(raw, "package_format", "directory")
        if package_format not in PACKAGE_FORMATS:
            raise _policy_error("unsupported package_format")
        profile = _policy_string(raw, "profile", "generic-text-v1")
        if profile != "generic-text-v1":
            raise _policy_error("unsupported profile")
        policy = cls(
            extensions={item.lower() for item in extensions},
            names=set(names),
            add_bom=_policy_bool(raw, "add_bom", True),
            hash_algorithm=hash_algorithm,
            max_bytes=_policy_int(raw, "max_bytes", 10 * 1024 * 1024),
            package_format=package_format,
            ignore_file=_policy_string(raw, "ignore_file", ".cttignore"),
            profile=profile,
            max_total_bytes=_policy_int(raw, "max_total_bytes", 100 * 1024 * 1024),
            max_files=_policy_int(raw, "max_files", 10_000),
            max_path_depth=_policy_int(raw, "max_path_depth", 32),
            max_path_length=_policy_int(raw, "max_path_length", 240),
            max_filename_length=_policy_int(raw, "max_filename_length", 120),
            max_line_length=_policy_int(raw, "max_line_length", 10_000),
            allow_unicode=_policy_bool(raw, "allow_unicode", True),
            allow_mixed_line_endings=_policy_bool(raw, "allow_mixed_line_endings", False),
            prohibited_patterns=_string_list(
                raw.get("prohibited_patterns", []),
                "prohibited_patterns",
            ),
        )
        policy.validate()
        return policy


@dataclass(frozen=True)
class PreflightDecision:
    """Explain the compatibility outcome for one source candidate."""

    path: str
    transfer_path: str
    status: str
    reasons: list[str]
    size: int
    transformations: list[str]


@dataclass(frozen=True)
class PreflightReport:
    """Collect deterministic preflight decisions and aggregate counts."""

    profile: str
    decisions: list[PreflightDecision]

    @property
    def accepted_count(self) -> int:
        """Return the number of accepted candidates."""
        return sum(decision.status == "accepted" for decision in self.decisions)

    @property
    def rejected_count(self) -> int:
        """Return the number of rejected candidates."""
        return len(self.decisions) - self.accepted_count

    @property
    def total_bytes(self) -> int:
        """Return the original byte total for accepted candidates."""
        return sum(decision.size for decision in self.decisions if decision.status == "accepted")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable report."""
        return {
            "profile": self.profile,
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "total_bytes": self.total_bytes,
            "decisions": [asdict(decision) for decision in self.decisions],
        }


@dataclass
class FileRecord:
    """Record reversible path, integrity, size, BOM, and mode metadata."""

    original_path: str
    transfer_path: str
    original_hash: str
    transfer_hash: str
    original_size: int
    transfer_size: int
    bom_added: bool
    original_bom: bool
    mode: int

    @classmethod
    def from_dict(cls, raw: object) -> FileRecord:
        """Validate and construct one manifest file record."""
        if not isinstance(raw, dict) or set(raw) != FILE_RECORD_FIELDS:
            raise TransferError("invalid manifest: invalid file record fields")
        values = cast(dict[str, Any], raw)
        string_fields = (
            "original_path",
            "transfer_path",
            "original_hash",
            "transfer_hash",
        )
        if any(not isinstance(values[name], str) for name in string_fields):
            raise TransferError("invalid manifest: invalid file record string")
        integer_fields = ("original_size", "transfer_size", "mode")
        if any(
            not isinstance(values[name], int) or isinstance(values[name], bool)
            for name in integer_fields
        ):
            raise TransferError("invalid manifest: invalid file record integer")
        if values["original_size"] < 0 or values["transfer_size"] < 0:
            raise TransferError("invalid manifest: negative file size")
        if not 0 <= values["mode"] <= 0o777:
            raise TransferError("invalid manifest: unsafe file mode")
        for name in ("original_hash", "transfer_hash"):
            value = values[name]
            if len(value) not in APPROVED_HASH_LENGTHS or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise TransferError("invalid manifest: invalid file hash")
        if not isinstance(values["bom_added"], bool) or not isinstance(
            values["original_bom"], bool
        ):
            raise TransferError("invalid manifest: invalid file record boolean")
        return cls(**values)


@dataclass
class Manifest:
    """Describe a versioned transfer package and its selected files."""

    format_version: int = 1
    hash_algorithm: str = "sha256"
    files: list[FileRecord] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    signature: Optional[dict[str, Any]] = None

    def write(self, path: Path) -> None:
        """Write deterministic UTF-8 JSON manifest bytes."""
        path.write_text(
            json.dumps(asdict(self), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def read(cls, path: Path) -> Manifest:
        """Read and validate a manifest with controlled schema errors."""
        try:
            raw = json.loads(path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            raise TransferError("invalid manifest: invalid JSON") from exc
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: object) -> Manifest:
        """Validate and construct a manifest from decoded JSON data."""
        if not isinstance(raw, dict):
            raise TransferError("invalid manifest: expected an object")
        values = cast(dict[str, Any], raw)
        fields = set(values)
        if not MANIFEST_REQUIRED_FIELDS <= fields:
            raise TransferError("invalid manifest: missing required field")
        if fields - MANIFEST_REQUIRED_FIELDS - MANIFEST_OPTIONAL_FIELDS:
            raise TransferError("invalid manifest: unknown field")
        format_version = values["format_version"]
        if not isinstance(format_version, int) or isinstance(format_version, bool):
            raise TransferError("invalid manifest: invalid format version")
        hash_algorithm = values["hash_algorithm"]
        if not isinstance(hash_algorithm, str):
            raise TransferError("invalid manifest: invalid hash algorithm")
        if hash_algorithm not in APPROVED_HASH_ALGORITHMS:
            raise TransferError("invalid manifest: unsupported hash algorithm")
        files = values["files"]
        if not isinstance(files, list):
            raise TransferError("invalid manifest: files must be a list")
        skipped = values.get("skipped", [])
        if not isinstance(skipped, list) or any(not isinstance(item, str) for item in skipped):
            raise TransferError("invalid manifest: skipped must be a list of strings")
        signature = values.get("signature")
        if signature is not None and not isinstance(signature, dict):
            raise TransferError("invalid manifest: signature must be an object or null")
        return cls(
            format_version=format_version,
            hash_algorithm=hash_algorithm,
            files=[FileRecord.from_dict(record) for record in files],
            skipped=skipped,
            signature=cast(Optional[dict[str, Any]], signature),
        )


def _safe_relative(root: Path, candidate: Path) -> Path:
    base, resolved = root.resolve(), candidate.resolve()
    if os.path.commonpath([str(base), str(resolved)]) != str(base):
        raise TransferError(f"path escapes root: {candidate}")
    return resolved.relative_to(base)


def _ignored(rel: str, patterns: Iterable[str]) -> bool:
    return any(
        fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(Path(rel).name, p)
        for p in patterns
        if p and not p.startswith("#")
    )


def _read_patterns(source: Path, filename: str) -> list[str]:
    path = source / filename
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]


def _text_bytes(data: bytes) -> bool:
    data.decode("utf-8-sig")
    return data.startswith(b"\xef\xbb\xbf")


def _content_reasons(text: str, policy: Policy, profile: CDSProfile) -> list[str]:
    reasons: list[str] = []
    if any(ord(character) < 32 and character not in "\t\r\n" for character in text):
        reasons.append("control_character")
    if (not policy.allow_unicode or not profile.allow_unicode) and any(
        ord(character) > 127 for character in text
    ):
        reasons.append("unicode_not_allowed")
    without_crlf = text.replace("\r\n", "")
    if "\r" in without_crlf:
        reasons.append("unsupported_line_endings")
    if (
        not policy.allow_mixed_line_endings
        and "\r\n" in text
        and ("\n" in without_crlf or "\r" in without_crlf)
    ):
        reasons.append("mixed_line_endings")
    if any(len(line) > policy.max_line_length for line in text.splitlines()):
        reasons.append("line_too_long")
    if any(pattern in text for pattern in policy.prohibited_patterns):
        reasons.append("prohibited_pattern")
    return reasons


def _scan_source(
    source: Path, policy: Policy
) -> tuple[PreflightReport, dict[str, bytes], dict[str, int]]:
    profile = policy.validate()
    source = source.resolve()
    if not source.is_dir():
        raise TransferError("source must be a directory")
    _validate_package_format(policy.package_format)
    patterns = _read_patterns(source, policy.ignore_file)
    decisions: list[PreflightDecision] = []
    captured: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    accepted_files = 0
    accepted_bytes = 0
    paths = sorted(
        path for path in source.rglob("*") if path.is_file() and path.name != policy.ignore_file
    )
    for path in paths:
        rel = _safe_relative(source, path).as_posix()
        before = path.stat()
        size = before.st_size
        reasons: list[str] = []
        if _ignored(rel, patterns):
            reasons.append("ignored")
        if size > policy.max_bytes:
            reasons.append("file_size_exceeded")
        if path.suffix.lower() not in policy.extensions and path.name not in policy.names:
            reasons.append("extension_not_allowed")
        if len(Path(rel).parts) > policy.max_path_depth:
            reasons.append("path_depth_exceeded")
        if len(rel) > policy.max_path_length:
            reasons.append("path_too_long")
        if len(path.name) > policy.max_filename_length:
            reasons.append("filename_too_long")
        if any(ord(character) < 32 for character in rel):
            reasons.append("filename_control_character")
        if any(character in '<>:"|?*;' for character in path.name):
            reasons.append("filename_character_not_allowed")
        data = b""
        if size <= policy.max_bytes:
            try:
                data = path.read_bytes()
                after = path.stat()
                if (
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ino,
                ) != (
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ino,
                ):
                    raise TransferError(f"source changed during preparation: {rel}")
                text = data.decode("utf-8-sig")
            except (UnicodeDecodeError, OSError):
                reasons.append("binary_or_unreadable")
            else:
                reasons.extend(_content_reasons(text, policy, profile))
        if not reasons:
            if accepted_files + 1 > policy.max_files:
                reasons.append("file_count_exceeded")
            if accepted_bytes + size > policy.max_total_bytes:
                reasons.append("total_size_exceeded")
        if not reasons:
            accepted_files += 1
            accepted_bytes += size
            captured[rel] = data
            modes[rel] = stat.S_IMODE(before.st_mode)
        decisions.append(
            PreflightDecision(
                path=rel,
                transfer_path=(Path("payload") / (rel + ".txt")).as_posix(),
                status="accepted" if not reasons else "rejected",
                reasons=reasons,
                size=size,
                transformations=(
                    [
                        "append_txt_suffix",
                        *(
                            ["add_utf8_bom"]
                            if policy.add_bom and not data.startswith(b"\xef\xbb\xbf")
                            else []
                        ),
                    ]
                    if not reasons
                    else []
                ),
            )
        )
    return PreflightReport(profile=policy.profile, decisions=decisions), captured, modes


def preflight(source: Path, policy: Policy) -> PreflightReport:
    """Evaluate every source candidate without writing package output."""
    report, _, _ = _scan_source(source, policy)
    return report


def _resolve_package_destination(destination: Path, fmt: str) -> Path:
    if fmt not in PACKAGE_SUFFIXES:
        return destination
    suffix = PACKAGE_SUFFIXES[fmt]
    dest_str = str(destination)
    if dest_str.endswith(suffix):
        return destination
    for old_suffix in (".tar.gz", ".tgz", ".zip", ".tar"):
        if dest_str.endswith(old_suffix):
            dest_str = dest_str[: -len(old_suffix)]
            break
    return Path(dest_str + suffix)


def _package(
    transfer: Path,
    fmt: str,
    *,
    archive: Optional[Path] = None,
    root_name: Optional[str] = None,
) -> Path:
    _validate_package_format(fmt)
    if fmt == "directory":
        return transfer
    archive = archive or _resolve_package_destination(transfer, fmt)
    if fmt == "zip":
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in transfer.rglob("*"):
                if p.is_file():
                    zf.write(p, p.relative_to(transfer))
    elif fmt in {"tar", "tgz"}:
        with tarfile.open(archive, "w:gz" if fmt == "tgz" else "w") as tf:
            tf.add(transfer, arcname=root_name or transfer.name)
    return archive


def _validate_package_format(fmt: str) -> None:
    if fmt not in PACKAGE_FORMATS:
        raise TransferError(f"unsupported package format: {fmt}")


def _archive_parts(name: str) -> tuple[str, ...]:
    if "\\" in name:
        raise TransferError("unsafe archive member path")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise TransferError("unsafe archive member path")
    return tuple(part for part in path.parts if part not in {"", "."})


def _archive_relative_parts(names: list[str], *, rooted: bool) -> list[tuple[str, ...]]:
    parsed = [_archive_parts(name) for name in names]
    if rooted:
        roots = {parts[0] for parts in parsed if parts}
        if len(roots) != 1:
            raise TransferError("invalid archive layout")
        parsed = [parts[1:] for parts in parsed]
    for parts in parsed:
        if not parts:
            continue
        if parts[0] in {"ctt-manifest.json.txt", "ctt-manifest.sig"} and len(parts) == 1:
            continue
        if parts[0] == "payload":
            continue
        raise TransferError("unexpected archive member")
    return parsed


def _write_archive_member(root: Path, parts: tuple[str, ...], data: bytes) -> None:
    if not parts:
        return
    destination = root.joinpath(*parts)
    _safe_relative(root, destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)


def _extract_zip(archive: Path, root: Path) -> None:
    try:
        with zipfile.ZipFile(archive) as source:
            members = source.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise TransferError("archive member limit exceeded")
            if sum(member.file_size for member in members) > MAX_ARCHIVE_BYTES:
                raise TransferError("archive expansion limit exceeded")
            parts_list = _archive_relative_parts(
                [member.filename for member in members],
                rooted=False,
            )
            seen: set[tuple[str, ...]] = set()
            for member, parts in zip(members, parts_list, strict=True):
                if parts in seen:
                    raise TransferError("duplicate archive member")
                seen.add(parts)
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise TransferError("unsupported archive member")
                if member.is_dir():
                    if parts:
                        root.joinpath(*parts).mkdir(parents=True, exist_ok=True)
                    continue
                _write_archive_member(root, parts, source.read(member))
    except zipfile.BadZipFile as exc:
        raise TransferError("invalid archive") from exc


def _extract_tar(archive: Path, root: Path) -> None:
    try:
        with tarfile.open(archive, "r:*") as source:
            members = source.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise TransferError("archive member limit exceeded")
            if sum(member.size for member in members if member.isfile()) > MAX_ARCHIVE_BYTES:
                raise TransferError("archive expansion limit exceeded")
            names = [member.name for member in members]
            rootless = any(
                parts and parts[0] in {"payload", "ctt-manifest.json.txt"}
                for parts in (_archive_parts(name) for name in names)
            )
            parts_list = _archive_relative_parts(names, rooted=not rootless)
            seen: set[tuple[str, ...]] = set()
            for member, parts in zip(members, parts_list, strict=True):
                if parts in seen:
                    raise TransferError("duplicate archive member")
                seen.add(parts)
                if member.isdir():
                    if parts:
                        root.joinpath(*parts).mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise TransferError("unsupported archive member")
                extracted = source.extractfile(member)
                if extracted is None:
                    raise TransferError("invalid archive member")
                _write_archive_member(root, parts, extracted.read())
    except (tarfile.TarError, EOFError) as exc:
        raise TransferError("invalid archive") from exc


def _is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _payload_files(payload: Path) -> list[Path]:
    if _is_link(payload):
        raise TransferError(f"linked package path is not allowed: {payload.name}")
    if not payload.exists():
        return []
    files: list[Path] = []
    for current, directories, filenames in os.walk(payload, followlinks=False):
        current_path = Path(current)
        for name in directories:
            candidate = current_path / name
            if _is_link(candidate):
                raise TransferError(
                    f"linked package path is not allowed: {candidate.relative_to(payload)}"
                )
        for name in filenames:
            candidate = current_path / name
            if _is_link(candidate):
                raise TransferError(
                    "symlink transfer file is not allowed: "
                    f"{candidate.relative_to(payload.parent)}"
                )
            files.append(candidate)
    return files


@contextmanager
def _package_directory(package: Path) -> Iterator[Path]:
    if _is_link(package):
        raise TransferError(f"linked package path is not allowed: {package}")
    if package.is_dir():
        yield package
        return
    if not package.is_file():
        raise FileNotFoundError(package)
    with tempfile.TemporaryDirectory(prefix="ctt-archive-") as temporary:
        root = Path(temporary) / "package"
        root.mkdir()
        if zipfile.is_zipfile(package):
            _extract_zip(package, root)
        elif tarfile.is_tarfile(package):
            _extract_tar(package, root)
        else:
            raise TransferError("unsupported archive format")
        yield root


def prepare(
    source: Path,
    transfer: Path,
    policy: Policy,
    *,
    dry_run: bool = False,
    strict: bool = False,
    signer: Optional[ManifestSigner] = None,
    key_label: str = "external-managed-key",
    logger: Optional[logging.Logger] = None,
    is_self_package: bool = False,
) -> Manifest:
    """Create one staged, self-verified transfer artifact.

    Directory format publishes ``transfer``; archive formats publish only the
    corresponding suffixed archive. Existing final artifacts are never replaced.
    """
    source, transfer = source.resolve(), transfer.resolve()
    report, source_data, source_modes = _scan_source(source, policy)
    if strict and report.rejected_count:
        raise TransferError(f"strict preflight rejected {report.rejected_count} file(s)")
    records: list[FileRecord] = []
    skipped: list[str] = []
    captured: dict[str, bytes] = {}
    for decision in report.decisions:
        if decision.status != "accepted":
            if decision.reasons == ["ignored"]:
                continue
            reason = {
                "file_size_exceeded": "oversize",
                "extension_not_allowed": "not allowlisted",
                "binary_or_unreadable": "binary or unreadable",
            }.get(decision.reasons[0], ",".join(decision.reasons))
            skipped.append(f"{decision.path} ({reason})")
            continue
        rel = decision.path
        data = source_data[rel]
        had_bom = _text_bytes(data)
        out = data if had_bom or not policy.add_bom else b"\xef\xbb\xbf" + data
        captured[rel] = out
        records.append(
            FileRecord(
                rel,
                decision.transfer_path,
                digest(data, policy.hash_algorithm),
                digest(out, policy.hash_algorithm),
                len(data),
                len(out),
                policy.add_bom and not had_bom,
                had_bom,
                source_modes[rel],
            )
        )
    manifest = Manifest(
        hash_algorithm=policy.hash_algorithm,
        files=sorted(records, key=lambda x: x.original_path),
        skipped=sorted(skipped),
        signature=(
            {"algorithm": signer.algorithm, "key_label": key_label} if signer is not None else None
        ),
    )
    if not dry_run:
        transfer.parent.mkdir(parents=True, exist_ok=True)
        if transfer.exists():
            raise FileExistsError(transfer)
        final_archive = (
            _resolve_package_destination(transfer, policy.package_format)
            if policy.package_format != "directory"
            else None
        )
        if final_archive is not None and final_archive.exists():
            raise FileExistsError(final_archive)
        stage = Path(
            tempfile.mkdtemp(
                prefix=f".{transfer.name}-",
                dir=transfer.parent,
            )
        )
        stage_archive: Optional[Path] = None
        published_path: Optional[Path] = None
        try:
            for rec in manifest.files:
                dst = stage / rec.transfer_path
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(captured[rec.original_path])
            manifest.write(stage / "ctt-manifest.json.txt")
            if is_self_package:
                bootstrap_file = _find_bootstrap_file(source)
                if bootstrap_file is not None and bootstrap_file.is_file():
                    (stage / "bootstrap.py.txt").write_bytes(bootstrap_file.read_bytes())
            if signer is not None:
                sign_manifest(
                    stage / "ctt-manifest.json.txt",
                    stage / "ctt-manifest.sig",
                    signer,
                    key_label=key_label,
                )
            _verify_directory(
                stage,
                signer=signer,
                require_signature=signer is not None,
            )
            if final_archive is not None:
                stage_archive = stage.with_suffix(PACKAGE_SUFFIXES[policy.package_format])
                _package(
                    stage,
                    policy.package_format,
                    archive=stage_archive,
                    root_name=transfer.name,
                )
            if final_archive is None:
                stage.replace(transfer)
                published_path = transfer
            elif stage_archive is not None:
                stage_archive.replace(final_archive)
                published_path = final_archive
                shutil.rmtree(stage)
        except Exception:
            if stage.exists():
                shutil.rmtree(stage)
            if stage_archive is not None and stage_archive.exists():
                stage_archive.unlink()
            if published_path is not None and published_path.exists():
                published_path.unlink()
            raise
    if logger:
        logger.info(
            "prepare_complete",
            extra={"files": len(records), "skipped": len(skipped), "dry_run": dry_run},
        )
    return manifest


def _verify_directory(
    transfer: Path,
    *,
    signer: Optional[ManifestSigner] = None,
    require_signature: bool = False,
    allow_unverified_signature: bool = False,
    logger: Optional[logging.Logger] = None,
) -> Manifest:
    if _is_link(transfer):
        raise TransferError(f"linked package path is not allowed: {transfer}")
    manifest_path = transfer / "ctt-manifest.json.txt"
    if _is_link(manifest_path):
        raise TransferError("linked package path is not allowed: ctt-manifest.json.txt")
    manifest = Manifest.read(manifest_path)
    signature_path = transfer / "ctt-manifest.sig"
    if _is_link(signature_path):
        raise TransferError("linked package path is not allowed: ctt-manifest.sig")
    has_signature = manifest.signature is not None or signature_path.exists()
    if require_signature and not has_signature:
        raise TransferError("manifest signature is required")
    if has_signature:
        if signer is None:
            if not allow_unverified_signature:
                raise TransferError("trusted signature verifier is required")
        else:
            if manifest.signature is None:
                raise TransferError("manifest signature metadata is required")
            if manifest.signature.get("algorithm") != signer.algorithm:
                raise TransferError("manifest signature algorithm mismatch")
            if not verify_manifest_signature(
                transfer / "ctt-manifest.json.txt",
                signature_path,
                signer,
            ):
                raise TransferError("manifest signature verification failed")
    if manifest.format_version != 1:
        raise TransferError(f"unsupported manifest format version: {manifest.format_version}")
    expected_paths = set()
    original_paths: set[str] = set()
    transfer_paths: set[str] = set()
    payload = transfer / "payload"
    payload_files = _payload_files(payload)
    for rec in manifest.files:
        if rec.original_path in original_paths:
            raise TransferError(f"duplicate original path: {rec.original_path}")
        if rec.transfer_path in transfer_paths:
            raise TransferError(f"duplicate transfer path: {rec.transfer_path}")
        original_paths.add(rec.original_path)
        transfer_paths.add(rec.transfer_path)
        path = transfer / rec.transfer_path
        if Path(rec.transfer_path).parts[:1] != ("payload",):
            raise TransferError(f"transfer path is outside payload: {rec.transfer_path}")
        try:
            _safe_relative(payload, path)
        except TransferError as exc:
            raise TransferError(f"transfer path is outside payload: {rec.transfer_path}") from exc
        if not path.is_file():
            raise TransferError(f"missing transfer file: {rec.transfer_path}")
        if digest(path.read_bytes(), manifest.hash_algorithm) != rec.transfer_hash:
            raise TransferError(f"checksum mismatch: {rec.transfer_path}")
        if path.stat().st_size != rec.transfer_size:
            raise TransferError(f"size mismatch: {rec.transfer_path}")
        expected_paths.add(path.resolve())
    for path in payload_files:
        if path.resolve() not in expected_paths:
            raise TransferError(f"unexpected transfer file: {path.relative_to(transfer)}")
    if logger:
        logger.info("verify_complete", extra={"files": len(manifest.files)})
    return manifest


def verify(
    transfer: Path,
    *,
    signer: Optional[ManifestSigner] = None,
    require_signature: bool = False,
    allow_unverified_signature: bool = False,
    logger: Optional[logging.Logger] = None,
) -> Manifest:
    """Verify package structure, integrity, and declared authenticity.

    A declared signature requires a trusted signer unless unverified processing
    is explicitly allowed.
    """
    with _package_directory(transfer) as package:
        return _verify_directory(
            package,
            signer=signer,
            require_signature=require_signature,
            allow_unverified_signature=allow_unverified_signature,
            logger=logger,
        )


def diff(
    source_package: Path,
    source: Path,
    policy: Policy,
    *,
    signer: Optional[ManifestSigner] = None,
    require_signature: bool = False,
    allow_unverified_signature: bool = False,
) -> dict[str, list[str]]:
    """Compare a prepared package with its current source directory.

    The package is verified first, and neither input is modified. Only files
    selected by the current policy participate in the added-file calculation.
    """
    manifest = verify(
        source_package,
        signer=signer,
        require_signature=require_signature,
        allow_unverified_signature=allow_unverified_signature,
    )
    expected = {record.original_path: record for record in manifest.files}
    patterns = _read_patterns(source, policy.ignore_file)
    current: dict[str, Path] = {}
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        rel = _safe_relative(source, path).as_posix()
        if path.name == policy.ignore_file or _ignored(rel, patterns):
            continue
        if path.suffix.lower() in policy.extensions or path.name in policy.names:
            current[rel] = path

    result: dict[str, list[str]] = {
        "added": [],
        "removed": [],
        "modified": [],
        "unchanged": [],
    }
    for rel, record in expected.items():
        current_path = current.get(rel)
        if current_path is None:
            result["removed"].append(rel)
        elif digest(current_path.read_bytes(), manifest.hash_algorithm) == record.original_hash:
            result["unchanged"].append(rel)
        else:
            result["modified"].append(rel)
    result["added"] = sorted(set(current) - set(expected))
    for values in result.values():
        values.sort()
    return result


def _restored_bytes(package: Path, record: FileRecord, algorithm: str) -> bytes:
    data = (package / record.transfer_path).read_bytes()
    data = data[3:] if data.startswith(b"\xef\xbb\xbf") else data
    data = (
        b"\xef\xbb\xbf" + data
        if record.original_bom and not data.startswith(b"\xef\xbb\xbf")
        else data
    )
    if len(data) != record.original_size:
        raise TransferError(f"restored size mismatch: {record.original_path}")
    if digest(data, algorithm) != record.original_hash:
        raise TransferError(f"restored checksum mismatch: {record.original_path}")
    return data


def restore(
    transfer: Path,
    destination: Path,
    *,
    dry_run: bool = False,
    signer: Optional[ManifestSigner] = None,
    require_signature: bool = False,
    allow_unverified_signature: bool = False,
    logger: Optional[logging.Logger] = None,
) -> Manifest:
    """Verify a package and atomically reconstruct original files."""
    with _package_directory(transfer) as package:
        manifest = _verify_directory(
            package,
            signer=signer,
            require_signature=require_signature,
            allow_unverified_signature=allow_unverified_signature,
            logger=logger,
        )
        for rec in manifest.files:
            _safe_relative(destination, destination / rec.original_path)
        if dry_run:
            for rec in manifest.files:
                _restored_bytes(package, rec, manifest.hash_algorithm)
        else:
            if destination.exists() or _is_link(destination):
                raise FileExistsError(destination)
            destination.parent.mkdir(parents=True, exist_ok=True)
            stage = Path(
                tempfile.mkdtemp(
                    prefix=f".{destination.name}-",
                    dir=destination.parent,
                )
            )
            try:
                for rec in manifest.files:
                    data = _restored_bytes(package, rec, manifest.hash_algorithm)
                    out = stage / rec.original_path
                    _safe_relative(stage, out)
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(data)
                    if digest(out.read_bytes(), manifest.hash_algorithm) != rec.original_hash:
                        raise TransferError(f"staged checksum mismatch: {rec.original_path}")
                    os.chmod(out, rec.mode)
                if destination.exists() or _is_link(destination):
                    raise FileExistsError(destination)
                stage.rename(destination)
            except Exception:
                if stage.exists():
                    shutil.rmtree(stage)
                raise
    if logger:
        logger.info("restore_complete", extra={"files": len(manifest.files), "dry_run": dry_run})
    return manifest


def _find_bootstrap_file(pkg_root: Path) -> Optional[Path]:
    candidates = [
        Path(__file__).resolve().parent / "bootstrap.py",
        pkg_root / "src" / "controlled_text_transfer" / "bootstrap.py",
    ]
    mei_pass = getattr(sys, "_MEIPASS", None)
    if mei_pass:
        candidates.insert(0, Path(mei_pass) / "controlled_text_transfer" / "bootstrap.py")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def self_package(
    destination: Path,
    source: Optional[Path] = None,
    *,
    package_format: str = "zip",
    policy: Optional[Policy] = None,
    signer: Optional[ManifestSigner] = None,
    dry_run: bool = False,
    logger: Optional[logging.Logger] = None,
) -> tuple[Manifest, Path]:
    """Package the CTT codebase into a .txt-only self-bootstrapping transfer bundle."""
    if policy is None:
        policy = Policy(package_format=package_format)
    else:
        policy.package_format = package_format

    if source is not None:
        pkg_root = source.resolve()
    else:
        cwd = Path.cwd().resolve()
        if (cwd / "pyproject.toml").is_file() or (
            cwd / "src" / "controlled_text_transfer"
        ).is_dir():
            pkg_root = cwd
        else:
            pkg_root = Path(__file__).resolve().parents[2]
            if not (pkg_root / "pyproject.toml").is_file():
                pkg_root = Path(__file__).resolve().parents[1]
            if not (pkg_root / "pyproject.toml").is_file():
                pkg_root = cwd

    if package_format in PACKAGE_SUFFIXES:
        destination = _resolve_package_destination(destination, package_format)
    elif package_format != "directory":
        raise TransferError(f"unsupported package format: {package_format}")

    manifest = prepare(
        pkg_root,
        destination,
        policy,
        dry_run=dry_run,
        strict=False,
        signer=signer,
        logger=logger,
        is_self_package=True,
    )
    return manifest, destination
