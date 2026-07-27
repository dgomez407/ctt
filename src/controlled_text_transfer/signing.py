"""Safe integration hooks for externally managed manifest signatures.

This module deliberately does not create, import, or store private keys. An
approved GPG, X.509, HSM, or enterprise signing service can implement the
small ``ManifestSigner`` protocol, or be called through ``ExternalCommandSigner``.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess  # nosec B404
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

MAX_SIGNATURE_BYTES = 256 * 1024
MAX_VERIFIER_OUTPUT_BYTES = 256 * 1024
MAX_SIGNER_IDENTITY_LENGTH = 512


@dataclass(frozen=True)
class SignatureVerification:
    """Describe signature validity and the identity authenticated by a verifier."""

    valid: bool
    identity: str | None


class ManifestSigner(Protocol):
    """Define detached manifest signing and verification behavior."""

    algorithm: str

    def sign(self, data: bytes) -> bytes:
        """Return a detached signature for exact manifest bytes."""
        ...

    def verify(self, data: bytes, signature: bytes) -> bool | SignatureVerification:
        """Return legacy validity or validity with authenticated signer identity."""
        ...


def _read_stable(path: Path, maximum: int, label: str) -> bytes:
    """Read one regular file through a stable descriptor with a hard size bound."""
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or bool(getattr(before, "st_reparse_tag", 0))
        or not stat.S_ISREG(before.st_mode)
    ):
        raise ValueError(f"{label} must be a regular unlinked file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        after = path.lstat()
        before_identity = (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode))
        opened_identity = (opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode))
        after_identity = (after.st_dev, after.st_ino, stat.S_IFMT(after.st_mode))
        if before_identity != opened_identity or opened_identity != after_identity:
            raise ValueError(f"{label} changed while it was opened")
        if opened.st_size > maximum:
            raise ValueError(f"{label} exceeds the security limit")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, min(64 * 1024, maximum + 1 - total)):
            total += len(chunk)
            if total > maximum:
                raise ValueError(f"{label} exceeds the security limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_identity(identity: object) -> str:
    """Return a safe authenticated signer identity."""
    if (
        not isinstance(identity, str)
        or not identity
        or len(identity) > MAX_SIGNER_IDENTITY_LENGTH
        or any(ord(character) < 32 for character in identity)
    ):
        raise ValueError("invalid signer identity")
    return identity


def sign_manifest(
    manifest_path: Path,
    signature_path: Path,
    signer: ManifestSigner,
    *,
    key_label: str = "external-managed-key",
) -> dict[str, str]:
    """Sign manifest bytes and write a detached signature sidecar."""
    signature = signer.sign(_read_stable(manifest_path, 2 * 1024 * 1024, "manifest"))
    if len(signature) > MAX_SIGNATURE_BYTES:
        raise ValueError("signature exceeds the security limit")
    signature_path.write_bytes(signature)
    metadata = {"algorithm": signer.algorithm, "key_label": key_label}
    identity = getattr(signer, "identity", None)
    if identity is not None:
        metadata["identity"] = _validate_identity(identity)
    return metadata


def verify_manifest_signature(
    manifest_path: Path, signature_path: Path, signer: ManifestSigner
) -> bool | SignatureVerification:
    """Verify a detached signature, returning ``False`` for a missing sidecar."""
    if not signature_path.is_file():
        return False
    return signer.verify(
        _read_stable(manifest_path, 2 * 1024 * 1024, "manifest"),
        _read_stable(signature_path, MAX_SIGNATURE_BYTES, "signature"),
    )


class ExternalCommandSigner:
    """Adapter for an approved signing command using stdin/stdout.

    Commands are argument vectors and always run with ``shell=False``. Secret
    flags are rejected because key custody and passphrases belong in the
    external tool's approved configuration, agent, HSM, or smart card.
    """

    _SECRET_FLAGS = {
        "--passphrase",
        "--passphrase-file",
        "--passphrase-fd",
        "--secret-key",
        "--private-key",
    }

    def __init__(
        self,
        sign_command: Sequence[str],
        verify_command: Sequence[str],
        *,
        algorithm: str = "external-command",
        timeout: float = 30.0,
        structured_verification: bool = False,
        identity: str | None = None,
    ) -> None:
        """Configure trusted sign and verify command argument vectors."""
        self._validate_command(sign_command)
        self._validate_command(verify_command)
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.sign_command = tuple(sign_command)
        self.verify_command = tuple(verify_command)
        self.algorithm = algorithm
        self.timeout = timeout
        self.structured_verification = structured_verification
        self.identity = _validate_identity(identity) if identity is not None else None

    @classmethod
    def _validate_command(cls, command: Sequence[str]) -> None:
        if not command:
            raise ValueError("signing command must be non-empty")
        if any(argument.partition("=")[0].casefold() in cls._SECRET_FLAGS for argument in command):
            raise ValueError("secret-handling arguments are not accepted by signing hooks")

    def _run(self, command: Sequence[str], data: bytes) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(  # nosec B603
            list(command),
            input=data,
            capture_output=True,
            check=False,
            shell=False,
            timeout=self.timeout,
        )

    def sign(self, data: bytes) -> bytes:
        """Sign data or raise ``RuntimeError`` when the command fails."""
        result = self._run(self.sign_command, data)
        if result.returncode != 0:
            raise RuntimeError("external signing command failed")
        if len(result.stdout) > MAX_SIGNATURE_BYTES:
            raise RuntimeError("external signing command output exceeded security limit")
        return result.stdout

    def verify(self, data: bytes, signature: bytes) -> bool | SignatureVerification:
        """Return whether the external command validates the signature."""
        result = self._run(self.verify_command, data + b"\n" + signature)
        if not self.structured_verification:
            return result.returncode == 0
        if (
            result.returncode != 0
            or len(result.stdout) > MAX_VERIFIER_OUTPUT_BYTES
            or len(result.stderr) > MAX_VERIFIER_OUTPUT_BYTES
        ):
            return SignatureVerification(False, None)
        try:
            raw = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return SignatureVerification(False, None)
        if not isinstance(raw, dict) or set(raw) != {"valid", "identity"}:
            return SignatureVerification(False, None)
        if raw["valid"] is not True:
            return SignatureVerification(False, None)
        try:
            identity = _validate_identity(raw["identity"])
        except ValueError:
            return SignatureVerification(False, None)
        return SignatureVerification(True, identity)
