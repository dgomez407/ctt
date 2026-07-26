"""Safe integration hooks for externally managed manifest signatures.

This module deliberately does not create, import, or store private keys. An
approved GPG, X.509, HSM, or enterprise signing service can implement the
small ``ManifestSigner`` protocol, or be called through ``ExternalCommandSigner``.
"""

from __future__ import annotations

import subprocess  # nosec B404
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol


class ManifestSigner(Protocol):
    """Define detached manifest signing and verification behavior."""

    algorithm: str

    def sign(self, data: bytes) -> bytes:
        """Return a detached signature for exact manifest bytes."""
        ...

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Return whether a signature authenticates exact manifest bytes."""
        ...


def sign_manifest(
    manifest_path: Path,
    signature_path: Path,
    signer: ManifestSigner,
    *,
    key_label: str = "external-managed-key",
) -> dict[str, str]:
    """Sign manifest bytes and write a detached signature sidecar."""
    signature_path.write_bytes(signer.sign(manifest_path.read_bytes()))
    return {"algorithm": signer.algorithm, "key_label": key_label}


def verify_manifest_signature(
    manifest_path: Path, signature_path: Path, signer: ManifestSigner
) -> bool:
    """Verify a detached signature, returning ``False`` for a missing sidecar."""
    if not signature_path.is_file():
        return False
    return signer.verify(manifest_path.read_bytes(), signature_path.read_bytes())


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
        return result.stdout

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Return whether the external command validates the signature."""
        result = self._run(self.verify_command, data + b"\n" + signature)
        return result.returncode == 0
