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
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol

MAX_SIGNATURE_BYTES = 256 * 1024
MAX_VERIFIER_OUTPUT_BYTES = 256 * 1024
MAX_SIGNER_IDENTITY_LENGTH = 512


class _CommandOutputLimitExceeded(RuntimeError):
    """Signal that an external command exceeded a bounded output stream."""


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
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or bool(getattr(before, "st_reparse_tag", 0))
            or not stat.S_ISREG(before.st_mode)
        ):
            raise ValueError(f"{label} must be a regular unlinked file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
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
        data = b"".join(chunks)
    except OSError as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise ValueError(f"{label} could not be read safely") from error
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise

    try:
        os.close(descriptor)
    except OSError as error:
        raise ValueError(f"{label} could not be read safely") from error
    return data


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

    def _run(
        self,
        command: Sequence[str],
        data: bytes,
        *,
        stdout_limit: int,
        stderr_limit: int,
    ) -> subprocess.CompletedProcess[bytes]:
        """Run a command while retaining no more than each stream's byte limit."""
        arguments = list(command)
        process = subprocess.Popen(  # nosec B603
            arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            bufsize=0,
        )
        if process.stdin is None or process.stdout is None or process.stderr is None:
            process.kill()
            process.wait()
            raise RuntimeError("external command pipes could not be created")
        stdin = process.stdin
        stdout_stream = process.stdout
        stderr_stream = process.stderr

        cancel = threading.Event()
        overflow = threading.Event()
        failures: list[BaseException] = []
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []

        def read_bounded(stream: BinaryIO, limit: int, chunks: list[bytes]) -> None:
            total = 0
            try:
                while chunk := stream.read(min(64 * 1024, limit + 1 - total)):
                    total += len(chunk)
                    if total > limit:
                        overflow.set()
                        cancel.set()
                        return
                    chunks.append(chunk)
            except (OSError, ValueError) as error:
                failures.append(error)
                cancel.set()

        def write_input() -> None:
            try:
                stdin.write(data)
                stdin.close()
            except (BrokenPipeError, OSError):
                pass

        threads = [
            threading.Thread(
                target=read_bounded,
                args=(stdout_stream, stdout_limit, stdout_chunks),
                daemon=True,
            ),
            threading.Thread(
                target=read_bounded,
                args=(stderr_stream, stderr_limit, stderr_chunks),
                daemon=True,
            ),
            threading.Thread(target=write_input, daemon=True),
        ]
        for thread in threads:
            thread.start()

        deadline = time.monotonic() + self.timeout
        timed_out = False
        while process.poll() is None:
            if cancel.wait(timeout=min(0.01, max(0.0, deadline - time.monotonic()))):
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break

        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                process.kill()
        process.wait()

        for stream in (stdin, stdout_stream, stderr_stream):
            try:
                stream.close()
            except OSError:
                pass
        for thread in threads:
            thread.join(timeout=0.25)

        stdout = b"".join(stdout_chunks)
        stderr = b"".join(stderr_chunks)
        if timed_out:
            raise subprocess.TimeoutExpired(arguments, self.timeout, output=stdout, stderr=stderr)
        if overflow.is_set():
            raise _CommandOutputLimitExceeded
        if failures or any(thread.is_alive() for thread in threads):
            raise RuntimeError("external command output could not be read safely")
        return subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)

    def sign(self, data: bytes) -> bytes:
        """Sign data or raise ``RuntimeError`` when the command fails."""
        try:
            result = self._run(
                self.sign_command,
                data,
                stdout_limit=MAX_SIGNATURE_BYTES,
                stderr_limit=MAX_VERIFIER_OUTPUT_BYTES,
            )
        except _CommandOutputLimitExceeded as error:
            raise RuntimeError("external signing command output exceeded security limit") from error
        if result.returncode != 0:
            raise RuntimeError("external signing command failed")
        if len(result.stdout) > MAX_SIGNATURE_BYTES or len(result.stderr) > MAX_VERIFIER_OUTPUT_BYTES:
            raise RuntimeError("external signing command output exceeded security limit")
        return result.stdout

    def verify(self, data: bytes, signature: bytes) -> bool | SignatureVerification:
        """Return whether the external command validates the signature."""
        try:
            result = self._run(
                self.verify_command,
                data + b"\n" + signature,
                stdout_limit=MAX_VERIFIER_OUTPUT_BYTES,
                stderr_limit=MAX_VERIFIER_OUTPUT_BYTES,
            )
        except _CommandOutputLimitExceeded:
            if self.structured_verification:
                return SignatureVerification(False, None)
            return False
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
