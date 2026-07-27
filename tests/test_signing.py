import json
import subprocess
import sys
from pathlib import Path

import pytest

from controlled_text_transfer.core import Policy, TransferError, prepare, verify
from controlled_text_transfer.signing import (
    ExternalCommandSigner,
    SignatureVerification,
    sign_manifest,
    verify_manifest_signature,
)


class FakeSigner:
    algorithm = "test-signature"

    def sign(self, data: bytes) -> bytes:
        return b"signature:" + data

    def verify(self, data: bytes, signature: bytes) -> bool:
        return signature == b"signature:" + data


class IdentitySigner(FakeSigner):
    identity = "SHA256:approved-fingerprint"

    def verify(self, data: bytes, signature: bytes) -> SignatureVerification:
        return SignatureVerification(
            signature == b"signature:" + data,
            self.identity,
        )


def test_sign_and_verify_manifest_with_hook(tmp_path: Path):
    manifest = tmp_path / "manifest.json.txt"
    signature = tmp_path / "manifest.sig"
    manifest.write_bytes(b"manifest")

    metadata = sign_manifest(manifest, signature, FakeSigner(), key_label="approved-key")

    assert metadata == {"algorithm": "test-signature", "key_label": "approved-key"}
    assert verify_manifest_signature(manifest, signature, FakeSigner()) is True


def test_tampered_signature_is_rejected(tmp_path: Path):
    manifest = tmp_path / "manifest.json.txt"
    signature = tmp_path / "manifest.sig"
    manifest.write_bytes(b"manifest")
    signature.write_bytes(b"bad")

    assert verify_manifest_signature(manifest, signature, FakeSigner()) is False


def test_external_signer_rejects_secret_arguments():
    with pytest.raises(ValueError, match="secret-handling"):
        ExternalCommandSigner(["gpg", "--passphrase", "secret"], ["gpg", "--verify"])


def test_external_signer_requires_argument_vectors():
    with pytest.raises(ValueError, match="non-empty"):
        ExternalCommandSigner([], ["gpg", "--verify"])


def test_verify_missing_signature_returns_false(tmp_path: Path):
    manifest = tmp_path / "manifest.json.txt"
    manifest.write_bytes(b"manifest")

    assert (
        verify_manifest_signature(
            manifest,
            tmp_path / "missing.sig",
            FakeSigner(),
        )
        is False
    )


def test_sign_manifest_uses_safe_default_key_label(tmp_path: Path):
    manifest = tmp_path / "manifest.json.txt"
    signature = tmp_path / "manifest.sig"
    manifest.write_bytes(b"manifest")

    metadata = sign_manifest(manifest, signature, FakeSigner())

    assert metadata == {
        "algorithm": "test-signature",
        "key_label": "external-managed-key",
    }


@pytest.mark.parametrize(
    "flag",
    ["--passphrase-file", "--PASSPHRASE-FD", "--secret-key", "--private-key"],
)
def test_external_signer_rejects_every_secret_bearing_flag(flag: str):
    with pytest.raises(ValueError, match="secret-handling"):
        ExternalCommandSigner(["signer", flag, "value"], ["verifier"])


@pytest.mark.parametrize(
    "argument",
    [
        "--passphrase=secret",
        "--PASSPHRASE-FILE=secret.txt",
        "--passphrase-fd=0",
        "--secret-key=private.pem",
        "--PRIVATE-KEY=private.pem",
    ],
)
def test_external_signer_rejects_secret_bearing_assignment_arguments(argument: str):
    with pytest.raises(ValueError, match="secret-handling"):
        ExternalCommandSigner(["signer", argument], ["verifier"])


@pytest.mark.parametrize("timeout", [0, -1])
def test_external_signer_requires_positive_timeout(timeout: float):
    with pytest.raises(ValueError, match="timeout must be positive"):
        ExternalCommandSigner(["signer"], ["verifier"], timeout=timeout)


def test_external_signer_passes_data_with_shell_disabled_and_timeout(monkeypatch):
    calls = []

    def fake_run(command, data, *, stdout_limit, stderr_limit):
        calls.append((command, data, stdout_limit, stderr_limit))
        return subprocess.CompletedProcess(command, 0, stdout=b"detached-signature", stderr=b"")

    signer = ExternalCommandSigner(
        ["approved-sign"],
        ["approved-verify"],
        timeout=2.5,
    )
    monkeypatch.setattr(signer, "_run", fake_run)

    assert signer.sign(b"manifest") == b"detached-signature"
    assert signer.verify(b"manifest", b"signature") is True

    assert calls[0][0:2] == (signer.sign_command, b"manifest")
    assert calls[1][0:2] == (signer.verify_command, b"manifest\nsignature")
    assert calls[0][2:] == (256 * 1024, 256 * 1024)
    assert calls[1][2:] == (256 * 1024, 256 * 1024)


def test_external_signer_fails_closed_on_command_errors(monkeypatch):
    def fake_run(command, data, **kwargs):
        return subprocess.CompletedProcess(command, 7, stdout=b"")

    signer = ExternalCommandSigner(["approved-sign"], ["approved-verify"])
    monkeypatch.setattr(signer, "_run", fake_run)

    with pytest.raises(RuntimeError, match="external signing command failed"):
        signer.sign(b"manifest")
    assert signer.verify(b"manifest", b"signature") is False


def test_prepare_and_verify_enforce_integrated_manifest_signature(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")
    package = tmp_path / "package"

    manifest = prepare(
        source,
        package,
        Policy(),
        signer=FakeSigner(),
        key_label="approved-key",
    )

    assert manifest.signature == {
        "algorithm": "test-signature",
        "key_label": "approved-key",
    }
    assert verify(package, signer=FakeSigner(), require_signature=True).files


def test_identity_bearing_signature_requires_matching_authenticated_identity(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")
    package = tmp_path / "package"

    manifest = prepare(source, package, Policy(), signer=IdentitySigner())

    assert manifest.signature == {
        "algorithm": "test-signature",
        "key_label": "external-managed-key",
        "identity": IdentitySigner.identity,
    }
    assert verify(package, signer=IdentitySigner(), require_signature=True).files

    class WrongIdentitySigner(IdentitySigner):
        identity = "SHA256:wrong-fingerprint"

    with pytest.raises(TransferError, match="signer identity mismatch"):
        verify(package, signer=WrongIdentitySigner(), require_signature=True)

    class MissingIdentitySigner(IdentitySigner):
        def verify(self, data: bytes, signature: bytes) -> SignatureVerification:
            return SignatureVerification(signature == b"signature:" + data, None)

    with pytest.raises(TransferError, match="authenticated signer identity is required"):
        verify(package, signer=MissingIdentitySigner(), require_signature=True)
    with pytest.raises(TransferError, match="authenticated signer identity is required"):
        verify(package, signer=FakeSigner(), require_signature=True)


def test_structured_external_verifier_parses_authenticated_identity(monkeypatch):
    def fake_run(command, data, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=b'{"valid":true,"identity":"SHA256:approved"}',
            stderr=b"",
        )

    signer = ExternalCommandSigner(
        ["approved-sign"],
        ["approved-verify"],
        structured_verification=True,
        identity="SHA256:approved",
    )
    monkeypatch.setattr(signer, "_run", fake_run)

    assert signer.verify(b"manifest", b"signature") == SignatureVerification(
        True,
        "SHA256:approved",
    )


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [
        (1, b'{"valid":true,"identity":"SHA256:approved"}'),
        (0, b"not-json"),
        (0, b'{"valid":true}'),
        (0, b'{"valid":false,"identity":"SHA256:approved"}'),
        (0, b'{"valid":true,"identity":""}'),
    ],
)
def test_structured_external_verifier_fails_closed(monkeypatch, returncode: int, stdout: bytes):
    def fake_run(command, data, **kwargs):
        return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=b"")

    signer = ExternalCommandSigner(
        ["approved-sign"],
        ["approved-verify"],
        structured_verification=True,
    )
    monkeypatch.setattr(signer, "_run", fake_run)

    assert signer.verify(b"manifest", b"signature") == SignatureVerification(False, None)


def _python_command(source: str) -> list[str]:
    return [sys.executable, "-c", source]


def test_external_signer_accepts_output_at_exact_stream_limits(monkeypatch):
    monkeypatch.setattr("controlled_text_transfer.signing.MAX_SIGNATURE_BYTES", 8)
    monkeypatch.setattr("controlled_text_transfer.signing.MAX_VERIFIER_OUTPUT_BYTES", 8)
    command = _python_command(
        "import sys; sys.stdin.buffer.read(); " "sys.stdout.buffer.write(b'x' * 8); sys.stderr.buffer.write(b'y' * 8)"
    )
    signer = ExternalCommandSigner(command, command)

    assert signer.sign(b"manifest") == b"x" * 8


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_external_signer_stops_capture_when_stream_exceeds_limit(monkeypatch, stream: str):
    monkeypatch.setattr("controlled_text_transfer.signing.MAX_SIGNATURE_BYTES", 8)
    monkeypatch.setattr("controlled_text_transfer.signing.MAX_VERIFIER_OUTPUT_BYTES", 8)
    source = (
        "import sys; sys.stdin.buffer.read(); " f"sys.{stream}.buffer.write(b'x' * 9); " f"sys.{stream}.buffer.flush()"
    )
    command = _python_command(source)
    signer = ExternalCommandSigner(command, command)

    with pytest.raises(RuntimeError, match="output exceeded"):
        signer.sign(b"manifest")
    assert signer.verify(b"manifest", b"signature") is False


def test_external_signer_drains_stdout_and_stderr_concurrently(monkeypatch):
    monkeypatch.setattr("controlled_text_transfer.signing.MAX_SIGNATURE_BYTES", 32)
    monkeypatch.setattr("controlled_text_transfer.signing.MAX_VERIFIER_OUTPUT_BYTES", 32)
    command = _python_command(
        "import sys; sys.stdin.buffer.read(); "
        "sys.stderr.buffer.write(b'e' * 131072); sys.stderr.buffer.flush(); "
        "sys.stdout.buffer.write(b'o' * 131072); sys.stdout.buffer.flush()"
    )
    signer = ExternalCommandSigner(command, command, timeout=2)

    with pytest.raises(RuntimeError, match="output exceeded"):
        signer.sign(b"manifest")


def test_external_signer_timeout_terminates_and_reaps_child():
    command = _python_command("import time; time.sleep(10)")
    signer = ExternalCommandSigner(command, command, timeout=0.1)

    with pytest.raises(subprocess.TimeoutExpired):
        signer.sign(b"manifest")


def test_external_signer_ignores_broken_stdin_after_successful_child_exit():
    command = _python_command("import sys; sys.stdout.buffer.write(b'signature')")
    signer = ExternalCommandSigner(command, command)

    assert signer.sign(b"x" * (1024 * 1024)) == b"signature"


def test_required_signature_fails_for_unsigned_or_tampered_packages(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")
    unsigned = tmp_path / "unsigned"
    prepare(source, unsigned, Policy())

    with pytest.raises(TransferError, match="signature is required"):
        verify(unsigned, signer=FakeSigner(), require_signature=True)

    signed = tmp_path / "signed"
    prepare(source, signed, Policy(), signer=FakeSigner())
    (signed / "ctt-manifest.sig").write_bytes(b"tampered")

    with pytest.raises(TransferError, match="manifest signature verification failed"):
        verify(signed, signer=FakeSigner(), require_signature=True)


def test_declared_signature_requires_verifier_by_default_with_explicit_override(
    tmp_path: Path,
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")
    package = tmp_path / "package"
    prepare(source, package, Policy(), signer=FakeSigner())

    with pytest.raises(TransferError, match="trusted signature verifier is required"):
        verify(package)

    assert verify(package, allow_unverified_signature=True).files


def test_signature_file_requires_manifest_signature_metadata(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")
    package = tmp_path / "package"
    prepare(source, package, Policy())
    (package / "ctt-manifest.sig").write_bytes(b"signature")

    with pytest.raises(TransferError, match="signature metadata is required"):
        verify(package, signer=FakeSigner())


def test_signature_algorithm_must_match_the_trusted_verifier(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("safe\n", encoding="utf-8")
    package = tmp_path / "package"
    prepare(source, package, Policy(), signer=FakeSigner())
    manifest_path = package / "ctt-manifest.json.txt"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["signature"]["algorithm"] = "different-algorithm"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(TransferError, match="signature algorithm mismatch"):
        verify(package, signer=FakeSigner())
