import json
import subprocess
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

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=b"detached-signature")

    monkeypatch.setattr("controlled_text_transfer.signing.subprocess.run", fake_run)
    signer = ExternalCommandSigner(
        ["approved-sign"],
        ["approved-verify"],
        timeout=2.5,
    )

    assert signer.sign(b"manifest") == b"detached-signature"
    assert signer.verify(b"manifest", b"signature") is True

    assert calls[0] == (
        ["approved-sign"],
        {
            "input": b"manifest",
            "capture_output": True,
            "check": False,
            "shell": False,
            "timeout": 2.5,
        },
    )
    assert calls[1][0] == ["approved-verify"]
    assert calls[1][1]["input"] == b"manifest\nsignature"
    assert calls[1][1]["shell"] is False


def test_external_signer_fails_closed_on_command_errors(monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 7, stdout=b"")

    monkeypatch.setattr("controlled_text_transfer.signing.subprocess.run", fake_run)
    signer = ExternalCommandSigner(["approved-sign"], ["approved-verify"])

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

    with pytest.raises(TransferError, match="authenticated signer identity is required"):
        verify(package, signer=FakeSigner(), require_signature=True)


def test_structured_external_verifier_parses_authenticated_identity(monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=b'{"valid":true,"identity":"SHA256:approved"}',
            stderr=b"",
        )

    monkeypatch.setattr("controlled_text_transfer.signing.subprocess.run", fake_run)
    signer = ExternalCommandSigner(
        ["approved-sign"],
        ["approved-verify"],
        structured_verification=True,
        identity="SHA256:approved",
    )

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
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=b"")

    monkeypatch.setattr("controlled_text_transfer.signing.subprocess.run", fake_run)
    signer = ExternalCommandSigner(
        ["approved-sign"],
        ["approved-verify"],
        structured_verification=True,
    )

    assert signer.verify(b"manifest", b"signature") == SignatureVerification(False, None)


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
