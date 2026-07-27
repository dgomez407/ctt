import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from controlled_text_transfer.cli import main
from controlled_text_transfer.core import Policy, prepare


class _FakeSigner:
    algorithm = "test-signature"

    def sign(self, data: bytes) -> bytes:
        return b"signature:" + data

    def verify(self, data: bytes, signature: bytes) -> bool:
        return signature == b"signature:" + data


def _source_with_file(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    (source / "nested").mkdir()
    (source / "nested" / "a.py").write_bytes(b"print('a')\n")
    return source


def test_zip_contains_manifest_and_relative_payload_layout(tmp_path: Path):
    source = _source_with_file(tmp_path)
    package = tmp_path / "package"

    prepare(source, package, Policy(package_format="zip"))

    assert not package.exists()
    with zipfile.ZipFile(package.with_suffix(".zip")) as archive:
        assert set(archive.namelist()) == {
            "ctt-manifest.json.txt",
            "payload/nested/a.py.txt",
        }


@pytest.mark.parametrize(
    ("package_format", "suffix", "mode"),
    [("tar", ".tar", "r"), ("tgz", ".tgz", "r:gz")],
)
def test_tar_archives_contain_canonical_package_layout(
    tmp_path: Path,
    package_format: str,
    suffix: str,
    mode: str,
):
    source = _source_with_file(tmp_path)
    package = tmp_path / f"package-{package_format}"

    prepare(source, package, Policy(package_format=package_format))

    assert not package.exists()
    with tarfile.open(package.with_suffix(suffix), mode) as archive:
        names = set(archive.getnames())
    assert f"{package.name}/ctt-manifest.json.txt" in names
    assert f"{package.name}/payload/nested/a.py.txt" in names


def test_tgz_archive_root_dir_omits_suffix(tmp_path: Path):
    source = _source_with_file(tmp_path)
    package = tmp_path / "ctt-bootstrap.tgz"

    prepare(source, package, Policy(package_format="tgz"))

    with tarfile.open(package, "r:gz") as archive:
        names = set(archive.getnames())
    assert "ctt-bootstrap/ctt-manifest.json.txt" in names
    assert "ctt-bootstrap.tgz/ctt-manifest.json.txt" not in names


def test_cli_accepts_readme_policy_option_after_prepare_arguments(tmp_path: Path, capsys):
    source = _source_with_file(tmp_path)
    package = tmp_path / "package"
    policy = tmp_path / "policy.yaml"
    policy.write_text("add_bom: false\n", encoding="utf-8")

    result = main(
        [
            "prepare",
            str(source),
            str(package),
            "--policy",
            str(policy),
        ]
    )

    assert result == 0
    assert not (package / "payload/nested/a.py.txt").read_bytes().startswith(b"\xef\xbb\xbf")
    capsys.readouterr()


def test_cli_accepts_runbook_log_option_after_prepare_arguments(tmp_path: Path, capsys):
    source = _source_with_file(tmp_path)
    package = tmp_path / "package"

    result = main(["prepare", str(source), str(package), "--log-json"])

    assert result == 0
    event = json.loads(capsys.readouterr().err.strip())
    assert event["event"] == "prepare_complete"
    assert event["files"] == 1
    assert event["skipped"] == 0


def test_cli_restore_dry_run_verifies_without_writing(tmp_path: Path, capsys):
    source = _source_with_file(tmp_path)
    package = tmp_path / "package"
    prepare(source, package, Policy())
    destination = tmp_path / "destination"

    result = main(["restore", str(package), str(destination), "--dry-run"])

    assert result == 0
    assert not destination.exists()
    capsys.readouterr()


def test_cli_plain_diff_lists_each_category_and_path(tmp_path: Path, capsys):
    source = _source_with_file(tmp_path)
    package = tmp_path / "package"
    prepare(source, package, Policy())
    (source / "nested" / "a.py").write_text("changed", encoding="utf-8")

    result = main(["diff", str(package), str(source)])

    assert result == 0
    output = capsys.readouterr().out
    assert "modified: 1" in output
    assert "  nested/a.py" in output


def test_cli_returns_two_and_logs_operational_errors(tmp_path: Path, capsys):
    result = main(["verify", str(tmp_path / "missing-package")])

    assert result == 2
    assert "ERROR:" in capsys.readouterr().err


def test_cli_invalid_package_format_leaves_no_output(tmp_path: Path, capsys):
    source = _source_with_file(tmp_path)
    package = tmp_path / "package"
    policy = tmp_path / "policy.yaml"
    policy.write_text("package_format: rar\n", encoding="utf-8")

    result = main(["prepare", str(source), str(package), "--policy", str(policy)])

    assert result == 2
    assert "unsupported package_format" in capsys.readouterr().err
    assert not package.exists()


def test_cli_preflight_emits_machine_readable_report(tmp_path: Path, capsys):
    source = _source_with_file(tmp_path)

    result = main(["preflight", str(source), "--json"])

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["profile"] == "generic-text-v1"
    assert report["accepted_count"] == 1
    assert report["decisions"][0]["path"] == "nested/a.py"


def test_cli_preflight_summarizes_report_for_people(tmp_path: Path, capsys):
    source = _source_with_file(tmp_path)

    result = main(["preflight", str(source)])

    assert result == 0
    assert capsys.readouterr().out == "accepted: 1\nrejected: 0\ntotal bytes: 11\n"


def test_cli_strict_prepare_writes_report_but_no_package_when_any_file_is_rejected(
    tmp_path: Path, capsys
):
    source = _source_with_file(tmp_path)
    (source / "binary.py").write_bytes(b"\xff")
    package = tmp_path / "package"
    report_path = tmp_path / "preflight.json"

    result = main(
        [
            "prepare",
            str(source),
            str(package),
            "--strict",
            "--json-report",
            str(report_path),
        ]
    )

    assert result == 2
    assert not package.exists()
    assert json.loads(report_path.read_text(encoding="utf-8"))["rejected_count"] == 1
    assert "strict preflight rejected" in capsys.readouterr().err


def test_cli_malformed_manifest_returns_two_without_traceback(tmp_path: Path, capsys):
    package = tmp_path / "package"
    package.mkdir()
    (package / "ctt-manifest.json.txt").write_text("[]", encoding="utf-8")

    result = main(["verify", str(package)])

    assert result == 2
    error = capsys.readouterr().err
    assert "ERROR: invalid manifest:" in error
    assert "Traceback" not in error


def test_cli_can_require_a_trusted_injected_signature_verifier(tmp_path: Path, capsys):
    source = _source_with_file(tmp_path)
    package = tmp_path / "package"
    prepare(source, package, Policy(), signer=_FakeSigner())

    result = main(
        ["verify", str(package), "--require-signature"],
        signer=_FakeSigner(),
    )

    assert result == 0
    capsys.readouterr()


def test_cli_requires_verifier_for_declared_signature_unless_explicitly_allowed(
    tmp_path: Path, capsys
):
    source = _source_with_file(tmp_path)
    package = tmp_path / "package"
    prepare(source, package, Policy(), signer=_FakeSigner())

    assert main(["verify", str(package)]) == 2
    assert "trusted signature verifier is required" in capsys.readouterr().err

    assert main(["verify", str(package), "--allow-unverified-signature"]) == 0
    capsys.readouterr()


def test_cli_refuses_signing_without_trusted_injected_signer(tmp_path: Path, capsys):
    source = _source_with_file(tmp_path)
    package = tmp_path / "package"

    result = main(["prepare", str(source), str(package), "--sign"])

    assert result == 2
    assert "trusted signer is required" in capsys.readouterr().err
    assert not package.exists()


def test_prepare_refuses_to_replace_existing_package_directory(tmp_path: Path):
    source = _source_with_file(tmp_path)
    package = tmp_path / "package"
    package.mkdir()

    with pytest.raises(FileExistsError):
        prepare(source, package, Policy())
