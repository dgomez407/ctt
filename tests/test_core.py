import json
from pathlib import Path

import pytest

from controlled_text_transfer.cli import main
from controlled_text_transfer.core import Policy, TransferError, diff, prepare, restore, verify


def test_round_trip_and_bom(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("print('x')\n", encoding="utf-8")
    (src / "image.bin").write_bytes(b"\x00\xff")
    (src / ".cttignore").write_text("ignored.*\n", encoding="utf-8")
    (src / "ignored.md").write_text("skip", encoding="utf-8")
    package = tmp_path / "package"
    m = prepare(src, package, Policy())
    assert len(m.files) == 1
    assert (package / "payload/a.py.txt").read_bytes().startswith(b"\xef\xbb\xbf")
    verify(package)
    out = tmp_path / "out"
    restore(package, out)
    assert (out / "a.py").read_text() == "print('x')\n"


def test_tamper_is_rejected(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.md").write_text("ok", encoding="utf-8")
    package = tmp_path / "p"
    prepare(src, package, Policy())
    (package / "payload/a.md.txt").write_text("tampered", encoding="utf-8")
    with pytest.raises(TransferError, match="checksum"):
        verify(package)


def test_unexpected_payload_file_is_rejected(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.py").write_text("ok", encoding="utf-8")
    package = tmp_path / "package"
    prepare(source, package, Policy())
    (package / "payload" / "unexpected.py.txt").write_text("extra", encoding="utf-8")

    with pytest.raises(TransferError, match="unexpected"):
        verify(package)


def test_dry_run_does_not_write(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x", encoding="utf-8")
    package = tmp_path / "p"
    m = prepare(src, package, Policy(), dry_run=True)
    assert len(m.files) == 1 and not package.exists()


def test_binary_and_non_allowlisted_are_skipped(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.bin").write_bytes(b"\0\xff")
    (src / "a.exe").write_text("not selected", encoding="utf-8")
    m = prepare(src, tmp_path / "p", Policy(), dry_run=True)
    assert len(m.files) == 0 and len(m.skipped) == 2


def test_policy_archive_and_cli(tmp_path: Path, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x", encoding="utf-8")
    policy = tmp_path / "policy.yaml"
    policy.write_text("package_format: zip\n", encoding="utf-8")
    package = tmp_path / "p"
    assert main(["prepare", str(src), str(package), "--policy", str(policy)]) == 0
    assert package.with_suffix(".zip").is_file()
    assert main(["verify", str(package.with_suffix(".zip"))]) == 0
    capsys.readouterr()


def test_tar_and_tar_gz_use_correct_archive_suffixes(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("x", encoding="utf-8")

    tar_package = tmp_path / "tar-package"
    prepare(source, tar_package, Policy(package_format="tar"))
    assert tar_package.with_suffix(".tar").is_file()

    gz_package = tmp_path / "gz-package"
    prepare(source, gz_package, Policy(package_format="tgz"))
    assert gz_package.with_suffix(".tgz").is_file()


def test_package_invalid_format(tmp_path: Path):
    from controlled_text_transfer.core import (
        TransferError,
        _package,
        _resolve_package_destination,
    )

    assert _resolve_package_destination(tmp_path / "mydir", "directory") == tmp_path / "mydir"
    with pytest.raises(TransferError, match="unsupported package format"):
        _package(tmp_path, "invalid")


def test_sha512_and_original_bom(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.md").write_bytes(b"\xef\xbb\xbfhello")
    package = tmp_path / "p"
    prepare(src, package, Policy(hash_algorithm="sha512"))
    out = tmp_path / "out"
    restore(package, out)
    assert (out / "a.md").read_bytes() == b"\xef\xbb\xbfhello"


def test_diff_reports_added_removed_modified_and_unchanged(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "same.py").write_text("same", encoding="utf-8")
    (source / "changed.py").write_text("before", encoding="utf-8")
    (source / "removed.py").write_text("gone", encoding="utf-8")
    package = tmp_path / "package"
    prepare(source, package, Policy())

    (source / "changed.py").write_text("after", encoding="utf-8")
    (source / "removed.py").unlink()
    (source / "added.py").write_text("new", encoding="utf-8")

    result = diff(package, source, Policy())

    assert result == {
        "added": ["added.py"],
        "removed": ["removed.py"],
        "modified": ["changed.py"],
        "unchanged": ["same.py"],
    }


def test_diff_is_read_only(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("a", encoding="utf-8")
    package = tmp_path / "package"
    prepare(source, package, Policy())
    before = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))

    assert diff(package, source, Policy())["unchanged"] == ["a.py"]
    after = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
    assert after == before


def test_cli_diff_supports_json_output(tmp_path: Path, capsys):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("a", encoding="utf-8")
    package = tmp_path / "package"
    prepare(source, package, Policy())

    assert main(["diff", str(package), str(source), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["unchanged"] == ["a.py"]


def test_cli_json_logging_contains_audit_timestamp(tmp_path: Path, capsys):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("a", encoding="utf-8")
    package = tmp_path / "package"

    assert main(["prepare", str(source), str(package), "--log-json"]) == 0
    log_line = capsys.readouterr().err.strip().splitlines()[-1]
    assert '"event": "prepare_complete"' in log_line
    assert '"timestamp":' in log_line
