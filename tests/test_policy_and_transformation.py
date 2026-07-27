import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from controlled_text_transfer.core import Policy, TransferError, diff, digest, prepare


def test_policy_from_file_loads_all_documented_options(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
allowlist:
  extensions: [".PY", ".md"]
  names: ["Dockerfile"]
add_bom: false
hash_algorithm: sha512
max_bytes: 42
package_format: tgz
ignore_file: .transferignore
profile: generic-text-v1
max_total_bytes: 84
max_files: 7
max_path_depth: 6
max_path_length: 120
max_filename_length: 40
max_line_length: 80
allow_unicode: false
allow_mixed_line_endings: true
prohibited_patterns: ["PRIVATE"]
""",
        encoding="utf-8",
    )

    policy = Policy.from_file(policy_path)

    assert policy.extensions == {".py", ".md"}
    assert policy.names == {"Dockerfile"}
    assert policy.add_bom is False
    assert policy.hash_algorithm == "sha512"
    assert policy.max_bytes == 42
    assert policy.package_format == "tgz"
    assert policy.ignore_file == ".transferignore"
    assert policy.profile == "generic-text-v1"
    assert policy.max_total_bytes == 84
    assert policy.max_files == 7
    assert policy.max_path_depth == 6
    assert policy.max_path_length == 120
    assert policy.max_filename_length == 40
    assert policy.max_line_length == 80
    assert policy.allow_unicode is False
    assert policy.allow_mixed_line_endings is True
    assert policy.prohibited_patterns == ["PRIVATE"]


def test_policy_from_none_returns_safe_independent_defaults():
    first = Policy.from_file(None)
    second = Policy.from_file(None)

    first.extensions.remove(".py")

    assert ".py" in second.extensions
    assert first.add_bom is True
    assert first.hash_algorithm == "sha256"
    assert first.max_bytes == 10 * 1024 * 1024


def test_policy_rejects_removed_workers_option(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("workers: 4\n", encoding="utf-8")

    with pytest.raises(TransferError, match="invalid policy: unknown field"):
        Policy.from_file(policy_path)


def test_prepare_respects_custom_allowlist_and_ignore_patterns(tmp_path: Path):
    source = tmp_path / "source"
    (source / "nested").mkdir(parents=True)
    (source / "keep.custom").write_text("keep", encoding="utf-8")
    (source / "Dockerfile").write_text("FROM scratch", encoding="utf-8")
    (source / "ignored.custom").write_text("ignored", encoding="utf-8")
    (source / "nested" / "ignored.custom").write_text("ignored", encoding="utf-8")
    (source / ".transferignore").write_text(
        "# comment\nignored.custom\n",
        encoding="utf-8",
    )

    manifest = prepare(
        source,
        tmp_path / "package",
        Policy(
            extensions={".custom"},
            names={"Dockerfile"},
            ignore_file=".transferignore",
        ),
        dry_run=True,
    )

    assert [record.original_path for record in manifest.files] == [
        "Dockerfile",
        "keep.custom",
    ]
    assert manifest.skipped == []


def test_prepare_reports_oversize_invalid_utf8_and_non_allowlisted_files(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "large.py").write_text("12345", encoding="utf-8")
    (source / "invalid.py").write_bytes(b"\xff")
    (source / "program.exe").write_text("text", encoding="utf-8")

    manifest = prepare(
        source,
        tmp_path / "package",
        Policy(max_bytes=4),
        dry_run=True,
    )

    assert manifest.skipped == [
        "invalid.py (binary or unreadable)",
        "large.py (oversize)",
        "program.exe (not allowlisted)",
    ]


def test_prepare_without_transport_bom_preserves_exact_bytes_and_manifest_metadata(
    tmp_path: Path,
):
    source = tmp_path / "source"
    source.mkdir()
    original = b"plain text\n"
    (source / "note.txt").write_bytes(original)
    package = tmp_path / "package"

    manifest = prepare(source, package, Policy(add_bom=False))
    record = manifest.files[0]

    assert (package / record.transfer_path).read_bytes() == original
    assert record.bom_added is False
    assert record.original_bom is False
    assert record.original_size == len(original)
    assert record.transfer_size == len(original)
    assert record.original_hash == hashlib.sha256(original).hexdigest()
    assert record.transfer_hash == record.original_hash


def test_prepare_is_non_destructive_and_manifest_order_is_deterministic(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    for name in ["z.py", "a.py", "m.py"]:
        (source / name).write_text(name, encoding="utf-8")
    before = {path.name: path.read_bytes() for path in source.iterdir()}

    manifest = prepare(source, tmp_path / "package", Policy())

    assert [record.original_path for record in manifest.files] == ["a.py", "m.py", "z.py"]
    assert {path.name: path.read_bytes() for path in source.iterdir()} == before


def test_prepare_rejects_non_directory_source(tmp_path: Path):
    source = tmp_path / "source.py"
    source.write_text("text", encoding="utf-8")

    with pytest.raises(TransferError, match="source must be a directory"):
        prepare(source, tmp_path / "package", Policy())


def test_digest_rejects_unsupported_algorithm():
    with pytest.raises(TransferError, match="unsupported hash algorithm"):
        digest(b"data", "not-a-hash")


def test_prepare_rejects_unsupported_package_format(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("a", encoding="utf-8")
    package = tmp_path / "package"

    with pytest.raises(TransferError, match="invalid policy: unsupported package_format"):
        prepare(source, package, Policy(package_format="rar"))

    assert not package.exists()


def test_prepare_dry_run_rejects_unsupported_package_format(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("a", encoding="utf-8")
    package = tmp_path / "package"

    with pytest.raises(TransferError, match="invalid policy: unsupported package_format"):
        prepare(source, package, Policy(package_format="rar"), dry_run=True)

    assert not package.exists()


def test_digest_uses_optional_blake3_when_available(monkeypatch):
    fake_module = SimpleNamespace(
        blake3=lambda data: SimpleNamespace(hexdigest=lambda: f"blake3:{data.decode()}")
    )
    monkeypatch.setitem(sys.modules, "blake3", fake_module)

    assert digest(b"data", "blake3") == "blake3:data"


def test_digest_fails_clearly_when_optional_blake3_is_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "blake3", None)

    with pytest.raises(TransferError, match="optional dependency is not installed"):
        digest(b"data", "blake3")


def test_policy_fails_clearly_when_yaml_dependency_is_unavailable(
    tmp_path: Path,
    monkeypatch,
):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("add_bom: false\n", encoding="utf-8")
    monkeypatch.setitem(sys.modules, "yaml", None)

    with pytest.raises(TransferError, match="YAML policy requires PyYAML"):
        Policy.from_file(policy_path)


def test_diff_excludes_ignored_and_non_allowlisted_added_files(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "existing.py").write_text("existing", encoding="utf-8")
    package = tmp_path / "package"
    prepare(source, package, Policy())
    (source / ".cttignore").write_text("ignored.py\n", encoding="utf-8")
    (source / "ignored.py").write_text("ignored", encoding="utf-8")
    (source / "binary.exe").write_text("not allowlisted", encoding="utf-8")

    result = diff(package, source, Policy())

    assert result == {
        "added": [],
        "removed": [],
        "modified": [],
        "unchanged": ["existing.py"],
    }
