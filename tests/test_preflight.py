import json
from pathlib import Path

import pytest

from controlled_text_transfer import core
from controlled_text_transfer.core import (
    CDSProfile,
    Policy,
    TransferError,
    get_profile,
    preflight,
    prepare,
)


@pytest.mark.parametrize(
    "content",
    [
        "- not\n- an object\n",
        "unknown: true\n",
        "workers: 0\n",
        "max_bytes: -1\n",
        "max_total_bytes: 0\n",
        "max_files: true\n",
        "hash_algorithm: not-a-hash\n",
        "package_format: rar\n",
        "profile: missing-profile\n",
        "allowlist: []\n",
        "allowlist:\n  unknown: []\n",
        'add_bom: "true"\n',
        "hash_algorithm: 1\n",
        'ignore_file: ""\n',
        "profile: 1\n",
        'prohibited_patterns: "SECRET"\n',
        'allowlist:\n  extensions: ".py"\n',
        "allowlist:\n  names: [1]\n",
    ],
)
def test_policy_rejects_malformed_or_unsupported_configuration(tmp_path: Path, content: str):
    path = tmp_path / "policy.yaml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(TransferError, match=r"^invalid policy:"):
        Policy.from_file(path)


def test_empty_yaml_policy_uses_defaults(tmp_path: Path):
    path = tmp_path / "policy.yaml"
    path.write_text("", encoding="utf-8")

    assert Policy.from_file(path) == Policy()


def test_policy_wraps_yaml_parser_errors(tmp_path: Path):
    path = tmp_path / "policy.yaml"
    path.write_text("[", encoding="utf-8")

    with pytest.raises(TransferError, match="invalid policy: malformed YAML"):
        Policy.from_file(path)


def test_profile_must_permit_txt_transfer_extension(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setitem(
        core.CDS_PROFILES,
        "csv-only",
        CDSProfile("csv-only", frozenset({".csv"})),
    )

    with pytest.raises(TransferError, match="profile does not permit .txt"):
        Policy(profile="csv-only").validate()


def test_preflight_returns_one_deterministic_decision_per_candidate(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "accepted.py").write_text("print('ok')\n", encoding="utf-8")
    (source / "binary.py").write_bytes(b"\xff")
    (source / "ignored.py").write_text("ignored\n", encoding="utf-8")
    (source / "program.exe").write_text("not allowed\n", encoding="utf-8")
    (source / ".cttignore").write_text("ignored.py\n", encoding="utf-8")

    report = preflight(source, Policy())

    assert [decision.path for decision in report.decisions] == [
        "accepted.py",
        "binary.py",
        "ignored.py",
        "program.exe",
    ]
    assert [decision.status for decision in report.decisions] == [
        "accepted",
        "rejected",
        "rejected",
        "rejected",
    ]
    assert report.accepted_count == 1
    assert report.rejected_count == 3
    assert report.decisions[0].transformations == [
        "append_txt_suffix",
        "add_utf8_bom",
    ]
    assert json.loads(json.dumps(report.to_dict()))["profile"] == "generic-text-v1"


def test_preflight_rejects_oversized_file_without_reading_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source"
    source.mkdir()
    oversized = source / "large.txt"
    oversized.write_bytes(b"12345")
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path == oversized:
            raise AssertionError("oversized file must not be read")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    report = preflight(source, Policy(max_bytes=4))

    assert report.decisions[0].status == "rejected"
    assert report.decisions[0].reasons == ["file_size_exceeded"]


def test_preflight_reads_file_at_exact_size_limit(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "limit.txt").write_bytes(b"1234")

    report = preflight(source, Policy(max_bytes=4))

    assert report.decisions[0].status == "accepted"


def test_preflight_reports_control_characters_in_relative_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source"
    source.mkdir()
    candidate = source / "safe.txt"
    candidate.write_text("safe", encoding="utf-8")
    monkeypatch.setattr(
        core,
        "_safe_relative",
        lambda _root, _candidate: Path("bad\nname.txt"),
    )

    report = preflight(source, Policy())

    assert "filename_control_character" in report.decisions[0].reasons


def test_repository_ignore_files_match_generated_files_inside_directories(tmp_path: Path):
    repository = Path(__file__).resolve().parents[1]
    ignore_content = (repository / ".cttignore").read_text(encoding="utf-8")
    assert ignore_content == (repository / ".cttignore.example").read_text(encoding="utf-8")

    source = tmp_path / "source"
    generated = [
        ".git/settings.py",
        ".venv/tool.py",
        "__pycache__/module.pyc",
        ".pytest_cache/state.py",
        ".mypy_cache/state.py",
        ".ruff_cache/state.py",
        "dist/application.py",
        "build/application.py",
        "reports/summary.txt",
        "src/package.egg-info/metadata.py",
        ".coverage",
    ]
    for relative in generated:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("generated\n", encoding="utf-8")
    (source / ".cttignore").write_text(ignore_content, encoding="utf-8")

    report = preflight(source, Policy())

    assert {decision.path for decision in report.decisions} == set(generated)
    assert all("ignored" in decision.reasons for decision in report.decisions)


def test_preflight_enforces_profile_limits_and_content_rules(tmp_path: Path):
    source = tmp_path / "source"
    (source / "deep").mkdir(parents=True)
    (source / "deep" / "nested.py").write_text("ok\n", encoding="utf-8")
    (source / "control.py").write_text("bad\x00value\n", encoding="utf-8")
    (source / "long.py").write_text("123456\n", encoding="utf-8")
    (source / "mixed.py").write_bytes(b"one\r\ntwo\n")
    (source / "secret.py").write_text("API_TOKEN=value\n", encoding="utf-8")

    report = preflight(
        source,
        Policy(
            max_path_depth=1,
            max_line_length=5,
            prohibited_patterns=["API_TOKEN="],
        ),
    )

    reasons = {decision.path: decision.reasons for decision in report.decisions}
    assert "path_depth_exceeded" in reasons["deep/nested.py"]
    assert "control_character" in reasons["control.py"]
    assert "line_too_long" in reasons["long.py"]
    assert "mixed_line_endings" in reasons["mixed.py"]
    assert "prohibited_pattern" in reasons["secret.py"]


def test_preflight_enforces_path_and_filename_length_limits(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "lengthy.py").write_text("ok\n", encoding="utf-8")

    report = preflight(
        source,
        Policy(max_path_length=5, max_filename_length=5),
    )

    assert report.decisions[0].reasons == [
        "path_too_long",
        "filename_too_long",
    ]


def test_preflight_enforces_file_count_and_total_size(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("1234", encoding="utf-8")
    (source / "b.py").write_text("5678", encoding="utf-8")

    report = preflight(source, Policy(max_files=1, max_total_bytes=6))

    assert report.accepted_count == 1
    assert report.rejected_count == 1
    assert report.decisions[1].reasons == [
        "file_count_exceeded",
        "total_size_exceeded",
    ]


def test_preflight_rejects_unsupported_filename_characters_and_line_endings(
    tmp_path: Path,
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "bad;name.py").write_text("ok\n", encoding="utf-8")
    (source / "legacy.py").write_bytes(b"one\rtwo\r")

    report = preflight(source, Policy())
    reasons = {decision.path: decision.reasons for decision in report.decisions}

    assert "filename_character_not_allowed" in reasons["bad;name.py"]
    assert "unsupported_line_endings" in reasons["legacy.py"]


def test_strict_prepare_rejects_before_writing_when_preflight_has_rejections(
    tmp_path: Path,
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "accepted.py").write_text("ok\n", encoding="utf-8")
    (source / "binary.py").write_bytes(b"\xff")
    package = tmp_path / "package"

    with pytest.raises(TransferError, match="strict preflight rejected"):
        prepare(source, package, Policy(), strict=True)

    assert not package.exists()


def test_non_strict_prepare_skips_every_file_rejected_by_preflight(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "accepted.py").write_text("ok\n", encoding="utf-8")
    (source / "control.py").write_text("bad\x00value\n", encoding="utf-8")
    package = tmp_path / "package"

    report = preflight(source, Policy())
    manifest = prepare(source, package, Policy())

    assert [decision.path for decision in report.decisions if decision.status == "accepted"] == [
        record.original_path for record in manifest.files
    ]
    assert manifest.skipped == ["control.py (control_character)"]
    assert not (package / "payload/control.py.txt").exists()


def test_named_profile_is_a_concrete_compatibility_contract(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "unicode.py").write_text("value = 'é'\n", encoding="utf-8")

    profile = get_profile("ascii-text-v1")
    report = preflight(source, Policy(profile=profile.name))

    assert isinstance(profile, CDSProfile)
    assert profile.permitted_transfer_extensions == frozenset({".txt"})
    assert report.decisions[0].reasons == ["unicode_not_allowed"]


def test_yaml_allow_unicode_false_rejects_non_ascii_content(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("allow_unicode: false\n", encoding="utf-8")
    source = tmp_path / "source"
    source.mkdir()
    (source / "unicode.py").write_text("value = 'é'\n", encoding="utf-8")

    report = preflight(source, Policy.from_file(policy_path))

    assert report.decisions[0].reasons == ["unicode_not_allowed"]


def test_prohibited_patterns_are_literal_and_case_sensitive(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "exact.py").write_text("SECRET=value\n", encoding="utf-8")
    (source / "lowercase.py").write_text("secret=value\n", encoding="utf-8")
    (source / "regex_like.py").write_text("SEC-anything-RET\n", encoding="utf-8")

    report = preflight(
        source,
        Policy(prohibited_patterns=["SECRET=", "SEC.*RET"]),
    )
    reasons = {decision.path: decision.reasons for decision in report.decisions}

    assert reasons["exact.py"] == ["prohibited_pattern"]
    assert reasons["lowercase.py"] == []
    assert reasons["regex_like.py"] == []


def test_yaml_policy_explicitly_rejects_programmatic_ascii_profile(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("profile: ascii-text-v1\n", encoding="utf-8")

    with pytest.raises(TransferError, match="invalid policy: unsupported profile"):
        Policy.from_file(policy_path)


@pytest.mark.parametrize(
    "policy",
    [
        Policy(max_bytes=-1),
        Policy(max_files=True),
        Policy(extensions={1}),  # type: ignore[arg-type]
        Policy(names={1}),  # type: ignore[arg-type]
        Policy(prohibited_patterns=[1]),  # type: ignore[list-item]
        Policy(add_bom=1),  # type: ignore[arg-type]
        Policy(hash_algorithm=1),  # type: ignore[arg-type]
        Policy(ignore_file=""),
        Policy(profile=1),  # type: ignore[arg-type]
        Policy(package_format="rar"),
        Policy(profile="missing-profile"),
    ],
)
def test_direct_policy_objects_are_validated_before_source_access(tmp_path: Path, policy: Policy):
    missing_source = tmp_path / "missing"

    with pytest.raises(TransferError, match=r"^invalid policy:"):
        preflight(missing_source, policy)


def test_optional_hash_dependency_is_validated_before_scanning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setitem(__import__("sys").modules, "blake3", None)

    def fail_if_scanned(self: Path, pattern: str):
        raise AssertionError("source was scanned before hash validation")

    monkeypatch.setattr(Path, "rglob", fail_if_scanned)

    with pytest.raises(TransferError, match="optional dependency is not installed"):
        preflight(source, Policy(hash_algorithm="blake3"))
