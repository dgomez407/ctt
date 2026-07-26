import argparse
import json
import re
from pathlib import Path

import pytest

from controlled_text_transfer.cli import _parser, main
from controlled_text_transfer.core import Policy, prepare

EXPECTED_OPTIONS = {
    "root": {"--help"},
    "prepare": {
        "--help",
        "--policy",
        "--log-json",
        "--dry-run",
        "--strict",
        "--json-report",
        "--sign",
        "--key-label",
    },
    "self-package": {
        "--help",
        "--policy",
        "--log-json",
        "--format",
        "--dry-run",
    },
    "preflight": {"--help", "--policy", "--json"},
    "verify": {
        "--help",
        "--log-json",
        "--require-signature",
        "--allow-unverified-signature",
    },
    "restore": {
        "--help",
        "--log-json",
        "--dry-run",
        "--require-signature",
        "--allow-unverified-signature",
    },
    "diff": {
        "--help",
        "--policy",
        "--json",
        "--require-signature",
        "--allow-unverified-signature",
    },
}


def _long_options(parser: argparse.ArgumentParser) -> set[str]:
    return {
        option
        for action in parser._actions
        for option in action.option_strings
        if option.startswith("--")
    }


def test_help_only_advertises_options_that_affect_each_command():
    parser = _parser()
    subparsers = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    actual = {"root": _long_options(parser)}
    actual.update(
        {
            command: _long_options(command_parser)
            for command, command_parser in subparsers.choices.items()
        }
    )

    assert actual == EXPECTED_OPTIONS


def test_every_advertised_option_is_documented_in_its_command_section():
    documentation = Path("docs/cli.md").read_text(encoding="utf-8")
    sections = {
        match.group("command"): match.group("body")
        for match in re.finditer(
            r"^## `(?P<command>[\w-]+)`\n(?P<body>.*?)(?=^## |\Z)",
            documentation,
            re.MULTILINE | re.DOTALL,
        )
    }

    assert set(sections) == set(EXPECTED_OPTIONS) - {"root"}
    assert "`--help`" in documentation
    for command, options in EXPECTED_OPTIONS.items():
        if command == "root":
            continue
        for option in options - {"--help"}:
            assert f"`{option}" in sections[command], f"{command} {option} is undocumented"


@pytest.mark.parametrize(
    "argv",
    [
        ["--policy", "ctt.yaml", "preflight", "source"],
        ["--log-json", "verify", "transfer"],
        ["preflight", "source", "--log-json"],
        ["verify", "transfer", "--policy", "ctt.yaml"],
        ["restore", "transfer", "destination", "--policy", "ctt.yaml"],
        ["diff", "transfer", "source", "--log-json"],
    ],
)
def test_removed_no_op_option_placements_are_rejected(argv: list[str], capsys):
    with pytest.raises(SystemExit) as exc_info:
        _parser().parse_args(argv)

    assert exc_info.value.code == 2
    assert "ctt: error:" in capsys.readouterr().err


class _FakeSigner:
    algorithm = "test-signature"

    def sign(self, data: bytes) -> bytes:
        return b"signature:" + data

    def verify(self, data: bytes, signature: bytes) -> bool:
        return signature == b"signature:" + data


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    (source / "note.txt").write_text("hello\n", encoding="utf-8")
    return source


@pytest.mark.parametrize("command", [None, "prepare", "preflight", "verify", "restore", "diff"])
def test_help_exits_successfully_and_names_the_requested_command(command: str | None, capsys):
    with pytest.raises(SystemExit) as exc_info:
        _parser().parse_args([command, "--help"] if command else ["--help"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "usage: ctt" in output
    if command:
        assert command in output


def test_prepare_dry_run_checks_source_without_creating_transfer(tmp_path: Path, capsys):
    source = _source(tmp_path)
    transfer = tmp_path / "transfer"

    assert main(["prepare", str(source), str(transfer), "--dry-run"]) == 0

    assert not transfer.exists()
    assert json.loads(capsys.readouterr().out)["files"] == 1


def test_prepare_strict_succeeds_when_every_file_is_accepted(tmp_path: Path, capsys):
    source = _source(tmp_path)
    transfer = tmp_path / "transfer"

    assert main(["prepare", str(source), str(transfer), "--strict"]) == 0

    assert transfer.exists()
    capsys.readouterr()


def test_prepare_json_report_records_each_decision(tmp_path: Path, capsys):
    source = _source(tmp_path)
    transfer = tmp_path / "transfer"
    report = tmp_path / "report.json"

    assert main(["prepare", str(source), str(transfer), "--json-report", str(report)]) == 0

    assert json.loads(report.read_text(encoding="utf-8"))["accepted_count"] == 1
    capsys.readouterr()


def test_prepare_sign_and_key_label_create_verifiable_signature(tmp_path: Path, capsys):
    source = _source(tmp_path)
    transfer = tmp_path / "transfer"

    assert (
        main(
            ["prepare", str(source), str(transfer), "--sign", "--key-label", "release-key"],
            signer=_FakeSigner(),
        )
        == 0
    )

    manifest = json.loads((transfer / "ctt-manifest.json.txt").read_text(encoding="utf-8"))
    assert manifest["signature"]["key_label"] == "release-key"
    assert main(["verify", str(transfer), "--require-signature"], signer=_FakeSigner()) == 0
    capsys.readouterr()


def test_preflight_policy_changes_acceptance_and_json_serializes_details(tmp_path: Path, capsys):
    source = _source(tmp_path)
    policy = tmp_path / "policy.yaml"
    policy.write_text("allowlist:\n  extensions: [.md]\n", encoding="utf-8")

    assert main(["preflight", str(source), "--policy", str(policy), "--json"]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["accepted_count"] == 0
    assert report["rejected_count"] == 1


@pytest.mark.parametrize(
    ("command", "event"),
    [
        ("verify", "verify_complete"),
        ("restore", "restore_complete"),
    ],
)
def test_log_json_emits_audit_event_for_supported_commands(
    command: str, event: str, tmp_path: Path, capsys
):
    source = _source(tmp_path)
    transfer = tmp_path / "transfer"
    prepare(source, transfer, Policy())
    argv = [command, str(transfer)]
    if command == "restore":
        argv.append(str(tmp_path / "restored"))
    argv.append("--log-json")

    assert main(argv) == 0

    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert events[-1]["event"] == event


@pytest.mark.parametrize("command", ["verify", "restore", "diff"])
def test_require_signature_is_enforced_by_every_consuming_command(
    command: str, tmp_path: Path, capsys
):
    source = _source(tmp_path)
    transfer = tmp_path / "transfer"
    prepare(source, transfer, Policy())
    argv = [command, str(transfer)]
    if command == "restore":
        argv.append(str(tmp_path / "restored"))
    elif command == "diff":
        argv.append(str(source))
    argv.append("--require-signature")

    assert main(argv, signer=_FakeSigner()) == 2

    assert "manifest signature is required" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["verify", "restore", "diff"])
def test_allow_unverified_signature_is_an_explicit_escape_hatch(
    command: str, tmp_path: Path, capsys
):
    source = _source(tmp_path)
    transfer = tmp_path / "transfer"
    prepare(source, transfer, Policy(), signer=_FakeSigner())
    argv = [command, str(transfer)]
    if command == "restore":
        argv.append(str(tmp_path / "restored"))
    elif command == "diff":
        argv.append(str(source))
    argv.append("--allow-unverified-signature")

    assert main(argv) == 0
    capsys.readouterr()


def test_diff_policy_controls_which_new_files_are_compared(tmp_path: Path, capsys):
    source = _source(tmp_path)
    transfer = tmp_path / "transfer"
    prepare(source, transfer, Policy())
    (source / "new.py").write_text("print('new')\n", encoding="utf-8")
    policy = tmp_path / "policy.yaml"
    policy.write_text("allowlist:\n  extensions: [.txt]\n", encoding="utf-8")

    assert main(["diff", str(transfer), str(source), "--policy", str(policy), "--json"]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["added"] == []
    assert result["unchanged"] == ["note.txt"]
