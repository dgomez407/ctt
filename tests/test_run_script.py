import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml


def _workflow(path: str) -> dict[str, object]:
    content = Path(path).read_text(encoding="utf-8")
    parsed = yaml.safe_load(content)
    assert isinstance(parsed, dict)
    return parsed


def _bash() -> str:
    git_bash = Path("C:/Program Files/Git/bin/bash.exe")
    if git_bash.is_file():
        return str(git_bash)
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("Bash is unavailable")
    return bash


def test_run_script_no_args_lists_concise_commands():
    result = subprocess.run(
        [_bash(), "scripts/run.sh"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("Usage: bash scripts/run.sh COMMAND [ARGS...]\n")
    assert "Check Usage:" not in result.stdout
    assert "Bootstrap Usage:" not in result.stdout
    assert "Release Usage:" not in result.stdout
    assert "Unrelease Usage:" not in result.stdout


def test_run_script_help_lists_supported_commands():
    result = subprocess.run(
        [_bash(), "scripts/run.sh", "help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("Usage: bash scripts/run.sh COMMAND [ARGS...]\n")
    assert "Check Usage:" in result.stdout
    assert "Bootstrap Usage:" in result.stdout
    assert "Release Usage:" in result.stdout
    assert "Unrelease Usage:" in result.stdout
    for command in (
        "setup",
        "test",
        "check",
        "report",
        "build",
        "bootstrap",
        "release",
        "unrelease",
        "clean",
    ):
        assert command in result.stdout


def test_run_script_bootstrap_subcommand(tmp_path: Path):
    target = tmp_path / "bootstrap_bundle.zip"
    result = subprocess.run(
        [_bash(), "scripts/run.sh", "bootstrap", str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert target.is_file()


def test_run_script_bootstrap_rejects_extra_args():
    result = subprocess.run(
        [_bash(), "scripts/run.sh", "bootstrap", "path1", "path2"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "bootstrap accepts at most one output_path argument" in result.stderr


def test_run_script_rejects_unknown_commands():
    result = subprocess.run(
        [_bash(), "scripts/run.sh", "unknown"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "unknown command: unknown" in result.stderr


def test_run_script_check_rejects_arguments():
    result = subprocess.run(
        [_bash(), "scripts/run.sh", "check", "--unexpected"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "check does not accept arguments" in result.stderr


def test_run_script_generates_pydoc_report(tmp_path: Path):
    output = tmp_path / "reports"

    result = subprocess.run(
        [
            _bash(),
            "scripts/run.sh",
            "report",
            "--pydoc-only",
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert (output / "index.html").is_file()
    assert (output / "pydoc" / "controlled_text_transfer.core.html").is_file()


def test_run_script_can_preview_environment_cleanup_with_default_python():
    result = subprocess.run(
        [_bash(), "scripts/run.sh", "clean", "--environment", "--dry-run"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    if Path(".venv").is_dir():
        assert "Would remove: .venv" in result.stdout


def test_old_dev_script_name_is_removed():
    assert not Path("scripts/dev.sh").exists()


def test_security_scans_cover_application_and_development_scripts():
    run_script = Path("scripts/run.sh").read_text(encoding="utf-8")
    report_script = Path("scripts/report.py").read_text(encoding="utf-8")

    assert "bandit -r src scripts" in run_script
    assert "pymarkdown scan ." in run_script
    assert '"bandit", "-r", "src", "scripts"' in report_script


def test_ci_workflow_has_exact_triggers_permissions_and_concurrency():
    workflow = _workflow(".github/workflows/ci.yml")

    assert workflow["on"] == {
        "push": {"branches": ["dev", "main"]},
        "pull_request": {"branches": ["main"]},
    }
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": "ci-${{ github.event_name }}-${{ github.ref }}",
        "cancel-in-progress": True,
    }


def test_ci_workflow_uses_locked_canonical_quality_gate_for_supported_pythons():
    workflow = _workflow(".github/workflows/ci.yml")
    test_job = workflow["jobs"]["test"]
    steps = test_job["steps"]

    assert test_job["strategy"]["matrix"]["python-version"] == ["3.12.13", "3.14"]
    assert {"run": "uv sync --frozen --extra dev"} in steps
    assert {"run": "bash scripts/run.sh check"} in steps
    assert all("pip install" not in step.get("run", "") for step in steps)
    codecov_step = next(step for step in steps if step.get("uses", "").startswith("codecov/codecov-action"))
    assert codecov_step["with"]["token"] == "${{ secrets.CODECOV_TOKEN }}"  # noqa: S105


def test_ci_workflow_pins_current_setup_actions_to_full_shas():
    workflow_text = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    pinned_actions = re.findall(
        r"uses:\s+([^@\s]+)@([0-9a-f]{40})\s+#\s+(\S+)",
        workflow_text,
    )

    assert pinned_actions == [
        (
            "actions/checkout",
            "3d3c42e5aac5ba805825da76410c181273ba90b1",
            "v7.0.1",
        ),
        (
            "actions/setup-python",
            "5fda3b95a4ea91299a34e894583c3862153e4b97",
            "v7.0.0",
        ),
        (
            "astral-sh/setup-uv",
            "c771a70e6277c0a99b617c7a806ffedaca235ff9",
            "v9.0.0",
        ),
        (
            "codecov/codecov-action",
            "fb8b3582c8e4def4969c97caa2f19720cb33a72f",
            "v7.0.0",
        ),
    ]


def test_dependabot_maintains_github_action_pins():
    dependabot = _workflow(".github/dependabot.yml")

    assert dependabot == {
        "version": 2,
        "updates": [
            {
                "package-ecosystem": "github-actions",
                "directory": "/",
                "schedule": {"interval": "weekly"},
            }
        ],
    }
