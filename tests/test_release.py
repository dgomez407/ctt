import runpy
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

import controlled_text_transfer

ROOT = Path(__file__).resolve().parents[1]
RELEASE_CHECK = runpy.run_path(str(ROOT / "scripts" / "check_release.py"))
ReleaseCheckError = RELEASE_CHECK["ReleaseCheckError"]
require_trusted_ref = RELEASE_CHECK["require_trusted_ref"]


def _project_metadata() -> dict[str, object]:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        return tomllib.load(stream)["project"]


def test_publication_metadata_identifies_license_platform_and_project_urls():
    project = _project_metadata()

    assert project["license"] == "MIT"
    assert "Operating System :: OS Independent" in project["classifiers"]
    assert project["urls"] == {
        "Homepage": "https://github.com/dgomez407/ctt",
        "Repository": "https://github.com/dgomez407/ctt",
        "Issues": "https://github.com/dgomez407/ctt/issues",
        "Changelog": "https://github.com/dgomez407/ctt/blob/main/CHANGELOG.md",
    }
    assert {"build>=1", "twine>=6"} <= set(project["optional-dependencies"]["dev"])


def test_release_version_is_consistent_across_package_and_documentation():
    version = _project_metadata()["version"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert controlled_text_transfer.__version__ == version
    assert readme.startswith(f"# Controlled Text Transfer {version}\n")
    assert changelog.count(f"## [{version}] - ") == 1
    assert "## [Unreleased]\n\n## [" in changelog
    assert "### Added" in changelog
    assert "### Changed\n\n### Fixed\n\n### Security" in changelog


def test_release_workflow_runs_locked_checks_and_validates_distribution():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    parsed = yaml.safe_load(workflow)
    build = parsed["jobs"]["build"]
    publish = parsed["jobs"]["publish"]

    assert parsed["permissions"] == {"contents": "read"}
    assert build["permissions"] == {"contents": "read"}
    assert any(step.get("run") == "uv sync --frozen --extra dev" for step in build["steps"])
    assert "bash scripts/run.sh check" in workflow
    assert (
        'uv run python scripts/check_release.py "$GITHUB_REF_NAME" ' "--trusted-ref origin/main"
    ) in workflow
    assert "uv run python -m build" in workflow
    assert "uv run python -m twine check dist/*" in workflow
    assert build["steps"][0]["with"] == {
        "fetch-depth": 0,
        "persist-credentials": False,
    }
    assert publish["needs"] == "build"
    assert publish["environment"] == {
        "name": "pypi",
        "url": "https://pypi.org/p/controlled-text-transfer",
    }
    assert publish["permissions"] == {"id-token": "write"}
    assert len(publish["steps"]) == 2


def test_release_workflow_pins_every_action_to_a_full_sha():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1" in workflow
    assert "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0" in workflow
    assert "astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9 # v9.0.0" in workflow
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1" in workflow
    assert "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1" in workflow
    assert (
        "pypa/gh-action-pypi-publish@ba38be9e461d3875417946c167d0b5f3d385a247 "
        "# v1.14.1" in workflow
    )
    assert workflow.count("uses:") == workflow.count("# v")


def test_automation_documentation_matches_workflow_contracts():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    workflow_docs = (ROOT / ".github" / "workflows" / "README.md").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    decision = (ROOT / "docs" / "decisions" / "0012-harden-github-automation.md").read_text(
        encoding="utf-8"
    )

    assert not (ROOT / ".github" / "README.md").exists()
    assert "## GitHub automation" in readme
    assert "[Workflow definitions](.github/workflows/README.md)" in readme
    assert "[`dependabot.yml`](.github/dependabot.yml)" in readme
    assert "repository `ctt`" in readme
    assert "commit belongs to `origin/main`" in readme
    for documentation in (workflow_docs, security, decision):
        normalized = " ".join(documentation.split())
        assert "pushes to `dev` and `main`" in normalized
        assert "pull requests targeting `main`" in normalized
        assert "uv sync --frozen --extra dev" in normalized
    assert "full commit SHA" in workflow_docs
    assert "least-privilege permissions" in security
    assert "branch run cannot cancel its corresponding pull-request run" in " ".join(
        decision.split()
    )


def test_source_distribution_includes_publication_documentation_and_examples():
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    assert (
        "include CHANGELOG.md README-quickstart.md SECURITY.md ctt.spec "
        "ctt.yaml.example .cttignore.example"
    ) in manifest
    assert "recursive-include docs *.md" in manifest
    assert "recursive-include scripts *.md *.py *.sh" in manifest
    assert "recursive-include tests *.md *.py" in manifest


def test_release_check_accepts_the_matching_version_tag():
    result = subprocess.run(
        [sys.executable, "scripts/check_release.py", "v0.1.0"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "release metadata is consistent for v0.1.0" in result.stdout


def test_release_check_rejects_a_mismatched_version_tag():
    result = subprocess.run(
        [sys.executable, "scripts/check_release.py", "v0.1.1"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "tag v0.1.1 does not match project version 0.1.0" in result.stderr
    assert "Traceback" not in result.stderr


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )


def test_release_check_accepts_commit_contained_in_trusted_main(tmp_path: Path):
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.name", "Release Test")
    _git(tmp_path, "config", "user.email", "release@example.invalid")
    (tmp_path / "release.txt").write_text("trusted\n", encoding="utf-8")
    _git(tmp_path, "add", "release.txt")
    _git(tmp_path, "commit", "-m", "trusted release")

    require_trusted_ref(tmp_path, "main")


def test_release_check_rejects_commit_not_contained_in_trusted_main(tmp_path: Path):
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.name", "Release Test")
    _git(tmp_path, "config", "user.email", "release@example.invalid")
    (tmp_path / "release.txt").write_text("trusted\n", encoding="utf-8")
    _git(tmp_path, "add", "release.txt")
    _git(tmp_path, "commit", "-m", "trusted release")
    _git(tmp_path, "switch", "-c", "unmerged")
    (tmp_path / "release.txt").write_text("unmerged\n", encoding="utf-8")
    _git(tmp_path, "commit", "-am", "unmerged release")

    with pytest.raises(
        ReleaseCheckError,
        match="release commit is not contained in trusted ref main",
    ):
        require_trusted_ref(tmp_path, "main")


def test_release_check_fails_closed_when_trusted_ref_is_missing(tmp_path: Path):
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.name", "Release Test")
    _git(tmp_path, "config", "user.email", "release@example.invalid")
    (tmp_path / "release.txt").write_text("trusted\n", encoding="utf-8")
    _git(tmp_path, "add", "release.txt")
    _git(tmp_path, "commit", "-m", "trusted release")

    with pytest.raises(
        ReleaseCheckError,
        match="could not verify trusted ref missing",
    ):
        require_trusted_ref(tmp_path, "missing")
