import re
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from controlled_text_transfer.core import Policy

REPOSITORY = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("filename", ["ctt.yaml", "ctt.yaml.example"])
def test_repository_policy_examples_parse(filename: str):
    policy = Policy.from_file(REPOSITORY / filename)

    assert policy.profile == "generic-text-v1"


def test_every_documented_yaml_policy_example_parses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    fake_blake3 = SimpleNamespace(
        blake3=lambda data: SimpleNamespace(hexdigest=lambda: f"blake3:{data.hex()}")
    )
    monkeypatch.setitem(sys.modules, "blake3", fake_blake3)
    documentation = (REPOSITORY / "docs" / "policy.md").read_text(encoding="utf-8")
    examples = re.findall(r"```yaml\n(.*?)```", documentation, flags=re.DOTALL)

    assert len(examples) == 3
    for index, example in enumerate(examples):
        policy_path = tmp_path / f"documented-policy-{index}.yaml"
        policy_path.write_text(example, encoding="utf-8")
        Policy.from_file(policy_path)


def test_documented_uv_blake3_command_matches_project_extra():
    project = tomllib.loads((REPOSITORY / "pyproject.toml").read_text(encoding="utf-8"))
    documentation = (REPOSITORY / "docs" / "policy.md").read_text(encoding="utf-8")

    assert project["project"]["optional-dependencies"]["blake3"] == ["blake3>=0.4"]
    assert "uv sync --extra blake3" in documentation
