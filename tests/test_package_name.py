import importlib.util
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, distribution

import pytest

from controlled_text_transfer.cli import _parser


def test_package_is_exposed_only_as_controlled_text_transfer():
    import controlled_text_transfer

    assert controlled_text_transfer.__version__ == "0.1.0"
    assert importlib.util.find_spec("cds") is None
    assert importlib.util.find_spec("cds_text") is None


def test_distribution_and_console_script_are_named_controlled_text_transfer():
    installed = distribution("controlled-text-transfer")

    assert installed.metadata["Name"] == "controlled-text-transfer"
    assert any(
        entry.name == "ctt" and entry.value == "controlled_text_transfer.cli:main"
        for entry in installed.entry_points
    )
    with pytest.raises(PackageNotFoundError):
        distribution("cds")


def test_cli_program_name_is_ctt():
    assert _parser().prog == "ctt"


def test_python_module_entry_point_displays_help():
    result = subprocess.run(
        [sys.executable, "-m", "controlled_text_transfer", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Prepare, verify, and restore text-only transfer packages." in result.stdout
