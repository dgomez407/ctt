import json
import re
import runpy
import subprocess
import sys
from pathlib import Path

import pytest


def test_pydoc_only_report_generates_browsable_html_and_summary(tmp_path: Path):
    output = tmp_path / "reports"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/report.py",
            "--output",
            str(output),
            "--pydoc-only",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert (output / "index.html").is_file()
    assert (output / "assets" / "report.css").is_file()
    assert (output / "pydoc" / "controlled_text_transfer.html").is_file()
    assert (output / "pydoc" / "controlled_text_transfer.__main__.html").is_file()
    assert (output / "pydoc" / "controlled_text_transfer.core.html").is_file()
    pydoc_page = (output / "pydoc" / "controlled_text_transfer.core.html").read_text(encoding="utf-8")
    assert 'href="../index.html"' in pydoc_page
    assert 'href="../assets/report.css"' in pydoc_page
    assert '<body class="pydoc-page">' in pydoc_page
    assert '<a class="skip-link" href="#pydoc-content">Skip to API content</a>' in pydoc_page
    assert '<main id="pydoc-content">' in pydoc_page
    assert 'aria-label="API modules"' in pydoc_page
    assert 'aria-label="On this page"' in pydoc_page
    assert 'href="#section-classes"' in pydoc_page
    assert 'href="controlled_text_transfer.cli.html"' in pydoc_page
    assert 'href="controlled_text_transfer.__main__.html"' in pydoc_page
    assert 'aria-current="page">core</a>' in pydoc_page
    assert '<nav class="pydoc-breadcrumb" aria-label="Breadcrumb">' in pydoc_page
    assert '<a href="controlled_text_transfer.html">controlled_text_transfer</a>' in pydoc_page
    assert '<span aria-current="page">core</span>' in pydoc_page
    assert '<strong class="title">controlled_text_transfer.core</strong>' in pydoc_page
    assert '<strong class="title"><a ' not in pydoc_page
    assert "bgcolor=" not in pydoc_page
    assert "&nbsp;" not in pydoc_page
    assert '<a name="CDSProfile">' in pydoc_page
    assert 'href="os.html"' not in pydoc_page
    assert '<code class="pydoc-reference">os</code>' in pydoc_page
    assert 'href="controlled_text_transfer.cli.html"' in pydoc_page
    index = (output / "index.html").read_text(encoding="utf-8")
    assert '<main id="main-content"' in index
    assert 'class="status status--passed"' in index
    assert 'href="assets/report.css"' in index
    assert "Runtime Metadata" in index
    assert index.count('href="pydoc/controlled_text_transfer.html"') == 1
    summary = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "passed"
    assert summary["reports"]["pydoc"] == "pydoc/controlled_text_transfer.html"
    assert "generated_at" in summary


def test_every_generated_pydoc_link_resolves_to_a_file_or_anchor(tmp_path: Path):
    output = tmp_path / "reports"
    result = subprocess.run(
        [sys.executable, "scripts/report.py", "--output", str(output), "--pydoc-only"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    for page_path in (output / "pydoc").glob("*.html"):
        page = page_path.read_text(encoding="utf-8")
        for href in re.findall(r'href="([^"]+)"', page):
            if href.startswith("#"):
                target_path = page_path
                fragment = href[1:]
            else:
                target, _, fragment = href.partition("#")
                target_path = (page_path.parent / target).resolve()
            assert target_path.is_file(), f"{page_path.name}: missing target {href}"
            if fragment:
                target_page = target_path.read_text(encoding="utf-8")
                assert f'id="{fragment}"' in target_page or f'name="{fragment}"' in target_page


def test_quality_metrics_are_extracted_from_coverage_and_junit(tmp_path: Path):
    report_module = runpy.run_path("scripts/report.py")
    collect_metrics = report_module["_collect_metrics"]
    (tmp_path / "coverage.json").write_text(
        json.dumps({"totals": {"percent_covered": 96.55}}),
        encoding="utf-8",
    )
    (tmp_path / "junit.xml").write_text(
        '<testsuites name="pytest tests"><testsuite tests="221" failures="1" '
        'errors="0" skipped="2" time="7.23"/></testsuites>',
        encoding="utf-8",
    )

    assert collect_metrics(tmp_path) == {
        "coverage": "96.55%",
        "tests": 221,
        "failures": 1,
        "errors": 0,
        "skipped": 2,
        "test_duration": "7.23s",
    }


def test_report_theme_uses_black_and_semantic_status_colors():
    report_module = runpy.run_path("scripts/report.py")
    stylesheet = report_module["REPORT_CSS"]

    assert "--background: #000000;" in stylesheet
    assert "--passed: #39d98a;" in stylesheet
    assert "--warning: #ff9f1c;" in stylesheet
    assert "--warning-bg: rgba(255, 159, 28, 0.14);" in stylesheet
    assert "--failed: #ff5c5c;" in stylesheet
    assert "--failed-bg: rgba(255, 92, 92, 0.14);" in stylesheet
    assert ".status--warning" in stylesheet
    assert ".card--warning { border-color: var(--warning); background: var(--warning-bg); }" in stylesheet
    assert ".card--failed { border-color: var(--failed); background: var(--failed-bg); }" in stylesheet


def test_pydoc_theme_is_scoped_responsive_and_printable():
    report_module = runpy.run_path("scripts/report.py")
    stylesheet = report_module["REPORT_CSS"]

    report_module["_validate_report_css"](stylesheet)
    assert ".pydoc-page .pydoc-layout" in stylesheet
    assert ".pydoc-page .pydoc-sidebar" in stylesheet
    assert ".pydoc-page #pydoc-content" in stylesheet
    assert ".pydoc-page table.section" in stylesheet
    assert ".pydoc-page .code" in stylesheet
    assert "table-layout: auto;" in stylesheet
    assert ".pydoc-page table.section td.decor:not([colspan]) { width: 0;" in stylesheet
    assert "td:nth-child(2):not([colspan])" not in stylesheet
    assert ".skip-link:focus" in stylesheet
    assert "@media (max-width: 48rem)" in stylesheet
    assert "@media print" in stylesheet


@pytest.mark.parametrize(
    ("broken_css", "message"),
    [
        ("body { color: white;", "balanced braces"),
        (
            ".pydoc-page .pydoc-layout { display: block; }",
            "desktop pydoc grid",
        ),
        (
            ".pydoc-page .pydoc-layout { display: grid; " "grid-template-columns: 15rem minmax(0, 1fr); }",
            "responsive pydoc layout",
        ),
        (
            ".pydoc-page .pydoc-layout { display: grid; "
            "grid-template-columns: 15rem minmax(0, 1fr); } "
            "@media (max-width: 48rem) { "
            ".pydoc-page .pydoc-layout { display: block; } }",
            "print pydoc layout",
        ),
    ],
)
def test_report_css_validation_rejects_layout_regressions(broken_css: str, message: str):
    report_module = runpy.run_path("scripts/report.py")

    with pytest.raises(ValueError, match=message):
        report_module["_validate_report_css"](broken_css)


def test_generated_stylesheet_matches_validated_source(tmp_path: Path):
    output = tmp_path / "reports"
    result = subprocess.run(
        [sys.executable, "scripts/report.py", "--output", str(output), "--pydoc-only"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    report_module = runpy.run_path("scripts/report.py")
    generated_css = (output / "assets" / "report.css").read_text(encoding="utf-8")
    assert generated_css == report_module["REPORT_CSS"] + "\n"
    report_module["_validate_report_css"](generated_css)


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    [
        ("coverage", "96.55%", "passed"),
        ("tests", 224, "passed"),
        ("skipped", 0, "passed"),
        ("skipped", 2, "warning"),
        ("failures", 1, "failed"),
        ("errors", 1, "failed"),
    ],
)
def test_metric_state_uses_warning_and_failure_severity(name: str, value: str | int, expected: str):
    report_module = runpy.run_path("scripts/report.py")

    assert report_module["_metric_state"](name, value) == expected


@pytest.mark.parametrize(
    ("checks", "metrics", "expected"),
    [
        ({"pytest": 0}, {"skipped": 0}, "passed"),
        ({"pytest": 0}, {"skipped": 2}, "warning"),
        ({"pytest": 1}, {"skipped": 0}, "failed"),
    ],
)
def test_overall_status_prioritizes_failures_then_warnings(
    checks: dict[str, int], metrics: dict[str, int], expected: str
):
    report_module = runpy.run_path("scripts/report.py")

    assert report_module["_overall_status"](checks, metrics) == expected


def test_report_page_escapes_command_output(tmp_path: Path):
    report_module = runpy.run_path("scripts/report.py")
    write_report_page = report_module["_write_report_page"]
    output = tmp_path / "reports"
    output.mkdir()

    write_report_page(output, "Example", "<script>alert('unsafe')</script>", "example.txt")

    page = (output / "example.html").read_text(encoding="utf-8")
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert 'href="example.txt"' in page
    assert 'href="index.html"' in page


def test_full_report_exposes_formatted_views_for_raw_results(tmp_path: Path):
    report_module = runpy.run_path("scripts/report.py")
    write_report_page = report_module["_write_report_page"]
    output = tmp_path / "reports"
    output.mkdir()

    for raw_name in (
        "pytest.txt",
        "ruff.json",
        "black.txt",
        "mypy.txt",
        "bandit.json",
        "dependencies.txt",
        "metadata.json",
    ):
        (output / raw_name).write_text("clean\n", encoding="utf-8")
        write_report_page(output, raw_name, "clean\n", raw_name)

    for page_name in (
        "pytest.html",
        "ruff.html",
        "black.html",
        "mypy.html",
        "bandit.html",
        "dependencies.html",
        "metadata.html",
    ):
        assert (output / page_name).is_file()


def test_generated_reports_are_not_source_control_inputs():
    assert "reports/" in Path(".gitignore").read_text(encoding="utf-8").splitlines()
    assert "reports/*" in Path(".cttignore").read_text(encoding="utf-8").splitlines()
    assert "reports/*" in Path(".cttignore.example").read_text(encoding="utf-8").splitlines()


@pytest.mark.parametrize("output", [Path("."), Path("src"), Path("docs/reports")])
def test_report_output_rejects_repository_source_directories(output: Path):
    report_module = runpy.run_path("scripts/report.py")
    validate_output = report_module["_validate_output"]

    with pytest.raises(ValueError, match="top-level reports directory"):
        validate_output(output)


def test_report_rejects_source_boundary_before_inspecting_links(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = tmp_path / "repository"
    repository.mkdir()
    report_module = runpy.run_path("scripts/report.py")
    validate_output = report_module["_validate_output"]
    monkeypatch.setitem(validate_output.__globals__, "REPOSITORY", repository)

    def fail_if_inspected(_output: Path) -> None:
        raise AssertionError("invalid source directory was inspected")

    monkeypatch.setitem(
        validate_output.__globals__,
        "_reject_linked_output",
        fail_if_inspected,
    )

    with pytest.raises(ValueError, match="top-level reports directory"):
        validate_output(repository)


def test_report_cli_rejects_source_output_before_writing():
    result = subprocess.run(
        [
            sys.executable,
            "scripts/report.py",
            "--output",
            "src",
            "--pydoc-only",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "must be the top-level reports directory" in result.stderr
    assert not Path("src/report.json").exists()
    assert not Path("src/pydoc").exists()


def test_report_output_rejects_canonical_directory_symlink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    reports = repository / "reports"
    try:
        reports.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    report_module = runpy.run_path("scripts/report.py")
    validate_output = report_module["_validate_output"]
    monkeypatch.setitem(validate_output.__globals__, "REPOSITORY", repository)

    with pytest.raises(ValueError, match="symbolic link or junction"):
        validate_output(reports)


def test_report_output_rejects_nested_directory_symlink(tmp_path: Path):
    output = tmp_path / "external-reports"
    output.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (output / "pydoc").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    report_module = runpy.run_path("scripts/report.py")
    validate_output = report_module["_validate_output"]

    with pytest.raises(ValueError, match="symbolic link or junction"):
        validate_output(output)
