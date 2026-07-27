"""Generate browsable documentation and quality reports for this repository."""

from __future__ import annotations

import argparse
import html
import importlib
import json
import os
import platform
import pydoc
import re
import shutil
import subprocess  # nosec B404
import sys
from collections.abc import Sequence
from contextlib import chdir
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[1]
PYDOC_MODULES = (
    "controlled_text_transfer",
    "controlled_text_transfer.__main__",
    "controlled_text_transfer.core",
    "controlled_text_transfer.cli",
    "controlled_text_transfer.signing",
    "controlled_text_transfer.cleanup",
)
REPORT_CSS = """
:root {
  color-scheme: dark;
  --background: #000000;
  --surface: #071009;
  --surface-muted: #0b1710;
  --text: #e8f5ec;
  --muted: #9ab3a2;
  --border: #21422d;
  --accent: #39d98a;
  --accent-strong: #7cf2b5;
  --passed: #39d98a;
  --passed-bg: #082a19;
  --warning: #ff9f1c;
  --warning-bg: rgba(255, 159, 28, 0.14);
  --failed: #ff5c5c;
  --failed-bg: rgba(255, 92, 92, 0.14);
  --radius: 0.5rem;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI",
    sans-serif;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--background);
  color: var(--text);
  line-height: 1.55;
}
a { color: var(--accent); text-underline-offset: 0.18em; }
a:hover { color: var(--accent-strong); }
.shell { width: min(72rem, calc(100% - 2rem)); margin: 0 auto; }
.site-header { padding: 2.5rem 0 1.5rem; border-bottom: 1px solid var(--border); }
.eyebrow {
  margin: 0 0 0.25rem;
  color: var(--muted);
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.09em;
  text-transform: uppercase;
}
h1 { margin: 0; font-size: clamp(1.75rem, 4vw, 2.5rem); line-height: 1.15; }
h2 { margin: 0 0 1rem; font-size: 1.2rem; }
.lede { max-width: 48rem; margin: 0.75rem 0 0; color: var(--muted); }
main { padding: 1.5rem 0 3rem; }
.status {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  margin-top: 1rem;
  padding: 0.35rem 0.65rem;
  border: 1px solid currentColor;
  border-radius: 999px;
  font-size: 0.85rem;
  font-weight: 700;
  text-transform: capitalize;
}
.status::before {
  content: "";
  width: 0.55rem;
  height: 0.55rem;
  border-radius: 50%;
  background: currentColor;
}
.status--passed { color: var(--passed); background: var(--passed-bg); }
.status--warning { color: var(--warning); background: var(--warning-bg); }
.status--failed { color: var(--failed); background: var(--failed-bg); }
.section { margin-top: 1.5rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: 0.75rem; }
.card {
  min-width: 0;
  padding: 1rem;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
}
.card--passed { border-color: var(--passed); }
.card--warning { border-color: var(--warning); background: var(--warning-bg); }
.card--failed { border-color: var(--failed); background: var(--failed-bg); }
.card h3 { margin: 0 0 0.35rem; font-size: 1rem; }
.card p { margin: 0; color: var(--muted); font-size: 0.9rem; }
.card__status { display: block; margin-top: 0.75rem; font-size: 0.8rem; font-weight: 700; }
.card__status--passed { color: var(--passed); }
.card__status--warning { color: var(--warning); }
.card__status--failed { color: var(--failed); }
.report-list { margin: 0; padding: 0; list-style: none; border-top: 1px solid var(--border); }
.report-list li {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.75rem 0;
  border-bottom: 1px solid var(--border);
}
.secondary-link { color: var(--muted); font-size: 0.85rem; }
.report-header { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; }
.pydoc-nav {
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
  font: 600 0.9rem/1.4 Inter, ui-sans-serif, system-ui, sans-serif;
}
.skip-link {
  position: fixed;
  top: 0.5rem;
  left: 0.5rem;
  z-index: 10;
  padding: 0.5rem 0.75rem;
  background: var(--accent);
  color: #001a0d;
  transform: translateY(-150%);
}
.skip-link:focus { transform: translateY(0); }
.pydoc-page .pydoc-header {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
}
.pydoc-page .pydoc-breadcrumb {
  display: flex;
  min-width: 0;
  flex-wrap: wrap;
  gap: 0.4rem;
  overflow-wrap: anywhere;
  font: 600 0.85rem/1.4 ui-monospace, SFMono-Regular, Consolas, monospace;
}
.pydoc-page .pydoc-breadcrumb [aria-hidden="true"] { color: var(--border); }
.pydoc-page .pydoc-breadcrumb [aria-current="page"] { color: var(--muted); }
.pydoc-page .pydoc-layout {
  display: grid;
  grid-template-columns: 15rem minmax(0, 1fr);
  width: min(100%, 96rem);
  margin: 0 auto;
}
.pydoc-page .pydoc-sidebar {
  position: sticky;
  top: 0;
  align-self: start;
  max-height: 100vh;
  overflow: auto;
  padding: 1rem;
  border-right: 1px solid var(--border);
}
.pydoc-page .pydoc-sidebar nav + nav { margin-top: 1.5rem; }
.pydoc-page .pydoc-sidebar h2 {
  margin: 0 0 0.5rem;
  color: var(--muted);
  font-size: 0.75rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.pydoc-page .pydoc-sidebar ul { margin: 0; padding: 0; list-style: none; }
.pydoc-page .pydoc-sidebar li + li { margin-top: 0.25rem; }
.pydoc-page .pydoc-sidebar a {
  display: block;
  padding: 0.3rem 0.45rem;
  border-left: 2px solid transparent;
  overflow-wrap: anywhere;
  text-decoration: none;
}
.pydoc-page .pydoc-sidebar a[aria-current="page"] {
  border-color: var(--accent);
  background: var(--passed-bg);
  color: var(--accent-strong);
}
.pydoc-page #pydoc-content { min-width: 0; padding: 1.25rem clamp(1rem, 3vw, 2.5rem) 3rem; }
.pydoc-page #pydoc-content > p { max-width: 72ch; }
.pydoc-page table {
  width: 100%;
  max-width: 100%;
  border-spacing: 0;
  color: var(--text);
  table-layout: auto;
}
.pydoc-page table.heading,
.pydoc-page table.section {
  width: 100%;
  margin: 0 0 1rem;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
}
.pydoc-page table.heading { margin-bottom: 1.25rem; }
.pydoc-page table.heading td { padding: 1rem; vertical-align: top; }
.pydoc-page table.heading .title { font-size: clamp(1.2rem, 3vw, 1.75rem); }
.pydoc-page table.heading .extra {
  max-width: 40%;
  color: var(--muted);
  font-size: 0.8rem;
  overflow-wrap: anywhere;
  text-align: right;
}
.pydoc-page table.section > tbody > tr > td { padding: 0.75rem; vertical-align: top; }
.pydoc-page td { min-width: 0; overflow-wrap: anywhere; }
.pydoc-page table.section td.decor:not([colspan]) { width: 0; padding-inline: 0; }
.pydoc-page table.section .section-title {
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--border);
  background: var(--surface-muted);
}
.pydoc-page .bigsection {
  color: var(--accent-strong);
  font-size: 1.05rem;
  scroll-margin-top: 1rem;
}
.pydoc-page .singlecolumn { width: 100%; }
.pydoc-page dl { margin: 0.75rem 0; }
.pydoc-page dt {
  padding: 0.45rem 0.65rem;
  border-left: 2px solid var(--border);
  background: rgba(255, 255, 255, 0.025);
  overflow-wrap: anywhere;
}
.pydoc-page dd { margin: 0; padding: 0.5rem 0.75rem 0.75rem; }
.pydoc-page .code {
  color: var(--text);
  font: 0.86rem/1.6 ui-monospace, SFMono-Regular, Consolas, monospace;
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}
.pydoc-page .grey { color: var(--muted); }
.pydoc-page .white { color: var(--accent-strong); }
.pydoc-page .pydoc-reference {
  color: var(--muted);
  font: 0.86rem/1.6 ui-monospace, SFMono-Regular, Consolas, monospace;
}
.pydoc-page hr { height: 1px; border: 0; background: var(--border); }
pre {
  max-height: 70vh;
  overflow: auto;
  margin: 1rem 0 0;
  padding: 1rem;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: #020503;
  color: #e7eee9;
  font: 0.85rem/1.55 ui-monospace, SFMono-Regular, Consolas, monospace;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.meta { color: var(--muted); font-size: 0.85rem; }
@media (max-width: 36rem) {
  .shell { width: min(100% - 1rem, 72rem); }
  .site-header { padding-top: 1.5rem; }
  .report-list li, .report-header { align-items: flex-start; flex-direction: column; gap: 0.25rem; }
}
@media (max-width: 48rem) {
  .pydoc-page .pydoc-layout { display: block; }
  .pydoc-page .pydoc-sidebar {
    position: static;
    max-height: none;
    border-right: 0;
    border-bottom: 1px solid var(--border);
  }
  .pydoc-page .pydoc-sidebar nav { display: inline-block; width: min(49%, 22rem); }
  .pydoc-page .pydoc-sidebar nav + nav { margin-top: 0; margin-left: 1%; }
  .pydoc-page table.heading .extra { display: none; }
  .pydoc-page table.section > tbody > tr > td { padding: 0.5rem; }
}
@media print {
  :root { color-scheme: light; }
  .pydoc-page { background: #ffffff; color: #000000; }
  .pydoc-page .pydoc-header,
  .pydoc-page .pydoc-sidebar,
  .skip-link { display: none; }
  .pydoc-page .pydoc-layout { display: block; }
  .pydoc-page #pydoc-content { padding: 0; }
  .pydoc-page table.heading,
  .pydoc-page table.section { border-color: #777777; background: #ffffff; }
  .pydoc-page .code,
  .pydoc-page .bigsection,
  .pydoc-page a { color: #000000; }
}
""".strip()


class ReportError(ValueError):
    """Report an unsafe or invalid report-generation request."""


def _is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _reject_linked_output(output: Path) -> None:
    if _is_link(output):
        raise ReportError("report output must not be a symbolic link or junction")
    if not output.exists():
        return
    for current, directories, files in os.walk(output, followlinks=False):
        current_path = Path(current)
        for name in [*directories, *files]:
            if _is_link(current_path / name):
                raise ReportError("report output must not contain a symbolic link or junction")


def _validate_output(output: Path) -> Path:
    requested = output.absolute()
    resolved = output.resolve()
    repository = REPOSITORY.resolve()
    canonical = repository / "reports"
    if resolved.is_relative_to(repository) and resolved != canonical:
        raise ReportError(
            "report output inside the repository must be the top-level reports directory"
        )
    _reject_linked_output(requested)
    return resolved


def _section_id(name: str) -> str:
    return "section-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _sanitize_pydoc_links(page: str) -> str:
    generated_pages = {f"{module_name}.html" for module_name in PYDOC_MODULES}

    def replace_anchor(match: re.Match[str]) -> str:
        attributes, content = match.groups()
        href_match = re.search(r'\bhref="([^"]+)"', attributes)
        if href_match is None:
            return match.group(0)
        href = href_match.group(1)
        target = href.partition("#")[0]
        if href.startswith("#") or target in generated_pages or target == "../index.html":
            return match.group(0)
        text = re.sub(r"<[^>]+>", "", content)
        return f'<code class="pydoc-reference">{text}</code>'

    return re.sub(r"<a\b([^>]*)>(.*?)</a>", replace_anchor, page, flags=re.IGNORECASE | re.DOTALL)


def _pydoc_breadcrumb(module_name: str) -> str:
    separator = '<span aria-hidden="true">/</span>'
    parts = ['<a href="../index.html">Report dashboard</a>', separator]
    if module_name == "controlled_text_transfer":
        parts.append('<span aria-current="page">controlled_text_transfer</span>')
    else:
        parts.extend(
            [
                '<a href="controlled_text_transfer.html">controlled_text_transfer</a>',
                separator,
                f'<span aria-current="page">{html.escape(module_name.rsplit(".", 1)[1])}</span>',
            ]
        )
    return '<nav class="pydoc-breadcrumb" aria-label="Breadcrumb">' + "".join(parts) + "</nav>"


def _enhance_pydoc(page: str, module_name: str) -> str:
    section_names = re.findall(r'<strong class="bigsection">([^<]+)</strong>', page)
    for section_name in section_names:
        section = (
            f'<strong class="bigsection" id="{_section_id(section_name)}">{section_name}</strong>'
        )
        page = page.replace(f'<strong class="bigsection">{section_name}</strong>', section, 1)

    module_links = []
    for documented_module in PYDOC_MODULES:
        target = documented_module + ".html"
        label = documented_module.removeprefix("controlled_text_transfer.").replace(
            "controlled_text_transfer", "package"
        )
        current = ' aria-current="page"' if documented_module == module_name else ""
        module_links.append(
            f'<li><a href="{html.escape(target)}"{current}>{html.escape(label)}</a></li>'
        )
    section_links = "".join(
        f'<li><a href="#{_section_id(name)}">{html.escape(name)}</a></li>' for name in section_names
    )
    navigation = (
        '<a class="skip-link" href="#pydoc-content">Skip to API content</a>'
        f'<header class="pydoc-header">{_pydoc_breadcrumb(module_name)}</header>'
        '<div class="pydoc-layout"><aside class="pydoc-sidebar">'
        '<nav aria-label="API modules"><h2>Modules</h2><ul>'
        f'{"".join(module_links)}</ul></nav>'
        '<nav aria-label="On this page"><h2>On this page</h2>'
        f"<ul>{section_links}</ul></nav></aside>"
        '<main id="pydoc-content">'
    )
    page = re.sub(r"\s+bgcolor=(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", "", page)
    page = page.replace("&nbsp;", " ")
    page = re.sub(
        r'<strong class="title">.*?</strong>',
        f'<strong class="title">{html.escape(module_name)}</strong>',
        page,
        count=1,
        flags=re.DOTALL,
    )
    page = re.sub(r"<body[^>]*>", f'<body class="pydoc-page">{navigation}', page, count=1)
    page = page.replace("</body>", "</main></div></body>", 1)
    page = page.replace(
        "</head>",
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<link rel="stylesheet" href="../assets/report.css"></head>',
        1,
    )
    return _sanitize_pydoc_links(page)


def _write_pydoc(output: Path) -> dict[str, str]:
    pydoc_output = output / "pydoc"
    pydoc_output.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(REPOSITORY / "src"))
    modules = [importlib.import_module(module_name) for module_name in PYDOC_MODULES]
    with chdir(pydoc_output):
        for module in modules:
            pydoc.writedoc(module)
    for module_name in PYDOC_MODULES:
        page_path = pydoc_output / f"{module_name}.html"
        page = page_path.read_text(encoding="utf-8")
        page_path.write_text(_enhance_pydoc(page, module_name), encoding="utf-8")
    return {"pydoc": "pydoc/controlled_text_transfer.html"}


def _run(command: list[str], output: Path) -> int:
    # Callers supply only repository-defined commands.
    result = subprocess.run(  # nosec B603
        command,
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(result.stdout + result.stderr, encoding="utf-8")
    return result.returncode


def _validate_report_css(stylesheet: str) -> None:
    """Reject stylesheet damage that would break the report's core layouts."""
    depth = 0
    for character in stylesheet:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth < 0:
                raise ValueError("report CSS must have balanced braces")
    if depth:
        raise ValueError("report CSS must have balanced braces")

    responsive_marker = "@media (max-width: 48rem)"
    print_marker = "@media print"
    desktop = stylesheet.split(responsive_marker, 1)[0]
    if (
        ".pydoc-page .pydoc-layout {" not in desktop
        or "display: grid;" not in desktop
        or "grid-template-columns: 15rem minmax(0, 1fr);" not in desktop
    ):
        raise ValueError("report CSS must preserve the desktop pydoc grid")
    if responsive_marker not in stylesheet:
        raise ValueError("report CSS must define a responsive pydoc layout")
    if print_marker not in stylesheet:
        raise ValueError("report CSS must define a print pydoc layout")

    _, responsive_and_print = stylesheet.split(responsive_marker, 1)
    responsive, print_styles = responsive_and_print.split(print_marker, 1)
    if (
        ".pydoc-page .pydoc-layout { display: block; }" not in responsive
        or "position: static;" not in responsive
    ):
        raise ValueError("report CSS must preserve the responsive pydoc layout")
    if (
        ".pydoc-page .pydoc-layout { display: block; }" not in print_styles
        or ".pydoc-page .pydoc-sidebar," not in print_styles
    ):
        raise ValueError("report CSS must preserve the print pydoc layout")


def _write_assets(output: Path) -> None:
    _validate_report_css(REPORT_CSS)
    assets = output / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    (assets / "report.css").write_text(REPORT_CSS + "\n", encoding="utf-8")


def _write_report_page(
    output: Path,
    title: str,
    content: str,
    raw_name: str,
) -> str:
    page_name = str(Path(raw_name).with_suffix(".html"))
    (output / page_name).write_text(
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)} · CTT reports</title>"
        '<link rel="stylesheet" href="assets/report.css"></head>\n'
        '<body><header class="site-header"><div class="shell">'
        '<p class="eyebrow">Controlled Text Transfer</p>'
        f"<h1>{html.escape(title)}</h1>"
        '</div></header><main id="main-content" class="shell">'
        '<div class="report-header">'
        '<a href="index.html">← Report dashboard</a>'
        f'<a class="secondary-link" href="{html.escape(raw_name)}">View raw output</a>'
        "</div>"
        f"<pre>{html.escape(content)}</pre>"
        "</main></body></html>\n",
        encoding="utf-8",
    )
    return page_name


def _collect_metrics(output: Path) -> dict[str, str | int]:
    metrics: dict[str, str | int] = {}
    try:
        coverage = json.loads((output / "coverage.json").read_text(encoding="utf-8"))
        metrics["coverage"] = f'{float(coverage["totals"]["percent_covered"]):.2f}%'
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        pass
    try:
        junit = (output / "junit.xml").read_text(encoding="utf-8")
        attribute_sets = (
            dict(re.findall(r'(\w+)="([0-9.]+)"', match))
            for match in re.findall(r"<testsuites?\b([^>]*)>", junit)
        )
        attributes = next(
            (attributes for attributes in attribute_sets if "tests" in attributes), None
        )
        if attributes is None:
            return metrics
        metrics.update(
            {
                "tests": int(attributes["tests"]),
                "failures": int(attributes.get("failures", "0")),
                "errors": int(attributes.get("errors", "0")),
                "skipped": int(attributes.get("skipped", "0")),
                "test_duration": f'{float(attributes.get("time", "0")):.2f}s',
            }
        )
    except (OSError, KeyError, ValueError):
        pass
    return metrics


def _metric_state(name: str, value: str | int) -> str:
    if name in {"failures", "errors"} and int(value) > 0:
        return "failed"
    if name == "skipped" and int(value) > 0:
        return "warning"
    return "passed"


def _overall_status(checks: dict[str, int], metrics: dict[str, str | int]) -> str:
    if any(code != 0 for code in checks.values()):
        return "failed"
    if int(metrics.get("skipped", 0)) > 0:
        return "warning"
    return "passed"


def _write_index(output: Path, summary: dict[str, Any]) -> None:
    report_items = "\n".join(
        "<li>"
        f'<a href="{html.escape(target)}">{html.escape(name.title())}</a>'
        + (
            f'<a class="secondary-link" href="{html.escape(summary["reports"][name])}">Raw</a>'
            if summary["reports"][name] != target
            else ""
        )
        + "</li>"
        for name, target in summary["views"].items()
        if name in summary["reports"]
    )
    direct_items = "\n".join(
        f'<li><a href="{html.escape(target)}">{html.escape(name.title())}</a></li>'
        for name, target in summary["views"].items()
        if name not in summary["reports"]
    )
    check_cards = "\n".join(
        f'<article class="card card--{"passed" if status == 0 else "failed"}">'
        f"<h3>{html.escape(name.title())}</h3>"
        f'<p class="card__status card__status--{"passed" if status == 0 else "failed"}">'
        f'{"✓ Passed" if status == 0 else f"✕ Failed (exit {status})"}</p>'
        "</article>"
        for name, status in summary["checks"].items()
    )
    metric_cards = "\n".join(
        f'<article class="card card--{_metric_state(name, value)}">'
        f"<h3>{html.escape(name.replace('_', ' ').title())}</h3>"
        f"<p>{html.escape(str(value))}</p>"
        "</article>"
        for name, value in summary["metrics"].items()
    )
    generated_at = html.escape(summary["generated_at"])
    status = html.escape(summary["status"])
    (output / "index.html").write_text(
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>CTT project reports</title>"
        '<link rel="stylesheet" href="assets/report.css"></head>\n'
        '<body><header class="site-header"><div class="shell">'
        '<p class="eyebrow">Release readiness</p>'
        "<h1>Controlled Text Transfer project reports</h1>"
        '<p class="lede">Tests, coverage, code quality, security, dependencies, '
        "and API documentation in one offline dashboard.</p>"
        f'<div class="status status--{status}" role="status">{status}</div>'
        f'<p class="meta">Generated {generated_at}</p>'
        '</div></header><main id="main-content" class="shell">'
        f'<section class="section" aria-labelledby="summary"><h2 id="summary">Summary</h2>'
        f'<div class="grid">{metric_cards or "<p>No test metrics were requested.</p>"}</div>'
        "</section>"
        f'<section class="section" aria-labelledby="checks"><h2 id="checks">Checks</h2>'
        f'<div class="grid">{check_cards or "<p>No quality checks were requested.</p>"}</div>'
        '</section><section class="section" aria-labelledby="reports">'
        f'<h2 id="reports">Reports</h2><ul class="report-list">{report_items}{direct_items}</ul>'
        "</section></main></body></html>\n",
        encoding="utf-8",
    )


def _python_executable() -> str:
    venv_dir = (REPOSITORY / ".venv").resolve()
    current_exe = Path(sys.executable).resolve()
    if current_exe == venv_dir or venv_dir in current_exe.parents:
        return sys.executable
    win_py = REPOSITORY / ".venv" / "Scripts" / "python.exe"
    if win_py.is_file():
        return str(win_py)
    posix_py = REPOSITORY / ".venv" / "bin" / "python"
    if posix_py.is_file():
        return str(posix_py)
    return sys.executable


def generate(output: Path, *, pydoc_only: bool = False) -> int:
    """Generate reports and return zero only when every requested check passes."""
    output = _validate_output(output)
    output.mkdir(parents=True, exist_ok=True)
    _write_assets(output)
    reports = _write_pydoc(output)
    views = {"pydoc": reports["pydoc"]}
    checks: dict[str, int] = {}

    generated_at = datetime.now(UTC).isoformat()
    metadata = {
        "application_version": version("controlled-text-transfer"),
        "python": sys.version,
        "platform": platform.platform(),
        "generated_at": generated_at,
    }
    metadata_text = json.dumps(metadata, indent=2) + "\n"
    (output / "metadata.json").write_text(metadata_text, encoding="utf-8")
    reports["runtime metadata"] = "metadata.json"
    views["runtime metadata"] = _write_report_page(
        output, "Runtime metadata", metadata_text, "metadata.json"
    )

    if not pydoc_only:
        python_exe = _python_executable()
        coverage = output / "coverage"
        checks["tests and coverage"] = _run(
            [
                python_exe,
                "-m",
                "pytest",
                "-q",
                f"--junitxml={output / 'junit.xml'}",
                f"--cov-report=html:{coverage}",
                f"--cov-report=json:{output / 'coverage.json'}",
            ],
            output / "pytest.txt",
        )
        reports.update(
            {
                "coverage": "coverage/index.html",
                "coverage data": "coverage.json",
                "test results": "junit.xml",
                "pytest output": "pytest.txt",
            }
        )
        views["coverage"] = reports["coverage"]
        views["test results"] = reports["test results"]
        views["pytest output"] = _write_report_page(
            output,
            "Pytest output",
            (output / "pytest.txt").read_text(encoding="utf-8"),
            "pytest.txt",
        )
        checks["ruff"] = _run(
            [python_exe, "-m", "ruff", "check", ".", "--output-format", "json"],
            output / "ruff.json",
        )
        reports["Ruff findings"] = "ruff.json"
        views["Ruff findings"] = _write_report_page(
            output,
            "Ruff findings",
            (output / "ruff.json").read_text(encoding="utf-8"),
            "ruff.json",
        )
        checks["black"] = _run(
            [python_exe, "-m", "black", "--check", "."],
            output / "black.txt",
        )
        reports["Black output"] = "black.txt"
        views["Black output"] = _write_report_page(
            output,
            "Black output",
            (output / "black.txt").read_text(encoding="utf-8"),
            "black.txt",
        )
        checks["mypy"] = _run(
            [python_exe, "-m", "mypy", "src"],
            output / "mypy.txt",
        )
        reports["MyPy output"] = "mypy.txt"
        views["MyPy output"] = _write_report_page(
            output,
            "MyPy output",
            (output / "mypy.txt").read_text(encoding="utf-8"),
            "mypy.txt",
        )
        checks["bandit"] = _run(
            [python_exe, "-m", "bandit", "-r", "src", "scripts", "-q", "-f", "json"],
            output / "bandit.json",
        )
        reports["Bandit findings"] = "bandit.json"
        views["Bandit findings"] = _write_report_page(
            output,
            "Bandit findings",
            (output / "bandit.json").read_text(encoding="utf-8"),
            "bandit.json",
        )
        uv = shutil.which("uv")
        if uv is None:
            checks["dependency tree"] = 1
            (output / "dependencies.txt").write_text("uv was not found\n", encoding="utf-8")
        else:
            checks["dependency tree"] = _run([uv, "tree"], output / "dependencies.txt")
        reports["dependency tree"] = "dependencies.txt"
        views["dependency tree"] = _write_report_page(
            output,
            "Dependency tree",
            (output / "dependencies.txt").read_text(encoding="utf-8"),
            "dependencies.txt",
        )

    metrics = _collect_metrics(output)
    status = _overall_status(checks, metrics)
    summary = {
        "status": status,
        "generated_at": generated_at,
        "metrics": metrics,
        "checks": checks,
        "reports": reports,
        "views": views,
    }
    (output / "report.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    _write_index(output, summary)
    print(f"Reports written to {output}")
    return 1 if status == "failed" else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("reports"))
    parser.add_argument(
        "--pydoc-only",
        action="store_true",
        help="generate API documentation and runtime metadata without quality reports",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Generate the requested report set."""
    args = _parser().parse_args(argv)
    try:
        return generate(args.output, pydoc_only=args.pydoc_only)
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
