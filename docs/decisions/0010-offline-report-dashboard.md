# ADR-010: Generate an offline report dashboard

[ADR index](README.md) | [Documentation index](../README.md)

## Status

Accepted

## Date

2026-07-25

## Context

The quality-report command produced useful coverage, test, lint, type-checking,
security, dependency, runtime, and pydoc artifacts, but its index was difficult
to scan and most results opened as raw text or JSON. Reports may also contain
local paths and environment details, so depending on hosted assets or an
external report service would create unnecessary availability and disclosure
risks.

## Decision

Generate a self-contained, responsive HTML dashboard alongside the raw report
artifacts. Keep the raw JSON, XML, and text outputs unchanged for automation,
and add escaped HTML views for human inspection. Include test and coverage
metrics, navigation from pydoc pages, and explicit textual status labels.

Continue generating API content with standard-library pydoc, then
post-process only its presentation. Add semantic landmarks, module and
on-page navigation, responsive scoped styles, and print rules while preserving
pydoc signatures, docstrings, anchors, and generated cross-module links.
Retain hyperlinks only when their local report target exists; render
standard-library, dependency, source-file, and other unavailable targets as
styled code text. Do not add a documentation framework solely for generated
review reports.

Generate pages for every application module, including `__main__`. Present
module identity as an explicit dashboard/package/current-page breadcrumb and
render the legacy pydoc title as one complete plain-text module name rather
than partially linking only its package prefix.

Use a black background with semantic status colors: green for passing results,
orange for warnings such as skipped tests, and red for failures. Warning and
failure cards use matching tinted interiors for visibility. Color never
acts as the only status indicator. Keep the entire `reports/` tree generated,
ignored by source control, and free of external web dependencies.

## Alternatives considered

### Publish reports to an external service

Rejected because local reports can expose machine paths, dependency versions,
and runtime information. Upload should remain an explicit user decision.

### Replace raw artifacts with HTML

Rejected because CI and other tools require stable machine-readable outputs.

### Use a JavaScript dashboard framework

Rejected because the report is static, and a framework would add dependencies,
loading complexity, and a larger attack surface without improving the core use
case.

### Replace pydoc with Sphinx or MkDocs

Rejected because the application needs an offline API inspection artifact,
not a separately configured documentation site. A scoped presentation layer
meets that need without another dependency or parallel source of API truth.

## Consequences

- `reports/index.html` is the primary human entry point.
- Raw report formats remain available and backward-compatible.
- Report content is HTML-escaped before rendering.
- Warning status does not fail the report command; failed checks still do.
- Dashboard rendering and semantic severity behavior require regression tests.
- Pydoc post-processing tests semantic landmarks and preserved anchors rather
  than snapshotting version-dependent generated markup.
- Every remaining relative pydoc link is verified against its generated file
  and optional anchor.
- Adding an application module requires adding it to the documented-module
  registry so navigation and link validation remain complete.
