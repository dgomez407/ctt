# Development Scripts

[Repository home](../README.md)

- [`run.sh`](run.sh) provides memorable commands for testing, quality checks,
  builds, and cleanup. Run `bash scripts/run.sh help` for its command list.
- [`clean.py`](clean.py) removes generated caches and build artifacts safely.
- [`report.py`](report.py) generates browsable API, test, coverage, quality,
  security, dependency, and runtime reports.
- [`check_release.py`](check_release.py) rejects a release tag when the package
  version, README title, or changelog is inconsistent.
- [`__init__.py`](__init__.py) makes cleanup helpers importable in tests.

See the [quick start](../README-quickstart.md) for common workflows.

## Generate Reports

```bash
bash scripts/run.sh report
```

The command writes an ignored `reports/` directory. Open `reports/index.html`
for an offline, responsive dashboard with overall status, test and coverage
metrics, check results, and links to every report. Generated human-readable
views provide dashboard navigation and preserve the corresponding raw artifact
for automation or detailed inspection.

- `index.html`, `assets/`, and `report.json`: styled human and machine-readable
  indexes
- `pydoc/`: responsive HTML API documentation with module navigation,
  on-page contents, preserved pydoc anchors, verified local links, and print
  styling; every application module, including `__main__`, has a page with
  explicit breadcrumbs, while unavailable dependency targets render as code
  instead of broken links
- `coverage/`, `coverage.json`, and `junit.xml`: coverage and test results
- `pytest.html`, `ruff.html`, `black.html`, `mypy.html`, `bandit.html`,
  `dependencies.html`, and `metadata.html`: formatted report views
- `.json`, `.xml`, and `.txt` files alongside those views: unchanged raw
  code-quality, security, dependency, and runtime data
- `dependencies.txt` and `metadata.json`: dependency and runtime context

For API documentation without running the quality suite:

```bash
bash scripts/run.sh report --pydoc-only
```

Use `--output PATH` for a directory outside the repository. Inside the
repository, output is restricted to the ignored top-level `reports/`
directory so generated files cannot become source. Running
`bash scripts/run.sh clean` removes that default directory.

Existing output trees containing symbolic links or Windows junctions are
rejected. Reports can contain local paths, runtime details, and dependency
versions; review them before sharing.

The offline rendering, raw-artifact compatibility, and status-color decisions
are recorded in [ADR-010](../docs/decisions/0010-offline-report-dashboard.md).
