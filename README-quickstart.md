# Controlled Text Transfer Quick Start

Run these commands from the repository root. `uv` creates and manages the
Python 3.12-or-newer environment automatically; no separate installation is
required.

## Show the CLI

```bash
uv run ctt --help
```

## Prepare and transfer files

Replace `./source` with the directory containing the files to transfer:

```bash
uv run ctt preflight ./source --json
uv run ctt prepare ./source ./transfer --strict
uv run ctt verify ./transfer
uv run ctt restore ./transfer ./restored
```

- `preflight` reports which files will be accepted, transformed, or rejected.
- `prepare --strict` creates nothing if any candidate is rejected.
- `verify` checks the manifest, paths, sizes, and hashes.
- `restore` recreates the original files in a new destination directory.

## Use a policy file

```bash
uv run ctt prepare ./source ./transfer --policy ./ctt.yaml --strict
```

The default `directory` package format creates `./transfer`. ZIP, TAR, and
TAR.GZ policies instead create `./transfer.zip`, `./transfer.tar`, or
`./transfer.tar.gz`.

For all options:

```bash
uv run ctt prepare --help
uv run ctt verify --help
```

The [complete CLI option reference](docs/cli.md) explains how and why to use
every option, including signing and machine-readable output.

To preview or perform a cleanup of generated repository artifacts:

```bash
uv run python scripts/clean.py --dry-run
uv run python scripts/clean.py
```

## Run the tests

From Bash, use the development dispatcher:

```bash
bash scripts/run.sh test
```

Run every quality gate before review:

```bash
bash scripts/run.sh check
```

After a fresh clone or after removing `.venv`, include the development extra:

```bash
uv run --extra dev pytest
```

For the same complete suite with concise output:

```bash
uv run --extra dev pytest -q
```

Alternatively, install all development tools first and then run commands
without repeating the extra:

```bash
uv sync --extra dev
uv run pytest
```

The suite enforces 100% aggregate statement coverage. Its terminal report omits
fully covered modules so remaining gaps are easier to review.

Other dispatcher commands are:

```bash
bash scripts/run.sh setup
bash scripts/run.sh report
bash scripts/run.sh build
bash scripts/run.sh release 0.1.1
bash scripts/run.sh unrelease 0.1.1
bash scripts/run.sh clean --dry-run
bash scripts/run.sh clean --environment
bash scripts/run.sh help
```

The report command writes a browsable `reports/index.html`. Use
`bash scripts/run.sh report --pydoc-only` for fast API documentation, or see
the [scripts guide](scripts/README.md) for every generated report.

See [README.md](./README.md) for architecture and
[docs/operations.md](./docs/operations.md) for operational guidance. See the
[policy reference](./docs/policy.md) for every supported field and practical
examples.
