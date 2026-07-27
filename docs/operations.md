# Operational Runbook

[Documentation index](./README.md) | [Repository home](../README.md)

## Generate Review Reports

Run `bash scripts/run.sh report` to create `reports/index.html` with pydoc API
pages, coverage and JUnit results, Ruff, MyPy, and Bandit findings, the resolved
dependency tree, Black formatting status, and runtime metadata. The command returns nonzero when a
reported quality check fails but retains its diagnostic files.

Use `bash scripts/run.sh report --pydoc-only` when only API documentation and
runtime metadata are needed. Generated reports are ignored by Git and removed
by `bash scripts/run.sh clean`.

`--output PATH` may target a directory outside the repository. Repository-local
output is restricted to the top-level `reports/` directory to prevent
generated files from being mistaken for source.

## Initial Deployment & Self-Bootstrapping

### Online Networks (PyPI Installation)

For destination networks with internet access, install directly from [PyPI (`controlled-text-transfer`)](https://pypi.org/project/controlled-text-transfer/):

```bash
pip install controlled-text-transfer
```

### Air-Gapped / Offline Networks (Self-Bootstrapping)

When transferring CTT to an isolated destination network that does not yet have CTT installed:

1. **Self-Package on Source Network**:
   ```text
   bash scripts/run.sh bootstrap dist/ctt-bootstrap.zip
   ```
   Or using CLI:
   ```text
   ctt self-package dist/ctt-bootstrap.zip --format zip
   ```

2. **Transfer Across Boundary**:
   Transfer `dist/ctt-bootstrap.zip` across the CDS boundary. All files end in `.txt` and comply with text policy rules.

3. **Bootstrap Restore on Destination Network**:
   On the destination host (which has Python 3.12.13+ installed but no CTT package):
   ```text
   unzip ctt-bootstrap.zip -d /tmp/ctt-bootstrap
   python /tmp/ctt-bootstrap/bootstrap.py.txt /tmp/ctt-bootstrap /opt/ctt
   ```

4. **Install CTT**:
   ```text
   pip install /opt/ctt
   ```

## Prepare

1. Review `ctt.yaml` and `.cttignore`.
   See the [policy reference](./policy.md) for field semantics and examples.
2. Run preflight and retain its machine-readable report:

   ```text
   ctt preflight SOURCE --policy ctt.yaml --json
   ```

3. Create the package, using `--strict` when every candidate must pass:

   ```text
   ctt prepare SOURCE TRANSFER --policy ctt.yaml --strict \
     --json-report preflight.json --log-json
   ```

4. Record the manifest and audit output according to the local procedure.

## Transfer and verify

After the package crosses the approved boundary, verify it before restoration:

```text
ctt verify TRANSFER
```

`TRANSFER` may be the canonical directory, ZIP, TAR, or TAR.GZ artifact.
Packages declaring a signature require a trusted verifier automatically.
Use `--require-signature` to reject unsigned packages too. The explicit
`--allow-unverified-signature` override performs integrity-only verification.

If a detached signature is used, verify it with the approved external GPG,
X.509, HSM, or enterprise tooling before accepting the package.

## Review changes

Compare the package with a source directory without changing either input:

```text
ctt diff TRANSFER SOURCE --json
```

Review `added`, `removed`, `modified`, and `unchanged` categories. A modified
or removed source file may be expected if the source changed after preparation;
it should never be silently ignored.

## Restore

Restore into a new directory:

```text
ctt restore TRANSFER RESTORED
```

The command verifies transfer hashes, restores into a sibling staging
directory, removes only the transport-added BOM, restores the original BOM
state and ordinary permission bits where supported, and validates every staged
file before atomically publishing the destination.

## Archive formats

Set `package_format` to one of `directory`, `zip`, `tar`, or `tgz`.
Directory format publishes the requested directory. Archive formats publish
only the corresponding archive after verifying its temporary canonical
layout. Every artifact must still be scanned by surrounding controls.

Receiver security ceilings are fixed and cannot be raised by policy or
manifest data. The current limits are a 2 MiB manifest, 256 KiB signature,
128 MiB archive input, 256 MiB expansion, 2,000 members, 10 MiB per member,
100:1 compression ratio, 16 path components, and 180 path characters. Units
are binary. Split larger transfers into independently verified packages; see
the [security hardening contract](./security-hardening.md).

## Failure handling

- Do not rerun restore into an existing destination.
- A failed restore removes staging and leaves the requested destination absent.
- Preserve the failed package and manifest for investigation.
- Treat checksum, traversal, resource-limit, encryption, unexpected-file,
  signature, and signer-identity failures as
  integrity failures, not as ordinary warnings.
- Do not disable allowlists, size limits, or external scanning to force a
  transfer through.
- Treat `generic-text-v1` as a compatibility baseline, not proof that a
  particular CDS will authorize the transfer.

## Release preparation

Before running a release:
1. Update `CHANGELOG.md` to move unreleased items under `## [<version>] - YYYY-MM-DD`.
2. Run `bash scripts/run.sh release <version>`.

The release command validates `CHANGELOG.md` readiness, bumps `pyproject.toml` version via `uv`, updates the `README.md` header title, executes `check_release.py` and the full quality gate, creates the `chore(release): prepare v<version>` commit and `v<version>` tag, and validates the snapshot offline using `scripts/ctt-release-check.sh`.

Publish online after verification:
```text
git push origin main
git push origin v<version>
```

### Unrelease & Backout Procedure

If last-minute corrections are needed before pushing:
```text
bash scripts/run.sh unrelease <version>
```
This deletes local tag `v<version>` and resets the `chore(release): prepare v<version>` commit (`git reset HEAD~1`), preserving modified files staged in your working directory for edits.

If the tag was already pushed to remote origin before PyPI publication completes:
```text
git tag -d v<version>
git push origin :refs/tags/v<version>
```
*(Note: Cancel the active GitHub Actions workflow if it has already started. If PyPI publication has already finished, version numbers are immutable and a patch bump `v<version+1>` must be prepared instead.)*

## Development environment cleanup

Run `bash scripts/run.sh clean --dry-run` before cleanup to review every
target. Run `bash scripts/run.sh clean` to remove repository-local build
outputs, coverage data, bytecode, package metadata, and test/lint/type-check
caches.

The default preserves `.venv`. Removing it requires
`bash scripts/run.sh clean --environment`. The dispatcher selects the first
`python` on `PATH` outside the project environment and falls back to uv only
when no default Python exists; the action fails safely if its selected
interpreter is inside the target.
Shared uv cache data is intentionally out of scope. Use `uv cache clean` only
as a separate, deliberate system-maintenance operation because it affects
other projects.

Removing `.venv` also removes pytest, Ruff, Black, MyPy, Bandit, and other
development-only tools. Restore them with `uv sync --extra dev`, or run the
complete tests directly with `uv run --extra dev pytest`. Without the extra,
`uv run pytest` may report `program not found` in a newly created environment.
