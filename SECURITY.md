# Security Guidance

Controlled Text Transfer (`ctt`) is a file transformation and integrity utility. It is not a Cross
Domain Solution, malware scanner, content disarm system, or authorization
boundary. Use it only inside an approved transfer procedure and keep the CDS,
anti-malware, and human review controls in place.

## Trust boundaries

- Treat the source directory, transfer medium, archive, and destination as
  separate trust zones.
- The source directory is read-only from the tool's perspective.
- A manifest checksum detects accidental or unauthorized modification but does
  not prove who created the package.
- Authenticity requires a separately managed signature and trusted key path.

## Safe operating procedure

1. Review the YAML policy and `.cttignore` file before preparation.
2. Inspect the prepare report and skipped-file list.
3. Run `verify` after the package crosses the transfer boundary.
4. If signatures are used, verify them with approved GPG, X.509, HSM, or
   enterprise tooling before restoration.
5. Restore into a new, empty destination directory.
6. Run destination malware scanning and application-specific tests.

## Signing hooks

The signing API accepts detached signatures through a small protocol or an
external command adapter. Private keys, passphrases, PINs, and trust stores
must remain in approved key-management tooling. Do not put them in command
arguments, environment variables, YAML, manifests, logs, or source files.
External commands are passed as argument vectors with `shell=False`; do not
replace this with shell-string execution. Secret-bearing flags are rejected in
both `--flag value` and `--flag=value` forms. CTT drains stdout and stderr
concurrently, retains no more than 256 KiB from either stream, and terminates a
command as soon as either stream exceeds that ceiling. Signing reports a
controlled failure; verification fails closed.

## File and archive safety

The tool uses an explicit text allowlist, UTF-8 decoding, file-size limits,
path and filename limits, content-policy checks, path-root checks, and checksum
verification. ZIP/TAR ingestion rejects traversal, links, special files,
duplicate members, unexpected layouts, and excessive expansion. Archives must
still be scanned by CDS and malware controls; renaming a file or adding a BOM
is not a security bypass.

Directory ingestion rejects symbolic links and Windows junctions at the
package root, metadata sidecars, payload root, and every payload descendant.
Manifests may select only SHA-256, SHA-512, or optional BLAKE3 and may restore
only ordinary permission bits from `0o000` through `0o777`. Oversized source
files are rejected before their content is read.

Preparation captures accepted bytes once, writes into a sibling staging
directory, self-verifies, and publishes by rename. This avoids ordinary partial
packages; filesystem or host failure semantics still apply. Signature
verifiers must be supplied through trusted operator configuration and must
never be selected from transferred data.

Security-sensitive reads use stable descriptors after rejecting links,
junctions, and non-regular files and comparing pre-open, opened, and post-open
identities. Archive ingestion streams observed bytes into staging under
immutable receiver ceilings that transferred data cannot raise. Exact binary
units, limits, compatibility effects, and test evidence are in the
[security hardening contract](./docs/security-hardening.md).

Identity-bearing manifests require an exact identity returned by the trusted
verifier. `key_label` is informational only; integrity success does not prove
authenticity. Legacy identity-free manifests may temporarily use boolean
verification. `--allow-unverified-signature` remains an explicit residual risk
and must not be treated as authorization to restore.

Restoration uses a sibling staging directory, validates reconstructed and
persisted bytes, applies validated modes, and publishes by rename. A failed
restore removes staging and leaves the requested destination absent.

## Repository cleanup

`scripts/clean.py` deletes only allowlisted generated paths contained within
the resolved repository root. Discovery does not follow symbolic links or
Windows junctions/reparse points, preventing repository content from
redirecting recursive deletion outside the checkout. Review `--dry-run`
output before cleanup. Removing `.venv` is opt-in and is refused when it
contains the active Python interpreter. The shared uv cache is outside this
capability's scope.

## Generated reports

Report output may contain absolute source paths, local account or platform
details, dependency versions, and diagnostic text. Treat `reports/` as
developer-local data: review and redact it before sharing, and never place
secrets in test, lint, type-check, or security-scan output.

The report generator rejects repository-local output outside the ignored
top-level `reports/` directory. It also rejects an existing output tree that
contains symbolic links or Windows junctions, preventing linked paths from
redirecting writes outside the selected directory.

## Repository automation

GitHub Actions use explicit least-privilege permissions and full commit SHA
references for third-party actions. Dependabot proposes updates to those pins;
review the referenced upstream release before merging an update. CI installs
the committed `uv.lock` state with `uv sync --frozen --extra dev`.

CI runs for pushes to `dev` and `main` and for pull requests targeting `main`.
The separate event concurrency groups intentionally preserve both branch-tip
and prospective-merge validation. PyPI publication remains isolated in its own
job with environment-scoped OIDC permission, and a release tag is rejected
unless its checked-out commit belongs to `origin/main`.

The zero-dependency bootstrap applies bounded, stable reads to package directories
and ZIP archives. It rejects links, duplicate or encrypted ZIP members, excessive
expansion or compression, unsafe paths, multiple manifests, and signed packages it
cannot authenticate. Signed packages must be restored with an installed, trusted CTT
verifier.

Python 3.12 support begins at 3.12.13, the current upstream security release.
CI pins that minimum patch explicitly and also tests Python 3.14. Operators
must update when a later security patch is released; Python 3.12 support will
be reassessed by October 2027 and removed no later than its October 2028
upstream end of life.

## Reporting

Do not include secrets or sensitive file contents in bug reports. Report code
execution, path traversal, unexpected overwrite, signature bypass, or secret
disclosure issues privately to the project maintainers before public
disclosure.
