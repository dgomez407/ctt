# CLI Option Reference

[Documentation index](README.md) | [Repository home](../README.md)

Run CTT with `uv run ctt COMMAND ...`. Add `--help` after the program or any
command to see installed syntax, for example `uv run ctt prepare --help`.
Options belong after their command.

There are no global behavior flags. Each option is accepted only by commands
where it changes behavior:

| Command | Supported options |
| --- | --- |
| `prepare` | `--policy`, `--log-json`, `--dry-run`, `--strict`, `--json-report`, `--sign`, `--key-label` |
| `self-package` | `--policy`, `--log-json`, `--source`, `--format`, `--dry-run` |
| `preflight` | `--policy`, `--json` |
| `verify` | `--log-json`, `--require-signature`, `--allow-unverified-signature` |
| `restore` | `--log-json`, `--dry-run`, `--require-signature`, `--allow-unverified-signature` |
| `diff` | `--policy`, `--json`, `--require-signature`, `--allow-unverified-signature` |

Unsupported combinations are rejected instead of being silently ignored. For
example, `verify` and `restore` do not accept `--policy`, while `preflight` and
`diff` do not accept `--log-json`.

## `prepare`

`uv run ctt prepare SOURCE TRANSFER [OPTIONS]` preflights `SOURCE`, creates
`TRANSFER` atomically, and self-verifies it.

| Option | How and why to use it |
| --- | --- |
| `--policy PATH` | Apply a YAML compatibility/content policy. Example: `--policy ctt.yaml`. |
| `--dry-run` | Check what can be packaged without creating output. |
| `--strict` | Fail instead of creating an incomplete package when any file is rejected. |
| `--json-report PATH` | Save every accepted/rejected decision for automation or audit review. |
| `--log-json` | Emit the completion audit event as JSON on stderr. |
| `--sign` | Sign using a trusted signer injected by an embedding host. The standalone CLI has no key provider and fails closed. |
| `--key-label LABEL` | With `--sign`, record a non-secret key identifier. It does not select or contain a key. |

```console
uv run ctt prepare ./source ./transfer --policy ./ctt.yaml --strict --json-report ./preflight.json
```

## `self-package`

`uv run ctt self-package DESTINATION [OPTIONS]` packages the `ctt` codebase into a
`.txt`-only self-bootstrapping transfer bundle containing an embedded zero-dependency
`bootstrap.py.txt` script.

| Option | How and why to use it |
| --- | --- |
| `--policy PATH` | Apply a YAML compatibility/content policy. Example: `--policy ctt.yaml`. |
| `--source PATH` | Select source directory to package (default: current directory). |
| `--format FORMAT` | Select package output format (`zip`, `directory`, `tar`, `tgz`). Default: `zip`. |
| `--dry-run` | Check what can be packaged without creating output. |
| `--log-json` | Emit the completion audit event as JSON on stderr. |

```console
uv run ctt self-package ./dist/ctt-bootstrap.zip --format zip
```

## `preflight`

`uv run ctt preflight SOURCE [OPTIONS]` evaluates files without packaging. Use
`--policy PATH` to select rules and `--json` for the complete machine-readable
report instead of a summary.

```console
uv run ctt preflight ./source --policy ./ctt.yaml --json
```

## `verify`

`uv run ctt verify TRANSFER [OPTIONS]` checks a package directory or supported
archive. Use `--log-json` for a JSON audit event. `--require-signature` rejects
unsigned packages and requires an injected trusted verifier.
`--allow-unverified-signature` deliberately permits integrity-only processing
when that verifier is unavailable; it does **not** establish authenticity.

```console
uv run ctt verify ./transfer --require-signature
```

## `restore`

`uv run ctt restore TRANSFER DESTINATION [OPTIONS]` verifies before creating a
new destination. `--dry-run` verifies without writing files. `--log-json`,
`--require-signature`, and `--allow-unverified-signature` have the same audit
and trust semantics described for `verify`.

```console
uv run ctt restore ./transfer ./restored --dry-run --log-json
```

## `diff`

`uv run ctt diff TRANSFER SOURCE [OPTIONS]` reports added, removed, modified,
and unchanged files. `--policy PATH` controls which current files qualify as
added. `--json` emits structured output. `--require-signature` and
`--allow-unverified-signature` have the same trust semantics described for
`verify`.

```console
uv run ctt diff ./transfer ./source --policy ./ctt.yaml --json
```

All commands return `0` on success and `2` for operational or validation errors.
See [Policy configuration](policy.md) for every policy field and more examples.

Verification and restoration also return `2` for immutable security-ceiling,
archive-encryption, compression-ratio, unstable-file, and signer-identity
failures. Directory and archive packages receive equivalent manifest,
signature, payload-size, and path validation. See the
[security hardening contract](security-hardening.md). The
`--allow-unverified-signature` option remains an explicit integrity-only
residual risk and does not establish signer authenticity.
