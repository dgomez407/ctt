# Policy Reference

[Documentation index](README.md) | [Repository home](../README.md)

CTT policies are strict YAML objects used by `preflight`, `prepare`, and
`diff`. Unknown fields, incorrect types, unsupported values, and limits below
one are rejected before source files are scanned. Start from
[`ctt.yaml.example`](../ctt.yaml.example), then run:

```bash
uv run ctt preflight SOURCE --policy POLICY.yaml --json
uv run ctt prepare SOURCE TRANSFER --policy POLICY.yaml --strict
```

`verify` and `restore` validate a package from its manifest and do not accept
`--policy`.

## Fields

| Field | Valid value and meaning | Default |
| --- | --- | --- |
| `allowlist.extensions` | List of permitted source suffixes, normalized to lowercase | Built-in text suffixes |
| `allowlist.names` | List of permitted exact filenames, such as `README` | Built-in text names |
| `add_bom` | Add a UTF-8 BOM to transfer copies; restoration removes only a BOM added by CTT | `true` |
| `hash_algorithm` | `sha256`, `sha512`, or `blake3` | `sha256` |
| `package_format` | `directory`, `zip`, `tar`, or `tgz` | `directory` |
| `ignore_file` | Non-empty filename read from the source root | `.cttignore` |
| `profile` | Named compatibility contract; YAML currently supports `generic-text-v1` | `generic-text-v1` |
| `max_bytes` | Maximum original bytes per file | `10485760` |
| `max_total_bytes` | Maximum original bytes across accepted files | `104857600` |
| `max_files` | Maximum number of accepted files | `10000` |
| `max_path_depth` | Maximum number of components in a relative source path | `32` |
| `max_path_length` | Maximum relative-path characters | `240` |
| `max_filename_length` | Maximum characters in one filename | `120` |
| `max_line_length` | Maximum characters in one decoded line | `10000` |
| `allow_unicode` | Permit non-ASCII text | `true` |
| `allow_mixed_line_endings` | Permit mixed LF and CRLF in one file; bare CR remains unsupported | `false` |
| `prohibited_patterns` | Case-sensitive literal substrings rejected when found in decoded text | `[]` |

All size, count, path, and line limits are positive integers. Boolean fields
must contain YAML booleans (`true` or `false`), not quoted strings.
`ascii-text-v1` exists for programmatic `Policy` construction but is not
currently accepted by `Policy.from_file`.

The default extension allowlist is:

```text
.cfg .conf .css .csv .html .ini .js .json .jsx .md .ps1 .py .rst .sh
.sql .toml .ts .tsx .txt .xml .yaml .yml
```

The default exact-name allowlist is `Dockerfile`, `LICENSE`, `Makefile`,
`NOTICE`, and `README`.

## Conservative source policy

This example narrows accepted content and prevents common secret-bearing text
from entering a package:

```yaml
allowlist:
  extensions: [.py, .md, .yaml, .json, .toml, .sh]
  names: [README, LICENSE]
add_bom: true
hash_algorithm: sha256
package_format: directory
ignore_file: .cttignore
profile: generic-text-v1
max_bytes: 1048576
max_total_bytes: 10485760
max_files: 500
max_path_depth: 12
max_path_length: 180
max_filename_length: 80
max_line_length: 1000
allow_unicode: false
allow_mixed_line_endings: false
prohibited_patterns:
  - "PRIVATE KEY"
  - "SECRET="
  - "PASSWORD="
```

Patterns are literal, case-sensitive substring checks, not regular
expressions. Content such as `secret=` does not match `SECRET=`.

## Archive policy

Only `package_format` needs to change to produce an archive:

```yaml
package_format: tgz
hash_algorithm: sha512
```

Preparing `./transfer` with this policy publishes `./transfer.tgz`; it does
not retain a second directory package. `verify` and `restore` accept the
archive path directly.

## BLAKE3 policy

Install the optional dependency before selecting BLAKE3:

```bash
uv sync --extra blake3
```

```yaml
hash_algorithm: blake3
```

Policy validation fails closed if the dependency is unavailable.

## Ignore patterns

The ignore file contains one glob per line. Blank lines and lines beginning
with `#` are ignored. Patterns are matched against both the relative path and
filename. Use file-matching globs for directory contents:

```text
.git/*
.venv/*
*__pycache__/*
dist/*
build/*
```

Ignored candidates appear in preflight with reason `ignored`. Consequently,
`prepare --strict` fails when ignored candidates are present; non-strict
preparation excludes them and records the decision in its preflight report.

## Choosing limits

Run preflight before tightening limits and retain its JSON report:

```bash
uv run ctt preflight SOURCE --policy POLICY.yaml --json
```

Review every rejection reason rather than increasing limits automatically.
A profile and successful preflight improve compatibility predictability but
cannot guarantee authorization by a particular controlled transfer system.
