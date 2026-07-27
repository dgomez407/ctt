# ADR-009: Require Python 3.12

[ADR index](./README.md) | [Documentation index](../README.md)

## Status

Accepted; amended by ADR-015

## Date

2026-07-25

## Context

Python 3.9 reached end of life on 2025-10-31 and no longer receives security
updates. Supporting it also required custom Windows reparse-point inspection
in security-sensitive cleanup code.

## Decision

Require Python 3.12 or newer. Align package metadata, Ruff, Black, MyPy, and CI
with that minimum. Use `Path.is_junction()` for native Windows junction
detection while retaining explicit symlink checks and bounded archive
extraction.

CI tests both Python 3.12 and 3.14.

## Alternatives considered

### Continue supporting Python 3.9

Rejected because an unsupported interpreter is not an acceptable foundation
for a security-focused first release.

### Require Python 3.14

Rejected because its safer archive defaults do not replace this application's
stricter manual extraction, while the higher minimum would unnecessarily
reduce deployment compatibility.

## Consequences

- Installations must provide Python 3.12 or newer.
- Cleanup code uses maintained standard-library filesystem primitives.
- Python 3.9 through 3.11 are intentionally unsupported.
