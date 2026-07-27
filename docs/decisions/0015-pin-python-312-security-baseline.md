# ADR-015: Pin Python 3.12.13 as the minimum security baseline

[ADR index](./README.md) | [Security guidance](../../SECURITY.md)

## Status

Accepted

## Date

2026-07-27

## Context

Python 3.12 remains under upstream security support until October 2028, but
3.12.13 is a security-only release containing fixes absent from earlier 3.12
patches. Floating minor-version CI does not prove the documented minimum patch,
and high-level `pathlib` queries have different internal call paths across
3.12 and 3.14.

## Decision

Require Python 3.12.13 or newer in package metadata and operator guidance.
Pin the minimum CI and release jobs to 3.12.13 while retaining Python 3.14 as
the current feature-line target.

Implement security-sensitive file inspection from captured non-following
metadata and descriptors rather than depending on the internal call order of
`Path.is_symlink()` or `Path.is_junction()`. Reassess 3.12 support by October
2027 and remove it no later than upstream end of life in October 2028.

## Alternatives considered

### Drop Python 3.12 immediately

Rejected because 3.12.13 is actively security-supported and provides the
Windows junction and accurate file-identity APIs CTT requires.

### Continue accepting every Python 3.12 patch

Rejected because earlier patches omit published upstream security fixes.

### Float the minimum CI job on `3.12`

Rejected because a moving target does not continuously prove compatibility
with the declared minimum runtime.

## Consequences

- Installers reject Python 3.12.0 through 3.12.12.
