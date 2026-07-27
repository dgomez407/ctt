# ADR-014: Use stable, bounded, authenticated package ingestion

[ADR index](README.md) | [Security contract](../security-hardening.md)

## Status

Accepted

## Date

2026-07-26

## Context

Path checks followed by pathname reads leave replacement race windows.
Metadata-only archive limits do not constrain dishonest or truncated streams,
and boolean signature verification proves validity without identifying which
trusted key verified the manifest.

## Decision

Read security-sensitive files through stable descriptors with link rejection
and pre/open/post identity comparison. Apply immutable conservative ceilings
to manifests, signatures, paths, archive inputs, members, expansion, and
compression. Stream extraction while accounting for observed bytes.

Add `SignatureVerification` for authenticated identity. Identity-bearing
manifests require an exact structured identity match; legacy identity-free
manifests temporarily retain boolean-verifier compatibility. `key_label`
remains informational.

## Alternatives considered

### Continue pathname reads after link checks

Rejected because a pathname can change after inspection.

### Trust archive and manifest declarations

Rejected because transferred metadata is attacker-controlled.

### Immediately remove boolean verifier support

Rejected to avoid making all existing trusted-host integrations unusable in
one release. Boolean results cannot verify new identity-bearing manifests.

### Make ceilings sender configurable

Rejected because an untrusted sender must not expand receiver resource limits.

## Consequences

- Packages outside the ceilings must be split.
- Highly repetitive legitimate archives can exceed the supplemental ratio
  limit.
- Existing packages remain compatible only within the ceilings.
- Filesystem and operating-system compromise remain outside CTT's boundary.
- Integrity-only processing remains an explicitly documented residual risk.
