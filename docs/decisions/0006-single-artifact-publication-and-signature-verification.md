# ADR-006: Publish one artifact and verify declared signatures

[ADR index](README.md) | [Documentation index](../README.md)

## Status

Accepted; supersedes ADR-003

## Date

2026-07-25

## Context

Publishing both a directory and an archive requires two filesystem renames.
Exceptions can be rolled back, but a host failure between renames cannot be
made atomic. Separately, accepting a package that declares a signature without
verifying it gives a misleading successful result.

## Decision

Directory format publishes one directory. ZIP, TAR, and TAR.GZ formats publish
only the selected archive; their build directory remains temporary. Each final
artifact is committed with one same-filesystem rename after self-verification.

When a manifest or signature sidecar declares authenticity, verification fails
unless a trusted verifier is supplied. Integrity-only inspection requires the
explicit `allow_unverified_signature` API option or
`--allow-unverified-signature` CLI flag. Signing and verification commands
remain trusted-host configuration and are never selected from transferred
data.

## Alternatives considered

### Best-effort two-artifact rollback

Rejected because rollback cannot run after sudden process, host, or power
failure.

### Ignore signatures unless explicitly required

Rejected because a successful result can be mistaken for authentication.

## Consequences

- Archive callers must use the archive path rather than the requested base
  directory after preparation.
- Each preparation publishes exactly one artifact.
- Signed packages fail closed by default.
- Operators can explicitly request integrity-only verification when the trust
  context permits it.
