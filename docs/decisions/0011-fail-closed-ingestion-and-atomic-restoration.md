# ADR-011: Fail closed at package boundaries and restore atomically

[ADR index](README.md) | [Documentation index](../README.md)

## Status

Accepted

## Date

2026-07-26

## Context

Verification and restoration consume package directories and manifests from a
less-trusted transfer zone. File-level link checks did not cover linked package
roots or payload directories, manifest hash algorithms were less strict than
policy algorithms, and restoration wrote directly into its final destination.
A late checksum or metadata failure could therefore expose files outside the
package or leave a partial destination.

Source preflight also inspected content after detecting that a file exceeded
its configured size limit, weakening the limit as a resource-exhaustion
control.

## Decision

Apply the same approved hash-algorithm allowlist to policies and manifests.
Validate digest shape and restrict restored modes to ordinary permission bits
from `0o000` through `0o777`.

Reject symbolic links and Windows junctions at the package root, manifest and
signature sidecars, payload root, and every payload descendant. Enforce
per-file size limits before reading source content.

Restore into a sibling staging directory. Reconstruct and hash every file,
verify the staged bytes, apply validated modes, and publish the destination
only with a final same-filesystem rename. Remove staging after any failure.

## Alternatives considered

### Resolve linked payload roots and continue

Rejected because resolving the package root makes an external directory appear
internal and permits package-controlled reads outside the transfer tree.

### Delete a partially restored destination after failure

Rejected because files become visible before validation completes, and cleanup
cannot provide the same publication boundary as staging.

### Accept every algorithm supported by `hashlib`

Rejected because runtime availability is not an approval policy. Manifests must
not downgrade integrity to MD5, SHA-1, or another undeclared algorithm.

## Consequences

- Oversized candidates are reported without reading their contents.
- Linked directory packages fail before manifest or payload processing.
- Restore failures leave neither a destination nor a staging directory.
- Atomic publication requires the staging directory and destination to share a
  filesystem.
- Manifests using unsupported hashes or special permission bits are rejected.
- Security scanning covers both shipped package code and repository scripts.
