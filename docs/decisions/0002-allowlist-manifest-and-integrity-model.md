# ADR-002: Use an allowlist, versioned manifest, and fail-closed verification

[ADR index](README.md) | [Documentation index](../README.md)

## Status

Accepted; parallelism consequence superseded by ADR-007

## Date

2026-07-25

## Context

An automated text detector alone is not sufficient for a controlled transfer:
some files may decode as text but still be inappropriate to move. The
destination also needs evidence that the transfer copy and restored file match
the source material.

## Decision

Use an explicit extension/name allowlist, `.cttignore` patterns, UTF-8
validation, and a per-file size limit. Record selected and skipped files in a
versioned JSON manifest. The manifest stores original and transfer hashes,
sizes, BOM state, paths, and permission bits.

SHA-256 is the default. SHA-512 is built in, and BLAKE3 is optional with a
clear failure if requested but unavailable.

Verification fails closed when a file is missing, modified, outside `payload`,
a symlink, or unexpectedly present in the payload. Restore requires a new
destination directory and verifies the reconstructed bytes.

## Alternatives considered

### Detect text by extension alone

Rejected because extensions are user-controlled and do not prove the content
is valid UTF-8 text.

### Convert every file that happens to decode as UTF-8

Rejected because allowlisting is a safer policy boundary and prevents
accidental transfer of unrelated repository content.

### Use checksums without a manifest

Rejected because a standalone checksum does not describe file identity,
mapping, skipped files, or transport transformations.

## Consequences

- Policy review is required before an approved file type is added.
- A checksum detects alteration but does not prove authenticity; signatures
  are handled separately under ADR-003.
- Preparation records are sorted deterministically.
- Skipped files are visible for human review instead of silently disappearing.

## Related implementation

- `src/controlled_text_transfer/core.py`: policy, manifest, hashing, and verification.
- `ctt.yaml`: baseline policy.
- `.cttignore`: repository exclusion examples.
