# ADR-005: Preflight, atomic publication, and trusted ingestion

[ADR index](README.md) | [Documentation index](../README.md)

## Status

Accepted

## Date

2026-07-25

## Context

Destination CDS installations impose limits beyond file extensions. Preparation
also needs to resist source changes, partial output, unsafe archives, and
unauthenticated manifests.

## Decision

Use a named compatibility profile and strict policy schema. A read-only
preflight produces one deterministic decision per candidate, including stable
reason codes and transformations. Preparation consumes that same scan and
captured byte snapshot.

Build packages in a sibling staging directory, verify them, and publish with
same-filesystem renames. ZIP and TAR input is extracted member-by-member with
path, type, duplication, member-count, and expanded-size checks.

Signature enforcement accepts only a verifier supplied by trusted operator
configuration. Commands or algorithms found in transferred data are never
executed.

## Alternatives considered

### Treat dry-run output as preflight

Rejected because free-form output is not a stable automation contract and
cannot account for every candidate with machine-readable reason codes.

### Copy directly into the destination

Rejected because a copy, manifest, archive, or verification failure can leave
a package that appears usable. Same-filesystem staging makes publication a
separate final step.

### Use standard archive extraction helpers

Rejected because generic `extractall` behavior does not enforce this format's
member allowlist, duplicate detection, expansion limits, or link prohibition.

### Select signature commands from policy or manifest data

Rejected because transferred or loosely controlled configuration must not gain
command-execution authority. A signer is injected by the trusted host.

## Consequences

- Strict mode publishes nothing when any candidate is rejected.
- Non-strict packages contain only files accepted by preflight.
- Archive verification uses bounded temporary storage.
- Atomic rename requires staging and destination to share a filesystem.
- A compatibility profile improves predictability but cannot guarantee CDS
  authorization.
- The stock console entry point cannot sign by itself; a trusted host must
  inject a signer or use the library API.
