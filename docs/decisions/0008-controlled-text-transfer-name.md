# ADR-008: Adopt the Controlled Text Transfer product identity

[ADR index](README.md) | [Documentation index](../README.md)

## Status

Accepted

## Date

2026-07-25

## Context

The original `cds` identity conflicts with an existing PyPI distribution and
is ambiguous outside environments that use "CDS" to mean Cross Domain
Solution. No public release of this application exists, so retaining aliases
would create permanent compatibility cost without protecting users.

## Decision

Name the product **Controlled Text Transfer** and use one consistent identifier
family:

- PyPI distribution: `controlled-text-transfer`
- Python package: `controlled_text_transfer`
- command and executable: `ctt`
- policy and ignore files: `ctt.yaml` and `.cttignore`
- package metadata: `ctt-manifest.json.txt` and `ctt-manifest.sig`

The term "CDS" remains only when referring to an external Cross Domain
Solution or its compatibility constraints.

## Alternatives considered

### Keep the `cds` command and import

Rejected because mixed branding would preserve ambiguity and make installation
instructions harder to understand.

### Add compatibility aliases

Rejected because the first public release has no installed user base to
migrate.

## Consequences

- All examples and integrations must use the new identifiers.
- Packages created by unpublished development versions are not compatible by
  filename with the first public release.
- The PyPI name is reserved only after the first successful publication.
