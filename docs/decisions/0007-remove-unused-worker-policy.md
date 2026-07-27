# ADR-007: Remove the unused worker-count policy option

[ADR index](./README.md) | [Documentation index](../README.md)

## Status

Accepted

## Date

2026-07-25

## Context

The policy exposed a `workers` setting, but preparation is sequential and the
value never changed application behavior. Keeping an ineffective setting makes
policy reviews misleading and implies a concurrency guarantee the application
does not provide.

## Decision

Remove `workers` from the `Policy` API and YAML schema. Strict policy parsing
rejects the former key as an unknown field so outdated configurations cannot
appear to take effect.

Preparation remains deterministic and performs stable source capture, staged
self-verification, and atomic publication.

## Alternatives considered

### Retain and ignore the option

Rejected because accepting an ineffective security-sensitive policy setting is
misleading.

### Implement parallel preparation

Rejected for the first release because it adds coordination complexity without
a demonstrated performance requirement.

## Consequences

- Existing policy files must remove the `workers:` entry before upgrading.
- The supported configuration matches actual runtime behavior.
- Parallel preparation can be proposed later with benchmarks and a new ADR.

## Related implementation

- `src/controlled_text_transfer/core.py`: strict policy model and parsing.
- `ctt.yaml` and `ctt.yaml.example`: supported policy examples.
