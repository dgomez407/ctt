# ADR-012: Harden GitHub automation and release provenance

[ADR index](./README.md) | [Documentation index](../README.md)

## Status

Accepted

## Date

2026-07-26

## Context

CI must provide feedback on the shared `dev` branch before a pull request while
still validating GitHub's prospective merge commit. Release automation also
executes third-party code and publishes a security-focused package, so mutable
action tags, unlocked tools, broad token permissions, and tags from unmerged
commits are unacceptable trust gaps.

## Decision

Run CI on pushes to `dev` and `main` and on pull requests targeting `main`.
Keep concurrency groups separate by event and ref so a branch run cannot
cancel its corresponding pull-request run. Install the committed dependency
state with `uv sync --frozen --extra dev` and invoke `scripts/run.sh check` as
the only quality-gate definition.

Pin every GitHub Action to a full commit SHA with a release-version comment,
grant only explicit required permissions, and use Dependabot for weekly pin
updates. Build releases with locked tools and publish through the protected
`pypi` environment using job-scoped OIDC. Require the tagged commit to be
contained in `origin/main` before building.

## Alternatives considered

### Run only pull-request CI

Rejected because it cannot confirm the pipeline before an official pull
request is opened.

### Cancel duplicate dev and pull-request runs

Rejected because the dev run validates the branch tip while the pull-request
run validates GitHub's prospective merge commit.

### Reference action major-version tags

Rejected because mutable tags can change the executed code without a reviewed
repository change.

## Consequences

- Developers receive automated feedback on `dev` before opening a pull request.
- An open `dev` to `main` pull request may legitimately produce two runs.
- Workflow dependency updates arrive as reviewable Dependabot changes.
- Missing history, a missing trusted ref, or an off-main release commit fails
  release validation closed.
