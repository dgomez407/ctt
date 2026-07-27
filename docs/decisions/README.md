# Architecture Decision Records

[Documentation index](../README.md) | [Repository home](../../README.md)

These records explain the durable design choices behind Controlled Text
Transfer. They are
numbered sequentially and should not be deleted; a changed decision should be
recorded in a new ADR that references the earlier one.

| ADR | Decision | Status |
| --- | --- | --- |
| [ADR-001](./0001-reversible-text-only-transfer.md) | Use reversible `.txt` filename translation with UTF-8/BOM handling | Accepted |
| [ADR-002](./0002-allowlist-manifest-and-integrity-model.md) | Use explicit selection, a versioned manifest, and fail-closed verification | Accepted; amended |
| [ADR-003](./0003-packaging-and-signing-boundaries.md) | Separate packaging from externally managed signature hooks | Superseded |
| [ADR-004](./0004-python-packaging-and-quality-gates.md) | Use a small Python package with pipx, PyInstaller, and CI quality gates | Accepted |
| [ADR-005](./0005-preflight-atomicity-and-trusted-ingestion.md) | Add compatibility preflight, atomic publication, and trusted ingestion | Accepted |
| [ADR-006](./0006-single-artifact-publication-and-signature-verification.md) | Publish one artifact and verify declared signatures | Accepted |
| [ADR-007](./0007-remove-unused-worker-policy.md) | Remove the unused worker-count policy option | Accepted |
| [ADR-008](./0008-controlled-text-transfer-name.md) | Adopt the Controlled Text Transfer product identity | Accepted |
| [ADR-009](./0009-python-312-minimum.md) | Require Python 3.12 for maintained security support and filesystem APIs | Accepted; amended |
| [ADR-010](./0010-offline-report-dashboard.md) | Generate an offline dashboard while preserving raw quality artifacts | Accepted |
| [ADR-011](./0011-fail-closed-ingestion-and-atomic-restoration.md) | Fail closed at package boundaries and restore atomically | Accepted |
| [ADR-012](./0012-harden-github-automation.md) | Harden GitHub automation and release provenance | Accepted |
| [ADR-013](./0013-release-alignment-and-rollback-operations.md) | Automate release alignment, verification, and unrelease operations | Accepted |
| [ADR-014](./0014-stable-bounded-authenticated-ingestion.md) | Use stable, bounded, authenticated package ingestion | Accepted |
| [ADR-015](./0015-pin-python-312-security-baseline.md) | Pin Python 3.12.13 as the minimum security baseline | Accepted |
