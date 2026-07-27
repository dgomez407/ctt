# CLI and Library API

[Documentation index](./README.md) | [Repository home](../README.md)

## CLI commands

| Command | Purpose |
|---|---|
| `preflight SOURCE` | Report compatibility decisions without writing |
| `prepare SOURCE TRANSFER` | Select and transform approved source files |
| `verify TRANSFER` | Validate manifest and transfer payload integrity |
| `restore TRANSFER DESTINATION` | Reconstruct original files and metadata |
| `diff TRANSFER SOURCE` | Report source/package differences without writing |

Options are scoped to commands where they have an effect. See the
[complete CLI option reference](./cli.md) for purposes and examples, and the
[policy reference](./policy.md) for policy fields. `verify` and `restore` are
manifest-driven and do not accept `--policy`.

`--sign` and authenticated verification require an application that calls
`controlled_text_transfer.cli.main(..., signer=trusted_signer)`. The standard console process has no
key or verifier configuration and therefore fails closed for signed packages.
`--allow-unverified-signature` explicitly requests integrity-only processing.

## Python API

The public core functions are available from `controlled_text_transfer.core`:

- `Policy.from_file(path)` loads a YAML policy or returns safe defaults.
- `preflight(source, policy)` returns a deterministic `PreflightReport` with
  accepted/rejected counts and per-file paths, reason codes, transformations,
  and sizes.
- `prepare(source, transfer, policy, dry_run=False, strict=False, signer=None,
  key_label="external-managed-key")` creates a self-verified package.
- `verify(transfer, signer=None, require_signature=False,
  allow_unverified_signature=False)` validates directory or archive packages.
  Declared signatures require a verifier unless explicitly allowed unverified.
- `restore(transfer, destination, dry_run=False, signer=None,
  require_signature=False, allow_unverified_signature=False)` reconstructs
  original bytes in staging and atomically publishes the completed destination.
- `diff(transfer, source, policy)` returns added, removed, modified, and
  unchanged relative paths.

Signing integration is available from `controlled_text_transfer.signing`:

- `SignatureVerification(valid, identity)` reports validity and the identity
  authenticated by the trusted verifier.
- `ManifestSigner` defines `sign` and transitional
  `verify -> bool | SignatureVerification` behavior.
- `sign_manifest` writes a detached signature sidecar.
- `verify_manifest_signature` validates a detached signature.
- `ExternalCommandSigner` calls approved tools with safe argument vectors.

Set `structured_verification=True` for an external verifier that emits bounded
UTF-8 JSON shaped exactly as
`{"valid": true, "identity": "SHA256:approved-fingerprint"}`. New manifests
created with a signer exposing `identity` require a matching structured result.
Legacy manifests without identity may use boolean verification. `key_label`
never authorizes a signer.

These signing hooks intentionally do not manage private keys or passphrases.
CLI embedding may inject a trusted `ManifestSigner` into `main`; transferred
manifests and policy files never select executable commands.
All APIs enforce the immutable limits in the
[security hardening contract](./security-hardening.md); violations raise
`TransferError` (or `ValueError`/`RuntimeError` at the low-level signer adapter).
