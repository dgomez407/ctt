# ADR-003: Separate packaging from externally managed signing

[ADR index](./README.md) | [Documentation index](../README.md)

## Status

Superseded by ADR-006

## Date

2026-07-25

## Context

Transfer packages may need to be delivered as a directory, ZIP, TAR, or
TAR.GZ archive. Some environments also require cryptographic signatures, but
private-key custody must remain under approved GPG, X.509, HSM, or enterprise
key-management controls.

## Decision

Create archives from the prepared directory and keep the manifest inside the
package. Provide a small detached-signature protocol and an external command
adapter using argument vectors, `shell=False`, bounded timeouts, and no
secret-bearing flags. The library does not generate, import, store, or log
private keys or passphrases.

## Alternatives considered

### Implement private-key handling inside `cds`

Rejected because it would create a new secret-management boundary and make
the tool responsible for key custody it cannot safely control.

### Treat a checksum as a signature

Rejected because checksums detect changes but do not authenticate the signer.

### Require one archive format

Rejected because controlled transfer environments differ in the packaging
formats they accept and inspect.

## Consequences

- Operators can use approved external signing infrastructure without changing
  the transfer transformation code.
- Signature verification remains an explicit operational step.
- Archives still require CDS and malware scanning; packaging is not a bypass.
- The external command adapter must remain an argument-vector interface and
  must not be changed to shell-string execution.

## Related implementation

- `src/controlled_text_transfer/core.py`: directory and archive packaging.
- `src/controlled_text_transfer/signing.py`: signer protocol and external adapter.
- `SECURITY.md`: key-custody and archive-safety guidance.
