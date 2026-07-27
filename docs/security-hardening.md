# Security Hardening Contract

[Documentation index](README.md) | [Security guidance](../SECURITY.md)

CTT treats source trees, package directories, archives, manifests, signature
sidecars, and restore destinations as separate trust boundaries. It is not a
Cross Domain Solution (CDS), malware scanner, or content-disarm system.

All limits use binary units: one KiB is 1,024 bytes and one MiB is 1,048,576
bytes. These verifier ceilings are compiled into CTT. Transferred policy and
manifest data cannot raise them.

| Resource | Hard ceiling |
| --- | ---: |
| Manifest | 2 MiB |
| Detached signature | 256 KiB |
| Archive input | 128 MiB |
| Expanded archive | 256 MiB |
| Archive members | 2,000 |
| Manifest file records | 2,000 |
| Individual member or payload file | 10 MiB |
| Compression ratio | 100:1 |
| Relative path depth | 16 components |
| Relative path length | 180 characters |
| Streaming buffer | 64 KiB |

Directory packages receive the same manifest, signature, file-count,
individual-size, aggregate-size, and path validation as archive packages.
ZIP, TAR, and TGZ additionally receive compressed-input, member, expansion,
type, encryption, and compression-ratio validation.

Expanded bytes, member count, and member size are the primary archive-bomb
controls. The ratio check is supplemental and can reject unusually repetitive
legitimate text. Split a transfer that exceeds any ceiling into independently
prepared, transferred, verified, and restored packages. Do not increase a
limit merely to force a rejected package through a CDS.

## Stable file access

Security-sensitive reads inspect a path with `lstat`, reject links, junctions,
and non-regular files, open one descriptor with `O_NOFOLLOW` when the platform
provides it, and compare pre-open, descriptor, and post-open file identities.
Content and hashes are then obtained from that descriptor. A replacement,
type change, size change, missing path, or read failure aborts processing.

This narrows time-of-check/time-of-use exposure. Host filesystem semantics,
privileged attackers, hardware failure, and operating-system compromise remain
outside CTT's security boundary.

## Streaming archive ingestion

Archive members are copied into temporary staging in 64 KiB chunks. CTT
accounts for observed bytes independently of archive metadata, requires
observed and declared member sizes to agree, and removes staging after any
failure. It rejects traversal, excessive paths, duplicate members, multiple
roots, links, special files, encrypted ZIP members, excessive compression,
truncation, and unexpected package layout.

## Authenticated signer identity

`SignatureVerification(valid, identity)` distinguishes cryptographic validity
from the identity authenticated by the trusted verifier. New identity-bearing
manifests require a structured result whose non-empty identity exactly matches
the signed manifest identity. Matching is case-sensitive; normalization is the
external verifier's responsibility.

Legacy manifests without `identity` may temporarily use boolean verifiers.
Boolean verifiers cannot authenticate identity-bearing manifests. `key_label`
is informational metadata only and must never be used for authorization.
Successful checksum or integrity verification is not proof of signer
authenticity.

Structured external verification emits bounded UTF-8 JSON:

```json
{"valid": true, "identity": "SHA256:approved-fingerprint"}
```

Unknown fields, malformed JSON, invalid identities, excessive output,
non-zero exit status, and contradictory results fail closed. Private keys and
passphrases remain outside CTT.

`--allow-unverified-signature` deliberately bypasses authenticity checking and
is a residual risk. Use it only for explicitly approved integrity-only
inspection; do not treat its success as authorization to restore.

## Failure response

Treat limit, traversal, checksum, signature, signer-identity, encryption, and
unexpected-member failures as security events. Preserve the package and audit
output according to local evidence-handling rules, do not restore it, and
escalate through the approved CDS procedure.

## Requirement-to-test matrix

| Contract | Automated evidence |
| --- | --- |
| Stable descriptors reject non-regular files, identity swaps, read failures, and overruns | `tests/test_hardening_limits.py`, `tests/test_security_invariants.py` |
| Manifest, member, aggregate, path, archive-input, and compression ceilings | `tests/test_hardening_limits.py`, `tests/test_archive_security.py` |
| Directory, ZIP, TAR, and TGZ round trips | `tests/test_archive_security.py`, `tests/test_core.py` |
| Links, traversal, duplicates, encryption, truncation, and cleanup | `tests/test_archive_security.py`, `tests/test_security_invariants.py` |
| Legacy and identity-bearing signatures | `tests/test_signing.py`, `tests/test_cli_options.py` |
| Structured verifier JSON and output limits | `tests/test_signing.py`, `tests/test_hardening_limits.py` |
| Policy example and immutable verifier/policy separation | `tests/test_documentation_contracts.py`, `tests/test_policy_and_transformation.py` |
| CLI options and help | `tests/test_cli_options.py`, `tests/test_cli_documentation.py` |
