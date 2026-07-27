# Deferred Security Hardening

[Documentation index](README.md) | [Security contract](security-hardening.md)

These items are intentionally deferred beyond ADR-014. Each requires its own
threat-model review, executable requirements, tests, documentation, and
changelog entry.

1. **Gate or remove integrity-only restoration.** Require an approved reason
   and high-severity audit event, or prohibit `--allow-unverified-signature`
   for restore. Depends on operator workflow review. Accept when unverified
   restoration cannot occur silently.
2. **Restrict external signer execution.** Require trusted executable paths,
   minimal environments, controlled working directories, and bounded process
   resources. Accept when PATH and environment manipulation cannot redirect
   the configured signer.
3. **Add replay and rollback resistance.** Sign package identifiers, creation
   times, policy digests, and optional expiration or sequence data. Accept when
   receivers can reject stale or previously consumed packages.
4. **Tighten restoration names and permissions.** Address executable bits,
   Windows device names, trailing dots/spaces, case-fold collisions, and
   Unicode-normalization collisions. Accept with cross-platform adversarial
   tests.
5. **Expand supply-chain assurance.** Add vulnerability and secret scanning,
   CodeQL, SBOM generation, and release-provenance verification. Accept when
   every release produces and verifies reviewable supply-chain evidence.
6. **Add fuzzing and resource regression tests.** Fuzz manifests, paths,
   transformations, archives, and signature states while asserting bounded
   memory and disk use. Accept with reproducible CI corpus handling.
7. **Add a stricter CDS profile.** Target a 1 MiB manifest, 64 KiB signature,
   32 MiB archive, 64 MiB expansion, 500 members, 5 MiB member, and 50:1
   compression ratio. Accept after compatibility testing with the target CDS.
