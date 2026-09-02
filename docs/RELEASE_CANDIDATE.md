# Release-candidate gate

## Candidate identity

- Distribution: `erp-security-evidence-workbench`
- Version: `0.1.0rc1`
- Intended tag: `v0.1.0rc1`
- Release type: GitHub prerelease
- License: MIT
- Runtime dependencies: none
- Runtime boundary: offline, local, synthetic-only, input-read-only, non-remediating
- Supported target: CPython 3.11–3.14 on the documented POSIX surface

The prerelease is an evaluation and portfolio artifact. It does not claim production readiness,
compliance coverage, live-system compatibility, or service-level guarantees. Publication to PyPI
or another package index is outside this release.

## Acceptance evidence

The tagged revision is acceptable only when every applicable item below is fresh and successful:

1. compilation, Ruff lint/format, strict mypy, and the complete pytest suite;
2. full tests and installed-package smoke on CPython 3.11, 3.12, 3.13, and 3.14;
3. deterministic synthetic-corpus and committed example-report checks;
4. two byte-identical wheel and source-distribution builds at the recorded epoch;
5. exact archive-member, path-safety, SPDX, checksum, and fail-closed resolved-`HEAD`
   tree/blob-bound source-snapshot checks;
6. clean index-disabled installation and CLI smoke from wheel and source distribution;
7. deterministic large synthetic JSONL generation and an environment-qualified local observation;
8. secret, local-path, symlink, provenance, dependency, privacy, and claims review;
9. focused code/security, packaging/supply-chain, and documentation review;
10. a successful GitHub Actions matrix for the exact release revision.

A generated artifact is not accepted merely because a build command exits successfully. Any failed
or unavailable item must be disclosed in the release notes.

## Artifact set

The GitHub prerelease may include:

- wheel and source distribution;
- deterministic `build-manifest.json`;
- deterministic `source-snapshot.json`;
- SPDX 2.3 JSON dependency inventory;
- sorted `SHA256SUMS`.

Checksums provide byte-integrity evidence, not authorship, confidentiality, vulnerability clearance,
or legal approval. The SPDX document records declared package metadata rather than a resolved,
platform-specific vulnerability inventory.

## Release limits

- The tag may be annotated but is not represented as cryptographically signed unless a verifiable
  signature is present.
- Direct development requirements are pinned, but transitive tools are not hash-locked for every
  platform.
- GitHub Actions and local matrix results qualify only the environments actually exercised.
- The release must remain marked as a prerelease and must not be labeled “latest.”
- Release notes must preserve the synthetic-only, offline, input-read-only boundary and vendor
  independence.
