# Changelog

All notable project changes are documented in this file.

## 0.2.0rc1 — 2026-09-03

Second prerelease candidate.

### Added

- Installed, deterministic `replay` command for digest-pinned synthetic multi-source manifests.
- ERP-neutral synthetic honeypot and local-only synthetic IP-indicator adapters, restricted to
  documentation address ranges.
- `ERP007`–`ERP009`, with explicit inclusive windows, stable correlation IDs, opaque dedupe keys,
  ordered evidence chains, and fixed human-review guidance.
- Additive `erpsec.report/v2` correlation contract across JSON, static HTML, and SARIF 2.1.0.
- Finding and clean replay scenarios with committed deterministic reports and checksums.

### Changed

- Kept `analyze` and its `erpsec.report/v1` contract intact while publishing the expanded nine-rule
  machine-readable catalog.
- Updated exact development pins to `mypy==2.3.1` and `pytest==9.1.1`, synchronized the reviewed
  release-policy metadata, and moved pytest beyond the GHSA-6w46-j5rx-g56g / CVE-2025-71176
  affected range. This candidate supersedes the two stale version-only Dependabot proposals.
- Expanded installed-wheel smoke coverage to execute replay under the runtime network/process
  denial hook.
- Defined ERP007 ordering by timestamps alone: qualifying failures must be strictly earlier than
  the success, so equal-second record identifiers cannot create or suppress a correlation.
- Aligned replay-type, provenance, CodeQL-permission, and packaged documentation claims with their
  implemented boundaries.

### Security and scope notes

- Replay remains offline, input-read-only, vendor-neutral, and synthetic-only; it accepts no URL,
  command, credential, live connector, or write-back configuration.
- Source SHA-256 values are mismatch checks, not signatures or authenticity proofs.

## 0.1.0rc1 — 2026-09-02

First prerelease candidate.

### Added

- Strict, transactional ingestion of independently authored synthetic CSV, JSON, and JSONL
  evidence.
- Six versioned, ERP-neutral rules with deterministic evaluations, findings, fingerprints, and
  field-level evidence references.
- Canonical JSON, self-contained HTML, and SARIF 2.1.0 report projections.
- Descriptor-anchored POSIX input handling and exclusive, no-overwrite report publication.
- Deterministic fictional scenarios, checked example reports, release-artifact inspection, SPDX
  generation, checksums, and an observed local performance harness.
- A macOS/Linux GitHub Actions matrix for CPython 3.11–3.14.
- MIT licensing, security reporting guidance, and contributor templates.

### Security and scope notes

- The application declares no third-party runtime dependencies.
- Inputs are restricted to the documented synthetic schema.
- Live ERP connectivity, credential handling, remediation, network scanning, and compliance claims
  remain outside the project boundary.
- This is a prerelease; no production-readiness or service-level claim is made.
