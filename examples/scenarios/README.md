# Synthetic scenario corpus

## Purpose

This corpus demonstrates deterministic, evidence-linked analysis across explicit CSV, JSON, and
JSONL files without a live ERP connection. Every record is fictional and created from first
principles for this repository. Nothing may be anonymized, redacted, sampled, transformed, or
otherwise derived from employer, customer, production, test-tenant, training, or support data.

The scenarios use the current evidence schema, rule definitions, resource limits, report contract,
and explicit analysis time `2026-09-01T00:00:00Z`.

## Primary scenarios

| Scenario | Managed inputs | Selected rules | Expected records | Expected result |
| --- | --- | --- | ---: | --- |
| `clean-baseline` | `clean-principals.csv`, `clean-permissions.jsonl`, `clean-events-controls.json` | `ERP001`–`ERP006` | 4 | Six `not_matched` evaluations; no findings; exit `0` |
| `access-governance` | `access-principals.csv`, `access-permissions.jsonl` | `ERP002`, `ERP003`, `ERP004` | 9 | One finding per selected rule; exact-cutoff negative remains clean; exit `1` |
| `authentication-control` | `auth-principals.csv`, `auth-events.jsonl`, `auth-control.json` | `ERP001`, `ERP005`, `ERP006` | 17 | One finding per selected rule; boundary negatives remain clean; exit `1` |

`manifest.json` is the machine-readable authority for record identifiers, source locators,
evaluation order and status, finding fingerprints, evidence links, output presence, and exit codes.

## Fail-closed validation cases

| Case | Purpose | Expected result |
| --- | --- | --- |
| `malformed-tail` | Valid JSONL prefix followed by a malformed final record | Exit `2`; no report |
| `incomplete-principal` | Valid input without required selected-rule evidence | Exit `2`; no report or false-clean result |
| `adversarial-extra-field` | Rejected extra field containing a fictional hostile marker | Exit `2`; no report; marker absent from the diagnostic |

The evidence schema does not retain arbitrary free text. These cases verify strict rejection and
diagnostic non-disclosure. Accepted report content is separately checked for context-safe HTML and
structured SARIF output.

## Determinism and checksums

`manifest.json`, `SHA256SUMS`, and every managed fixture are generated from an independently
authored in-repository specification. Expected outcomes are explicit reviewed constants rather than
values derived by asking the evaluator to grade its own fixtures.

`SHA256SUMS` contains sorted lowercase SHA-256 entries in the form
`<64 hexadecimal characters><two spaces><POSIX relative path><LF>`. It covers the generated
manifest and fixtures, excludes itself to avoid self-reference, and excludes this hand-authored
README.

Regeneration reconstructs the managed set and compares it byte-for-byte without rewriting the
committed corpus. Replay writes reports only to temporary storage.

## Local development commands

Generate a preview into a new or empty destination:

```bash
PYTHONPATH=src python3.11 scripts/synthetic_corpus.py \
  generate --output /tmp/erpsec-synthetic-corpus-preview
```

Check deterministic regeneration:

```bash
PYTHONPATH=src python3.11 scripts/synthetic_corpus.py \
  check --corpus examples/scenarios
```

Verify checksums and replay each primary and validation case:

```bash
PYTHONPATH=src python3.11 scripts/synthetic_corpus.py \
  replay --manifest examples/scenarios/manifest.json
```

The helper exits `0` for a verified corpus, `1` for a checksum or behavior mismatch, and `2`
for invalid usage or an invalid manifest. Per-scenario expectations retain the application CLI's
`0` clean, `1` findings, and `2` failure meanings.

## Safety and claim boundary

- Replay is local, offline, file-only, and input-read-only.
- The manifest is declarative and cannot supply arbitrary commands.
- No connector, credential path, active scan, writeback, subprocess integration, or remediation is
  part of the corpus.
- Generic thresholds and capabilities are fictional test configuration, not standards, benchmarks,
  company policy, vendor role matrices, or compliance requirements.
- A clean scenario proves only the documented rule behavior over the supplied synthetic records; it
  does not prove source-system completeness, compliance, or absence of risk.
- This prerelease corpus is suitable for tests and demonstration, not production or customer data.
