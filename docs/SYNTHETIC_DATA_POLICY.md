# Synthetic data policy

## Definition

Every accepted example and fixture must be fictional and created from first principles specifically
for this project. Synthetic does not mean anonymized, pseudonymized, redacted, sampled,
transformed, or otherwise disguised real data.

The `dataset_classification: synthetic` value is a required contract marker, not a content
classifier. The tool cannot prove that an operator labeled a file correctly.

## Requirements

- Every input record must declare `dataset_classification` as `synthetic`.
- Current records use `erpsec.synthetic-evidence/v1`; the only legacy exception is the preserved
  single-object `erpsec.synthetic-control-state/v1` JSON compatibility path.
- Records are limited to `principal`, `role_assignment`, `permission_assignment`,
  `auth_event`, `change_event`, and `control_state`.
- Names, identifiers, timestamps, controls, capabilities, thresholds, and scenarios must be
  fictional and generic.
- Project defaults are test configuration, not copied standards, benchmarks, company policy, or
  recommended security baselines.
- Fixtures must not be derived from employer, customer, production, test-tenant, training, or
  support data.
- Fixtures must not contain vendor transaction codes, authorization objects, screenshots, logos,
  credentials, secrets, real hostnames, account names, or realistic organizational identifiers.
- Fixture provenance must identify the authoring method and intended test behavior.
- Unknown or non-synthetic classification is rejected rather than silently accepted.
- Adapters retain only validated canonical fields and minimized source provenance. Unknown fields
  and arbitrary payload data are rejected.
- An invalid record, malformed trailing JSONL line, duplicate record ID, or exceeded resource
  ceiling invalidates the complete multi-file ingest.

## Generated-corpus contract

The committed corpus demonstrates three scenarios: a complete clean baseline, access-governance
findings, and authentication/control findings across multiple explicit local files.

- Every fixture is produced from an independently authored deterministic in-repository
  specification.
- Expected outcomes are explicit reviewed constants; the generator does not ask the evaluator to
  grade its own fixtures.
- Manifest entries record path, format, byte count, record count where parseable, SHA-256,
  first-principles origin, and intended test behavior.
- Scenario entries record the analysis time, selected rules, normalized record expectations,
  evaluations, findings, evidence links, output presence, and exit code.
- `SHA256SUMS` contains sorted lowercase SHA-256 entries for the generated manifest and fixture
  files. It excludes itself and the hand-authored scenario README.
- Regeneration is compared byte-for-byte without rewriting the committed corpus.
- Replay writes reports only to temporary storage. It is a development check, not an installed
  command, connector, source adapter, or separate evidence/report schema.
- Malformed, incomplete, and adversarial-string fixtures must fail closed with exit code `2`,
  publish no report, and avoid reflecting hostile payloads in diagnostics.
- Accepted text rendered in HTML is context escaped; SARIF is emitted as structured JSON with the
  documented minimized provenance.

## Ingestion limits

Synthetic-only operation remains offline and input-read-only. Inputs are limited to 32 explicit
local files, 1 MiB and 1,000 records per file, 32 MiB of source bytes and 5,000 records per run, and
64 KiB per JSONL line or CSV physical row. Scalars, object fields, JSON depth, and accepted finding
evidence references are also bounded.

## Review rule

Reject any fixture whose origin or publication rights are unclear. Openly licensed datasets and
real, transformed, anonymized, or organizational data are outside this project's accepted evidence
boundary and require a separate design, provenance, privacy, and legal review before the boundary
could change.
