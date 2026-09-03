# Product and security boundary

## Status

ERP Security Evidence Workbench is an independent, vendor-neutral prerelease for deterministic
analysis of explicitly supplied synthetic evidence. It is a local command-line tool, not a hosted
service, production security product, live scanner, compliance assessment, or ERP integration.

The repository and examples contain only independently authored project material and fictional
data. The project is not affiliated with, endorsed by, or an official product of SAP SE, Oracle, or
another ERP vendor.

## Supported behavior

- `analyze` reads up to 32 explicitly supplied ordinary local `.csv`, `.json`, or `.jsonl`
  evidence files; `replay` reads one manifest plus 2–32 declared local source files.
- Accept only the fixed core/replay schemas documented in [REPLAY_CONTRACT.md](REPLAY_CONTRACT.md),
  each with `dataset_classification: synthetic`.
- Normalize six core evidence types (`principal`, `role_assignment`, `permission_assignment`,
  `auth_event`, `change_event`, and `control_state`) plus replay-only `observed_event` and
  `threat_indicator` records.
- Preserve the legacy single-object `erpsec.synthetic-control-state/v1` JSON compatibility path.
- Generate a deterministic full SHA-256 identifier from canonical semantic content when
  `record_id` is omitted, and reject duplicate identifiers across the input set.
- Fail the entire run on a parse, schema, coverage, duplicate, path, or resource-limit error.
- Anchor each input read to an opened parent-directory descriptor, refuse a final-component
  symbolic link, require a regular file, and compare identity and mutation-sensitive state around
  parsing.
- Evaluate a selected subset of six versioned ERP-neutral rules documented in [RULES.md](RULES.md).
- Replay two or more digest-pinned local synthetic sources through three additional fixed
  detection/correlation rules, using only allowlisted adapters and documentation-range IP data.
- Reject a run before report construction if accepted finding evidence exceeds 30,000 references.
- Render deterministic JSON, self-contained HTML, or SARIF 2.1.0 from the same engine-validated
  outcome.
- Publish one report to a new, distinct local output path without overwriting an existing name.
- Generate and replay the deterministic fictional corpus in `examples/scenarios/` as a
  development verification aid.

## Report boundary

`analyze` JSON is the canonical `erpsec.report/v1` representation; `replay` uses the additive
`erpsec.report/v2` correlation contract. HTML is static and self-contained, with
escaped dynamic values, one hash-authorized inline stylesheet, and no JavaScript or external
resources. SARIF contains relative percent-encoded source basenames and uses physical line locations
for CSV/JSONL where available; JSON retains its RFC 6901 pointer without an invented line or column.

Every format is derived from the same validated findings and evaluations. A renderer or publication
failure exits `2` and does not deliberately promote a partial report. Reports include bounded
provenance needed for review and must be treated as potentially sensitive. See
[REPORT_FORMATS.md](REPORT_FORMATS.md) and [PRIVACY_MODEL.md](PRIVACY_MODEL.md).

## Synthetic corpus boundary

The repository corpus contains three fictional investigation scenarios:

- a complete clean baseline evaluated against all six rules;
- access-governance evidence for `ERP002`–`ERP004`;
- authentication/control evidence for `ERP001`, `ERP005`, and `ERP006`.

Malformed-tail, incomplete-coverage, and adversarial-extra-field fixtures demonstrate fail-closed
behavior. All records, identifiers, timestamps, capabilities, and event sequences must be authored
from first principles for this repository. They must not be transformed from real or organizational
material.

The original corpus manifest and checksums remain development metadata. Separately,
`examples/replay/` contains one finding and one clean scenario for the installed `replay` command.
Replay manifests declare data paths and adapters only; they cannot contain or execute commands.
The runtime adds no dependency and does not connect to another system.

## Resource bounds

- Maximum 1 MiB and 1,000 parser records per input file.
- `analyze` accepts at most 32 evidence files; `replay` accepts one manifest plus 2–32 declared
  source files.
- Maximum 32 MiB across input bytes; replay counts its manifest and declared sources together.
- Maximum 5,000 normalized evidence records across one run.
- Maximum 64 KiB per JSONL line or CSV physical row, 4,096 characters per scalar, 32 fields per
  object, and JSON nesting depth 8.
- Maximum 30,000 accepted finding evidence references per run.
- Duplicate input paths and ambiguous source basenames are rejected.

These are rejection ceilings, not CPU, memory, throughput, latency, or service-level guarantees.

## Explicit non-goals

- Live SAP, Oracle, ERP, database, cloud, RFC, OData, CDS, or API connectivity.
- Runtime URL input, network discovery, outbound calls, telemetry, analytics, update checks, or
  remote schema retrieval.
- Online threat-intelligence feeds or claims that a synthetic documentation-range address is a
  real-world indicator.
- Credentials, secrets, tokens, cookies, accounts, or sessions.
- Exploitation, brute forcing, active scanning, subprocess integrations, or writeback.
- Automated remediation or a conclusion that a finding is a complete security or compliance
  decision.
- Vendor-specific schemas, transaction codes, authorization objects, role matrices, copied control
  text, or proprietary product terminology.
- Employer or customer code, data, prompts, documentation, screenshots, architecture, or rules.
- Real, anonymized, pseudonymized, redacted, sampled, or transformed organizational data.

## Filesystem assumptions

The implementation assumes local POSIX descriptor-relative, inode, hard-link, no-follow, and
sticky-bit behavior as exercised on macOS and Linux. The publisher rejects a group- or
world-writable non-sticky output parent, creates a temporary file no broader than mode `0600`,
forces exact `0600` before writing, synchronizes the file, creates the final name through an
exclusive hard link, and verifies the expected inode and parent binding.

These controls do not isolate root or another process with the same user identity. The containing
directory is not synchronized, so crash durability is not claimed. Cleanup is bounded best effort;
rare repeated cleanup failure can leave a mode-`0600` temporary or complete final name. See
[LIMITATIONS.md](LIMITATIONS.md) for the exact interruption and residual-file contract.

## Scope-change rule

A connector, vendor-specific schema, real or transformed data, network behavior, credential path,
runtime dependency, write action, or automated remediation changes the security boundary and
requires dedicated design, privacy, dependency, threat-model, and claim review before acceptance.
