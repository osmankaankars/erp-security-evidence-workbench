# ERP Security Evidence Workbench

[![CI](https://github.com/osmankaankars/erp-security-evidence-workbench/actions/workflows/ci.yml/badge.svg)](https://github.com/osmankaankars/erp-security-evidence-workbench/actions/workflows/ci.yml)
[![Python 3.11–3.14](https://img.shields.io/badge/Python-3.11%E2%80%933.14-3776AB.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

ERP Security Evidence Workbench is an independent Python CLI for deterministic analysis of
synthetic, ERP-neutral security evidence. It reads explicit local CSV, JSON, and JSONL files,
evaluates a fixed versioned rule pack, and produces JSON, self-contained HTML, or SARIF 2.1.0
reports.

`0.1.0rc1` is a prerelease intended for evaluation and portfolio demonstration with the included
fictional data. It is not a production service, compliance product, live scanner, or ERP connector.

## Highlights

- Offline and file-only application runtime, with no third-party runtime dependencies.
- Strict synthetic-evidence schema with transactional, fail-closed multi-file validation.
- Six deterministic rules covering audit logging, inactive privileged access, direct privileged
  grants, a configurable generic segregation-of-duties pair, emergency access timing, and repeated
  sign-in failures.
- Stable findings, fingerprints, evaluation order, and field-level evidence references.
- Canonical JSON, static HTML, and SARIF 2.1.0 projections from the same validated result.
- Descriptor-anchored POSIX reads and exclusive, no-overwrite report publication with mode `0600`.
- Deterministic fictional scenarios, example reports, package checks, SBOM generation, and exact
  release-artifact policies.

## Safety boundary

Use only independently created, non-secret synthetic evidence. The CLI does not connect to SAP,
Oracle, another ERP, a database, a cloud service, or any live system. It does not collect
credentials, discover assets, scan networks, modify accounts or configuration, or perform
remediation.

The rules and defaults are fictional project test configuration. A clean report means only that
the selected rules did not match the supplied files; it does not establish source completeness,
security, regulatory compliance, or absence of risk. See [Product boundary](docs/PRODUCT_BOUNDARY.md)
and [Limitations](docs/LIMITATIONS.md).

This project is independent and is not affiliated with, endorsed by, or an official product of SAP
SE or any other ERP vendor.

## Quick start

Prerequisites: a POSIX environment (macOS or Linux) and Python 3.11–3.14.

```bash
git clone https://github.com/osmankaankars/erp-security-evidence-workbench.git
cd erp-security-evidence-workbench

python3.11 -m venv .venv
.venv/bin/python -m pip install .
```

List the deterministic rule catalog:

```bash
.venv/bin/erpsec rules
```

Analyze the included synthetic example with the default compatibility rule (`ERP001`):

```bash
.venv/bin/erpsec analyze \
  examples/audit-logging-disabled.json \
  --as-of 2026-09-01T00:00:00Z \
  --format json \
  --output /tmp/erpsec-report.json
```

Evaluate all six rules and create a self-contained HTML report:

```bash
.venv/bin/erpsec analyze \
  examples/rule-pack-findings.json \
  --as-of 2026-09-01T00:00:00Z \
  --rule all \
  --format html \
  --output /tmp/erpsec-rule-pack-report.html
```

The output path must not already exist and must be distinct from every input path. Select individual
rules by repeating `--rule`, for example `--rule ERP002 --rule ERP004`.

Exit codes:

- `0`: complete evaluation with no findings;
- `1`: complete evaluation with one or more findings;
- `2`: usage, validation, coverage, read, rendering, or publication failure.

## Evidence and reports

New records use schema `erpsec.synthetic-evidence/v1` and one of six record types: `principal`,
`role_assignment`, `permission_assignment`, `auth_event`, `change_event`, or `control_state`. The
legacy single-object `erpsec.synthetic-control-state/v1` JSON form remains available for the
single-control workflow.

The frozen input ceilings are 32 files, 1 MiB and 1,000 records per file, 32 MiB of source bytes and
5,000 records per run, 64 KiB per JSONL line or CSV physical row, and 30,000 accepted finding
evidence references per run. These are rejection limits, not performance guarantees.

All report formats describe the same engine-validated outcome:

- JSON is the canonical `erpsec.report/v1` document.
- HTML is escaped, static, self-contained, and has no JavaScript or external resources.
- SARIF targets 2.1.0 and preserves rule identity, native severity, fingerprints, and available
  source locations.

Reports intentionally retain limited provenance such as basenames, record IDs, locators, and
digests. Treat every report as potentially sensitive even when its inputs are synthetic. Details
are in [Report formats](docs/REPORT_FORMATS.md) and the [Privacy model](docs/PRIVACY_MODEL.md).

## Synthetic scenarios

The repository includes deterministic fictional scenarios for a clean baseline, access governance,
and authentication/control investigation. Validate and replay them without rewriting the committed
corpus:

```bash
PYTHONPATH=src python3.11 scripts/synthetic_corpus.py check \
  --corpus examples/scenarios

PYTHONPATH=src python3.11 scripts/synthetic_corpus.py replay \
  --manifest examples/scenarios/manifest.json
```

See [Synthetic scenario corpus](examples/scenarios/README.md) and the
[Synthetic data policy](docs/SYNTHETIC_DATA_POLICY.md).

## Development

Install the exact development tool versions and run the complete local gate:

```bash
make bootstrap
make check
```

`make check` compiles the codebase, runs Ruff lint and format checks, performs strict mypy checking,
runs the complete pytest suite, and exercises a clean installed-wheel smoke test. Development setup
may access the configured Python package index; the installed application runtime remains offline.

For release reproducibility and artifact inspection, see [Reproducibility](docs/REPRODUCIBILITY.md),
[Release candidate](docs/RELEASE_CANDIDATE.md), and [Release artifacts](release/README.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Rules and exact semantics](docs/RULES.md)
- [Rule authoring contract](docs/RULE_AUTHORING.md)
- [Product boundary](docs/PRODUCT_BOUNDARY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Privacy model](docs/PRIVACY_MODEL.md)
- [Limitations](docs/LIMITATIONS.md)
- [Claim-to-evidence map](docs/CLAIM_EVIDENCE.md)
- [Dependency and CI review](docs/DEPENDENCY_REVIEW.md)

## Contributing and security

Contributions that preserve the synthetic-only, offline, read-only boundary are welcome. Read
[CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md) before opening a
pull request. Report security concerns privately as described in [SECURITY.md](SECURITY.md).

## License

Licensed under the [MIT License](LICENSE). Copyright © 2026 Osman Kaan Kars.
