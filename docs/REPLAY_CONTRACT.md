# Replay import and correlation contract

## Boundary

The `replay` command is an offline, input-read-only workflow for independently created fictional
evidence. It does not connect to a honeypot, SIEM, threat-intelligence feed, ERP, employer system,
customer system, or vendor API. It cannot collect events, enrich indicators online, block an
address, change a user, or remediate a finding.

Every accepted manifest and source record must declare `dataset_classification: synthetic`.
Honeypot and indicator addresses are limited to the IANA IPv4 documentation networks
`192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`, or IPv6 `2001:db8::/32`. This deliberately
prevents the bundled adapter from representing an arbitrary live address.

## Installed command

```console
erpsec replay REPLAY_MANIFEST.json \
  --as-of 2026-09-01T12:45:00Z \
  --rule all \
  --format json \
  --output NEW_REPORT.json
```

With no `--rule`, replay selects `ERP007`, `ERP008`, and `ERP009`. `--rule all` means the same replay
pack; it does not implicitly run the six v1 evidence rules. Individual replay rule IDs may be
repeated. Exit codes retain the `analyze` contract: `0` for no findings, `1` for findings, and `2`
for any usage, validation, completeness, rendering, or publication failure.

## Manifest schema

The manifest is a JSON array containing exactly one
`erpsec.synthetic-replay-manifest/v1` object:

```json
[
  {
    "dataset_classification": "synthetic",
    "replay_id": "scenario-detection-correlation",
    "schema_version": "erpsec.synthetic-replay-manifest/v1",
    "sources": [
      {
        "adapter": "erpsec.synthetic-honeypot/v1",
        "path": "honeypot-events.jsonl",
        "sha256": "<lowercase SHA-256>",
        "source_id": "source-honeypot"
      },
      {
        "adapter": "erpsec.synthetic-threat-intel/v1",
        "path": "threat-indicators.json",
        "sha256": "<lowercase SHA-256>",
        "source_id": "source-threat-intel"
      }
    ]
  }
]
```

The manifest must declare between two and 32 distinct sources. `source_id` and `path` values are
unique. Paths are basenames resolved beside the manifest; absolute paths, path separators, `.` and
`..` are rejected. Each source must be a distinct, non-symlink regular file whose bytes match the
declared digest. The existing bounded parser and aggregate byte/record ceilings apply. Any source
failure rejects the complete replay and no valid report is published. The 32 MiB aggregate byte
ceiling counts the manifest and every declared source; the 5,000-record ceiling counts normalized
evidence records from the declared sources.

## Allowlisted adapters

### `erpsec.synthetic-honeypot/v1`

Accepts a non-empty JSON array or one-record-per-line JSONL source with schema
`erpsec.synthetic-honeypot-event/v1` and the exact fields
`schema_version`, `dataset_classification`, `event_id`, `sensor_id`, `principal_id`,
`source_address`, `action`, `outcome`, and `occurred_at`. The v1 adapter accepts only the generic
`SIGN_IN` action and the explicit outcomes `success`, `failure`, or `denied`. It normalizes to the
vendor-neutral `observed_event` model.

### `erpsec.synthetic-threat-intel/v1`

Accepts a non-empty JSON array or one-record-per-line JSONL source with schema
`erpsec.synthetic-threat-indicator/v1` and the exact fields `schema_version`,
`dataset_classification`, `indicator_id`, `indicator_type`, `value`,
`valid_from`, `valid_until`, and `confidence`. Version 1 supports only documentation-range IP
indicators and the confidence literals `low`, `medium`, and `high`. Validity endpoints are
seconds-precision RFC 3339 timestamps. No URL or feed configuration exists.

### `erpsec.synthetic-evidence/v1`

Imports the existing canonical synthetic CSV, JSON, or JSONL evidence contract. This is how the
example replay supplies the generic `change_event` records used by `ERP009`; it is not a live ERP
connector.

## Determinism, deduplication, and time

All timestamps normalize to UTC seconds. Replay ignores supported event records after the explicit
`--as-of` time. Correlation windows use `closed_interval_inclusive`: records exactly at either
boundary qualify. Each episode records `start`, `end`, and `maximum_seconds` in the v2 report.

Each rule defines an opaque SHA-256 `dedupe_key` from its stable semantic grouping and retains the
earliest deterministic qualifying episode for that key. A `correlation_id` is another SHA-256 over
the rule identity, dedupe key, ordered record IDs, and explicit window endpoints. Source filenames,
source digests, and manifest ordering do not enter these identities. Correlation steps remain
ordered and carry source IDs, record identities, timestamps, explanations, and field-level evidence
references.

The hashes provide reproducible identity and deduplication only. They are not signatures,
authenticity proofs, or tamper-evident attestations.

## Report versioning

`analyze` continues to emit `erpsec.report/v1`. `replay` emits `erpsec.report/v2`. The v2 JSON
document adds `replay` and `correlations` top-level members and adds `correlation_id` to correlated
findings. HTML renders the same episodes as static tables. SARIF remains a valid 2.1.0 envelope and
places replay/correlation metadata in namespaced `properties`. The three projections originate from
the same re-evaluated in-memory result.
