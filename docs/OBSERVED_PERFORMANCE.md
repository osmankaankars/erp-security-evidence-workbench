# Observed local performance

## Status and claims boundary

This is a development measurement record for one deterministic synthetic scenario. It is not a
product command, security benchmark, capacity rating, production workload, SLA, or claim about
another machine, Python build, dataset, filesystem, or level of concurrency. The scenario does not
model real ERP data or prove detection coverage.

`scripts/observed_performance.py` keeps input generation, verification, and measurement outside the
runtime CLI. It never raises the product's ingestion or finding-evidence limits. The generated
900-row JSONL input is temporary unless an operator explicitly chooses a new output path; no
900-row fixture is stored in the repository.

## Frozen scenario

The reviewed contract is `benchmarks/observed-performance-v1.json`:

- scenario `large-balanced-jsonl-v1`;
- `900` records and `247744` ASCII JSONL bytes;
- maximum physical line length `298` bytes;
- SHA-256 `405baf54be60287df31db2c7823b08280373499ab0b9bfce1dc94d38130e10d2`;
- fixed analysis time `2026-09-01T00:00:00Z` and all six rules selected;
- 150 principals, 150 role assignments, 150 permission assignments, 200 authentication events,
  200 change events, and 50 control states;
- exactly one frozen finding for each of `ERP001` through `ERP006` and 38 total evidence
  references (`1`, `5`, `2`, `4`, `6`, and `20`, respectively).

Every record declares `dataset_classification: synthetic`. Identifiers, capabilities, and
timestamps are deterministic, generic, and generated from first principles. The input is below the
existing per-source ceilings of 1 MiB, 1,000 records, and 64 KiB per JSONL line. Those ceilings are
denial-of-service bounds, not performance guarantees.

## Development CLI

Run these commands from a development checkout whose Python environment can import the project.
Use the fixed generic input basename when comparing report hashes across observations, because
reports intentionally retain the source basename as provenance.

```bash
ERPSEC_OBSERVATION_DIR="$(mktemp -d)"

python3.11 scripts/observed_performance.py generate \
  --output "${ERPSEC_OBSERVATION_DIR}/large-balanced-jsonl-v1.jsonl"

python3.11 scripts/observed_performance.py check \
  --input "${ERPSEC_OBSERVATION_DIR}/large-balanced-jsonl-v1.jsonl"

python3.11 scripts/observed_performance.py measure \
  --python /path/to/environment/bin/python \
  --input "${ERPSEC_OBSERVATION_DIR}/large-balanced-jsonl-v1.jsonl" \
  --output "${ERPSEC_OBSERVATION_DIR}/measurement.json"
```

`generate` and `measure` require a new output path, create it at exact mode `0600`, complete direct
writes, and file-synchronize it. They never overwrite. `check` is read-only. Successful commands
exit `0`; an input/check mismatch or incomplete measurement exits `1`; invalid arguments,
environment, or output state exit `2`. Diagnostics are fixed categories and do not echo supplied
paths.

The default measurement is three warm-up runs followed by 20 recorded runs per format. `--warmups`
accepts `0` through `5`; `--samples` accepts `1` through `30`. These bounds prevent an accidental
unbounded local run and do not define supported product load.

## Method

For each of `json`, `html`, and `sarif`, the harness:

1. verifies the exact input bytes, manifest digest, record counts, evaluations, finding
   fingerprints, and evidence-reference counts;
2. starts a fresh target-interpreter process with Python isolated mode and bytecode writes disabled;
3. invokes `analyze` with the fixed analysis time, explicit format, and `--rule all`;
4. requires finding exit code `1`, an exact-`0600` report no larger than 16 MiB, and the frozen
   semantics in that format;
5. requires every warm-up and sample for one format to have identical report bytes and SHA-256;
6. records the parent-observed end-to-end wall time, child user/system CPU, absolute peak RSS,
   report bytes, report digest, and CLI exit code;
7. reports min, max, median, and nearest-rank p95 over measured samples; warm-ups are excluded.

Wall time includes interpreter startup, package import, input handling, all six rule evaluations,
rendering, restricted report publication, wrapper metric serialization, and process exit. Child
CPU is sampled immediately after the CLI returns. It is not wall time and must not be added to it.

`ru_maxrss` is an absolute process peak, not an incremental allocation measurement. The JSON keeps
both the raw value and normalized MiB. Raw units are bytes on Darwin and KiB on Linux; unsupported
platforms fail rather than guessing. Python allocations, kernel cache, shared-library accounting,
filesystem cache, and child startup baseline are not separated.

The environment allowlist contains only logical CPU count, architecture, operating-system name and
release, Python implementation/version, tool version, and raw RSS unit. The harness does not emit a
hostname, username, home directory, executable/input/output path, full environment, hardware serial,
or network identifier.

## Failure-atomic behavior

One timeout, nonzero wrapper exit, unexpected stdout/stderr, missing or oversized report, permission
error, target semantic drift, environment drift, output digest drift, malformed metrics, or input
drift invalidates the whole observation. A child has a fixed 60-second timeout. No final measurement
JSON is written until all formats and samples pass. The final JSON itself is capped at 1 MiB and
published only to a new path.

Temporary child reports live in a private temporary directory and are removed when the run leaves
that context. Process interruption or operating-system cleanup failure can still leave temporary
filesystem state; this development harness is not a sandbox, secure-erasure mechanism, or
crash-durability system.

## One local observation

The following local observation was recorded on 2026-09-02 with the default 3 warm-ups and 20
fresh-process samples per format. The target was the exact
`erp_security_evidence_workbench-0.1.0rc1-py3-none-any.whl` release-candidate artifact, installed
into a newly created temporary virtual environment with `--no-index --no-deps`. The wheel SHA-256
was `36a6af496b48829d8216b49cb6b5367e0ed295e8aa9784eb046c9fcd9ef23383`, and the harness recorded
tool version `0.1.0rc1`. Environment: CPython `3.11.14`, Darwin `24.6.0`, `arm64`, eight logical
CPUs. Host and user identifiers were intentionally not recorded.

| Format | Median / p95 wall | Median / p95 user CPU | Median / p95 system CPU | Median / p95 absolute peak RSS | Output bytes | Output SHA-256 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| JSON | 104.530 / 116.681 ms | 82.320 / 86.001 ms | 12.117 / 13.844 ms | 22.547 / 22.906 MiB | 329204 | `b035fb9972b0c782e6d5c3d89f9157248f8b7bbd32f68f890f1d55b3994a6bbd` |
| HTML | 98.897 / 102.266 ms | 76.122 / 79.531 ms | 11.424 / 12.486 ms | 21.094 / 21.359 MiB | 31532 | `9aa5fa00b311ef93a0872dbca6230e9f55d2fb4ac40bc8fb0bc28bbff5d10510` |
| SARIF | 96.489 / 101.827 ms | 75.950 / 78.739 ms | 10.762 / 11.361 ms | 21.117 / 21.312 MiB | 52330 | `2766ce56e2952357bba810b3066b6e27adad8ad0888ed7ff88a671ea9ff0920d` |

The median raw peak-RSS observations were 23,642,112 bytes for JSON, 22,118,400 bytes for HTML, and
22,142,976 bytes for SARIF. The machine was not CPU-pinned; processor frequency, background load,
power mode, thermal state, and cold/warm filesystem cache were not controlled. The numbers are
useful only as a reproducible record of this one local release-candidate run. They do not support a
performance guarantee or extrapolation to another workload, and a different final artifact requires
a new observation.
