# Architecture

## Purpose and boundary

ERP Security Evidence Workbench is an offline, local command-line prerelease for
deterministic analysis of supplied synthetic ERP-neutral security evidence. It does not connect to
an ERP system, discover assets, collect credentials, modify a source, remediate a finding, or prove
compliance.

```text
explicit local paths + options
            |
            v
CLI validation and alias checks
            |
            v
descriptor-anchored bounded adapters
  CSV / JSON / JSONL -> located payloads
            |
            v
strict normalization -> immutable canonical records
            |
            v
transactional multi-source evidence bundle
            |
            v
coverage preflight -> fixed rule registry -> bounded findings
            |
            v
engine-coherent report document
       /          |          \
 canonical JSON  static HTML  SARIF 2.1.0
       \          |          /
        exclusive mode-0600 publication
```

## Components

### Command surface

`cli.py` defines two commands: `rules`, which emits the deterministic catalog, and `analyze`, which
requires explicit input paths, analysis time, output format, and a new output path. It maps clean,
finding, and failure states to exit codes `0`, `1`, and `2`. Argument and operational diagnostics
are deliberately generic.

### Input adapters and normalization

`adapters.py` performs bounded CSV, JSON, and JSONL parsing through descriptor-relative POSIX file
operations. It refuses a final-component symlink or non-regular file and compares source identity
and state at defined checkpoints. `normalization.py` accepts only the fixed schema and produces one
of six canonical record types from `models.py`; unknown fields and non-synthetic classifications
fail closed.

`ingest.py` composes all explicit sources transactionally. Any malformed record, duplicate ID,
missing required field, incomplete selected-rule coverage, or exceeded resource ceiling rejects
the complete run. Arbitrary source payload objects are not retained after normalization.

### Rule engine

`rules.py` contains a static, ordered registry of six versioned rules. Coverage is checked before
evaluation. Evaluators consume only the canonical evidence bundle, a normalized UTC analysis time,
and validated `RuleParameters`. Results use stable ordering, full SHA-256 semantic identifiers, and
exact evidence references. The accepted finding-evidence fanout is capped before report creation.

There is no dynamic rule loading or executable configuration. Rule changes follow
`docs/RULE_AUTHORING.md`.

### Report projections

`reporting.py` reconstructs and validates rule outcomes before producing a canonical report
document. JSON serializes that document directly; `html_report.py` renders an escaped, static,
self-contained investigation view; `sarif_report.py` creates the structured SARIF projection.
Each format describes the same selected rules, evaluations, findings, fingerprints, severities,
and evidence semantics, subject to its documented privacy minimization.

The publisher writes complete bytes to a mode-`0600` temporary inode, synchronizes the file, creates a
new final name exclusively, verifies it, and performs bounded cleanup. It never intentionally
replaces an existing report.

### Development and release evidence

Scripts under `scripts/` generate or check only deterministic synthetic fixtures, installed-package
smoke behavior, example reports, release artifacts, and observed local performance evidence. They
are development tooling, not installed product commands. Runtime dependencies are empty.

The release source-snapshot path resolves one committed Git `HEAD`, rejects staged or unstaged
tracked changes and non-ordinary index flags, and reads its file set and bytes exclusively from
regular-file tree and blob objects. It rechecks repository state and the resolved revision before
writing the manifest. There is no working-tree, untracked-file, or non-Git fallback.

## Trust boundaries

1. Untrusted argument strings cross into CLI validation.
2. Untrusted local namespace entries and bytes cross descriptor and parser checks.
3. Located payloads cross strict schema normalization into canonical records.
4. Canonical records cross coverage and resource gates into rule evaluation.
5. Validated in-memory report bytes cross the local filesystem publication boundary.
6. Build, development dependencies, and hosted CI remain a separate supply-chain boundary.
7. The local Git executable and object database are trusted release inputs for source snapshots;
   the resulting manifest is integrity evidence, not a signed attestation.

The detailed attacker model and filesystem assumptions are in `docs/THREAT_MODEL.md`.

## Determinism

For identical accepted input bytes, input order, selected rules, validated parameters, analysis
time, and format, the engine and serializers produce identical bytes. Determinism is enforced with
canonical timestamps, stable registry and record ordering, canonical JSON, versioned rule
definitions, and sorted generated manifests. It does not imply source completeness, correctness of
operator-supplied facts, or cryptographic authenticity.
