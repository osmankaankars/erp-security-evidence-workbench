# Rule authoring contract

## Design rule

Rules are static, deterministic, vendor-neutral Python definitions over the canonical synthetic
evidence model. There is no dynamic plugin, expression evaluator, downloaded rule pack, arbitrary
query, or executable configuration. Adding or changing a rule is a source-code change with tests,
versioning, documentation, provenance, privacy, and claim review.

## Required definition

Each rule in `rules.py` must have:

- a unique stable identifier and semantic `rule_version`;
- a concise title, severity, description, and fixed human-review guidance;
- the minimum required canonical record types;
- explicit configurable `parameters` separated from non-configurable `fixed_conditions`;
- a deterministic evaluator selected by the static registry;
- findings with stable semantic fingerprints and exact field-level evidence references.

Identifiers must not be reused. Increment the rule version whenever accepted inputs, matching
semantics, evidence selection, severity, title, description, or guidance changes in a way visible
to a report consumer. A documentation-only clarification that does not change serialized behavior
may retain the version, but the distinction must be reviewed.

## Evaluator constraints

- Consume only `EvidenceBundle`, normalized UTC `as_of`, validated `RuleParameters`, and the
  corresponding `RuleDefinition`.
- Do not read files, inspect environment variables, use network/process APIs, mutate the bundle,
  depend on wall-clock time, or generate random values.
- Perform coverage preflight before evaluation and fail explicitly when minimum evidence is absent.
- Use canonical record IDs and `SourceRef` locators; do not retain or reflect arbitrary raw input.
- Define inclusive/exclusive time and threshold boundaries exactly.
- Canonicalize sets, pairs, joins, and output ordering before creating findings.
- Keep evidence relevant and bounded. The aggregate accepted evidence-reference ceiling remains a
  final fail-closed guard, not a target.
- Treat default thresholds and capability names as fictional test configuration, not standards,
  recommendations, or copied organizational policy.

## Test matrix for a rule change

At minimum, add red-first tests for:

1. catalog schema, metadata, registry order, and version;
2. sufficient clean evidence with no match;
3. one direct match with exact evidence links and fingerprint;
4. missing required record types and incomplete cross-record coverage;
5. exact threshold/time boundary behavior on both sides;
6. deterministic behavior under reordered input where the contract permits;
7. duplicate, malformed, unknown-field, and non-synthetic rejection as applicable;
8. finding fanout/resource limits;
9. JSON/HTML/SARIF parity and context-safe rendering;
10. installed-wheel CLI behavior and updated synthetic scenario expectations.

Run the complete project gate, not only the new evaluator tests. Update `docs/RULES.md`,
`docs/SYNTHETIC_DATA_POLICY.md`, `docs/PRODUCT_BOUNDARY.md`, `docs/THREAT_MODEL.md`,
`docs/PRIVACY_MODEL.md`, `docs/REPORT_FORMATS.md`, and `docs/CLAIM_EVIDENCE.md` when the
change affects them.

## Review questions

- Is every predicate expressible from existing canonical fields without hidden assumptions?
- Is its provenance independent and safe to publish?
- Could the title, severity, or guidance be mistaken for a compliance conclusion?
- Can an incomplete source silently appear clean?
- Are all joins, time comparisons, and evidence ordering deterministic?
- Could a valid input create unbounded findings or evidence references?
- Does the report provide enough synthetic evidence for human review without copying raw payloads?
