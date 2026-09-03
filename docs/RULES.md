# ERP-Neutral Rule Pack

## Status and boundary

This is the versioned `0.2.0rc1` rule contract. The rules operate only on supplied synthetic,
vendor-neutral evidence. They do not inspect a live system, reproduce a company or customer
methodology, establish compliance, or authorize automated remediation.

The engine applies a cumulative accepted finding-evidence-reference ceiling without changing rule
matching, versions, severity, fingerprints, or guidance. Release verification exercises the same
rule and report semantics across the supported Python matrix.

Rule versions identify evaluation semantics. A change to matching logic, evidence requirements,
default parameters, fingerprint inputs, severity, or fixed guidance requires a version review.

## Selection and coverage

- The compatibility CLI path evaluates only `ERP001` when no `--rule` option is supplied.
- On `analyze`, repeat `--rule` to select `ERP001`–`ERP006`; `--rule all` selects those six in ID
  order.
- On `replay`, no selection or `--rule all` selects `ERP007`–`ERP009`; individual replay IDs may
  also be selected.
- `all` cannot be combined with individual IDs, and duplicate selections are rejected.
- Every selected rule is preflighted before evaluation. If a required record type or required
  `AUDIT_LOGGING` control is absent, the run fails as incomplete and publishes no partial report.
- `coverage: complete` means that every selected rule received its minimum required synthetic
  record types and all supplied files were processed. It does not prove that a source system,
  identity inventory, or assignment population is complete.

## Evaluation resource guard

An accepted selected-rule run may contain at most 30,000 cumulative finding evidence references.
The engine adds a rule's complete evidence-reference count after that rule evaluator returns and
fails the run before report construction if the cumulative value exceeds the ceiling. Exact equality
is accepted. A limit failure publishes no valid final report.

This is an accepted-run and output-fanout guard, not a streaming allocation limit inside one rule
evaluator. It does not establish a hard process-memory, CPU, or wall-time ceiling and must not be
described as a performance or denial-of-service guarantee.

## Default parameters

Defaults are independently selected, fictional test configuration. They are not copied standards,
benchmarks, product defaults, compliance thresholds, or security recommendations.

- inactive threshold: `90` days before the explicit `--as-of` time;
- privileged permissions: `ADMINISTER_SYSTEM`, `APPROVE_PAYMENT`;
- toxic pair: `CREATE_VENDOR` plus `APPROVE_PAYMENT`;
- emergency access window: the closed interval from four hours before `--as-of` through `--as-of`;
- repeated-failure threshold: five failed `SIGN_IN` events within a closed 15-minute interval.

The Python `RuleParameters` contract permits vendor-neutral overrides. The machine-readable
catalog lists these values under `parameters`. Rule predicates that are deliberately not
configurable are listed separately under `fixed_conditions`: `control: AUDIT_LOGGING` and
`enabled: false` for `ERP001`; `enabled: true` for `ERP002`; `assignment_mode: direct` for
`ERP003`; `action: SIGN_IN`, `outcome: success`, and `principal_kind: emergency` for `ERP005`;
and `action: SIGN_IN` plus `outcome: failure` for `ERP006`. `ERP004` has no fixed literal filter
beyond its configured unordered pair and same-principal correlation. Parameter and record order
must not alter evaluation results.

Replay-rule literals are fixed conditions rather than live or standards-derived configuration:
three strictly earlier failures and an inclusive maximum of 600 seconds for `ERP007`; a
successful `SIGN_IN` inside an inclusive local
indicator-validity interval for `ERP008`; and successful `SIGN_IN`, a fixed
`DISABLE_AUDIT`/`GRANT_PRIVILEGE` action, and 1,800 seconds for `ERP009`.

## Registry

### ERP001 v1.0.0 — Required audit logging is disabled

- Required evidence: `control_state`, including `control: AUDIT_LOGGING`.
- Match: a supplied required audit-logging control is explicitly disabled.
- Severity: high, because disabled audit logging can materially reduce investigation and
  accountability evidence.
- Limitation: supplied synthetic control state cannot verify live-system logging coverage.
- Remediation: review the configuration and enable the required control through an authorized
  human change process.

### ERP002 v1.0.0 — Enabled privileged principal is inactive

- Required evidence: `principal`, `permission_assignment`.
- Match: an enabled principal has a configured privileged permission and `last_active_at` is
  strictly older than the configured cutoff. Exact cutoff equality does not match.
- Severity: high, because stale privileged access can increase unnecessary access and misuse risk.
- Limitation: only supplied principals, permissions, and activity timestamps are evaluated.
- Remediation: human reviewers should revalidate the access need and then disable or retain access
  through an authorized access-governance process.

### ERP003 v1.0.0 — Privileged permission is assigned directly

- Required evidence: `permission_assignment`.
- Match: a configured privileged permission has `assignment_mode: direct`.
- Severity: high, because direct privileged grants can bypass role-based governance and complicate
  access review.
- Limitation: justification, approval, and effective access are not inferred.
- Remediation: human reviewers should validate the exception and remove or replace the direct
  grant through an authorized role-governance process when appropriate.

### ERP004 v1.0.0 — Configured toxic permission pair is present

- Required evidence: `permission_assignment`.
- Match: the same principal has both capabilities in a configured unordered pair.
- Severity: high, because combined incompatible capabilities can weaken independent oversight.
- Limitation: the generic example pair is not a vendor role matrix or authoritative SoD policy.
- Remediation: human reviewers should separate or formally mitigate the capabilities through an
  authorized segregation-of-duties process.

### ERP005 v1.0.0 — Emergency access occurs outside the approved window

- Required evidence: `principal`, `auth_event`.
- Match: an emergency principal has a successful `SIGN_IN` event outside the configured closed
  window. Events exactly at either endpoint do not match.
- Severity: high, because out-of-window emergency access can indicate unreviewed privileged use.
- Limitation: business approval, ticket context, and live-session activity are not available.
- Remediation: human reviewers should investigate authorization and context, then document or
  contain the event through an approved emergency-access process.

### ERP006 v1.0.0 — Repeated authentication failures occur

- Required evidence: `auth_event`.
- Match: one principal has the configured number of failed `SIGN_IN` events within the configured
  closed interval. Only the earliest deterministic triggering window is reported per principal.
- Severity: medium, because a short failure burst can indicate credential misuse or an operational
  access problem but is not proof of an attack.
- Limitation: source network context, device context, and cause are not available.
- Remediation: human reviewers should validate the principal and event context, then follow the
  appropriate incident-response or access-support process.

### ERP007 v1.0.0 — Failed sign-ins are followed by a successful sign-in

- Required evidence: `observed_event` from the ERP-neutral synthetic honeypot adapter.
- Match: for one source ID, principal, and documentation-range address, three failed `SIGN_IN`
  events with strictly earlier timestamps are followed by a successful `SIGN_IN` within a
  600-second interval. Equality at the 600-second lower boundary matches; failures timestamped at
  exactly the same second as the success do not establish order and never match. The most recent
  three qualifying failures are retained, and only the earliest deterministic episode is emitted
  for the semantic dedupe key.
- Severity: high, because the pattern can justify prompt review but is not proof of compromise.
- Limitation: source identity, user intent, device context, and real-world completeness are not
  established by fictional records.
- Remediation: validate the principal and source context through an authorized incident-response
  or access-support process.

### ERP008 v1.0.0 — Successful sign-in matches a local synthetic threat indicator

- Required evidence: `observed_event`, `threat_indicator`.
- Match: a successful `SIGN_IN` address exactly equals a supplied local synthetic IP indicator and
  the event timestamp falls inside the indicator's closed validity interval.
- Severity: high, because the supplied association can prioritize review.
- Limitation: the engine performs no online lookup and never asserts that the documentation-range
  address is malicious in the real world.
- Remediation: validate the indicator provenance and event context before any authorized response.

### ERP009 v1.0.0 — Successful sign-in precedes a sensitive change

- Required evidence: `observed_event`, `change_event`.
- Match: a successful synthetic sign-in is followed strictly later by a successful `DISABLE_AUDIT`
  or `GRANT_PRIVILEGE` change for the same principal, at most 1,800 seconds after the sign-in. The
  nearest preceding qualifying sign-in is retained; same-second records do not establish causal
  order, and only the earliest deterministic episode per principal, action, and object is emitted.
- Severity: medium, because timing alone cannot determine authorization or intent.
- Limitation: the pattern is not an insider-threat verdict, policy violation, or compliance result.
- Remediation: compare both steps with the authorized change record and follow the documented human
  investigation process.

## Evidence and determinism

Every finding carries field-level source references for decisive fields present in normalized
records. Replay `source_id` is manifest-supplied source metadata rather than a source-record field;
it is exposed in the source manifest and correlation steps but is not represented as a field-level
record reference. The compatibility rule `ERP001` deliberately preserves its original
evidence-reference shape: the finding points to the `enabled` field, while its fixed
`AUDIT_LOGGING` condition is explicit in the rule catalog and the complete record provenance
remains present in the evidence manifest. Findings are ordered by rule ID and fingerprint;
evaluations follow registry order; evidence references are ordered by canonical record type,
record ID, and field. New fingerprints use stable rule identity, sorted record IDs, and only a
stable semantic key when needed. Source paths, digests, locators, and input ordering never enter a
finding fingerprint. `ERP001` retains its existing fingerprint bytes.

Replay findings additionally reference a stable correlation episode. Its opaque `dedupe_key` and
`correlation_id`, closed-window fields, ordered chain steps, and source identities are defined in
the [Replay contract](REPLAY_CONTRACT.md).

Remediation text is fixed, advisory, and human-review oriented. No rule changes input evidence,
accounts, permissions, controls, or another system.
