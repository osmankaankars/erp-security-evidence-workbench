"""Deterministic, vendor-neutral rules over canonical synthetic evidence."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from erp_security_evidence_workbench.errors import (
    IncompleteEvidenceError,
    InputValidationError,
)
from erp_security_evidence_workbench.models import (
    AuthEvent,
    CanonicalRecord,
    ChangeEvent,
    ControlState,
    CorrelationEpisode,
    CorrelationStep,
    EvidenceBundle,
    Finding,
    FindingEvidence,
    ObservedEvent,
    PermissionAssignment,
    Principal,
    RuleEvaluation,
    ThreatIndicator,
)
from erp_security_evidence_workbench.timestamps import normalize_rfc3339_seconds

# Compatibility exports retained for callers of the initial rule API.
RULE_ID = "ERP001"
RULE_VERSION = "1.0.0"

RULE_CATALOG_SCHEMA_VERSION = "erpsec.rule-catalog/v1"
_CAPABILITY_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_MAX_CONFIGURED_CAPABILITIES = 64
_MAX_AUTH_FAILURE_THRESHOLD = 5_000
MAX_FINDING_EVIDENCE_REFS = 30_000

ParameterDefault = bool | int | str | tuple[str, ...] | tuple[tuple[str, str], ...]


def _require_positive_int(value: int, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _require_capability(value: object) -> None:
    if type(value) is not str or _CAPABILITY_PATTERN.fullmatch(value) is None:
        raise ValueError("configured capability is invalid")


def _canonical_capabilities(values: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ValueError("configured capabilities must be a tuple")
    if len(values) > _MAX_CONFIGURED_CAPABILITIES:
        raise ValueError("too many configured capabilities")
    for value in values:
        _require_capability(value)
    return tuple(sorted(set(values)))


@dataclass(frozen=True, slots=True)
class RuleParameter:
    """One documented configurable value or fixed literal in the rule catalog."""

    name: str
    default: ParameterDefault
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "default": self.default,
            "description": self.description,
            "name": self.name,
        }


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """Stable metadata and fixed human-review guidance for one rule."""

    rule_id: str
    rule_version: str
    title: str
    severity: str
    severity_rationale: str
    required_evidence_types: tuple[str, ...]
    parameters: tuple[RuleParameter, ...]
    limitation: str
    remediation: str
    fixed_conditions: tuple[RuleParameter, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixed_conditions": [condition.to_dict() for condition in self.fixed_conditions],
            "limitation": self.limitation,
            "parameters": [parameter.to_dict() for parameter in self.parameters],
            "remediation": self.remediation,
            "required_evidence_types": list(self.required_evidence_types),
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "severity": self.severity,
            "severity_rationale": self.severity_rationale,
            "title": self.title,
        }


@dataclass(frozen=True, slots=True)
class RuleParameters:
    """Vendor-neutral evaluation parameters with deterministic tuple semantics."""

    inactive_days: int = 90
    privileged_permissions: tuple[str, ...] = (
        "ADMINISTER_SYSTEM",
        "APPROVE_PAYMENT",
    )
    toxic_permission_pairs: tuple[tuple[str, str], ...] = (("CREATE_VENDOR", "APPROVE_PAYMENT"),)
    emergency_window_hours: int = 4
    auth_failure_threshold: int = 5
    auth_failure_window_minutes: int = 15

    def __post_init__(self) -> None:
        _require_positive_int(self.inactive_days, "inactive day threshold")
        _require_positive_int(self.emergency_window_hours, "emergency window")
        _require_positive_int(self.auth_failure_window_minutes, "authentication window")
        _require_positive_int(self.auth_failure_threshold, "authentication failure threshold")
        if self.auth_failure_threshold > _MAX_AUTH_FAILURE_THRESHOLD:
            raise ValueError("authentication failure threshold exceeds the record limit")

        privileged = _canonical_capabilities(self.privileged_permissions)
        if not privileged:
            raise ValueError("at least one privileged permission is required")
        object.__setattr__(self, "privileged_permissions", privileged)

        if not isinstance(self.toxic_permission_pairs, tuple):
            raise ValueError("toxic permission pairs must be a tuple")
        if len(self.toxic_permission_pairs) > _MAX_CONFIGURED_CAPABILITIES:
            raise ValueError("too many toxic permission pairs")

        pairs_by_key: dict[tuple[str, str], tuple[str, str]] = {}
        for pair in self.toxic_permission_pairs:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise ValueError("each toxic permission pair must contain two capabilities")
            first, second = pair
            _require_capability(first)
            _require_capability(second)
            if first == second:
                raise ValueError("a toxic permission pair must contain distinct capabilities")
            key = (first, second) if first < second else (second, first)
            pairs_by_key.setdefault(key, (first, second))
        if not pairs_by_key:
            raise ValueError("at least one toxic permission pair is required")
        object.__setattr__(
            self,
            "toxic_permission_pairs",
            tuple(pairs_by_key[key] for key in sorted(pairs_by_key)),
        )


@dataclass(frozen=True, slots=True)
class RuleRun:
    """Findings and conclusive evaluations for one selected rule set."""

    findings: tuple[Finding, ...]
    evaluations: tuple[RuleEvaluation, ...]
    correlations: tuple[CorrelationEpisode, ...] = ()


RULE_REGISTRY: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        rule_id="ERP001",
        rule_version="1.0.0",
        title="Required audit logging is disabled",
        severity="high",
        severity_rationale=(
            "Disabled audit logging can materially reduce investigation and accountability "
            "evidence."
        ),
        required_evidence_types=("control_state",),
        parameters=(),
        fixed_conditions=(
            RuleParameter(
                name="control",
                default="AUDIT_LOGGING",
                description="Generic control that must be represented in supplied evidence.",
            ),
            RuleParameter(
                name="enabled",
                default=False,
                description="Explicit disabled state matched by this rule.",
            ),
        ),
        limitation=(
            "ERP001 evaluates only supplied synthetic control-state evidence; it does not verify "
            "a live system or prove logging coverage."
        ),
        remediation=(
            "Review the audit logging configuration and enable the required control through an "
            "authorized change process."
        ),
    ),
    RuleDefinition(
        rule_id="ERP002",
        rule_version="1.0.0",
        title="Enabled privileged principal is inactive",
        severity="high",
        severity_rationale=(
            "Enabled principals with privileged permissions and prolonged inactivity can retain "
            "unnecessary access and increase account-misuse risk."
        ),
        required_evidence_types=("permission_assignment", "principal"),
        parameters=(
            RuleParameter(
                name="inactive_days",
                default=90,
                description="Days before the explicit analysis time; exact equality is clean.",
            ),
            RuleParameter(
                name="privileged_permissions",
                default=("ADMINISTER_SYSTEM", "APPROVE_PAYMENT"),
                description="Configured generic capabilities treated as privileged.",
            ),
        ),
        fixed_conditions=(
            RuleParameter(
                name="enabled",
                default=True,
                description="Only explicitly enabled principals are matched by this rule.",
            ),
        ),
        limitation=(
            "ERP002 evaluates only supplied synthetic principal and permission-assignment "
            "evidence; it does not prove identity, assignment, or activity completeness."
        ),
        remediation=(
            "Review the principal's current need for privileged access and disable or revalidate "
            "it through an authorized access-governance process."
        ),
    ),
    RuleDefinition(
        rule_id="ERP003",
        rule_version="1.0.0",
        title="Privileged permission is assigned directly",
        severity="high",
        severity_rationale=(
            "Direct privileged grants can bypass role-based governance and make access review "
            "more difficult."
        ),
        required_evidence_types=("permission_assignment",),
        parameters=(
            RuleParameter(
                name="privileged_permissions",
                default=("ADMINISTER_SYSTEM", "APPROVE_PAYMENT"),
                description="Configured generic capabilities treated as privileged.",
            ),
        ),
        fixed_conditions=(
            RuleParameter(
                name="assignment_mode",
                default="direct",
                description="Only explicitly direct assignments are matched by this rule.",
            ),
        ),
        limitation=(
            "ERP003 evaluates only assignment mode and configured capability names; it does not "
            "infer approval, justification, role design, or effective access."
        ),
        remediation=(
            "Review the direct assignment and replace or remove it through an authorized "
            "role-governance process when it is not explicitly justified."
        ),
    ),
    RuleDefinition(
        rule_id="ERP004",
        rule_version="1.0.0",
        title="Configured toxic permission pair is present",
        severity="high",
        severity_rationale=(
            "Combining configured conflicting capabilities can enable incompatible actions "
            "without independent oversight."
        ),
        required_evidence_types=("permission_assignment",),
        parameters=(
            RuleParameter(
                name="toxic_permission_pairs",
                default=(("CREATE_VENDOR", "APPROVE_PAYMENT"),),
                description="Configured unordered pairs of generic capabilities.",
            ),
        ),
        limitation=(
            "ERP004 evaluates only configured synthetic capability pairs; the defaults are not a "
            "vendor role matrix, customer policy, or authoritative segregation-of-duties model."
        ),
        remediation=(
            "Review the combined capabilities and separate or formally mitigate them through an "
            "authorized segregation-of-duties process."
        ),
    ),
    RuleDefinition(
        rule_id="ERP005",
        rule_version="1.0.0",
        title="Emergency access occurs outside the approved window",
        severity="high",
        severity_rationale=(
            "Successful use of emergency access outside an approved window can indicate "
            "unreviewed privileged activity."
        ),
        required_evidence_types=("auth_event", "principal"),
        parameters=(
            RuleParameter(
                name="emergency_window_hours",
                default=4,
                description="Closed approved window ending at the explicit analysis time.",
            ),
        ),
        fixed_conditions=(
            RuleParameter(
                name="action",
                default="SIGN_IN",
                description="Generic successful authentication action evaluated by this rule.",
            ),
            RuleParameter(
                name="outcome",
                default="success",
                description="Successful outcome required by this rule.",
            ),
            RuleParameter(
                name="principal_kind",
                default="emergency",
                description="Only explicitly emergency principals are matched by this rule.",
            ),
        ),
        limitation=(
            "ERP005 evaluates only supplied synthetic principal and authentication evidence; it "
            "cannot determine business approval, ticket context, or live-session activity."
        ),
        remediation=(
            "Investigate the event's authorization and context, then document or contain it "
            "through an approved emergency-access process."
        ),
    ),
    RuleDefinition(
        rule_id="ERP006",
        rule_version="1.0.0",
        title="Repeated authentication failures occur",
        severity="medium",
        severity_rationale=(
            "Repeated sign-in failures in a short interval can indicate credential misuse or an "
            "operational access problem."
        ),
        required_evidence_types=("auth_event",),
        parameters=(
            RuleParameter(
                name="auth_failure_threshold",
                default=5,
                description="Failed sign-in events required for one deterministic burst.",
            ),
            RuleParameter(
                name="auth_failure_window_minutes",
                default=15,
                description="Inclusive interval spanning the first and last triggering event.",
            ),
        ),
        fixed_conditions=(
            RuleParameter(
                name="action",
                default="SIGN_IN",
                description="Generic authentication action evaluated by this rule.",
            ),
            RuleParameter(
                name="outcome",
                default="failure",
                description="Failed outcome required by this rule.",
            ),
        ),
        limitation=(
            "ERP006 evaluates only supplied synthetic sign-in outcomes; it cannot determine "
            "network source, device context, user intent, or root cause."
        ),
        remediation=(
            "Review the authentication context, validate the principal, and follow the "
            "appropriate incident-response or access-support process."
        ),
    ),
)

DETECTION_RULE_REGISTRY: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        rule_id="ERP007",
        rule_version="1.0.0",
        title="Failed sign-ins are followed by a successful sign-in",
        severity="high",
        severity_rationale=(
            "A success after repeated failures from the same synthetic source can warrant "
            "review for credential misuse or an operational access issue."
        ),
        required_evidence_types=("observed_event",),
        parameters=(),
        fixed_conditions=(
            RuleParameter(
                name="failure_threshold",
                default=3,
                description="Exactly three preceding failures are retained in each episode.",
            ),
            RuleParameter(
                name="maximum_window_seconds",
                default=600,
                description=(
                    "At most 600 seconds from the first retained failure through a strictly "
                    "later success; the 600-second boundary is inclusive."
                ),
            ),
            RuleParameter(
                name="action",
                default="SIGN_IN",
                description="Generic authentication action evaluated by this rule.",
            ),
        ),
        limitation=(
            "ERP007 evaluates only supplied synthetic events and cannot establish attacker "
            "identity, intent, device context, or source-system completeness."
        ),
        remediation=(
            "Review the correlated evidence chain, validate the principal and source context, "
            "and follow an authorized incident-response or access-support process."
        ),
    ),
    RuleDefinition(
        rule_id="ERP008",
        rule_version="1.0.0",
        title="Successful sign-in matches a local synthetic threat indicator",
        severity="high",
        severity_rationale=(
            "A successful sign-in from an address present in a supplied local indicator set can "
            "justify prioritized human review."
        ),
        required_evidence_types=("observed_event", "threat_indicator"),
        parameters=(),
        fixed_conditions=(
            RuleParameter(
                name="action",
                default="SIGN_IN",
                description="Generic authentication action evaluated by this rule.",
            ),
            RuleParameter(
                name="outcome",
                default="success",
                description="Only explicitly successful synthetic events are correlated.",
            ),
            RuleParameter(
                name="indicator_validity",
                default="inclusive",
                description="Event time must be inside the closed indicator-validity interval.",
            ),
        ),
        limitation=(
            "ERP008 uses only a user-supplied local synthetic indicator file; it performs no "
            "online lookup and does not assert that an address is malicious in the real world."
        ),
        remediation=(
            "Validate the indicator source and event context, then follow the authorized triage "
            "process before taking any containment action."
        ),
    ),
    RuleDefinition(
        rule_id="ERP009",
        rule_version="1.0.0",
        title="Successful sign-in precedes a sensitive change",
        severity="medium",
        severity_rationale=(
            "A sensitive change shortly after authentication can warrant review of authorization "
            "and change-management context."
        ),
        required_evidence_types=("change_event", "observed_event"),
        parameters=(),
        fixed_conditions=(
            RuleParameter(
                name="maximum_window_seconds",
                default=1800,
                description=(
                    "Sensitive change must occur strictly after the successful sign-in and no "
                    "more than 1,800 seconds later."
                ),
            ),
            RuleParameter(
                name="sensitive_actions",
                default=("DISABLE_AUDIT", "GRANT_PRIVILEGE"),
                description="Fixed vendor-neutral synthetic change actions.",
            ),
            RuleParameter(
                name="outcome",
                default="success",
                description="Both the sign-in and change must have successful outcomes.",
            ),
        ),
        limitation=(
            "ERP009 identifies a supplied synthetic timing pattern only; it does not determine "
            "malicious intent, policy violation, or whether the change was approved."
        ),
        remediation=(
            "Review the authentication and change evidence against the authorized change record "
            "and escalate only through the documented investigation process."
        ),
    ),
)

FULL_RULE_REGISTRY = (*RULE_REGISTRY, *DETECTION_RULE_REGISTRY)
ALL_RULE_IDS: tuple[str, ...] = tuple(definition.rule_id for definition in RULE_REGISTRY)
DETECTION_RULE_IDS: tuple[str, ...] = tuple(
    definition.rule_id for definition in DETECTION_RULE_REGISTRY
)
FULL_RULE_IDS = (*ALL_RULE_IDS, *DETECTION_RULE_IDS)
DEFAULT_RULE_PARAMETERS = RuleParameters()
_DEFINITIONS_BY_ID = {definition.rule_id: definition for definition in FULL_RULE_REGISTRY}


def evaluate(bundle: EvidenceBundle) -> tuple[Finding, ...]:
    """Evaluate only ERP001 for compatibility with the original Python seam."""
    return evaluate_rules(
        bundle,
        as_of="1970-01-01T00:00:00Z",
        selected_rule_ids=(RULE_ID,),
    ).findings


def evaluate_rules(
    bundle: EvidenceBundle,
    *,
    as_of: str,
    selected_rule_ids: Sequence[str] = ALL_RULE_IDS,
    parameters: RuleParameters = DEFAULT_RULE_PARAMETERS,
) -> RuleRun:
    """Preflight and evaluate a deterministic selected rule set."""
    definitions = _selected_definitions(selected_rule_ids)
    if not isinstance(parameters, RuleParameters):
        raise InputValidationError("rule parameters are invalid")
    try:
        canonical_as_of = normalize_rfc3339_seconds(as_of)
        as_of_datetime = _as_datetime(canonical_as_of)
        _preflight_coverage(bundle, definitions, parameters)
        findings_by_rule: list[tuple[RuleDefinition, tuple[Finding, ...]]] = []
        evidence_reference_count = 0
        for definition in definitions:
            evaluator = _EVALUATORS[definition.rule_id]
            rule_findings = evaluator(bundle, as_of_datetime, parameters, definition)
            evidence_reference_count += sum(
                len(finding.supporting_evidence) if finding.supporting_evidence else 1
                for finding in rule_findings
            )
            if evidence_reference_count > MAX_FINDING_EVIDENCE_REFS:
                raise InputValidationError("rule evaluation exceeds the evidence-reference limit")
            findings_by_rule.append((definition, rule_findings))
    except (OverflowError, ValueError) as exc:
        raise InputValidationError("rule parameters or analysis time are invalid") from exc

    findings = tuple(
        sorted(
            (finding for _, rule_findings in findings_by_rule for finding in rule_findings),
            key=lambda finding: (finding.rule_id, finding.fingerprint),
        )
    )
    evaluations = tuple(
        RuleEvaluation(
            rule_id=definition.rule_id,
            rule_version=definition.rule_version,
            status="matched" if rule_findings else "not_matched",
        )
        for definition, rule_findings in findings_by_rule
    )
    correlations_by_id = {
        finding.correlation.correlation_id: finding.correlation
        for finding in findings
        if finding.correlation is not None
    }
    return RuleRun(
        findings=findings,
        evaluations=evaluations,
        correlations=tuple(correlations_by_id[key] for key in sorted(correlations_by_id)),
    )


def build_rule_catalog() -> bytes:
    """Serialize the stable rule registry as deterministic JSON."""
    document = {
        "rules": [definition.to_dict() for definition in FULL_RULE_REGISTRY],
        "schema_version": RULE_CATALOG_SCHEMA_VERSION,
    }
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _selected_definitions(selected_rule_ids: Sequence[str]) -> tuple[RuleDefinition, ...]:
    selected = tuple(selected_rule_ids)
    if not selected or any(type(rule_id) is not str for rule_id in selected):
        raise InputValidationError("at least one rule must be selected")
    if len(set(selected)) != len(selected):
        raise InputValidationError("rule selections must be unique")
    if any(rule_id not in _DEFINITIONS_BY_ID for rule_id in selected):
        raise InputValidationError("rule selection is unsupported")
    selected_set = set(selected)
    return tuple(
        definition for definition in FULL_RULE_REGISTRY if definition.rule_id in selected_set
    )


def _preflight_coverage(
    bundle: EvidenceBundle,
    definitions: tuple[RuleDefinition, ...],
    parameters: RuleParameters,
) -> None:
    if not bundle.complete or not bundle.records:
        raise IncompleteEvidenceError("evidence coverage is incomplete")

    record_types = {record.record_type for record in bundle.records}
    if any(
        required_type not in record_types
        for definition in definitions
        for required_type in definition.required_evidence_types
    ):
        raise IncompleteEvidenceError("evidence coverage is incomplete")

    selected_ids = {definition.rule_id for definition in definitions}
    if selected_ids.intersection(DETECTION_RULE_IDS) and bundle.replay is None:
        raise IncompleteEvidenceError("replay evidence coverage is incomplete")
    if "ERP001" in selected_ids and not any(
        isinstance(record, ControlState) and record.control == "AUDIT_LOGGING"
        for record in bundle.records
    ):
        raise IncompleteEvidenceError("evidence coverage is incomplete")

    if selected_ids.intersection({"ERP002", "ERP005"}):
        principals = _principal_index(bundle.records)
        if "ERP002" in selected_ids:
            privileged_permissions = set(parameters.privileged_permissions)
            for record in bundle.records:
                if (
                    isinstance(record, PermissionAssignment)
                    and record.permission in privileged_permissions
                    and record.principal_id not in principals
                ):
                    raise IncompleteEvidenceError("evidence coverage is incomplete")
        if "ERP005" in selected_ids:
            for record in bundle.records:
                if (
                    isinstance(record, AuthEvent)
                    and record.action == "SIGN_IN"
                    and record.outcome == "success"
                    and record.principal_id not in principals
                ):
                    raise IncompleteEvidenceError("evidence coverage is incomplete")


def _principal_index(records: tuple[CanonicalRecord, ...]) -> dict[str, Principal]:
    result: dict[str, Principal] = {}
    for record in records:
        if not isinstance(record, Principal):
            continue
        if record.principal_id in result:
            raise IncompleteEvidenceError("evidence coverage is incomplete")
        result[record.principal_id] = record
    return result


def _evaluate_erp001(
    bundle: EvidenceBundle,
    as_of: datetime,
    parameters: RuleParameters,
    definition: RuleDefinition,
) -> tuple[Finding, ...]:
    del as_of, parameters
    findings: list[Finding] = []
    for record in bundle.records:
        if not isinstance(record, ControlState):
            continue
        if record.control != "AUDIT_LOGGING" or record.enabled:
            continue
        findings.append(
            Finding(
                rule_id=definition.rule_id,
                rule_version=definition.rule_version,
                severity=definition.severity,
                severity_rationale=definition.severity_rationale,
                title=definition.title,
                description=(
                    "The supplied control-state evidence explicitly marks required audit "
                    "logging as disabled."
                ),
                fingerprint=_fingerprint(definition, (record,)),
                evidence_record=record,
                limitation=definition.limitation,
                remediation=definition.remediation,
                required_evidence_types=definition.required_evidence_types,
            )
        )
    return tuple(sorted(findings, key=lambda finding: finding.fingerprint))


def _evaluate_erp002(
    bundle: EvidenceBundle,
    as_of: datetime,
    parameters: RuleParameters,
    definition: RuleDefinition,
) -> tuple[Finding, ...]:
    cutoff = as_of - timedelta(days=parameters.inactive_days)
    privileged = set(parameters.privileged_permissions)
    assignments: dict[str, list[PermissionAssignment]] = {}
    for record in bundle.records:
        if isinstance(record, PermissionAssignment) and record.permission in privileged:
            assignments.setdefault(record.principal_id, []).append(record)

    findings: list[Finding] = []
    principals = sorted(
        (record for record in bundle.records if isinstance(record, Principal)),
        key=lambda record: (record.principal_id, record.record_id),
    )
    for principal in principals:
        supporting_assignments = sorted(
            assignments.get(principal.principal_id, []),
            key=lambda record: (record.permission, record.record_id),
        )
        if (
            not principal.enabled
            or not supporting_assignments
            or _as_datetime(principal.last_active_at) >= cutoff
        ):
            continue
        assignment_evidence = tuple(
            evidence_item
            for record in supporting_assignments
            for evidence_item in (
                FindingEvidence(record, "permission"),
                FindingEvidence(record, "principal_id"),
            )
        )
        evidence = (
            FindingEvidence(principal, "enabled"),
            FindingEvidence(principal, "last_active_at"),
            FindingEvidence(principal, "principal_id"),
            *assignment_evidence,
        )
        findings.append(
            _finding(
                definition,
                description=(
                    "The supplied evidence shows an enabled principal with a configured "
                    "privileged permission and activity older than the configured cutoff."
                ),
                evidence=evidence,
            )
        )
    return tuple(findings)


def _evaluate_erp003(
    bundle: EvidenceBundle,
    as_of: datetime,
    parameters: RuleParameters,
    definition: RuleDefinition,
) -> tuple[Finding, ...]:
    del as_of
    privileged = set(parameters.privileged_permissions)
    findings = [
        _finding(
            definition,
            description=(
                "The supplied evidence shows a configured privileged permission assigned "
                "directly rather than inherited through a role."
            ),
            evidence=(
                FindingEvidence(record, "assignment_mode"),
                FindingEvidence(record, "permission"),
            ),
        )
        for record in sorted(
            (
                item
                for item in bundle.records
                if isinstance(item, PermissionAssignment)
                and item.permission in privileged
                and item.assignment_mode == "direct"
            ),
            key=lambda item: (item.principal_id, item.permission, item.record_id),
        )
    ]
    return tuple(findings)


def _evaluate_erp004(
    bundle: EvidenceBundle,
    as_of: datetime,
    parameters: RuleParameters,
    definition: RuleDefinition,
) -> tuple[Finding, ...]:
    del as_of
    assignments_by_principal: dict[str, list[PermissionAssignment]] = {}
    for record in bundle.records:
        if isinstance(record, PermissionAssignment):
            assignments_by_principal.setdefault(record.principal_id, []).append(record)

    canonical_pairs = sorted({tuple(sorted(pair)) for pair in parameters.toxic_permission_pairs})
    findings: list[Finding] = []
    for principal_id in sorted(assignments_by_principal):
        assignments = assignments_by_principal[principal_id]
        permissions = {record.permission for record in assignments}
        for pair in canonical_pairs:
            if not set(pair).issubset(permissions):
                continue
            supporting = sorted(
                (record for record in assignments if record.permission in pair),
                key=lambda record: (record.permission, record.record_id),
            )
            findings.append(
                _finding(
                    definition,
                    description=(
                        "The supplied evidence assigns both capabilities in a configured toxic "
                        "permission pair to the same principal."
                    ),
                    evidence=tuple(
                        evidence_item
                        for record in supporting
                        for evidence_item in (
                            FindingEvidence(record, "permission"),
                            FindingEvidence(record, "principal_id"),
                        )
                    ),
                    finding_key="|".join(pair),
                )
            )
    return tuple(findings)


def _evaluate_erp005(
    bundle: EvidenceBundle,
    as_of: datetime,
    parameters: RuleParameters,
    definition: RuleDefinition,
) -> tuple[Finding, ...]:
    window_start = as_of - timedelta(hours=parameters.emergency_window_hours)
    principals = _principal_index(bundle.records)
    findings: list[Finding] = []
    events = sorted(
        (record for record in bundle.records if isinstance(record, AuthEvent)),
        key=lambda record: (record.occurred_at, record.record_id),
    )
    for event in events:
        if event.action != "SIGN_IN" or event.outcome != "success":
            continue
        principal = principals[event.principal_id]
        occurred_at = _as_datetime(event.occurred_at)
        if principal.principal_kind != "emergency" or window_start <= occurred_at <= as_of:
            continue
        findings.append(
            _finding(
                definition,
                description=(
                    "The supplied evidence shows successful emergency sign-in activity outside "
                    "the configured approved window."
                ),
                evidence=(
                    FindingEvidence(principal, "principal_id"),
                    FindingEvidence(principal, "principal_kind"),
                    FindingEvidence(event, "action"),
                    FindingEvidence(event, "occurred_at"),
                    FindingEvidence(event, "outcome"),
                    FindingEvidence(event, "principal_id"),
                ),
            )
        )
    return tuple(findings)


def _evaluate_erp006(
    bundle: EvidenceBundle,
    as_of: datetime,
    parameters: RuleParameters,
    definition: RuleDefinition,
) -> tuple[Finding, ...]:
    del as_of
    failures_by_principal: dict[str, list[AuthEvent]] = {}
    for record in bundle.records:
        if (
            isinstance(record, AuthEvent)
            and record.action == "SIGN_IN"
            and record.outcome == "failure"
        ):
            failures_by_principal.setdefault(record.principal_id, []).append(record)

    threshold = parameters.auth_failure_threshold
    interval = timedelta(minutes=parameters.auth_failure_window_minutes)
    findings: list[Finding] = []
    for principal_id in sorted(failures_by_principal):
        failures = sorted(
            failures_by_principal[principal_id],
            key=lambda record: (record.occurred_at, record.record_id),
        )
        for start in range(0, len(failures) - threshold + 1):
            window = failures[start : start + threshold]
            if (
                _as_datetime(window[-1].occurred_at) - _as_datetime(window[0].occurred_at)
                > interval
            ):
                continue
            findings.append(
                _finding(
                    definition,
                    description=(
                        "The supplied evidence contains the configured number of failed sign-in "
                        "events for one principal within the configured interval."
                    ),
                    evidence=tuple(
                        evidence_item
                        for record in window
                        for evidence_item in (
                            FindingEvidence(record, "action"),
                            FindingEvidence(record, "occurred_at"),
                            FindingEvidence(record, "outcome"),
                            FindingEvidence(record, "principal_id"),
                        )
                    ),
                )
            )
            break
    return tuple(findings)


def _evaluate_erp007(
    bundle: EvidenceBundle,
    as_of: datetime,
    parameters: RuleParameters,
    definition: RuleDefinition,
) -> tuple[Finding, ...]:
    del parameters
    threshold = 3
    maximum = timedelta(seconds=600)
    events_by_key: dict[tuple[str, str, str], list[ObservedEvent]] = {}
    for record in bundle.records:
        if (
            isinstance(record, ObservedEvent)
            and record.action == "SIGN_IN"
            and _as_datetime(record.occurred_at) <= as_of
        ):
            key = (record.source_id, record.principal_id, record.source_address)
            events_by_key.setdefault(key, []).append(record)

    findings: list[Finding] = []
    for key in sorted(events_by_key):
        ordered = sorted(
            events_by_key[key],
            key=lambda item: (item.occurred_at, item.record_id),
        )
        for success in ordered:
            if success.outcome != "success":
                continue
            success_time = _as_datetime(success.occurred_at)
            failures = [
                item
                for item in ordered
                if item.outcome == "failure"
                and _as_datetime(item.occurred_at) < success_time
                and success_time - _as_datetime(item.occurred_at) <= maximum
            ]
            if len(failures) < threshold:
                continue
            retained = tuple(failures[-threshold:])
            records: tuple[CanonicalRecord, ...] = (*retained, success)
            correlation = _correlation(
                bundle,
                definition,
                records,
                dedupe_material={
                    "principal_id": key[1],
                    "source_address": key[2],
                    "source_id": key[0],
                },
                window_start=retained[0].occurred_at,
                window_end=success.occurred_at,
                maximum_seconds=600,
                summaries=(*("Failed synthetic sign-in" for _ in retained), "Successful sign-in"),
                fields=(
                    *(
                        (
                            "action",
                            "occurred_at",
                            "outcome",
                            "principal_id",
                            "source_address",
                        )
                        for _ in retained
                    ),
                    (
                        "action",
                        "occurred_at",
                        "outcome",
                        "principal_id",
                        "source_address",
                    ),
                ),
            )
            evidence = tuple(
                FindingEvidence(record, field)
                for record in records
                for field in (
                    "action",
                    "occurred_at",
                    "outcome",
                    "principal_id",
                    "source_address",
                )
            )
            findings.append(
                _finding(
                    definition,
                    description=(
                        "Three failed synthetic sign-ins from the same source and principal are "
                        "timestamped strictly before a success inside the inclusive ten-minute "
                        "window."
                    ),
                    evidence=evidence,
                    correlation=correlation,
                )
            )
            break
    return tuple(findings)


def _evaluate_erp008(
    bundle: EvidenceBundle,
    as_of: datetime,
    parameters: RuleParameters,
    definition: RuleDefinition,
) -> tuple[Finding, ...]:
    del parameters
    indicators_by_value: dict[str, list[ThreatIndicator]] = {}
    for record in bundle.records:
        if isinstance(record, ThreatIndicator):
            indicators_by_value.setdefault(record.value, []).append(record)

    findings: list[Finding] = []
    seen_dedupe_keys: set[str] = set()
    events = sorted(
        (
            record
            for record in bundle.records
            if isinstance(record, ObservedEvent)
            and record.action == "SIGN_IN"
            and record.outcome == "success"
            and _as_datetime(record.occurred_at) <= as_of
        ),
        key=lambda item: (item.occurred_at, item.record_id),
    )
    for event in events:
        event_time = _as_datetime(event.occurred_at)
        matching = sorted(
            (
                indicator
                for indicator in indicators_by_value.get(event.source_address, [])
                if _as_datetime(indicator.valid_from)
                <= event_time
                <= _as_datetime(indicator.valid_until)
            ),
            key=lambda item: (item.indicator_id, item.record_id),
        )
        if not matching:
            continue
        indicator = matching[0]
        dedupe_material = {
            "principal_id": event.principal_id,
            "source_address": event.source_address,
            "source_id": event.source_id,
        }
        dedupe_key = _stable_digest({"rule_id": definition.rule_id, **dedupe_material})
        if dedupe_key in seen_dedupe_keys:
            continue
        seen_dedupe_keys.add(dedupe_key)
        maximum_seconds = int(
            (
                _as_datetime(indicator.valid_until) - _as_datetime(indicator.valid_from)
            ).total_seconds()
        )
        correlation = _correlation(
            bundle,
            definition,
            (indicator, event),
            dedupe_material=dedupe_material,
            window_start=indicator.valid_from,
            window_end=indicator.valid_until,
            maximum_seconds=maximum_seconds,
            summaries=("Local synthetic IP indicator", "Successful sign-in from matched address"),
            fields=(
                ("value", "valid_from", "valid_until", "confidence"),
                ("source_address", "action", "outcome", "occurred_at"),
            ),
        )
        findings.append(
            _finding(
                definition,
                description=(
                    "A successful synthetic sign-in source address exactly matches a supplied "
                    "local synthetic indicator during its inclusive validity interval."
                ),
                evidence=(
                    FindingEvidence(indicator, "value"),
                    FindingEvidence(indicator, "valid_from"),
                    FindingEvidence(indicator, "valid_until"),
                    FindingEvidence(event, "source_address"),
                    FindingEvidence(event, "action"),
                    FindingEvidence(event, "occurred_at"),
                    FindingEvidence(event, "outcome"),
                ),
                correlation=correlation,
            )
        )
    return tuple(findings)


def _evaluate_erp009(
    bundle: EvidenceBundle,
    as_of: datetime,
    parameters: RuleParameters,
    definition: RuleDefinition,
) -> tuple[Finding, ...]:
    del parameters
    maximum = timedelta(seconds=1800)
    sensitive_actions = {"DISABLE_AUDIT", "GRANT_PRIVILEGE"}
    successes_by_principal: dict[str, list[ObservedEvent]] = {}
    for record in bundle.records:
        if (
            isinstance(record, ObservedEvent)
            and record.action == "SIGN_IN"
            and record.outcome == "success"
            and _as_datetime(record.occurred_at) <= as_of
        ):
            successes_by_principal.setdefault(record.principal_id, []).append(record)

    findings: list[Finding] = []
    seen_dedupe_keys: set[str] = set()
    changes = sorted(
        (
            record
            for record in bundle.records
            if isinstance(record, ChangeEvent)
            and record.action in sensitive_actions
            and record.outcome == "success"
            and _as_datetime(record.occurred_at) <= as_of
        ),
        key=lambda item: (item.occurred_at, item.record_id),
    )
    for change in changes:
        change_time = _as_datetime(change.occurred_at)
        candidates = sorted(
            (
                event
                for event in successes_by_principal.get(change.principal_id, [])
                if _as_datetime(event.occurred_at)
                < change_time
                <= _as_datetime(event.occurred_at) + maximum
            ),
            key=lambda item: (item.occurred_at, item.record_id),
        )
        if not candidates:
            continue
        sign_in = candidates[-1]
        dedupe_material = {
            "action": change.action,
            "object_id": change.object_id,
            "principal_id": change.principal_id,
        }
        dedupe_key = _stable_digest({"rule_id": definition.rule_id, **dedupe_material})
        if dedupe_key in seen_dedupe_keys:
            continue
        seen_dedupe_keys.add(dedupe_key)
        correlation = _correlation(
            bundle,
            definition,
            (sign_in, change),
            dedupe_material=dedupe_material,
            window_start=sign_in.occurred_at,
            window_end=change.occurred_at,
            maximum_seconds=1800,
            summaries=("Successful sign-in", "Successful sensitive synthetic change"),
            fields=(
                ("principal_id", "occurred_at", "outcome"),
                ("principal_id", "object_id", "action", "occurred_at", "outcome"),
            ),
        )
        findings.append(
            _finding(
                definition,
                description=(
                    "A successful synthetic sign-in is followed by a successful sensitive change "
                    "for the same principal inside the inclusive thirty-minute window."
                ),
                evidence=(
                    FindingEvidence(sign_in, "principal_id"),
                    FindingEvidence(sign_in, "occurred_at"),
                    FindingEvidence(sign_in, "outcome"),
                    FindingEvidence(change, "principal_id"),
                    FindingEvidence(change, "object_id"),
                    FindingEvidence(change, "action"),
                    FindingEvidence(change, "occurred_at"),
                    FindingEvidence(change, "outcome"),
                ),
                correlation=correlation,
            )
        )
    return tuple(findings)


Evaluator = Callable[
    [EvidenceBundle, datetime, RuleParameters, RuleDefinition],
    tuple[Finding, ...],
]
_EVALUATORS: dict[str, Evaluator] = {
    "ERP001": _evaluate_erp001,
    "ERP002": _evaluate_erp002,
    "ERP003": _evaluate_erp003,
    "ERP004": _evaluate_erp004,
    "ERP005": _evaluate_erp005,
    "ERP006": _evaluate_erp006,
    "ERP007": _evaluate_erp007,
    "ERP008": _evaluate_erp008,
    "ERP009": _evaluate_erp009,
}


def _finding(
    definition: RuleDefinition,
    *,
    description: str,
    evidence: tuple[FindingEvidence, ...],
    finding_key: str | None = None,
    correlation: CorrelationEpisode | None = None,
) -> Finding:
    records = tuple(item.record for item in evidence)
    return Finding(
        rule_id=definition.rule_id,
        rule_version=definition.rule_version,
        severity=definition.severity,
        severity_rationale=definition.severity_rationale,
        title=definition.title,
        description=description,
        fingerprint=_fingerprint(definition, records, finding_key=finding_key),
        evidence_record=None,
        limitation=definition.limitation,
        remediation=definition.remediation,
        required_evidence_types=definition.required_evidence_types,
        supporting_evidence=evidence,
        correlation=correlation,
    )


def _correlation(
    bundle: EvidenceBundle,
    definition: RuleDefinition,
    records: tuple[CanonicalRecord, ...],
    *,
    dedupe_material: dict[str, str],
    window_start: str,
    window_end: str,
    maximum_seconds: int,
    summaries: tuple[str, ...],
    fields: tuple[tuple[str, ...], ...],
) -> CorrelationEpisode:
    if len(records) != len(summaries) or len(records) != len(fields):
        raise ValueError("correlation step definitions are inconsistent")
    dedupe_key = _stable_digest(
        {
            "dedupe": dedupe_material,
            "rule_id": definition.rule_id,
            "rule_version": definition.rule_version,
        }
    )
    correlation_id = _stable_digest(
        {
            "dedupe_key": dedupe_key,
            "record_ids": [record.record_id for record in records],
            "rule_id": definition.rule_id,
            "rule_version": definition.rule_version,
            "window_end": window_end,
            "window_start": window_start,
        }
    )
    source_ids = {
        source.path: source.source_id for source in bundle.sources if source.source_id is not None
    }
    steps = tuple(
        CorrelationStep(
            position=index,
            source_id=(
                record.source_id
                if isinstance(record, (ObservedEvent, ThreatIndicator))
                else source_ids.get(record.source_ref.path, "")
            ),
            record=record,
            occurred_at=_correlation_time(record),
            summary=summary,
            fields=step_fields,
        )
        for index, (record, summary, step_fields) in enumerate(
            zip(records, summaries, fields, strict=True),
            start=1,
        )
    )
    return CorrelationEpisode(
        correlation_id=correlation_id,
        dedupe_key=dedupe_key,
        rule_id=definition.rule_id,
        rule_version=definition.rule_version,
        window_start=window_start,
        window_end=window_end,
        maximum_seconds=maximum_seconds,
        steps=steps,
    )


def _stable_digest(material: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            material,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


def _correlation_time(record: CanonicalRecord) -> str:
    if isinstance(record, ThreatIndicator):
        return record.valid_from
    if isinstance(record, (ObservedEvent, AuthEvent, ChangeEvent)):
        return record.occurred_at
    raise ValueError("record type cannot be used as a correlation step")


def _fingerprint(
    definition: RuleDefinition,
    records: tuple[CanonicalRecord, ...],
    *,
    finding_key: str | None = None,
) -> str:
    material: dict[str, Any] = {
        "record_ids": sorted({record.record_id for record in records}),
        "rule_id": definition.rule_id,
        "rule_version": definition.rule_version,
    }
    if finding_key is not None:
        material["finding_key"] = finding_key
    encoded = json.dumps(
        material,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _as_datetime(value: str) -> datetime:
    iso_value = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(iso_value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(UTC)
