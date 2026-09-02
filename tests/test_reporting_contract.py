"""Direct contracts for coherent rule evaluations in JSON reports."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from erp_security_evidence_workbench.errors import (
    IncompleteEvidenceError,
    InputValidationError,
    WorkbenchError,
)
from erp_security_evidence_workbench.models import (
    ControlState,
    EvidenceBundle,
    Finding,
    PermissionAssignment,
    Principal,
    RuleEvaluation,
    SourceRef,
)
from erp_security_evidence_workbench.reporting import build_json_report
from erp_security_evidence_workbench.rules import evaluate_rules

AS_OF = "2026-09-01T00:00:00Z"


def _source_ref(record_id: str) -> SourceRef:
    return SourceRef(
        sha256=hashlib.sha256(record_id.encode()).hexdigest(),
        path="synthetic-evidence.json",
        json_pointer="/0",
    )


def _control(*, enabled: bool = False) -> ControlState:
    return ControlState(
        record_id="control.audit",
        control="AUDIT_LOGGING",
        enabled=enabled,
        source_ref=_source_ref("control.audit"),
    )


def _principal() -> Principal:
    return Principal(
        record_id="principal.user",
        principal_id="user",
        principal_kind="human",
        enabled=True,
        last_active_at="2026-08-31T00:00:00Z",
        source_ref=_source_ref("principal.user"),
    )


def _permission(
    record_id: str,
    principal_id: str,
    permission: str,
    *,
    mode: str = "inherited",
) -> PermissionAssignment:
    return PermissionAssignment(
        record_id=record_id,
        principal_id=principal_id,
        permission=permission,
        assignment_mode=mode,  # type: ignore[arg-type]
        assigned_at="2026-01-01T00:00:00Z",
        source_ref=_source_ref(record_id),
    )


def _finding(rule_id: str, rule_version: str = "1.0.0") -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_version=rule_version,
        severity="high",
        severity_rationale="Synthetic test rationale.",
        title="Synthetic test finding",
        description="Synthetic test description.",
        fingerprint=hashlib.sha256(f"{rule_id}:{rule_version}".encode()).hexdigest(),
        evidence_record=_control(),
        limitation="Synthetic test limitation.",
        remediation="Review the evidence through an authorized process.",
        required_evidence_types=("control_state",),
    )


def _report(
    bundle: EvidenceBundle,
    findings: tuple[Finding, ...],
    *,
    evaluations: tuple[RuleEvaluation, ...] | None = None,
) -> dict[str, object]:
    return json.loads(
        build_json_report(
            bundle,
            findings,
            as_of=AS_OF,
            evaluations=evaluations,
        )
    )


def test_omitted_evaluations_preserve_erp001_legacy_finding_and_clean_paths() -> None:
    matched_bundle = EvidenceBundle(records=(_control(),))
    clean_bundle = EvidenceBundle(records=(_control(enabled=True),))
    matched_run = evaluate_rules(
        matched_bundle,
        as_of=AS_OF,
        selected_rule_ids=("ERP001",),
    )
    clean_run = evaluate_rules(
        clean_bundle,
        as_of=AS_OF,
        selected_rule_ids=("ERP001",),
    )

    matched = _report(matched_bundle, matched_run.findings)
    clean = _report(clean_bundle, clean_run.findings)

    assert matched["evaluations"] == [
        {"rule_id": "ERP001", "rule_version": "1.0.0", "status": "matched"}
    ]
    assert clean["evaluations"] == [
        {"rule_id": "ERP001", "rule_version": "1.0.0", "status": "not_matched"}
    ]


@pytest.mark.parametrize(
    ("bundle", "findings"),
    [
        (EvidenceBundle(records=(_control(),)), (_finding("ERP002"),)),
        (EvidenceBundle(records=(_control(),)), (_finding("ERP001", "2.0.0"),)),
        (EvidenceBundle(records=(_principal(),)), ()),
    ],
)
def test_omitted_evaluations_fail_closed_outside_the_erp001_legacy_contract(
    bundle: EvidenceBundle,
    findings: tuple[Finding, ...],
) -> None:
    with pytest.raises(WorkbenchError, match="evaluation|coverage"):
        _report(bundle, findings)


def test_supplied_evaluations_reject_duplicate_rule_ids() -> None:
    evaluations = (
        RuleEvaluation("ERP001", "1.0.0", "matched"),
        RuleEvaluation("ERP001", "2.0.0", "matched"),
    )

    with pytest.raises(InputValidationError, match="evaluation"):
        _report(
            EvidenceBundle(records=(_control(),)),
            (_finding("ERP001"),),
            evaluations=evaluations,
        )


def test_supplied_evaluations_require_every_finding_rule_and_version_to_be_a_member() -> None:
    evaluations = (RuleEvaluation("ERP002", "2.0.0", "matched"),)

    with pytest.raises(InputValidationError, match="evaluation"):
        _report(
            EvidenceBundle(records=(_control(),)),
            (_finding("ERP002"),),
            evaluations=evaluations,
        )


@pytest.mark.parametrize(
    "evaluation",
    [
        RuleEvaluation("ERP999", "1.0.0", "not_matched"),
        RuleEvaluation("ERP002", "2.0.0", "not_matched"),
    ],
)
def test_supplied_evaluations_must_belong_to_the_frozen_registry(
    evaluation: RuleEvaluation,
) -> None:
    with pytest.raises(InputValidationError, match="evaluation"):
        _report(
            EvidenceBundle(records=(_control(),)),
            (),
            evaluations=(evaluation,),
        )


def test_legacy_reporting_rejects_false_clean_disabled_control() -> None:
    with pytest.raises(InputValidationError, match="evaluation"):
        _report(EvidenceBundle(records=(_control(),)), ())


def test_supplied_evaluations_do_not_bypass_selected_rule_coverage() -> None:
    with pytest.raises(IncompleteEvidenceError, match="coverage"):
        _report(
            EvidenceBundle(records=(_control(enabled=True),)),
            (),
            evaluations=(RuleEvaluation("ERP006", "1.0.0", "not_matched"),),
        )


def test_report_rejects_finding_evidence_that_is_not_in_the_bundle() -> None:
    with pytest.raises(InputValidationError, match="evaluation"):
        _report(
            EvidenceBundle(records=(_control(enabled=True),)),
            (_finding("ERP001"),),
            evaluations=(RuleEvaluation("ERP001", "1.0.0", "matched"),),
        )


def test_report_rejects_forged_fixed_finding_guidance() -> None:
    bundle = EvidenceBundle(records=(_control(),))
    run = evaluate_rules(bundle, as_of=AS_OF, selected_rule_ids=("ERP001",))
    forged = replace(run.findings[0], remediation="Unreviewed replacement guidance.")

    with pytest.raises(InputValidationError, match="evaluation"):
        _report(bundle, (forged,), evaluations=run.evaluations)


@pytest.mark.parametrize(
    ("findings", "evaluation"),
    [
        ((), RuleEvaluation("ERP002", "1.0.0", "matched")),
        ((_finding("ERP002"),), RuleEvaluation("ERP002", "1.0.0", "not_matched")),
    ],
)
def test_supplied_evaluation_status_must_agree_with_finding_presence(
    findings: tuple[Finding, ...],
    evaluation: RuleEvaluation,
) -> None:
    bundle = EvidenceBundle(
        records=(
            Principal(
                record_id="principal.old",
                principal_id="candidate",
                principal_kind="human",
                enabled=True,
                last_active_at="2026-01-01T00:00:00Z",
                source_ref=_source_ref("principal.old"),
            ),
            _permission("permission.admin", "candidate", "ADMINISTER_SYSTEM"),
        )
    )
    with pytest.raises(InputValidationError, match="evaluation"):
        _report(bundle, findings, evaluations=(evaluation,))


def test_coherent_supplied_evaluations_are_emitted_in_registry_order() -> None:
    bundle = EvidenceBundle(
        records=(
            Principal(
                record_id="principal.old",
                principal_id="candidate",
                principal_kind="human",
                enabled=True,
                last_active_at="2026-01-01T00:00:00Z",
                source_ref=_source_ref("principal.old"),
            ),
            _permission(
                "permission.admin",
                "candidate",
                "ADMINISTER_SYSTEM",
                mode="direct",
            ),
            _permission("permission.create", "candidate", "CREATE_VENDOR"),
            _permission("permission.approve", "candidate", "APPROVE_PAYMENT"),
        )
    )
    run = evaluate_rules(
        bundle,
        as_of=AS_OF,
        selected_rule_ids=("ERP002", "ERP003", "ERP004"),
    )

    report = _report(
        bundle,
        tuple(reversed(run.findings)),
        evaluations=tuple(reversed(run.evaluations)),
    )

    assert report["evaluations"] == [
        RuleEvaluation("ERP002", "1.0.0", "matched").to_dict(),
        RuleEvaluation("ERP003", "1.0.0", "matched").to_dict(),
        RuleEvaluation("ERP004", "1.0.0", "matched").to_dict(),
    ]
