"""Behavior checks for every configurable rule parameter."""

from __future__ import annotations

import hashlib
from typing import Literal

from erp_security_evidence_workbench.models import (
    AuthEvent,
    EvidenceBundle,
    PermissionAssignment,
    Principal,
    SourceRef,
)
from erp_security_evidence_workbench.rules import RuleParameters, evaluate_rules

AS_OF = "2026-09-01T00:00:00Z"


def _ref(record_id: str) -> SourceRef:
    return SourceRef(
        sha256=hashlib.sha256(record_id.encode()).hexdigest(),
        path="parameter-tests.json",
        json_pointer=f"/{record_id}",
    )


def _principal(
    record_id: str,
    principal_id: str,
    *,
    kind: Literal["human", "service", "emergency"] = "human",
    last_active_at: str = "2026-08-31T23:00:00Z",
) -> Principal:
    return Principal(
        record_id=record_id,
        principal_id=principal_id,
        principal_kind=kind,
        enabled=True,
        last_active_at=last_active_at,
        source_ref=_ref(record_id),
    )


def _permission(
    record_id: str,
    principal_id: str,
    permission: str,
    *,
    mode: Literal["direct", "inherited"] = "inherited",
) -> PermissionAssignment:
    return PermissionAssignment(
        record_id=record_id,
        principal_id=principal_id,
        permission=permission,
        assignment_mode=mode,
        assigned_at="2026-01-01T00:00:00Z",
        source_ref=_ref(record_id),
    )


def _failure(index: int, minute: int) -> AuthEvent:
    record_id = f"auth.failure.{index}"
    return AuthEvent(
        record_id=record_id,
        principal_id="candidate",
        action="SIGN_IN",
        outcome="failure",
        occurred_at=f"2026-08-31T12:{minute:02d}:00Z",
        source_ref=_ref(record_id),
    )


def _matched(
    records: tuple[Principal | PermissionAssignment | AuthEvent, ...],
    rule_id: str,
    parameters: RuleParameters,
) -> bool:
    run = evaluate_rules(
        EvidenceBundle(records=records),
        as_of=AS_OF,
        selected_rule_ids=(rule_id,),
        parameters=parameters,
    )
    return bool(run.findings)


def test_custom_inactive_cutoff_changes_erp002_boundary() -> None:
    records = (
        _principal(
            "principal.candidate",
            "candidate",
            last_active_at="2026-07-18T00:00:00Z",
        ),
        _permission("permission.admin", "candidate", "ADMINISTER_SYSTEM"),
    )

    assert not _matched(records, "ERP002", RuleParameters())
    assert _matched(records, "ERP002", RuleParameters(inactive_days=30))


def test_custom_privileged_capability_changes_erp003_selection() -> None:
    records = (_permission("permission.post", "candidate", "POST_ENTRY", mode="direct"),)

    assert not _matched(records, "ERP003", RuleParameters())
    assert _matched(
        records,
        "ERP003",
        RuleParameters(privileged_permissions=("POST_ENTRY",)),
    )


def test_custom_emergency_window_changes_erp005_boundary() -> None:
    event = AuthEvent(
        record_id="auth.emergency",
        principal_id="break-glass",
        action="SIGN_IN",
        outcome="success",
        occurred_at="2026-08-31T19:00:00Z",
        source_ref=_ref("auth.emergency"),
    )
    records = (
        _principal("principal.emergency", "break-glass", kind="emergency"),
        event,
    )

    assert _matched(records, "ERP005", RuleParameters())
    assert not _matched(records, "ERP005", RuleParameters(emergency_window_hours=6))


def test_custom_failure_threshold_and_window_change_erp006_selection() -> None:
    records = tuple(_failure(index, minute) for index, minute in enumerate((0, 3, 6, 9), 1))

    assert not _matched(records, "ERP006", RuleParameters())
    assert _matched(
        records,
        "ERP006",
        RuleParameters(auth_failure_threshold=4, auth_failure_window_minutes=10),
    )
    assert not _matched(
        records,
        "ERP006",
        RuleParameters(auth_failure_threshold=4, auth_failure_window_minutes=8),
    )


def test_erp006_threshold_minus_one_is_clean() -> None:
    records = tuple(_failure(index, minute) for index, minute in enumerate((0, 3, 6, 9), 1))

    assert not _matched(records, "ERP006", RuleParameters())
