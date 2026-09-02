"""Golden fingerprints for the frozen rule versions."""

from __future__ import annotations

import hashlib

from erp_security_evidence_workbench.models import (
    AuthEvent,
    EvidenceBundle,
    PermissionAssignment,
    Principal,
    SourceRef,
)
from erp_security_evidence_workbench.rules import evaluate_rules

AS_OF = "2026-09-01T00:00:00Z"


def _source_ref(record_id: str) -> SourceRef:
    return SourceRef(
        sha256=hashlib.sha256(record_id.encode()).hexdigest(),
        path="synthetic-evidence.json",
        json_pointer=f"/{record_id}",
    )


def _principal(
    record_id: str,
    principal_id: str,
    *,
    kind: str = "human",
    last_active_at: str = "2026-08-31T23:00:00Z",
) -> Principal:
    return Principal(
        record_id=record_id,
        principal_id=principal_id,
        principal_kind=kind,  # type: ignore[arg-type]
        enabled=True,
        last_active_at=last_active_at,
        source_ref=_source_ref(record_id),
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


def _auth(record_id: str, principal_id: str, occurred_at: str) -> AuthEvent:
    return AuthEvent(
        record_id=record_id,
        principal_id=principal_id,
        action="SIGN_IN",
        outcome="failure",
        occurred_at=occurred_at,
        source_ref=_source_ref(record_id),
    )


def test_new_rule_fingerprints_are_pinned_to_rule_version_1_0_0() -> None:
    scenarios = {
        "ERP002": (
            _principal(
                "principal.old",
                "old-user",
                last_active_at="2026-06-02T23:59:59Z",
            ),
            _permission("permission.admin", "old-user", "ADMINISTER_SYSTEM"),
        ),
        "ERP003": (
            _permission(
                "permission.direct-admin",
                "admin-user",
                "ADMINISTER_SYSTEM",
                mode="direct",
            ),
        ),
        "ERP004": (
            _permission("permission.create", "operator", "CREATE_VENDOR"),
            _permission("permission.approve", "operator", "APPROVE_PAYMENT"),
        ),
        "ERP005": (
            _principal("principal.emergency", "break-glass", kind="emergency"),
            AuthEvent(
                record_id="auth.emergency.outside",
                principal_id="break-glass",
                action="SIGN_IN",
                outcome="success",
                occurred_at="2026-08-31T19:59:59Z",
                source_ref=_source_ref("auth.emergency.outside"),
            ),
        ),
        "ERP006": tuple(
            _auth(
                f"auth.failure.{index}",
                "locked-user",
                f"2026-08-31T12:{minute:02d}:00Z",
            )
            for index, minute in enumerate((0, 3, 6, 9, 15), start=1)
        ),
    }
    expected = {
        "ERP002": "418aef772b042694d2b2757a19ca4f7d113b216f1456870d33d9d903d342baff",
        "ERP003": "21f0ce42a9136463375705ab91ee3270de13d58925627211c7aa8ddf0e66aca6",
        "ERP004": "35111b769b133da44ef20f2084c6f76b1b8fb7f7f88a8298a9881257cde08c76",
        "ERP005": "0cc13bcc7c820096ceab39a0e689d726ad8c499db25dc191f271bf6eeba53343",
        "ERP006": "8162e4b9557203cc8a49bbd549c18ed58516ba3765c76068b05ea5a547ebc87f",
    }

    actual: dict[str, str] = {}
    for rule_id, records in scenarios.items():
        run = evaluate_rules(
            EvidenceBundle(records=records),  # type: ignore[arg-type]
            as_of=AS_OF,
            selected_rule_ids=(rule_id,),
        )
        assert len(run.findings) == 1
        assert run.findings[0].rule_version == "1.0.0"
        actual[rule_id] = run.findings[0].fingerprint

    assert actual == expected
