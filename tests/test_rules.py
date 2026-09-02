"""Contracts for the deterministic vendor-neutral rule pack."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from itertools import permutations

import pytest

from erp_security_evidence_workbench import rules
from erp_security_evidence_workbench.errors import IncompleteEvidenceError
from erp_security_evidence_workbench.models import (
    AuthEvent,
    ControlState,
    EvidenceBundle,
    PermissionAssignment,
    Principal,
    SourceRef,
)

AS_OF = "2026-09-01T00:00:00Z"
AS_OF_DATETIME = datetime(2026, 9, 1, tzinfo=UTC)
RULE_IDS = ("ERP001", "ERP002", "ERP003", "ERP004", "ERP005", "ERP006")


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


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
    enabled: bool = True,
    last_active_at: str = AS_OF,
) -> Principal:
    return Principal(
        record_id=record_id,
        principal_id=principal_id,
        principal_kind=kind,  # type: ignore[arg-type]
        enabled=enabled,
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


def _auth(
    record_id: str,
    principal_id: str,
    occurred_at: str,
    *,
    outcome: str = "failure",
) -> AuthEvent:
    return AuthEvent(
        record_id=record_id,
        principal_id=principal_id,
        action="SIGN_IN",
        outcome=outcome,  # type: ignore[arg-type]
        occurred_at=occurred_at,
        source_ref=_source_ref(record_id),
    )


def _control(record_id: str, *, control: str = "AUDIT_LOGGING", enabled: bool) -> ControlState:
    return ControlState(
        record_id=record_id,
        control=control,
        enabled=enabled,
        source_ref=_source_ref(record_id),
    )


def _bundle(*records: object) -> EvidenceBundle:
    return EvidenceBundle(records=records)  # type: ignore[arg-type]


def _parameters(**overrides: object) -> object:
    values: dict[str, object] = {
        "inactive_days": 90,
        "privileged_permissions": ("ADMINISTER_SYSTEM", "APPROVE_PAYMENT"),
        "toxic_permission_pairs": (("CREATE_VENDOR", "APPROVE_PAYMENT"),),
        "emergency_window_hours": 4,
        "auth_failure_threshold": 5,
        "auth_failure_window_minutes": 15,
    }
    values.update(overrides)
    return rules.RuleParameters(**values)  # type: ignore[attr-defined]


def _evaluate(
    bundle: EvidenceBundle,
    *rule_ids: str,
    parameters: object | None = None,
) -> object:
    return rules.evaluate_rules(  # type: ignore[attr-defined]
        bundle,
        as_of=AS_OF,
        selected_rule_ids=tuple(rule_ids),
        parameters=_parameters() if parameters is None else parameters,
    )


def _evaluation_values(run: object) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        (evaluation.rule_id, evaluation.rule_version, evaluation.status)
        for evaluation in run.evaluations  # type: ignore[attr-defined]
    )


def _finding_dicts(run: object) -> tuple[dict[str, object], ...]:
    return tuple(
        finding.to_dict()
        for finding in run.findings  # type: ignore[attr-defined]
    )


def _one_finding(run: object) -> dict[str, object]:
    findings = _finding_dicts(run)
    assert len(findings) == 1
    return findings[0]


def _ref_fields(finding: dict[str, object]) -> set[tuple[str, str]]:
    refs = finding["evidence_refs"]
    assert isinstance(refs, list)
    result: set[tuple[str, str]] = set()
    for ref in refs:
        assert isinstance(ref, dict)
        source_ref = ref["source_ref"]
        assert isinstance(source_ref, dict)
        if source_ref["format"] == "json":
            pointer = source_ref["json_pointer"]
            assert isinstance(pointer, str)
            field = pointer.rsplit("/", 1)[-1]
        else:
            field = source_ref["field"]
            assert isinstance(field, str)
        result.add((str(ref["record_id"]), field))
    return result


def _auth_failures(
    principal_id: str,
    offsets: tuple[timedelta, ...],
    *,
    prefix: str = "auth.failure",
) -> tuple[AuthEvent, ...]:
    start = datetime(2026, 8, 31, 12, tzinfo=UTC)
    return tuple(
        _auth(f"{prefix}.{index}", principal_id, _timestamp(start + offset))
        for index, offset in enumerate(offsets, start=1)
    )


def _matched_records(rule_id: str) -> tuple[object, ...]:
    if rule_id == "ERP001":
        return (
            _control("control.audit", enabled=False),
            _control("control.other", control="SESSION_MONITORING", enabled=True),
        )
    if rule_id == "ERP002":
        return (
            _principal(
                "principal.old",
                "old-user",
                last_active_at=_timestamp(AS_OF_DATETIME - timedelta(days=90, seconds=1)),
            ),
            _permission("permission.admin", "old-user", "ADMINISTER_SYSTEM"),
        )
    if rule_id == "ERP003":
        return (
            _principal("principal.active-admin", "admin-user"),
            _permission(
                "permission.direct-admin",
                "admin-user",
                "ADMINISTER_SYSTEM",
                mode="direct",
            ),
            _permission("permission.other", "admin-user", "READ_REPORT"),
        )
    if rule_id == "ERP004":
        return (
            _principal("principal.operator", "operator"),
            _permission("permission.create", "operator", "CREATE_VENDOR"),
            _permission("permission.approve", "operator", "APPROVE_PAYMENT"),
        )
    if rule_id == "ERP005":
        return (
            _principal("principal.emergency", "break-glass", kind="emergency"),
            _auth(
                "auth.emergency.outside",
                "break-glass",
                _timestamp(AS_OF_DATETIME - timedelta(hours=4, seconds=1)),
                outcome="success",
            ),
        )
    if rule_id == "ERP006":
        return _auth_failures(
            "locked-user",
            (
                timedelta(minutes=0),
                timedelta(minutes=3),
                timedelta(minutes=6),
                timedelta(minutes=9),
                timedelta(minutes=15),
            ),
        )
    raise AssertionError("unsupported test rule")


def test_rule_registry_has_stable_ordered_ids_and_versions() -> None:
    registry = rules.RULE_REGISTRY  # type: ignore[attr-defined]

    assert tuple(definition.rule_id for definition in registry) == RULE_IDS
    assert tuple(definition.rule_version for definition in registry) == ("1.0.0",) * 6
    assert all(definition.remediation for definition in registry)
    assert all(definition.severity_rationale for definition in registry)
    assert all(definition.limitation for definition in registry)
    assert all(definition.required_evidence_types for definition in registry)


def test_rule_parameters_have_documented_defaults() -> None:
    parameters = rules.RuleParameters()  # type: ignore[attr-defined]

    assert parameters.inactive_days == 90
    assert parameters.privileged_permissions == ("ADMINISTER_SYSTEM", "APPROVE_PAYMENT")
    assert parameters.toxic_permission_pairs == (("CREATE_VENDOR", "APPROVE_PAYMENT"),)
    assert parameters.emergency_window_hours == 4
    assert parameters.auth_failure_threshold == 5
    assert parameters.auth_failure_window_minutes == 15


@pytest.mark.parametrize(
    "overrides",
    [
        {"inactive_days": 0},
        {"privileged_permissions": ()},
        {"toxic_permission_pairs": (("CREATE_VENDOR", "CREATE_VENDOR"),)},
        {"auth_failure_threshold": 0},
    ],
)
def test_rule_parameters_reject_invalid_or_empty_configuration(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        _parameters(**overrides)


def test_legacy_evaluate_remains_erp001_only_for_a_mixed_bundle() -> None:
    records = (
        _control("control.audit", enabled=False),
        *_matched_records("ERP002"),
        *_matched_records("ERP003"),
    )

    findings = rules.evaluate(_bundle(*records))

    assert [finding.rule_id for finding in findings] == ["ERP001"]


def test_erp001_matches_disabled_control_and_keeps_enabled_boundary_clean() -> None:
    matched = _evaluate(_bundle(_control("control.disabled", enabled=False)), "ERP001")
    clean = _evaluate(_bundle(_control("control.enabled", enabled=True)), "ERP001")

    finding = _one_finding(matched)
    assert _ref_fields(finding) == {("control.disabled", "enabled")}
    assert _evaluation_values(matched) == (("ERP001", "1.0.0", "matched"),)
    assert _finding_dicts(clean) == ()
    assert _evaluation_values(clean) == (("ERP001", "1.0.0", "not_matched"),)


def test_erp002_matches_only_enabled_privileged_principal_older_than_cutoff() -> None:
    cutoff = _timestamp(AS_OF_DATETIME - timedelta(days=90))
    older = _timestamp(AS_OF_DATETIME - timedelta(days=90, seconds=1))
    privileged = _permission("permission.admin", "candidate", "ADMINISTER_SYSTEM")

    matched = _evaluate(
        _bundle(_principal("principal.old", "candidate", last_active_at=older), privileged),
        "ERP002",
    )
    at_boundary = _evaluate(
        _bundle(_principal("principal.boundary", "candidate", last_active_at=cutoff), privileged),
        "ERP002",
    )
    disabled = _evaluate(
        _bundle(
            _principal("principal.disabled", "candidate", enabled=False, last_active_at=older),
            privileged,
        ),
        "ERP002",
    )
    not_privileged = _evaluate(
        _bundle(
            _principal("principal.regular", "candidate", last_active_at=older),
            _permission("permission.read", "candidate", "READ_REPORT"),
        ),
        "ERP002",
    )

    finding = _one_finding(matched)
    assert _ref_fields(finding) == {
        ("principal.old", "enabled"),
        ("principal.old", "last_active_at"),
        ("principal.old", "principal_id"),
        ("permission.admin", "permission"),
        ("permission.admin", "principal_id"),
    }
    assert _finding_dicts(at_boundary) == ()
    assert _finding_dicts(disabled) == ()
    assert _finding_dicts(not_privileged) == ()


def test_erp003_matches_direct_privileged_assignment_but_not_inherited_or_regular() -> None:
    matched = _evaluate(
        _bundle(
            _permission(
                "permission.direct-admin",
                "candidate",
                "ADMINISTER_SYSTEM",
                mode="direct",
            )
        ),
        "ERP003",
    )
    inherited = _evaluate(
        _bundle(_permission("permission.inherited-admin", "candidate", "ADMINISTER_SYSTEM")),
        "ERP003",
    )
    regular = _evaluate(
        _bundle(_permission("permission.direct-read", "candidate", "READ_REPORT", mode="direct")),
        "ERP003",
    )

    finding = _one_finding(matched)
    assert {
        ("permission.direct-admin", "assignment_mode"),
        ("permission.direct-admin", "permission"),
    } <= _ref_fields(finding)
    assert _finding_dicts(inherited) == ()
    assert _finding_dicts(regular) == ()


def test_erp004_matches_configured_toxic_pair_and_preserves_both_records() -> None:
    create = _permission("permission.create", "operator", "CREATE_VENDOR")
    approve = _permission("permission.approve", "operator", "APPROVE_PAYMENT")
    matched = _evaluate(_bundle(create, approve), "ERP004")
    one_side_only = _evaluate(_bundle(create), "ERP004")

    finding = _one_finding(matched)
    assert _ref_fields(finding) == {
        ("permission.create", "permission"),
        ("permission.create", "principal_id"),
        ("permission.approve", "permission"),
        ("permission.approve", "principal_id"),
    }
    assert _finding_dicts(one_side_only) == ()


def test_cross_record_join_preserves_csv_and_jsonl_field_provenance() -> None:
    csv_assignment = PermissionAssignment(
        record_id="permission.create.csv",
        principal_id="operator",
        permission="CREATE_VENDOR",
        assignment_mode="inherited",
        assigned_at="2026-01-01T00:00:00Z",
        source_ref=SourceRef(
            sha256="a" * 64,
            path="permissions.csv",
            format="csv",
            json_pointer=None,
            row=2,
        ),
    )
    jsonl_assignment = PermissionAssignment(
        record_id="permission.approve.jsonl",
        principal_id="operator",
        permission="APPROVE_PAYMENT",
        assignment_mode="inherited",
        assigned_at="2026-01-01T00:00:00Z",
        source_ref=SourceRef(
            sha256="b" * 64,
            path="permissions.jsonl",
            format="jsonl",
            json_pointer=None,
            line=1,
        ),
    )

    finding = _one_finding(_evaluate(_bundle(csv_assignment, jsonl_assignment), "ERP004"))

    assert finding["evidence_refs"] == [
        {
            "record_id": "permission.approve.jsonl",
            "source_ref": {
                "adapter": "erpsec.jsonl/v1",
                "field": "permission",
                "format": "jsonl",
                "line": 1,
                "path": "permissions.jsonl",
                "sha256": "b" * 64,
            },
        },
        {
            "record_id": "permission.approve.jsonl",
            "source_ref": {
                "adapter": "erpsec.jsonl/v1",
                "field": "principal_id",
                "format": "jsonl",
                "line": 1,
                "path": "permissions.jsonl",
                "sha256": "b" * 64,
            },
        },
        {
            "record_id": "permission.create.csv",
            "source_ref": {
                "adapter": "erpsec.csv/v1",
                "field": "permission",
                "format": "csv",
                "path": "permissions.csv",
                "row": 2,
                "sha256": "a" * 64,
            },
        },
        {
            "record_id": "permission.create.csv",
            "source_ref": {
                "adapter": "erpsec.csv/v1",
                "field": "principal_id",
                "format": "csv",
                "path": "permissions.csv",
                "row": 2,
                "sha256": "a" * 64,
            },
        },
    ]


def test_erp002_cross_format_join_preserves_every_decisive_field() -> None:
    principal = Principal(
        record_id="principal.old.csv",
        principal_id="candidate",
        principal_kind="human",
        enabled=True,
        last_active_at="2026-01-01T00:00:00Z",
        source_ref=SourceRef(
            sha256="c" * 64,
            path="principals.csv",
            format="csv",
            json_pointer=None,
            row=2,
        ),
    )
    assignment = PermissionAssignment(
        record_id="permission.admin.jsonl",
        principal_id="candidate",
        permission="ADMINISTER_SYSTEM",
        assignment_mode="inherited",
        assigned_at="2026-01-01T00:00:00Z",
        source_ref=SourceRef(
            sha256="d" * 64,
            path="permissions.jsonl",
            format="jsonl",
            json_pointer=None,
            line=3,
        ),
    )

    finding = _one_finding(_evaluate(_bundle(principal, assignment), "ERP002"))

    assert _ref_fields(finding) == {
        ("permission.admin.jsonl", "permission"),
        ("permission.admin.jsonl", "principal_id"),
        ("principal.old.csv", "enabled"),
        ("principal.old.csv", "last_active_at"),
        ("principal.old.csv", "principal_id"),
    }
    refs = finding["evidence_refs"]
    assert isinstance(refs, list)
    assert all(
        ref["source_ref"].get("line") == 3
        for ref in refs
        if ref["record_id"] == "permission.admin.jsonl"
    )
    assert all(
        ref["source_ref"].get("row") == 2 for ref in refs if ref["record_id"] == "principal.old.csv"
    )


def test_erp004_uses_configured_generic_pair_instead_of_a_hidden_matrix() -> None:
    parameters = _parameters(toxic_permission_pairs=(("POST_ENTRY", "APPROVE_ENTRY"),))
    matched = _evaluate(
        _bundle(
            _permission("permission.post", "accountant", "POST_ENTRY"),
            _permission("permission.approve", "accountant", "APPROVE_ENTRY"),
        ),
        "ERP004",
        parameters=parameters,
    )

    assert _one_finding(matched)["rule_id"] == "ERP004"


def test_parameter_order_does_not_change_privilege_or_pair_findings() -> None:
    records = _bundle(
        _principal(
            "principal.old",
            "candidate",
            last_active_at="2026-01-01T00:00:00Z",
        ),
        _permission(
            "permission.direct-admin",
            "candidate",
            "ADMINISTER_SYSTEM",
            mode="direct",
        ),
        _permission("permission.create", "candidate", "CREATE_VENDOR"),
        _permission("permission.approve", "candidate", "APPROVE_PAYMENT"),
    )
    first_parameters = _parameters()
    reversed_parameters = _parameters(
        privileged_permissions=("APPROVE_PAYMENT", "ADMINISTER_SYSTEM"),
        toxic_permission_pairs=(("APPROVE_PAYMENT", "CREATE_VENDOR"),),
    )

    first = _evaluate(
        records,
        "ERP002",
        "ERP003",
        "ERP004",
        parameters=first_parameters,
    )
    reversed_run = _evaluate(
        records,
        "ERP002",
        "ERP003",
        "ERP004",
        parameters=reversed_parameters,
    )

    assert _finding_dicts(first) == _finding_dicts(reversed_run)
    assert _evaluation_values(first) == _evaluation_values(reversed_run)


def test_erp005_uses_closed_approved_window_and_only_successful_emergency_access() -> None:
    start = AS_OF_DATETIME - timedelta(hours=4)
    principal = _principal("principal.emergency", "break-glass", kind="emergency")
    before = _evaluate(
        _bundle(
            principal,
            _auth(
                "auth.before",
                "break-glass",
                _timestamp(start - timedelta(seconds=1)),
                outcome="success",
            ),
        ),
        "ERP005",
    )
    at_start = _evaluate(
        _bundle(
            principal,
            _auth("auth.start", "break-glass", _timestamp(start), outcome="success"),
        ),
        "ERP005",
    )
    at_end = _evaluate(
        _bundle(
            principal,
            _auth("auth.end", "break-glass", AS_OF, outcome="success"),
        ),
        "ERP005",
    )
    failed_outside = _evaluate(
        _bundle(
            principal,
            _auth("auth.failed", "break-glass", _timestamp(start - timedelta(hours=1))),
        ),
        "ERP005",
    )
    human_outside = _evaluate(
        _bundle(
            _principal("principal.human", "human-user"),
            _auth(
                "auth.human",
                "human-user",
                _timestamp(start - timedelta(hours=1)),
                outcome="success",
            ),
        ),
        "ERP005",
    )

    finding = _one_finding(before)
    assert _ref_fields(finding) == {
        ("principal.emergency", "principal_id"),
        ("principal.emergency", "principal_kind"),
        ("auth.before", "action"),
        ("auth.before", "occurred_at"),
        ("auth.before", "outcome"),
        ("auth.before", "principal_id"),
    }
    assert _finding_dicts(at_start) == ()
    assert _finding_dicts(at_end) == ()
    assert _finding_dicts(failed_outside) == ()
    assert _finding_dicts(human_outside) == ()


def test_erp005_cross_format_join_preserves_every_decisive_field() -> None:
    principal = Principal(
        record_id="principal.emergency.jsonl",
        principal_id="break-glass",
        principal_kind="emergency",
        enabled=True,
        last_active_at=AS_OF,
        source_ref=SourceRef(
            sha256="e" * 64,
            path="principals.jsonl",
            format="jsonl",
            json_pointer=None,
            line=4,
        ),
    )
    event = AuthEvent(
        record_id="auth.emergency.csv",
        principal_id="break-glass",
        action="SIGN_IN",
        outcome="success",
        occurred_at="2026-08-31T19:59:59Z",
        source_ref=SourceRef(
            sha256="f" * 64,
            path="auth.csv",
            format="csv",
            json_pointer=None,
            row=7,
        ),
    )

    finding = _one_finding(_evaluate(_bundle(principal, event), "ERP005"))

    assert _ref_fields(finding) == {
        ("auth.emergency.csv", "action"),
        ("auth.emergency.csv", "occurred_at"),
        ("auth.emergency.csv", "outcome"),
        ("auth.emergency.csv", "principal_id"),
        ("principal.emergency.jsonl", "principal_id"),
        ("principal.emergency.jsonl", "principal_kind"),
    }
    refs = finding["evidence_refs"]
    assert isinstance(refs, list)
    assert all(
        ref["source_ref"].get("row") == 7
        for ref in refs
        if ref["record_id"] == "auth.emergency.csv"
    )
    assert all(
        ref["source_ref"].get("line") == 4
        for ref in refs
        if ref["record_id"] == "principal.emergency.jsonl"
    )


def test_time_based_rules_treat_equivalent_as_of_offsets_identically() -> None:
    records = _bundle(*_matched_records("ERP002"), *_matched_records("ERP005"))
    parameters = _parameters()

    utc_run = rules.evaluate_rules(
        records,
        as_of="2026-09-01T00:00:00Z",
        selected_rule_ids=("ERP002", "ERP005"),
        parameters=parameters,  # type: ignore[arg-type]
    )
    offset_run = rules.evaluate_rules(
        records,
        as_of="2026-09-01T03:00:00+03:00",
        selected_rule_ids=("ERP002", "ERP005"),
        parameters=parameters,  # type: ignore[arg-type]
    )

    assert _finding_dicts(utc_run) == _finding_dicts(offset_run)
    assert _evaluation_values(utc_run) == _evaluation_values(offset_run)


def test_erp006_exact_interval_matches_and_just_over_interval_is_clean() -> None:
    exact_offsets = (
        timedelta(minutes=0),
        timedelta(minutes=3),
        timedelta(minutes=6),
        timedelta(minutes=9),
        timedelta(minutes=15),
    )
    over_offsets = (*exact_offsets[:-1], timedelta(minutes=15, seconds=1))

    matched = _evaluate(_bundle(*_auth_failures("candidate", exact_offsets)), "ERP006")
    clean = _evaluate(_bundle(*_auth_failures("candidate", over_offsets)), "ERP006")

    finding = _one_finding(matched)
    assert _ref_fields(finding) == {
        (f"auth.failure.{index}", field)
        for index in range(1, 6)
        for field in ("action", "occurred_at", "outcome", "principal_id")
    }
    assert _finding_dicts(clean) == ()


def test_erp006_emits_only_earliest_triggering_window_per_principal() -> None:
    offsets = tuple(timedelta(minutes=index) for index in range(10))

    run = _evaluate(_bundle(*_auth_failures("candidate", offsets)), "ERP006")

    finding = _one_finding(run)
    assert _ref_fields(finding) == {
        (f"auth.failure.{index}", field)
        for index in range(1, 6)
        for field in ("action", "occurred_at", "outcome", "principal_id")
    }


def test_erp006_ignores_success_denied_and_non_sign_in_events() -> None:
    start = datetime(2026, 8, 31, 12, tzinfo=UTC)
    records: list[AuthEvent] = [
        _auth(
            f"auth.success.{index}",
            "candidate",
            _timestamp(start + timedelta(minutes=index)),
            outcome="success",
        )
        for index in range(5)
    ]
    records.extend(
        _auth(
            f"auth.denied.{index}",
            "candidate",
            _timestamp(start + timedelta(minutes=index)),
            outcome="denied",
        )
        for index in range(5)
    )
    records.extend(
        AuthEvent(
            record_id=f"auth.other.{index}",
            principal_id="candidate",
            action="AUTHORIZE_ACTION",
            outcome="failure",
            occurred_at=_timestamp(start + timedelta(minutes=index)),
            source_ref=_source_ref(f"auth.other.{index}"),
        )
        for index in range(5)
    )

    run = _evaluate(_bundle(*records), "ERP006")

    assert _finding_dicts(run) == ()
    assert _evaluation_values(run) == (("ERP006", "1.0.0", "not_matched"),)


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_each_rule_is_deterministic_when_evidence_order_is_shuffled(rule_id: str) -> None:
    records = _matched_records(rule_id)

    expected = _evaluate(_bundle(*records), rule_id)

    for ordered_records in permutations(records):
        shuffled = _evaluate(_bundle(*ordered_records), rule_id)
        assert _finding_dicts(expected) == _finding_dicts(shuffled)
        assert _evaluation_values(expected) == _evaluation_values(shuffled)


@pytest.mark.parametrize(
    ("rule_id", "records"),
    [
        ("ERP001", (_control("control.other", control="SESSION_MONITORING", enabled=True),)),
        (
            "ERP002",
            (
                _principal(
                    "principal.old",
                    "candidate",
                    last_active_at=_timestamp(AS_OF_DATETIME - timedelta(days=91)),
                ),
            ),
        ),
        (
            "ERP002",
            (_permission("permission.admin", "candidate", "ADMINISTER_SYSTEM"),),
        ),
        ("ERP003", (_control("control.audit", enabled=True),)),
        ("ERP004", (_control("control.audit", enabled=True),)),
        (
            "ERP005",
            (_principal("principal.emergency", "break-glass", kind="emergency"),),
        ),
        (
            "ERP005",
            (
                _auth(
                    "auth.emergency",
                    "break-glass",
                    "2026-08-31T00:00:00Z",
                    outcome="success",
                ),
            ),
        ),
        ("ERP006", (_principal("principal.regular", "candidate"),)),
    ],
)
def test_selected_rule_never_reports_clean_when_required_evidence_is_missing(
    rule_id: str, records: tuple[object, ...]
) -> None:
    with pytest.raises(IncompleteEvidenceError, match="coverage"):
        _evaluate(_bundle(*records), rule_id)


@pytest.mark.parametrize(
    ("rule_id", "records"),
    [
        (
            "ERP002",
            (
                _principal("principal.unrelated", "known-user"),
                _permission("permission.orphan", "missing-user", "ADMINISTER_SYSTEM"),
            ),
        ),
        (
            "ERP002",
            (
                _principal("principal.first", "ambiguous-user"),
                _principal("principal.second", "ambiguous-user"),
                _permission(
                    "permission.ambiguous",
                    "ambiguous-user",
                    "ADMINISTER_SYSTEM",
                ),
            ),
        ),
        (
            "ERP005",
            (
                _principal("principal.unrelated", "known-user"),
                _auth(
                    "auth.orphan",
                    "missing-user",
                    "2026-08-31T00:00:00Z",
                    outcome="success",
                ),
            ),
        ),
        (
            "ERP005",
            (
                _principal("principal.first", "ambiguous-user", kind="emergency"),
                _principal("principal.second", "ambiguous-user", kind="emergency"),
                _auth(
                    "auth.ambiguous",
                    "ambiguous-user",
                    "2026-08-31T00:00:00Z",
                    outcome="success",
                ),
            ),
        ),
    ],
)
def test_join_rules_fail_closed_on_missing_or_ambiguous_principal(
    rule_id: str, records: tuple[object, ...]
) -> None:
    with pytest.raises(IncompleteEvidenceError, match="coverage"):
        _evaluate(_bundle(*records), rule_id)


def test_all_rule_evaluations_follow_registry_order_and_have_fixed_remediation() -> None:
    records: list[object] = []
    for rule_id in RULE_IDS:
        records.extend(_matched_records(rule_id))

    run = _evaluate(_bundle(*records), *reversed(RULE_IDS))

    assert tuple(value[0] for value in _evaluation_values(run)) == RULE_IDS
    assert {finding["rule_id"] for finding in _finding_dicts(run)} == set(RULE_IDS)
    remediation_by_rule = {
        definition.rule_id: definition.remediation
        for definition in rules.RULE_REGISTRY  # type: ignore[attr-defined]
    }
    assert all(
        finding["remediation"] == remediation_by_rule[finding["rule_id"]]
        for finding in _finding_dicts(run)
    )
