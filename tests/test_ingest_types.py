from __future__ import annotations

import json
from pathlib import Path

from erp_security_evidence_workbench.ingest import load_evidence
from erp_security_evidence_workbench.models import canonical_record_data

SCHEMA = "erpsec.synthetic-evidence/v1"


def test_all_six_record_types_normalize_to_fixed_typed_contracts(tmp_path: Path) -> None:
    input_path = tmp_path / "all-types.json"
    payloads = [
        {
            "schema_version": SCHEMA,
            "dataset_classification": "synthetic",
            "record_type": "principal",
            "record_id": "principal.1",
            "principal_id": "user.1",
            "principal_kind": "human",
            "enabled": True,
            "last_active_at": "2026-09-01T03:00:00+03:00",
        },
        {
            "schema_version": SCHEMA,
            "dataset_classification": "synthetic",
            "record_type": "role_assignment",
            "record_id": "role-assignment.1",
            "principal_id": "user.1",
            "role_id": "role.reviewer",
            "assignment_mode": "direct",
            "assigned_at": "2026-09-01T00:00:00Z",
        },
        {
            "schema_version": SCHEMA,
            "dataset_classification": "synthetic",
            "record_type": "permission_assignment",
            "record_id": "permission-assignment.1",
            "principal_id": "user.1",
            "permission": "REVIEW_DOCUMENT",
            "assignment_mode": "inherited",
            "assigned_at": "2026-09-01T00:00:00Z",
        },
        {
            "schema_version": SCHEMA,
            "dataset_classification": "synthetic",
            "record_type": "auth_event",
            "record_id": "auth.1",
            "principal_id": "user.1",
            "action": "SIGN_IN",
            "outcome": "success",
            "occurred_at": "2026-09-01T00:00:00Z",
        },
        {
            "schema_version": SCHEMA,
            "dataset_classification": "synthetic",
            "record_type": "change_event",
            "record_id": "change.1",
            "principal_id": "user.1",
            "object_id": "document.1",
            "action": "UPDATE_DOCUMENT",
            "outcome": "success",
            "occurred_at": "2026-09-01T00:00:00Z",
        },
        {
            "schema_version": SCHEMA,
            "dataset_classification": "synthetic",
            "record_type": "control_state",
            "record_id": "control.1",
            "control": "AUDIT_LOGGING",
            "enabled": False,
        },
    ]
    input_path.write_text(json.dumps(payloads), encoding="utf-8")

    bundle = load_evidence([input_path])

    records = [canonical_record_data(record) for record in bundle.records]
    assert [record["record_type"] for record in records] == [
        "auth_event",
        "change_event",
        "control_state",
        "permission_assignment",
        "principal",
        "role_assignment",
    ]
    principal = next(record for record in records if record["record_type"] == "principal")
    assert principal["last_active_at"] == "2026-09-01T00:00:00Z"
    pointers = {
        record.record_id: record.source_ref.to_dict()["json_pointer"] for record in bundle.records
    }
    assert pointers == {
        "auth.1": "/3",
        "change.1": "/4",
        "control.1": "/5",
        "permission-assignment.1": "/2",
        "principal.1": "/0",
        "role-assignment.1": "/1",
    }
    assert all(not hasattr(record, "raw_payload") for record in bundle.records)


def test_generated_event_id_is_format_and_timezone_independent(tmp_path: Path) -> None:
    json_path = tmp_path / "event.json"
    jsonl_path = tmp_path / "event.jsonl"
    utc_event = {
        "schema_version": SCHEMA,
        "dataset_classification": "synthetic",
        "record_type": "auth_event",
        "principal_id": "user.1",
        "action": "SIGN_IN",
        "outcome": "failure",
        "occurred_at": "2026-09-01T00:00:00Z",
    }
    offset_event = {**utc_event, "occurred_at": "2026-09-01T03:00:00+03:00"}
    json_path.write_text(json.dumps([utc_event]), encoding="utf-8")
    jsonl_path.write_text(json.dumps(offset_event) + "\n", encoding="utf-8")

    json_record = load_evidence([json_path]).records[0]
    jsonl_record = load_evidence([jsonl_path]).records[0]

    assert json_record.record_id == jsonl_record.record_id
    assert json_record.record_id.startswith("auto:auth_event:")
    assert canonical_record_data(json_record) == canonical_record_data(jsonl_record)
