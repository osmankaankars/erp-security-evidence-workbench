"""Contract tests for canonical evidence records and provenance."""

from __future__ import annotations

import pytest

from erp_security_evidence_workbench.models import (
    ControlState,
    Principal,
    SourceRef,
    canonical_record_data,
)

SHA256 = "a" * 64


def test_json_source_ref_separates_record_and_field_provenance() -> None:
    source_ref = SourceRef(
        sha256=SHA256,
        path="evidence.json",
        json_pointer="/0",
    )

    assert source_ref.to_dict() == {
        "adapter": "erpsec.json/v1",
        "format": "json",
        "json_pointer": "/0",
        "path": "evidence.json",
        "sha256": SHA256,
    }
    assert source_ref.to_dict(field="enabled")["json_pointer"] == "/0/enabled"
    assert source_ref.to_dict(field="a/b~c")["json_pointer"] == "/0/a~1b~0c"

    legacy_field_ref = SourceRef(
        sha256=SHA256,
        path="legacy.json",
        json_pointer="/enabled",
    )
    assert legacy_field_ref.to_dict(field="enabled")["json_pointer"] == "/enabled"


@pytest.mark.parametrize(
    ("source_ref", "locator", "value"),
    [
        (
            SourceRef(
                sha256=SHA256,
                path="evidence.csv",
                format="csv",
                json_pointer=None,
                row=2,
            ),
            "row",
            2,
        ),
        (
            SourceRef(
                sha256=SHA256,
                path="evidence.jsonl",
                format="jsonl",
                json_pointer=None,
                line=1,
            ),
            "line",
            1,
        ),
    ],
)
def test_tabular_source_ref_refines_with_field(
    source_ref: SourceRef, locator: str, value: int
) -> None:
    assert source_ref.to_dict()[locator] == value
    assert "field" not in source_ref.to_dict()
    assert source_ref.to_dict(field="enabled")["field"] == "enabled"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"json_pointer": None},
        {"row": 2},
        {"json_pointer": "", "line": 1},
        {"format": "csv", "json_pointer": "", "row": 2},
    ],
)
def test_source_ref_requires_one_format_matching_locator(kwargs: object) -> None:
    assert isinstance(kwargs, dict)
    with pytest.raises(ValueError, match="locator"):
        SourceRef(sha256=SHA256, path="evidence.json", **kwargs)


def test_control_state_keeps_slice_two_constructor_and_refines_finding_field() -> None:
    source_ref = SourceRef(sha256=SHA256, path="control.json")
    record = ControlState("control-1", "AUDIT_LOGGING", False, source_ref)

    assert record.record_type == "control_state"
    assert record.schema_version == "erpsec.synthetic-evidence/v1"
    assert record.source_ref.to_dict()["json_pointer"] == ""
    assert record.source_ref.to_dict(field="enabled")["json_pointer"] == "/enabled"


def test_canonical_record_data_excludes_source_provenance() -> None:
    record = Principal(
        record_id="principal-1",
        principal_id="user-1",
        principal_kind="human",
        enabled=True,
        last_active_at="2026-09-01T12:34:56Z",
        source_ref=SourceRef(sha256=SHA256, path="principal.json"),
    )

    assert canonical_record_data(record) == {
        "enabled": True,
        "last_active_at": "2026-09-01T12:34:56Z",
        "principal_id": "user-1",
        "principal_kind": "human",
        "record_id": "principal-1",
        "record_type": "principal",
        "schema_version": "erpsec.synthetic-evidence/v1",
    }
