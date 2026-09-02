"""CLI and report integration contracts for multi-format evidence."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest

from erp_security_evidence_workbench.cli import main

INPUT_SCHEMA_VERSION = "erpsec.synthetic-evidence/v1"
AS_OF = "2026-09-01T00:00:00Z"
CONTROL_ID = "control.audit.disabled"
PRINCIPAL_ID = "principal.fixture-persona-alpha"

CONTROL_PAYLOAD: dict[str, object] = {
    "schema_version": INPUT_SCHEMA_VERSION,
    "dataset_classification": "synthetic",
    "record_type": "control_state",
    "record_id": CONTROL_ID,
    "control": "AUDIT_LOGGING",
    "enabled": False,
}

PRINCIPAL_PAYLOAD: dict[str, object] = {
    "schema_version": INPUT_SCHEMA_VERSION,
    "dataset_classification": "synthetic",
    "record_type": "principal",
    "record_id": PRINCIPAL_ID,
    "principal_id": "fixture-persona-alpha",
    "principal_kind": "human",
    "enabled": True,
    "last_active_at": "2026-09-01T00:00:00Z",
}


def _compact_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _csv_record(payload: dict[str, object]) -> bytes:
    if payload["record_type"] == "control_state":
        return (
            "schema_version,dataset_classification,record_type,record_id,control,enabled\n"
            f"{INPUT_SCHEMA_VERSION},synthetic,control_state,{CONTROL_ID},"
            "AUDIT_LOGGING,false\n"
        ).encode()
    if payload["record_type"] == "principal":
        return (
            "schema_version,dataset_classification,record_type,record_id,principal_id,"
            "principal_kind,enabled,last_active_at\n"
            f"{INPUT_SCHEMA_VERSION},synthetic,principal,{PRINCIPAL_ID},fixture-persona-alpha,human,true,"
            "2026-09-01T00:00:00Z\n"
        ).encode()
    raise AssertionError("test fixture record type is unsupported")


def _format_record(source_format: str, payload: dict[str, object]) -> bytes:
    if source_format == "json":
        return _compact_json([payload])
    if source_format == "jsonl":
        return _compact_json(payload)
    if source_format == "csv":
        return _csv_record(payload)
    raise AssertionError("test fixture format is unsupported")


def _write_record(path: Path, source_format: str, payload: dict[str, object]) -> bytes:
    content = _format_record(source_format, payload)
    path.write_bytes(content)
    return content


def _analyze(inputs: list[Path], output_path: Path) -> int:
    return main(
        [
            "analyze",
            *(str(path) for path in inputs),
            "--as-of",
            AS_OF,
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )


@pytest.mark.parametrize(
    ("source_format", "record_locator", "field_locator"),
    [
        ("json", {"json_pointer": "/0"}, {"json_pointer": "/0/enabled"}),
        ("csv", {"row": 2}, {"row": 2, "field": "enabled"}),
        ("jsonl", {"line": 1}, {"line": 1, "field": "enabled"}),
    ],
)
def test_analyze_each_slice_three_format_reports_exact_record_and_field_provenance(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    source_format: str,
    record_locator: dict[str, object],
    field_locator: dict[str, object],
) -> None:
    input_path = tmp_path / f"control.{source_format}"
    output_path = tmp_path / f"{source_format}-report.json"
    input_bytes = _write_record(input_path, source_format, CONTROL_PAYLOAD)
    digest = hashlib.sha256(input_bytes).hexdigest()
    common_source = {
        "adapter": f"erpsec.{source_format}/v1",
        "format": source_format,
        "path": input_path.name,
        "sha256": digest,
    }

    assert _analyze([input_path], output_path) == 1

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["evidence_manifest"] == [
        {
            "record_id": CONTROL_ID,
            "record_type": "control_state",
            "source_ref": {**common_source, **record_locator},
        }
    ]
    assert report["findings"][0]["evidence_refs"] == [
        {
            "record_id": CONTROL_ID,
            "source_ref": {**common_source, **field_locator},
        }
    ]
    assert report["source_manifest"] == [
        {
            "adapter": f"erpsec.{source_format}/v1",
            "byte_count": len(input_bytes),
            "format": source_format,
            "path": input_path.name,
            "record_count": 1,
            "sha256": digest,
        }
    ]
    assert str(tmp_path) not in output_path.read_text(encoding="utf-8")
    assert capsys.readouterr().out == ""


def test_plural_input_order_produces_byte_identical_reports(tmp_path: Path) -> None:
    principal_path = tmp_path / "a-principal.json"
    control_path = tmp_path / "z-control.csv"
    first_output = tmp_path / "first-report.json"
    second_output = tmp_path / "second-report.json"
    _write_record(principal_path, "json", PRINCIPAL_PAYLOAD)
    _write_record(control_path, "csv", CONTROL_PAYLOAD)

    assert _analyze([control_path, principal_path], first_output) == 1
    assert _analyze([principal_path, control_path], second_output) == 1

    assert first_output.read_bytes() == second_output.read_bytes()
    report = json.loads(first_output.read_text(encoding="utf-8"))
    assert [source["path"] for source in report["source_manifest"]] == [
        principal_path.name,
        control_path.name,
    ]


def test_later_invalid_source_fails_transactionally_without_report_or_temp_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    valid_path = tmp_path / "first-valid.json"
    invalid_path = tmp_path / "second-invalid.jsonl"
    output_path = tmp_path / "report.json"
    _write_record(valid_path, "json", CONTROL_PAYLOAD)
    invalid_path.write_bytes(_compact_json(PRINCIPAL_PAYLOAD) + b'{"schema_version":')

    assert _analyze([valid_path, invalid_path], output_path) == 2

    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []
    assert capsys.readouterr().err.startswith("error: ")


def test_output_alias_against_second_input_is_rejected_before_analysis(
    tmp_path: Path,
) -> None:
    first_path = tmp_path / "first-principal.json"
    second_path = tmp_path / "second-control.jsonl"
    first_bytes = _write_record(first_path, "json", PRINCIPAL_PAYLOAD)
    second_bytes = _write_record(second_path, "jsonl", CONTROL_PAYLOAD)

    assert _analyze([first_path, second_path], second_path) == 2

    assert first_path.read_bytes() == first_bytes
    assert second_path.read_bytes() == second_bytes
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


def test_principal_and_control_mixed_json_bundle_is_evaluable(tmp_path: Path) -> None:
    input_path = tmp_path / "mixed.json"
    output_path = tmp_path / "mixed-report.json"
    input_path.write_bytes(_compact_json([PRINCIPAL_PAYLOAD, CONTROL_PAYLOAD]))

    assert _analyze([input_path], output_path) == 1

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["run"]["input_count"] == 2
    assert [(item["record_type"], item["record_id"]) for item in report["evidence_manifest"]] == [
        ("control_state", CONTROL_ID),
        ("principal", PRINCIPAL_ID),
    ]
    assert report["findings"][0]["evidence_refs"][0]["record_id"] == CONTROL_ID
    assert report["source_manifest"][0]["record_count"] == 2


def test_principal_only_bundle_exits_two_without_publishing_a_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "principal-only.json"
    output_path = tmp_path / "report.json"
    _write_record(input_path, "json", PRINCIPAL_PAYLOAD)

    assert _analyze([input_path], output_path) == 2

    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []
    assert capsys.readouterr().err.startswith("error: ")


@pytest.mark.parametrize("source_format", ["json", "csv", "jsonl"])
def test_analysis_preserves_input_bytes_mode_and_mtime(tmp_path: Path, source_format: str) -> None:
    input_path = tmp_path / f"immutable-control.{source_format}"
    output_path = tmp_path / f"{source_format}-report.json"
    original_bytes = _write_record(input_path, source_format, CONTROL_PAYLOAD)
    input_path.chmod(0o640)
    before = input_path.stat()

    assert _analyze([input_path], output_path) == 1

    after = input_path.stat()
    assert input_path.read_bytes() == original_bytes
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
    assert after.st_mtime_ns == before.st_mtime_ns
