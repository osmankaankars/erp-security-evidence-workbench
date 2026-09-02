"""CLI contracts for explicit rule selection and catalog output."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from erp_security_evidence_workbench.cli import main

SCHEMA = "erpsec.synthetic-evidence/v1"
AS_OF = "2026-09-01T00:00:00Z"
RULE_IDS = ("ERP001", "ERP002", "ERP003", "ERP004", "ERP005", "ERP006")


def _record(record_type: str, record_id: str, **fields: object) -> dict[str, object]:
    return {
        "schema_version": SCHEMA,
        "dataset_classification": "synthetic",
        "record_type": record_type,
        "record_id": record_id,
        **fields,
    }


def _full_pack_payload() -> list[dict[str, object]]:
    payload = [
        _record(
            "control_state",
            "control.audit",
            control="AUDIT_LOGGING",
            enabled=False,
        ),
        _record(
            "principal",
            "principal.old-admin",
            principal_id="old-admin",
            principal_kind="human",
            enabled=True,
            last_active_at="2026-05-01T00:00:00Z",
        ),
        _record(
            "permission_assignment",
            "permission.admin",
            principal_id="old-admin",
            permission="ADMINISTER_SYSTEM",
            assignment_mode="direct",
            assigned_at="2026-01-01T00:00:00Z",
        ),
        _record(
            "permission_assignment",
            "permission.create",
            principal_id="operator",
            permission="CREATE_VENDOR",
            assignment_mode="inherited",
            assigned_at="2026-01-01T00:00:00Z",
        ),
        _record(
            "permission_assignment",
            "permission.approve",
            principal_id="operator",
            permission="APPROVE_PAYMENT",
            assignment_mode="inherited",
            assigned_at="2026-01-01T00:00:00Z",
        ),
        _record(
            "principal",
            "principal.operator",
            principal_id="operator",
            principal_kind="human",
            enabled=True,
            last_active_at="2026-08-31T23:00:00Z",
        ),
        _record(
            "principal",
            "principal.emergency",
            principal_id="break-glass",
            principal_kind="emergency",
            enabled=True,
            last_active_at="2026-08-31T19:59:59Z",
        ),
        _record(
            "auth_event",
            "auth.emergency",
            principal_id="break-glass",
            action="SIGN_IN",
            outcome="success",
            occurred_at="2026-08-31T19:59:59Z",
        ),
    ]
    for index, minute in enumerate((0, 3, 6, 9, 15), start=1):
        payload.append(
            _record(
                "auth_event",
                f"auth.failure.{index}",
                principal_id="locked-user",
                action="SIGN_IN",
                outcome="failure",
                occurred_at=f"2026-08-31T12:{minute:02d}:00Z",
            )
        )
    return payload


def _write_payload(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _analyze(
    input_path: Path,
    output_path: Path,
    *,
    rule_args: tuple[str, ...] = (),
) -> int:
    return _analyze_inputs((input_path,), output_path, rule_args=rule_args)


def _analyze_inputs(
    input_paths: tuple[Path, ...],
    output_path: Path,
    *,
    rule_args: tuple[str, ...] = (),
) -> int:
    return main(
        [
            "analyze",
            *(str(input_path) for input_path in input_paths),
            "--as-of",
            AS_OF,
            "--format",
            "json",
            "--output",
            str(output_path),
            *rule_args,
        ]
    )


def test_rules_command_emits_deterministic_machine_readable_catalog(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["rules"]) == 0
    first = capsys.readouterr()
    assert main(["rules"]) == 0
    second = capsys.readouterr()

    assert first.err == second.err == ""
    assert first.out == second.out
    assert first.out.endswith("\n")
    assert hashlib.sha256(first.out.encode()).hexdigest() == (
        "c196234926d347d153e4796180c3299073665a99372456d3ba83537e9e24f2fc"
    )
    catalog_document = json.loads(first.out)
    assert catalog_document["schema_version"] == "erpsec.rule-catalog/v1"
    catalog = catalog_document["rules"]
    assert [item["rule_id"] for item in catalog] == list(RULE_IDS)
    assert [item["rule_version"] for item in catalog] == ["1.0.0"] * 6
    for item in catalog:
        assert {
            "fixed_conditions",
            "limitation",
            "parameters",
            "remediation",
            "required_evidence_types",
            "rule_id",
            "rule_version",
            "severity",
            "severity_rationale",
            "title",
        } <= set(item)


def test_default_analyze_selection_remains_erp001_only(tmp_path: Path) -> None:
    input_path = tmp_path / "full-pack.json"
    output_path = tmp_path / "default-report.json"
    _write_payload(input_path, _full_pack_payload())

    assert _analyze(input_path, output_path) == 1

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert [evaluation["rule_id"] for evaluation in report["evaluations"]] == ["ERP001"]
    assert {finding["rule_id"] for finding in report["findings"]} == {"ERP001"}


def test_repeatable_rule_option_evaluates_only_explicit_selection(tmp_path: Path) -> None:
    input_path = tmp_path / "full-pack.json"
    output_path = tmp_path / "selected-report.json"
    _write_payload(input_path, _full_pack_payload())

    assert (
        _analyze(
            input_path,
            output_path,
            rule_args=("--rule", "ERP003", "--rule", "ERP002"),
        )
        == 1
    )

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert [evaluation["rule_id"] for evaluation in report["evaluations"]] == [
        "ERP002",
        "ERP003",
    ]
    assert {finding["rule_id"] for finding in report["findings"]} == {"ERP002", "ERP003"}


def test_rule_all_produces_six_evaluations_and_six_scenario_findings(tmp_path: Path) -> None:
    input_path = tmp_path / "full-pack.json"
    output_path = tmp_path / "full-report.json"
    _write_payload(input_path, _full_pack_payload())

    assert _analyze(input_path, output_path, rule_args=("--rule", "all")) == 1

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert [evaluation["rule_id"] for evaluation in report["evaluations"]] == list(RULE_IDS)
    assert all(evaluation["status"] == "matched" for evaluation in report["evaluations"])
    assert len(report["findings"]) == 6
    assert {finding["rule_id"] for finding in report["findings"]} == set(RULE_IDS)


def test_rule_all_missing_required_record_types_never_publishes_partial_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "control-only.json"
    output_path = tmp_path / "partial-report.json"
    _write_payload(
        input_path,
        [
            _record(
                "control_state",
                "control.audit",
                control="AUDIT_LOGGING",
                enabled=True,
            )
        ],
    )

    assert _analyze(input_path, output_path, rule_args=("--rule", "all")) == 2

    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error: ")


@pytest.mark.parametrize(
    "rule_args",
    [
        ("--rule", "all", "--rule", "ERP001"),
        ("--rule", "ERP002", "--rule", "ERP002"),
    ],
)
def test_ambiguous_or_duplicate_rule_selection_fails_without_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    rule_args: tuple[str, ...],
) -> None:
    input_path = tmp_path / "full-pack.json"
    output_path = tmp_path / "invalid-selection-report.json"
    _write_payload(input_path, _full_pack_payload())

    assert _analyze(input_path, output_path, rule_args=rule_args) == 2

    assert not output_path.exists()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error: ")


def test_rule_all_report_is_identical_when_input_records_are_shuffled(tmp_path: Path) -> None:
    first_input = tmp_path / "first.json"
    second_input = tmp_path / "second.json"
    first_output = tmp_path / "first-report.json"
    second_output = tmp_path / "second-report.json"
    payload = _full_pack_payload()
    _write_payload(first_input, payload)
    _write_payload(second_input, list(reversed(payload)))

    assert _analyze(first_input, first_output, rule_args=("--rule", "all")) == 1
    assert _analyze(second_input, second_output, rule_args=("--rule", "all")) == 1

    first = json.loads(first_output.read_text(encoding="utf-8"))
    second = json.loads(second_output.read_text(encoding="utf-8"))
    assert first["evaluations"] == second["evaluations"]
    first_semantic = [
        {key: value for key, value in finding.items() if key != "evidence_refs"}
        for finding in first["findings"]
    ]
    second_semantic = [
        {key: value for key, value in finding.items() if key != "evidence_refs"}
        for finding in second["findings"]
    ]
    assert first_semantic == second_semantic
    assert [
        [
            (ref["record_id"], ref["source_ref"]["json_pointer"].rsplit("/", 1)[-1])
            for ref in finding["evidence_refs"]
        ]
        for finding in first["findings"]
    ] == [
        [
            (ref["record_id"], ref["source_ref"]["json_pointer"].rsplit("/", 1)[-1])
            for ref in finding["evidence_refs"]
        ]
        for finding in second["findings"]
    ]


def test_rule_all_report_bytes_are_identical_when_source_order_is_reversed(
    tmp_path: Path,
) -> None:
    payload = _full_pack_payload()
    input_paths = (
        tmp_path / "a-controls-and-principals.json",
        tmp_path / "m-permissions.json",
        tmp_path / "z-auth-events.json",
    )
    _write_payload(input_paths[0], payload[:4])
    _write_payload(input_paths[1], payload[4:8])
    _write_payload(input_paths[2], payload[8:])
    first_output = tmp_path / "forward-report.json"
    second_output = tmp_path / "reverse-report.json"

    assert (
        _analyze_inputs(
            input_paths,
            first_output,
            rule_args=("--rule", "all"),
        )
        == 1
    )
    assert (
        _analyze_inputs(
            tuple(reversed(input_paths)),
            second_output,
            rule_args=("--rule", "all"),
        )
        == 1
    )

    assert first_output.read_bytes() == second_output.read_bytes()
