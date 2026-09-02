"""Report-minimization and evaluation-budget contracts."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from erp_security_evidence_workbench import rules
from erp_security_evidence_workbench.cli import main
from erp_security_evidence_workbench.errors import InputValidationError
from erp_security_evidence_workbench.ingest import load_evidence
from erp_security_evidence_workbench.rules import evaluate_rules

SCHEMA = "erpsec.synthetic-evidence/v1"
AS_OF = "2026-09-01T00:00:00Z"
CANARY = "ghp_SYNTHETIC_CREDENTIAL_CANARY_1234567890"


def _permission(record_id: str, permission: str, *, principal_id: str = "persona.alpha") -> dict:
    return {
        "schema_version": SCHEMA,
        "dataset_classification": "synthetic",
        "record_type": "permission_assignment",
        "record_id": record_id,
        "principal_id": principal_id,
        "permission": permission,
        "assignment_mode": "direct",
        "assigned_at": "2026-08-01T00:00:00Z",
    }


def _write_records(path: Path, records: list[dict]) -> bytes:
    content = (json.dumps(records, indent=2, sort_keys=True) + "\n").encode("ascii")
    path.write_bytes(content)
    return content


def _analyze(input_path: Path, output_path: Path, *, report_format: str, rule_id: str) -> int:
    return main(
        [
            "analyze",
            str(input_path),
            "--as-of",
            AS_OF,
            "--format",
            report_format,
            "--output",
            str(output_path),
            "--rule",
            rule_id,
        ]
    )


def test_custom_rule_fanout_over_evidence_reference_budget_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_path = tmp_path / "permissions.json"
    input_bytes = _write_records(
        input_path,
        [
            _permission("permission.create", "CREATE_VENDOR"),
            _permission("permission.approve", "APPROVE_PAYMENT"),
        ],
    )
    original_stat = input_path.stat()
    bundle = load_evidence((input_path,))
    monkeypatch.setattr(rules, "MAX_FINDING_EVIDENCE_REFS", 3, raising=False)

    with pytest.raises(InputValidationError, match="rule evaluation exceeds"):
        evaluate_rules(bundle, as_of=AS_OF, selected_rule_ids=("ERP004",))

    final_stat = input_path.stat()
    assert input_path.read_bytes() == input_bytes
    assert stat.S_IMODE(final_stat.st_mode) == stat.S_IMODE(original_stat.st_mode)
    assert final_stat.st_mtime_ns == original_stat.st_mtime_ns


def test_evidence_reference_budget_accepts_its_exact_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_path = tmp_path / "permissions.json"
    _write_records(
        input_path,
        [
            _permission("permission.create", "CREATE_VENDOR"),
            _permission("permission.approve", "APPROVE_PAYMENT"),
        ],
    )
    bundle = load_evidence((input_path,))
    monkeypatch.setattr(rules, "MAX_FINDING_EVIDENCE_REFS", 4, raising=False)

    run = evaluate_rules(bundle, as_of=AS_OF, selected_rule_ids=("ERP004",))

    assert len(run.findings) == 1
    assert len(run.findings[0].supporting_evidence) == 4


def test_budget_failure_through_cli_publishes_no_final_or_temporary_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    input_path = tmp_path / "permissions.json"
    output_path = tmp_path / "report.json"
    input_bytes = _write_records(
        input_path,
        [
            _permission("permission.create", "CREATE_VENDOR"),
            _permission("permission.approve", "APPROVE_PAYMENT"),
        ],
    )
    original_stat = input_path.stat()
    monkeypatch.setattr(rules, "MAX_FINDING_EVIDENCE_REFS", 3, raising=False)

    assert _analyze(input_path, output_path, report_format="json", rule_id="ERP004") == 2

    assert capsys.readouterr().err == (
        "error: rule evaluation exceeds the evidence-reference limit\n"
    )
    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []
    final_stat = input_path.stat()
    assert input_path.read_bytes() == input_bytes
    assert stat.S_IMODE(final_stat.st_mode) == stat.S_IMODE(original_stat.st_mode)
    assert final_stat.st_mtime_ns == original_stat.st_mtime_ns


@pytest.mark.parametrize("report_format", ["json", "html", "sarif"])
def test_semantic_credential_like_value_is_not_emitted_in_reports(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    report_format: str,
) -> None:
    input_path = tmp_path / "synthetic-permission.json"
    output_path = tmp_path / f"report.{report_format}"
    _write_records(
        input_path,
        [
            _permission(
                "permission.synthetic.admin",
                "ADMINISTER_SYSTEM",
                principal_id=CANARY,
            )
        ],
    )

    assert _analyze(input_path, output_path, report_format=report_format, rule_id="ERP003") == 1

    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert CANARY.encode("ascii") not in output_path.read_bytes()


@pytest.mark.parametrize("report_format", ["json", "html", "sarif"])
def test_explicit_record_id_remains_reportable_provenance_even_when_token_shaped(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    report_format: str,
) -> None:
    input_path = tmp_path / "synthetic-permission.json"
    output_path = tmp_path / f"report.{report_format}"
    _write_records(
        input_path,
        [_permission(CANARY, "ADMINISTER_SYSTEM", principal_id="persona.alpha")],
    )

    assert _analyze(input_path, output_path, report_format=report_format, rule_id="ERP003") == 1

    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert CANARY.encode("ascii") in output_path.read_bytes()


def test_credential_like_provenance_is_not_echoed_in_fatal_diagnostic(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    input_path = tmp_path / f"{CANARY}.json"
    output_path = tmp_path / "report.json"
    _write_records(
        input_path,
        [
            {
                "schema_version": SCHEMA,
                "dataset_classification": "synthetic",
                "record_type": "principal",
                "record_id": CANARY,
                "principal_id": "persona.alpha",
                "principal_kind": "human",
                "enabled": True,
                "last_active_at": "2026-08-01T00:00:00Z",
            }
        ],
    )

    assert _analyze(input_path, output_path, report_format="json", rule_id="ERP002") == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: evidence coverage is incomplete\n"
    assert CANARY not in captured.err
    assert not output_path.exists()


def test_clean_sarif_artifact_contains_only_allowlisted_provenance(tmp_path: Path) -> None:
    input_path = tmp_path / "audit-enabled.json"
    output_path = tmp_path / "report.sarif"
    _write_records(
        input_path,
        [
            {
                "schema_version": SCHEMA,
                "dataset_classification": "synthetic",
                "record_type": "control_state",
                "record_id": "control.audit.enabled",
                "control": "AUDIT_LOGGING",
                "enabled": True,
            }
        ],
    )

    assert _analyze(input_path, output_path, report_format="sarif", rule_id="ERP001") == 0

    document = json.loads(output_path.read_text(encoding="utf-8"))
    run = document["runs"][0]
    assert run["results"] == []
    assert len(run["artifacts"]) == 1
    artifact = run["artifacts"][0]
    assert set(artifact) == {"hashes", "length", "location", "properties", "roles"}
    assert set(artifact["properties"]) == {
        "erpsec.adapter",
        "erpsec.format",
        "erpsec.recordCount",
    }
    assert artifact["location"] == {"index": 0, "uri": input_path.name}
    serialized = json.dumps(artifact, sort_keys=True)
    assert "control.audit.enabled" not in serialized
    assert str(tmp_path) not in serialized
