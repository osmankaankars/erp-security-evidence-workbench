"""End-to-end scenario replay and failure-contract tests."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from erp_security_evidence_workbench.cli import main
from erp_security_evidence_workbench.ingest import load_evidence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = PROJECT_ROOT / "examples" / "scenarios"
CORPUS_TOOL = PROJECT_ROOT / "scripts" / "synthetic_corpus.py"
AS_OF = "2026-09-01T00:00:00Z"

EXPECTED_SCENARIOS: dict[str, dict[str, object]] = {
    "clean-baseline": {
        "record_count": 4,
        "selected_rules": ("ERP001", "ERP002", "ERP003", "ERP004", "ERP005", "ERP006"),
        "statuses": ("not_matched",) * 6,
        "fingerprints": {},
        "exit_code": 0,
    },
    "access-governance": {
        "record_count": 9,
        "selected_rules": ("ERP002", "ERP003", "ERP004"),
        "statuses": ("matched", "matched", "matched"),
        "fingerprints": {
            "ERP002": "5fcaa53c2b2dfa4876d13b290bfe0466380b073950f65b30919f3c8037f5ef31",
            "ERP003": "ea1222dbc95da3713f7aa4fc325417e90ad5c6de52c902177b5f44c0f9f46125",
            "ERP004": "28cebe7564a901c9ace0646d74373bbd40af951f9ce4b73d72c4d0af8f7aea4e",
        },
        "exit_code": 1,
    },
    "authentication-control": {
        "record_count": 17,
        "selected_rules": ("ERP001", "ERP005", "ERP006"),
        "statuses": ("matched", "matched", "matched"),
        "fingerprints": {
            "ERP001": "5e8e54ccb2d8a4e08413e1c52c0938f2646bc01b767508ba383a8e4dca1eab53",
            "ERP005": "d30f1e317f1680d2e7951e59098e2da7ee33dc5dd4ac46dc6880658dbe9bd7e1",
            "ERP006": "847311517adac28d910ef1cf15a26dbed13a993b17d78eb3cbd15165ef0fb657",
        },
        "exit_code": 1,
    },
}

EXPECTED_EVIDENCE_FIELDS: dict[str, dict[str, set[str]]] = {
    "ERP001": {"control.auth.audit": {"enabled"}},
    "ERP002": {
        "permission.access.stale-admin": {"permission", "principal_id"},
        "principal.access.stale": {"enabled", "last_active_at", "principal_id"},
    },
    "ERP003": {
        "permission.access.direct-admin": {"assignment_mode", "permission"},
    },
    "ERP004": {
        "permission.access.approve-payment": {"permission", "principal_id"},
        "permission.access.create-vendor": {"permission", "principal_id"},
    },
    "ERP005": {
        "auth.emergency.outside": {"action", "occurred_at", "outcome", "principal_id"},
        "principal.auth.emergency": {"principal_id", "principal_kind"},
    },
    "ERP006": {
        f"auth.failure.match.{index}": {"action", "occurred_at", "outcome", "principal_id"}
        for index in range(1, 6)
    },
}


def _manifest() -> dict[str, Any]:
    value = json.loads((CORPUS_ROOT / "manifest.json").read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _scenario(scenario_id: str) -> dict[str, Any]:
    return next(
        scenario for scenario in _manifest()["scenarios"] if scenario["scenario_id"] == scenario_id
    )


def _validation(validation_id: str) -> dict[str, Any]:
    return next(
        case for case in _manifest()["validation_cases"] if case["validation_id"] == validation_id
    )


def _input_paths(item: dict[str, Any]) -> tuple[Path, ...]:
    return tuple(CORPUS_ROOT / relative for relative in item["input_paths"])


def _analyze(
    input_paths: tuple[Path, ...],
    output_path: Path,
    selected_rules: tuple[str, ...],
) -> int:
    arguments = [
        "analyze",
        *(str(path) for path in input_paths),
        "--as-of",
        AS_OF,
        "--format",
        "json",
        "--output",
        str(output_path),
    ]
    if selected_rules == ("ERP001", "ERP002", "ERP003", "ERP004", "ERP005", "ERP006"):
        arguments.extend(("--rule", "all"))
    else:
        for rule_id in selected_rules:
            arguments.extend(("--rule", rule_id))
    return main(arguments)


def _record_projection(report: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for record in report["evidence_manifest"]:
        source_ref = record["source_ref"]
        locator = {
            key: source_ref[key] for key in ("json_pointer", "row", "line") if key in source_ref
        }
        result.append(
            {
                "record_id": record["record_id"],
                "record_type": record["record_type"],
                "source": {"locator": locator, "path": source_ref["path"]},
            }
        )
    return result


def _finding_projection(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "evidence_refs": finding["evidence_refs"],
            "fingerprint": finding["fingerprint"],
            "rule_id": finding["rule_id"],
            "rule_version": finding["rule_version"],
        }
        for finding in report["findings"]
    ]


def _evidence_fields(finding: dict[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for evidence in finding["evidence_refs"]:
        source_ref = evidence["source_ref"]
        field = source_ref.get("field")
        if field is None:
            field = source_ref["json_pointer"].rsplit("/", 1)[-1]
        result[evidence["record_id"]].add(field)
    return dict(result)


@pytest.mark.parametrize("scenario_id", tuple(EXPECTED_SCENARIOS))
def test_scenario_replay_matches_frozen_outcomes_and_manifest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    scenario_id: str,
) -> None:
    frozen = EXPECTED_SCENARIOS[scenario_id]
    scenario = _scenario(scenario_id)
    input_paths = _input_paths(scenario)
    output_path = tmp_path / f"{scenario_id}.json"
    selected_rules = tuple(frozen["selected_rules"])

    exit_code = _analyze(input_paths, output_path, selected_rules)

    assert exit_code == frozen["exit_code"] == scenario["expected"]["exit_code"]
    assert output_path.exists() is scenario["expected"]["output_present"]
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["run"] == {
        "as_of": AS_OF,
        "coverage": "complete",
        "input_count": frozen["record_count"],
        "result": "findings" if frozen["fingerprints"] else "no_findings",
    }
    assert report["evaluations"] == scenario["expected"]["evaluations"]
    assert [evaluation["rule_id"] for evaluation in report["evaluations"]] == list(selected_rules)
    assert tuple(evaluation["status"] for evaluation in report["evaluations"]) == frozen["statuses"]
    assert _record_projection(report) == scenario["expected"]["records"]
    assert _finding_projection(report) == scenario["expected"]["findings"]
    assert {finding["rule_id"]: finding["fingerprint"] for finding in report["findings"]} == (
        frozen["fingerprints"]
    )

    evidence_manifest = {
        record["record_id"]: record["source_ref"] for record in report["evidence_manifest"]
    }
    for finding in report["findings"]:
        assert _evidence_fields(finding) == EXPECTED_EVIDENCE_FIELDS[finding["rule_id"]]
        for evidence in finding["evidence_refs"]:
            record_source = evidence_manifest[evidence["record_id"]]
            field_source = evidence["source_ref"]
            for key in ("adapter", "format", "path", "sha256", "row", "line"):
                if key in record_source:
                    assert field_source[key] == record_source[key]
            if "json_pointer" in record_source:
                assert field_source["json_pointer"].startswith(record_source["json_pointer"])

    source_manifest = {source["path"]: source for source in report["source_manifest"]}
    fixture_by_path = {fixture["path"]: fixture for fixture in _manifest()["fixtures"]}
    assert set(source_manifest) == {path.name for path in input_paths}
    for relative in scenario["input_paths"]:
        fixture = fixture_by_path[relative]
        source = source_manifest[Path(relative).name]
        source_path = CORPUS_ROOT / relative
        assert source == {
            "adapter": f"erpsec.{fixture['format']}/v1",
            "byte_count": fixture["byte_count"],
            "format": fixture["format"],
            "path": source_path.name,
            "record_count": fixture["record_count"],
            "sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        }


@pytest.mark.parametrize("scenario_id", tuple(EXPECTED_SCENARIOS))
def test_scenario_report_bytes_are_stable_when_sources_are_reordered(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    scenario_id: str,
) -> None:
    scenario = _scenario(scenario_id)
    selected_rules = tuple(scenario["selected_rules"])
    inputs = _input_paths(scenario)
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    first_exit = _analyze(inputs, first, selected_rules)
    second_exit = _analyze(tuple(reversed(inputs)), second, selected_rules)

    assert first_exit == second_exit == scenario["expected"]["exit_code"]
    assert first.read_bytes() == second.read_bytes()
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_corpus_pins_time_boundaries_on_both_sides() -> None:
    access = load_evidence(_input_paths(_scenario("access-governance")))
    access_activity = {
        record.last_active_at for record in access.records if record.record_type == "principal"
    }
    assert {"2026-06-02T23:59:59Z", "2026-06-03T00:00:00Z"} <= access_activity

    authentication = load_evidence(_input_paths(_scenario("authentication-control")))
    successful_sign_ins = {
        record.occurred_at
        for record in authentication.records
        if record.record_type == "auth_event"
        and record.action == "SIGN_IN"
        and record.outcome == "success"
    }
    assert {
        "2026-08-31T19:59:59Z",
        "2026-08-31T20:00:00Z",
        "2026-09-01T00:00:00Z",
    } <= successful_sign_ins

    failures_by_principal: dict[str, list[datetime]] = defaultdict(list)
    for record in authentication.records:
        if (
            record.record_type == "auth_event"
            and record.action == "SIGN_IN"
            and record.outcome == "failure"
        ):
            failures_by_principal[record.principal_id].append(
                datetime.fromisoformat(record.occurred_at.replace("Z", "+00:00"))
            )
    spans = {
        int((max(values) - min(values)).total_seconds())
        for values in failures_by_principal.values()
        if len(values) == 5
    }
    assert {15 * 60, 15 * 60 + 1} <= spans


@pytest.mark.parametrize(
    "validation_id",
    ("malformed-tail", "incomplete-principal", "adversarial-extra-field"),
)
def test_validation_replays_fail_closed_without_raw_diagnostic_leakage(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    validation_id: str,
) -> None:
    case = _validation(validation_id)
    input_paths = _input_paths(case)
    output_path = tmp_path / f"{validation_id}.json"
    before = {path: path.read_bytes() for path in input_paths}

    exit_code = _analyze(input_paths, output_path, tuple(case["selected_rules"]))

    assert exit_code == case["expected"]["exit_code"] == 2
    assert output_path.exists() is case["expected"]["output_present"] is False
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []
    assert {path: path.read_bytes() for path in input_paths} == before
    captured = capsys.readouterr()
    assert captured.out == ""
    documented = case["expected"]["diagnostic"]
    expected_diagnostic = documented if documented.endswith("\n") else f"{documented}\n"
    assert captured.err == expected_diagnostic
    assert captured.err.startswith("error: ")
    assert captured.err.count("\n") == 1
    assert "Traceback" not in captured.err
    assert "\x1b" not in captured.err
    for excluded in case["expected"]["diagnostic_excludes"]:
        assert excluded not in captured.err


def test_json_report_escapes_a_valid_quoted_source_basename(tmp_path: Path) -> None:
    clean = _scenario("clean-baseline")
    source = next(
        CORPUS_ROOT / relative for relative in clean["input_paths"] if relative.endswith(".json")
    )
    quoted_source = tmp_path / 'synthetic-"quoted".json'
    quoted_source.write_bytes(source.read_bytes())
    output_path = tmp_path / "quoted-report.json"

    exit_code = _analyze((quoted_source,), output_path, ("ERP001",))

    assert exit_code == 0
    report_bytes = output_path.read_bytes()
    assert b'synthetic-\\"quoted\\".json' in report_bytes
    report = json.loads(report_bytes)
    assert report["source_manifest"][0]["path"] == quoted_source.name


def test_replay_command_verifies_the_committed_manifest() -> None:
    assert CORPUS_TOOL.is_file(), "synthetic corpus tool has not been implemented"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")

    result = subprocess.run(
        [
            sys.executable,
            str(CORPUS_TOOL),
            "replay",
            "--manifest",
            str(CORPUS_ROOT / "manifest.json"),
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
