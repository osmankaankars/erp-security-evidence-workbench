"""Deterministic input and observed-performance contracts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, NoReturn

import pytest

from erp_security_evidence_workbench.ingest import load_evidence
from erp_security_evidence_workbench.rules import ALL_RULE_IDS, evaluate_rules
from scripts import observed_performance

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOL = PROJECT_ROOT / "scripts" / "observed_performance.py"
MANIFEST_PATH = PROJECT_ROOT / "benchmarks" / "observed-performance-v1.json"
AS_OF = "2026-09-01T00:00:00Z"
EXPECTED_RECORD_TYPES = {
    "auth_event": 200,
    "change_event": 200,
    "control_state": 50,
    "permission_assignment": 150,
    "principal": 150,
    "role_assignment": 150,
}
EXPECTED_EVIDENCE_REFERENCE_COUNTS = {
    "ERP001": 1,
    "ERP002": 5,
    "ERP003": 2,
    "ERP004": 4,
    "ERP005": 6,
    "ERP006": 20,
}
EXPECTED_FINGERPRINTS = {
    "ERP001": "52976c0de19409a63081f221614654a5ab84f058803a60fe4ef9e6ee20d63e37",
    "ERP002": "2736b4e4225cc5176df94eb1aa1028aa101ceb8aa7bd4ef8eeedbe1868ca11e1",
    "ERP003": "5250308d96df7b99e507635cd1c5236f0b644094d318cacc4dc829af39ddf2e5",
    "ERP004": "957680236cc65d5fc4db1b907824be1c01ee48655ee7687d2a034a866c99fd1b",
    "ERP005": "0cc13bcc7c820096ceab39a0e689d726ad8c499db25dc191f271bf6eeba53343",
    "ERP006": "fc4ac80e3e4ef528755328b2e6c6eb9d31b265714b8b57d69e192e83ffc8cee6",
}


def _run_tool(*arguments: str) -> subprocess.CompletedProcess[str]:
    assert TOOL.is_file(), "observed-performance tool has not been implemented"
    return subprocess.run(
        [sys.executable, str(TOOL), *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )


def _manifest() -> dict[str, Any]:
    value = json.loads(MANIFEST_PATH.read_text(encoding="ascii"))
    assert isinstance(value, dict)
    return value


def _records(content: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in content.decode("ascii").splitlines()]


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def test_generate_is_byte_deterministic_bounded_and_manifested(tmp_path: Path) -> None:
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"

    first_result = _run_tool("generate", "--output", str(first))
    second_result = _run_tool("generate", "--output", str(second))

    assert first_result.returncode == second_result.returncode == 0
    assert first_result.stdout == second_result.stdout == "synthetic measurement input generated\n"
    assert first_result.stderr == second_result.stderr == ""
    first_bytes = first.read_bytes()
    assert first_bytes == second.read_bytes()
    assert first_bytes.endswith(b"\n")
    assert b"\r" not in first_bytes
    assert len(first_bytes) < 1024 * 1024
    assert max(len(line) for line in first_bytes.splitlines()) < 64 * 1024
    assert stat.S_IMODE(first.stat().st_mode) == 0o600

    records = _records(first_bytes)
    assert len(records) == 900
    assert Counter(record["record_type"] for record in records) == EXPECTED_RECORD_TYPES
    assert {record["dataset_classification"] for record in records} == {"synthetic"}
    assert len({record["record_id"] for record in records}) == len(records)

    manifest = _manifest()
    assert set(manifest) == {
        "as_of",
        "byte_count",
        "claims_boundary",
        "dataset_classification",
        "expected",
        "format",
        "generator",
        "max_line_bytes",
        "origin",
        "record_count",
        "record_type_counts",
        "scenario_id",
        "schema_version",
        "selected_rules",
        "sha256",
    }
    assert manifest["schema_version"] == "erpsec.observed-performance-scenario/v1"
    assert manifest["scenario_id"] == "large-balanced-jsonl-v1"
    assert manifest["as_of"] == AS_OF
    assert manifest["selected_rules"] == list(ALL_RULE_IDS)
    assert manifest["record_count"] == len(records)
    assert manifest["record_type_counts"] == EXPECTED_RECORD_TYPES
    assert manifest["byte_count"] == len(first_bytes)
    assert manifest["max_line_bytes"] == max(len(line) for line in first_bytes.splitlines())
    assert manifest["sha256"] == _sha256(first_bytes)
    assert manifest["generator"] == {
        "path": "scripts/observed_performance.py",
        "version": "1.0.0",
    }
    assert manifest["origin"].startswith("First-principles deterministic generator")
    assert "not an SLA" in manifest["claims_boundary"]


def test_generate_refuses_an_existing_path_without_changing_it(tmp_path: Path) -> None:
    output = tmp_path / "existing.jsonl"
    original = b"keep-this-byte-for-byte\n"
    output.write_bytes(original)
    before = output.stat()

    result = _run_tool("generate", "--output", str(output))

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "error: invalid observed-performance operation\n"
    assert output.read_bytes() == original
    after = output.stat()
    assert after.st_mtime_ns == before.st_mtime_ns
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)


def test_check_is_read_only_and_rejects_byte_drift(tmp_path: Path) -> None:
    generated = tmp_path / "scenario.jsonl"
    assert _run_tool("generate", "--output", str(generated)).returncode == 0
    original = generated.read_bytes()
    before = generated.stat()

    accepted = _run_tool("check", "--input", str(generated))

    assert accepted.returncode == 0
    assert accepted.stdout == "synthetic measurement input verified\n"
    assert accepted.stderr == ""
    after = generated.stat()
    assert generated.read_bytes() == original
    assert after.st_mtime_ns == before.st_mtime_ns
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)

    drifted = tmp_path / "drifted.jsonl"
    drifted.write_bytes(original + b"\n")
    drifted_before = drifted.stat()
    rejected = _run_tool("check", "--input", str(drifted))

    assert rejected.returncode == 1
    assert rejected.stdout == ""
    assert rejected.stderr == "error: synthetic measurement input mismatch\n"
    assert drifted.read_bytes() == original + b"\n"
    assert drifted.stat().st_mtime_ns == drifted_before.st_mtime_ns


def test_frozen_scenario_has_exact_low_fanout_six_rule_outcome(tmp_path: Path) -> None:
    generated = tmp_path / "scenario.jsonl"
    assert _run_tool("generate", "--output", str(generated)).returncode == 0

    bundle = load_evidence((generated,))
    run = evaluate_rules(bundle, as_of=AS_OF, selected_rule_ids=ALL_RULE_IDS)

    assert len(bundle.records) == 900
    assert [(item.rule_id, item.status) for item in run.evaluations] == [
        (rule_id, "matched") for rule_id in ALL_RULE_IDS
    ]
    assert Counter(finding.rule_id for finding in run.findings) == {
        rule_id: 1 for rule_id in ALL_RULE_IDS
    }
    evidence_counts = {
        finding.rule_id: (len(finding.supporting_evidence) if finding.supporting_evidence else 1)
        for finding in run.findings
    }
    assert evidence_counts == EXPECTED_EVIDENCE_REFERENCE_COUNTS
    assert sum(evidence_counts.values()) == 38
    assert {
        finding.rule_id: finding.fingerprint for finding in run.findings
    } == EXPECTED_FINGERPRINTS

    manifest = _manifest()
    assert manifest["expected"]["cli_exit_code"] == 1
    assert manifest["expected"]["evaluations"] == [
        {"rule_id": rule_id, "status": "matched"} for rule_id in ALL_RULE_IDS
    ]
    assert {
        finding["rule_id"]: finding["evidence_reference_count"]
        for finding in manifest["expected"]["findings"]
    } == EXPECTED_EVIDENCE_REFERENCE_COUNTS
    assert {
        finding["rule_id"]: finding["fingerprint"] for finding in manifest["expected"]["findings"]
    } == EXPECTED_FINGERPRINTS


def test_generated_scenario_contains_only_generic_synthetic_material(tmp_path: Path) -> None:
    generated = tmp_path / "scenario.jsonl"
    assert _run_tool("generate", "--output", str(generated)).returncode == 0
    content = generated.read_bytes()
    lowered = content.lower()

    prohibited = (
        b"@",
        b"http://",
        b"https://",
        b"exampleproduct",
        b"oracle",
        b"password",
        b"sap",
        b"fictionalcorp",
        b"token",
    )
    assert all(value not in lowered for value in prohibited)
    assert re.search(rb"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", content) is None


def test_measure_records_fresh_process_observations_for_all_formats(tmp_path: Path) -> None:
    input_path = tmp_path / "large-balanced-jsonl-v1.jsonl"
    output_path = tmp_path / "measurement.json"
    assert _run_tool("generate", "--output", str(input_path)).returncode == 0

    result = _run_tool(
        "measure",
        "--python",
        sys.executable,
        "--input",
        str(input_path),
        "--output",
        str(output_path),
        "--warmups",
        "0",
        "--samples",
        "1",
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "observed performance measurement recorded\n"
    assert result.stderr == ""
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600
    document = json.loads(output_path.read_text(encoding="ascii"))
    assert set(document) == {
        "claims_boundary",
        "environment",
        "protocol",
        "results",
        "scenario",
        "schema_version",
    }
    assert document["schema_version"] == "erpsec.observed-performance/v1"
    assert "not an SLA" in document["claims_boundary"]
    assert document["scenario"] == {
        "as_of": AS_OF,
        "byte_count": _manifest()["byte_count"],
        "record_count": 900,
        "scenario_id": "large-balanced-jsonl-v1",
        "selected_rules": list(ALL_RULE_IDS),
        "sha256": _manifest()["sha256"],
    }
    assert set(document["environment"]) == {
        "cpu_count",
        "machine",
        "operating_system",
        "operating_system_release",
        "peak_rss_raw_unit",
        "python_implementation",
        "python_version",
        "tool_version",
    }
    assert document["protocol"] == {
        "formats": ["json", "html", "sarif"],
        "fresh_process_per_run": True,
        "samples_per_format": 1,
        "statistics": "median and nearest-rank p95; warmups excluded",
        "timeout_seconds": 60,
        "warmups_per_format": 0,
    }

    assert [item["format"] for item in document["results"]] == ["json", "html", "sarif"]
    for format_result in document["results"]:
        assert set(format_result) == {
            "expected_cli_exit_code",
            "format",
            "output_bytes",
            "output_sha256",
            "samples",
            "summary",
        }
        assert format_result["expected_cli_exit_code"] == 1
        assert format_result["output_bytes"] > 0
        assert re.fullmatch(r"[0-9a-f]{64}", format_result["output_sha256"])
        assert len(format_result["samples"]) == 1
        sample = format_result["samples"][0]
        assert sample["index"] == 1
        assert sample["cli_exit_code"] == 1
        assert sample["wall_time_ns"] > 0
        assert sample["user_cpu_ns"] >= 0
        assert sample["system_cpu_ns"] >= 0
        assert sample["peak_rss_raw"] > 0
        assert sample["peak_rss_raw_unit"] in {"bytes", "kibibytes"}
        assert sample["peak_rss_mib"] > 0
        assert sample["output_bytes"] == format_result["output_bytes"]
        assert sample["output_sha256"] == format_result["output_sha256"]
        assert set(format_result["summary"]) == {
            "peak_rss_mib",
            "peak_rss_raw",
            "system_cpu_ns",
            "user_cpu_ns",
            "wall_time_ns",
        }
        for metric, summary in format_result["summary"].items():
            assert set(summary) == {"max", "median", "min", "p95"}
            assert len(set(summary.values())) == 1, metric

    serialized = output_path.read_text(encoding="ascii")
    assert str(tmp_path) not in serialized
    assert str(Path.home()) not in serialized
    assert os.environ.get("USER", "a-user-value-that-is-not-present") not in serialized
    assert sys.executable not in serialized


def test_measure_refuses_existing_output_and_drift_without_artifacts(tmp_path: Path) -> None:
    input_path = tmp_path / "large-balanced-jsonl-v1.jsonl"
    assert _run_tool("generate", "--output", str(input_path)).returncode == 0
    existing = tmp_path / "existing.json"
    existing.write_bytes(b"preserve\n")
    before = existing.stat()

    refused = _run_tool(
        "measure",
        "--python",
        sys.executable,
        "--input",
        str(input_path),
        "--output",
        str(existing),
        "--warmups",
        "0",
        "--samples",
        "1",
    )

    assert refused.returncode == 2
    assert existing.read_bytes() == b"preserve\n"
    assert existing.stat().st_mtime_ns == before.st_mtime_ns

    drifted = tmp_path / "drifted.jsonl"
    drifted.write_bytes(input_path.read_bytes() + b"\n")
    absent = tmp_path / "absent.json"
    rejected = _run_tool(
        "measure",
        "--python",
        sys.executable,
        "--input",
        str(drifted),
        "--output",
        str(absent),
        "--warmups",
        "0",
        "--samples",
        "1",
    )

    assert rejected.returncode == 1
    assert rejected.stdout == ""
    assert rejected.stderr == "error: observed performance measurement incomplete\n"
    assert not absent.exists()


@pytest.mark.parametrize(
    ("option", "value"),
    [("--warmups", "-1"), ("--warmups", "6"), ("--samples", "0"), ("--samples", "31")],
)
def test_measure_rejects_unbounded_run_counts(tmp_path: Path, option: str, value: str) -> None:
    input_path = tmp_path / "large-balanced-jsonl-v1.jsonl"
    output_path = tmp_path / "measurement.json"
    assert _run_tool("generate", "--output", str(input_path)).returncode == 0

    result = _run_tool(
        "measure",
        "--python",
        sys.executable,
        "--input",
        str(input_path),
        "--output",
        str(output_path),
        option,
        value,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "error: invalid observed-performance operation\n"
    assert not output_path.exists()


def test_help_exits_successfully_without_unexpected_failure() -> None:
    result = _run_tool("--help")

    assert result.returncode == 0
    assert result.stdout.startswith("usage: observed_performance.py")
    assert result.stderr == ""


def test_measurement_failure_is_atomic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "large-balanced-jsonl-v1.jsonl"
    output_path = tmp_path / "measurement.json"
    input_path.write_bytes(observed_performance._scenario_bytes())

    def fail_collection(**kwargs: object) -> dict[str, object]:
        del kwargs
        raise observed_performance.MeasurementIncomplete("injected incomplete series")

    monkeypatch.setattr(observed_performance, "_collect_measurement", fail_collection)

    exit_code = observed_performance.main(
        [
            "measure",
            "--python",
            sys.executable,
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--warmups",
            "0",
            "--samples",
            "1",
        ]
    )

    assert exit_code == 1
    assert capsys.readouterr().err == "error: observed performance measurement incomplete\n"
    assert not output_path.exists()


def test_child_timeout_and_output_drift_invalidate_a_series(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def time_out(*args: object, **kwargs: object) -> NoReturn:
        del args, kwargs
        raise subprocess.TimeoutExpired(cmd="installed-python", timeout=60)

    monkeypatch.setattr(observed_performance.subprocess, "run", time_out)
    with pytest.raises(observed_performance.MeasurementIncomplete):
        observed_performance._run_child(
            python=Path(sys.executable),
            input_path=tmp_path / "input.jsonl",
            output_path=tmp_path / "output.json",
            report_format="json",
            timeout_seconds=60,
        )

    unit = "bytes" if sys.platform == "darwin" else "kibibytes"
    environment = {
        "cpu_count": 1,
        "machine": "generic",
        "operating_system": "Generic",
        "operating_system_release": "1",
        "peak_rss_raw_unit": unit,
        "python_implementation": "CPython",
        "python_version": "3.11.0",
        "tool_version": "0.1.0.dev0",
    }
    observations = iter(
        [
            {
                "environment": environment,
                "sample": {
                    "cli_exit_code": 1,
                    "output_bytes": 10,
                    "output_sha256": "a" * 64,
                    "peak_rss_mib": 1.0,
                    "peak_rss_raw": 1024,
                    "peak_rss_raw_unit": unit,
                    "system_cpu_ns": 1,
                    "user_cpu_ns": 1,
                    "wall_time_ns": 1,
                },
            },
            {
                "environment": environment,
                "sample": {
                    "cli_exit_code": 1,
                    "output_bytes": 10,
                    "output_sha256": "b" * 64,
                    "peak_rss_mib": 1.0,
                    "peak_rss_raw": 1024,
                    "peak_rss_raw_unit": unit,
                    "system_cpu_ns": 1,
                    "user_cpu_ns": 1,
                    "wall_time_ns": 1,
                },
            },
        ]
    )
    monkeypatch.setattr(
        observed_performance,
        "_run_child",
        lambda **kwargs: next(observations),
    )
    with pytest.raises(observed_performance.MeasurementIncomplete):
        observed_performance._measure_format(
            python=Path(sys.executable),
            input_path=tmp_path / "input.jsonl",
            directory=tmp_path,
            report_format="json",
            warmups=0,
            samples=2,
            timeout_seconds=60,
        )


def test_measure_rejects_an_installed_target_with_wrong_report_semantics() -> None:
    with pytest.raises(observed_performance.MeasurementIncomplete):
        observed_performance._validate_report_contract("json", b"{}\n", _manifest())
