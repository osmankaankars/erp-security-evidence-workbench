#!/usr/bin/env python3
"""Generate, verify, and measure one deterministic synthetic performance scenario."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from contextlib import suppress
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, NoReturn

AS_OF = "2026-09-01T00:00:00Z"
EVIDENCE_SCHEMA_VERSION = "erpsec.synthetic-evidence/v1"
SCENARIO_SCHEMA_VERSION = "erpsec.observed-performance-scenario/v1"
SCENARIO_ID = "large-balanced-jsonl-v1"
GENERATOR_VERSION = "1.0.0"
MEASUREMENT_SCHEMA_VERSION = "erpsec.observed-performance/v1"
SCENARIO_ORIGIN = (
    "First-principles deterministic generator using fictional generic identifiers and fixed "
    "timestamps."
)
SCENARIO_CLAIMS_BOUNDARY = (
    "Single-host synthetic observation input; not an SLA, security benchmark, capacity rating, "
    "or production workload."
)
RULE_IDS = ("ERP001", "ERP002", "ERP003", "ERP004", "ERP005", "ERP006")
REPORT_FORMATS = ("json", "html", "sarif")
RECORD_TYPE_COUNTS = {
    "auth_event": 200,
    "change_event": 200,
    "control_state": 50,
    "permission_assignment": 150,
    "principal": 150,
    "role_assignment": 150,
}
EXPECTED_RECORD_COUNT = 900
MAX_INPUT_BYTES = 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_MEASUREMENT_BYTES = 1024 * 1024
MAX_WARMUPS = 5
MAX_SAMPLES = 30
CHILD_TIMEOUT_SECONDS = 60
PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = PROJECT_ROOT / "benchmarks" / "observed-performance-v1.json"


class ObservedPerformanceError(Exception):
    """Base class for safely reportable development-tool failures."""


class OperationError(ObservedPerformanceError):
    """The requested operation or local environment is invalid."""


class ScenarioMismatch(ObservedPerformanceError):
    """The supplied scenario or an observed result differs from its frozen contract."""


class MeasurementIncomplete(ObservedPerformanceError):
    """At least one required observation failed or drifted."""


class _SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser whose failures do not echo user-controlled values."""

    def error(self, message: str) -> NoReturn:
        del message
        raise OperationError("invalid arguments")


def _record(record_type: str, record_id: str, **fields: object) -> dict[str, object]:
    return {
        "dataset_classification": "synthetic",
        "record_id": record_id,
        "record_type": record_type,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        **fields,
    }


def _scenario_records() -> tuple[dict[str, object], ...]:
    records: list[dict[str, object]] = [
        _record(
            "principal",
            "principal.stale",
            principal_id="persona.stale",
            principal_kind="human",
            enabled=True,
            last_active_at="2026-05-01T00:00:00Z",
        ),
        _record(
            "principal",
            "principal.toxic",
            principal_id="persona.toxic",
            principal_kind="human",
            enabled=True,
            last_active_at="2026-08-31T23:30:00Z",
        ),
        _record(
            "principal",
            "principal.emergency",
            principal_id="persona.emergency",
            principal_kind="emergency",
            enabled=True,
            last_active_at="2026-08-31T23:30:00Z",
        ),
        _record(
            "principal",
            "principal.failure",
            principal_id="persona.failure",
            principal_kind="human",
            enabled=True,
            last_active_at="2026-08-31T23:30:00Z",
        ),
        _record(
            "permission_assignment",
            "permission.stale.admin",
            principal_id="persona.stale",
            permission="ADMINISTER_SYSTEM",
            assignment_mode="direct",
            assigned_at="2026-01-01T00:00:00Z",
        ),
        _record(
            "permission_assignment",
            "permission.toxic.create",
            principal_id="persona.toxic",
            permission="CREATE_VENDOR",
            assignment_mode="inherited",
            assigned_at="2026-01-01T00:00:00Z",
        ),
        _record(
            "permission_assignment",
            "permission.toxic.approve",
            principal_id="persona.toxic",
            permission="APPROVE_PAYMENT",
            assignment_mode="inherited",
            assigned_at="2026-01-01T00:00:00Z",
        ),
        _record(
            "auth_event",
            "auth.emergency.outside",
            principal_id="persona.emergency",
            action="SIGN_IN",
            outcome="success",
            occurred_at="2026-08-31T19:59:59Z",
        ),
        _record(
            "control_state",
            "control.audit.disabled",
            control="AUDIT_LOGGING",
            enabled=False,
        ),
    ]

    failure_times = ("12:00:00", "12:03:00", "12:06:00", "12:09:00", "12:15:00")
    records.extend(
        _record(
            "auth_event",
            f"auth.failure.{index:03d}",
            principal_id="persona.failure",
            action="SIGN_IN",
            outcome="failure",
            occurred_at=f"2026-08-31T{clock}Z",
        )
        for index, clock in enumerate(failure_times, start=1)
    )

    records.extend(
        _record(
            "principal",
            f"principal.filler.{index:03d}",
            principal_id=f"persona.filler.{index:03d}",
            principal_kind="human",
            enabled=True,
            last_active_at="2026-08-31T23:30:00Z",
        )
        for index in range(146)
    )
    records.extend(
        _record(
            "role_assignment",
            f"role.assignment.{index:03d}",
            principal_id=f"persona.filler.{index % 146:03d}",
            role_id=f"role.generic.{index:03d}",
            assignment_mode="inherited",
            assigned_at="2026-08-01T00:00:00Z",
        )
        for index in range(150)
    )
    records.extend(
        _record(
            "permission_assignment",
            f"permission.filler.{index:03d}",
            principal_id=f"persona.filler.{index % 146:03d}",
            permission="VIEW_RECORDS",
            assignment_mode="inherited",
            assigned_at="2026-08-01T00:00:00Z",
        )
        for index in range(147)
    )
    records.extend(
        _record(
            "auth_event",
            f"auth.filler.{index:03d}",
            principal_id=f"persona.filler.{index % 146:03d}",
            action="VIEW_RECORD",
            outcome="success",
            occurred_at="2026-08-31T23:00:00Z",
        )
        for index in range(194)
    )
    records.extend(
        _record(
            "change_event",
            f"change.filler.{index:03d}",
            principal_id=f"persona.filler.{index % 146:03d}",
            object_id=f"object.generic.{index:03d}",
            action="UPDATE_RECORD",
            outcome="success",
            occurred_at="2026-08-31T23:00:00Z",
        )
        for index in range(200)
    )
    records.extend(
        _record(
            "control_state",
            f"control.filler.{index:03d}",
            control=f"GENERIC_CONTROL_{index:03d}",
            enabled=True,
        )
        for index in range(49)
    )

    ordered = tuple(
        sorted(records, key=lambda value: (str(value["record_type"]), str(value["record_id"])))
    )
    counts = Counter(str(record["record_type"]) for record in ordered)
    if len(ordered) != EXPECTED_RECORD_COUNT or dict(sorted(counts.items())) != RECORD_TYPE_COUNTS:
        raise AssertionError("internal scenario record contract is inconsistent")
    return ordered


def _scenario_bytes() -> bytes:
    lines = (
        json.dumps(
            record,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        for record in _scenario_records()
    )
    content = ("\n".join(lines) + "\n").encode("ascii")
    if len(content) >= MAX_INPUT_BYTES:
        raise AssertionError("internal scenario exceeds the input byte contract")
    if max(len(line) for line in content.splitlines()) >= MAX_LINE_BYTES:
        raise AssertionError("internal scenario exceeds the line byte contract")
    return content


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _write_new_file(path: Path, content: bytes) -> None:
    descriptor = -1
    created = False
    identity: tuple[int, int] | None = None
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino)
        view = memoryview(content)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise OSError("write made no progress")
            offset += written
        os.fsync(descriptor)
    except (OSError, ValueError) as exc:
        raise OperationError("could not create output") from exc
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        if created and sys.exc_info()[0] is not None:
            try:
                current = os.lstat(path)
                if identity is not None and (current.st_dev, current.st_ino) == identity:
                    os.unlink(path)
            except OSError:
                pass


def _read_exact_input(path: Path, expected: bytes) -> bytes:
    descriptor = -1
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OperationError("input is not a regular file")
        if opened.st_size != len(expected):
            raise ScenarioMismatch("input byte count differs")
        chunks: list[bytes] = []
        remaining = len(expected) + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
    except ScenarioMismatch:
        raise
    except (OSError, ValueError) as exc:
        raise OperationError("could not read input") from exc
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
    if content != expected:
        raise ScenarioMismatch("input bytes differ")
    return content


def _load_manifest() -> dict[str, Any]:
    try:
        raw = MANIFEST_PATH.read_bytes()
    except OSError as exc:
        raise OperationError("scenario manifest is unavailable") from exc
    if len(raw) > 64 * 1024:
        raise OperationError("scenario manifest is invalid")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OperationError("scenario manifest is invalid") from exc
    if not isinstance(value, dict):
        raise OperationError("scenario manifest is invalid")
    return value


def _finding_contract(finding: Any) -> dict[str, object]:
    evidence_reference_count = (
        len(finding.supporting_evidence) if finding.supporting_evidence else 1
    )
    return {
        "evidence_reference_count": evidence_reference_count,
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
    }


def _verify_semantics(path: Path, manifest: dict[str, Any]) -> None:
    try:
        from erp_security_evidence_workbench.ingest import load_evidence
        from erp_security_evidence_workbench.rules import evaluate_rules

        bundle = load_evidence((path,))
        run = evaluate_rules(bundle, as_of=AS_OF, selected_rule_ids=RULE_IDS)
    except Exception as exc:
        raise ScenarioMismatch("scenario evaluation failed") from exc
    actual = {
        "cli_exit_code": 1 if run.findings else 0,
        "evaluations": [
            {"rule_id": evaluation.rule_id, "status": evaluation.status}
            for evaluation in run.evaluations
        ],
        "findings": [_finding_contract(finding) for finding in run.findings],
    }
    if len(bundle.records) != EXPECTED_RECORD_COUNT or actual != manifest.get("expected"):
        raise ScenarioMismatch("scenario semantics differ")


def _check_input(path: Path) -> None:
    expected = _scenario_bytes()
    content = _read_exact_input(path, expected)
    manifest = _load_manifest()
    expected_manifest_fields = {
        "as_of": AS_OF,
        "byte_count": len(content),
        "dataset_classification": "synthetic",
        "format": "jsonl",
        "max_line_bytes": max(len(line) for line in content.splitlines()),
        "record_count": EXPECTED_RECORD_COUNT,
        "record_type_counts": RECORD_TYPE_COUNTS,
        "scenario_id": SCENARIO_ID,
        "schema_version": SCENARIO_SCHEMA_VERSION,
        "selected_rules": list(RULE_IDS),
        "sha256": _sha256(content),
    }
    expected_keys = {
        *expected_manifest_fields,
        "claims_boundary",
        "expected",
        "generator",
        "origin",
    }
    if (
        set(manifest) != expected_keys
        or any(manifest.get(key) != value for key, value in expected_manifest_fields.items())
        or manifest.get("claims_boundary") != SCENARIO_CLAIMS_BOUNDARY
        or manifest.get("generator")
        != {"path": "scripts/observed_performance.py", "version": GENERATOR_VERSION}
        or manifest.get("origin") != SCENARIO_ORIGIN
    ):
        raise ScenarioMismatch("scenario manifest differs")
    _verify_semantics(path, manifest)


_CHILD_PROGRAM = r"""
import json
import os
import platform
import resource
import sys

from erp_security_evidence_workbench import __version__
from erp_security_evidence_workbench.cli import main

input_path, output_path, report_format, as_of = sys.argv[1:5]
cli_exit_code = main(
    [
        "analyze",
        input_path,
        "--as-of",
        as_of,
        "--format",
        report_format,
        "--output",
        output_path,
        "--rule",
        "all",
    ]
)
usage = resource.getrusage(resource.RUSAGE_SELF)
system = platform.system()
peak_rss_raw = int(usage.ru_maxrss)
if system == "Darwin":
    peak_rss_raw_unit = "bytes"
    peak_rss_mib = peak_rss_raw / (1024 * 1024)
elif system == "Linux":
    peak_rss_raw_unit = "kibibytes"
    peak_rss_mib = peak_rss_raw / 1024
else:
    raise RuntimeError("unsupported measurement platform")
payload = {
    "environment": {
        "cpu_count": os.cpu_count(),
        "machine": platform.machine(),
        "operating_system": system,
        "operating_system_release": platform.release(),
        "peak_rss_raw_unit": peak_rss_raw_unit,
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "tool_version": __version__,
    },
    "metrics": {
        "cli_exit_code": cli_exit_code,
        "peak_rss_mib": round(peak_rss_mib, 6),
        "peak_rss_raw": peak_rss_raw,
        "peak_rss_raw_unit": peak_rss_raw_unit,
        "system_cpu_ns": round(usage.ru_stime * 1_000_000_000),
        "user_cpu_ns": round(usage.ru_utime * 1_000_000_000),
    },
}
sys.stdout.write(json.dumps(payload, allow_nan=False, ensure_ascii=True, sort_keys=True) + "\n")
""".lstrip()


def _require_new_path(path: Path) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except (OSError, ValueError) as exc:
        raise OperationError("output path is invalid") from exc
    raise OperationError("output path already exists")


def _validated_python(path: Path) -> Path:
    try:
        candidate = Path(os.path.abspath(path))
        metadata = candidate.stat()
    except (OSError, ValueError) as exc:
        raise OperationError("installed Python path is invalid") from exc
    if not stat.S_ISREG(metadata.st_mode) or not os.access(candidate, os.X_OK):
        raise OperationError("installed Python path is invalid")
    return candidate


def _safe_metadata_string(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}", value) is None:
        raise MeasurementIncomplete("child environment metadata is invalid")
    return value


def _validated_environment(value: object) -> dict[str, object]:
    expected_keys = {
        "cpu_count",
        "machine",
        "operating_system",
        "operating_system_release",
        "peak_rss_raw_unit",
        "python_implementation",
        "python_version",
        "tool_version",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise MeasurementIncomplete("child environment metadata is incomplete")
    cpu_count = value["cpu_count"]
    if cpu_count is not None and (type(cpu_count) is not int or cpu_count <= 0):
        raise MeasurementIncomplete("child CPU metadata is invalid")
    environment: dict[str, object] = {"cpu_count": cpu_count}
    for key in expected_keys - {"cpu_count"}:
        environment[key] = _safe_metadata_string(value[key])
    if environment["operating_system"] not in {"Darwin", "Linux"}:
        raise MeasurementIncomplete("child operating system is unsupported")
    expected_unit = "bytes" if environment["operating_system"] == "Darwin" else "kibibytes"
    if environment["peak_rss_raw_unit"] != expected_unit:
        raise MeasurementIncomplete("child RSS metadata is inconsistent")
    return {key: environment[key] for key in sorted(environment)}


def _nonnegative_int(value: object, name: str) -> int:
    if type(value) is not int or value < 0:
        raise MeasurementIncomplete(f"child {name} metric is invalid")
    return value


def _positive_int(value: object, name: str) -> int:
    result = _nonnegative_int(value, name)
    if result == 0:
        raise MeasurementIncomplete(f"child {name} metric is invalid")
    return result


def _validated_metrics(value: object, environment: dict[str, object]) -> dict[str, object]:
    expected_keys = {
        "cli_exit_code",
        "peak_rss_mib",
        "peak_rss_raw",
        "peak_rss_raw_unit",
        "system_cpu_ns",
        "user_cpu_ns",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise MeasurementIncomplete("child metrics are incomplete")
    if value["cli_exit_code"] != 1:
        raise MeasurementIncomplete("child analysis did not produce the frozen finding result")
    peak_rss_mib = value["peak_rss_mib"]
    if type(peak_rss_mib) not in {int, float} or peak_rss_mib <= 0:
        raise MeasurementIncomplete("child peak RSS metric is invalid")
    if value["peak_rss_raw_unit"] != environment["peak_rss_raw_unit"]:
        raise MeasurementIncomplete("child peak RSS unit drifted")
    return {
        "cli_exit_code": 1,
        "peak_rss_mib": float(peak_rss_mib),
        "peak_rss_raw": _positive_int(value["peak_rss_raw"], "peak RSS"),
        "peak_rss_raw_unit": value["peak_rss_raw_unit"],
        "system_cpu_ns": _nonnegative_int(value["system_cpu_ns"], "system CPU"),
        "user_cpu_ns": _nonnegative_int(value["user_cpu_ns"], "user CPU"),
    }


def _read_report(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_REPORT_BYTES:
            raise MeasurementIncomplete("child report is missing or unbounded")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise MeasurementIncomplete("child report permissions are invalid")
        content = path.read_bytes()
    except MeasurementIncomplete:
        raise
    except OSError as exc:
        raise MeasurementIncomplete("child report is unavailable") from exc
    if len(content) != metadata.st_size:
        raise MeasurementIncomplete("child report changed while being read")
    return content


def _expected_report_contract(
    manifest: dict[str, Any],
) -> tuple[list[tuple[str, str]], list[tuple[str, str, int]]]:
    try:
        expected = manifest["expected"]
        evaluations = [
            (str(item["rule_id"]), str(item["status"])) for item in expected["evaluations"]
        ]
        findings = [
            (
                str(item["rule_id"]),
                str(item["fingerprint"]),
                int(item["evidence_reference_count"]),
            )
            for item in expected["findings"]
        ]
    except (KeyError, TypeError, ValueError) as exc:
        raise MeasurementIncomplete("frozen report contract is invalid") from exc
    return evaluations, findings


class _ObservedHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.evaluations: list[tuple[str, str]] = []
        self.findings: list[tuple[str, str]] = []
        self.evidence_counts: Counter[str] = Counter()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del tag
        attributes = dict(attrs)
        role = attributes.get("data-erpsec-role")
        if role == "evaluation":
            self.evaluations.append(
                (attributes.get("data-rule-id", ""), attributes.get("data-status", ""))
            )
        elif role == "finding":
            self.findings.append(
                (
                    attributes.get("data-rule-id", ""),
                    attributes.get("data-fingerprint", ""),
                )
            )
        elif role == "evidence":
            self.evidence_counts[attributes.get("data-fingerprint", "")] += 1


def _validate_report_contract(report_format: str, content: bytes, manifest: dict[str, Any]) -> None:
    expected_evaluations, expected_findings = _expected_report_contract(manifest)
    try:
        if report_format == "json":
            document = json.loads(content.decode("ascii"))
            actual_evaluations = [
                (str(item["rule_id"]), str(item["status"])) for item in document["evaluations"]
            ]
            actual_findings = [
                (
                    str(item["rule_id"]),
                    str(item["fingerprint"]),
                    len(item["evidence_refs"]),
                )
                for item in document["findings"]
            ]
        elif report_format == "sarif":
            document = json.loads(content.decode("ascii"))
            run = document["runs"][0]
            actual_evaluations = [
                (str(item["rule_id"]), str(item["status"]))
                for item in run["properties"]["erpsec.evaluations"]
            ]
            actual_findings = [
                (
                    str(item["ruleId"]),
                    str(item["fingerprints"]["erpsec/v1"]),
                    len(item["locations"]),
                )
                for item in run["results"]
            ]
        elif report_format == "html":
            parser = _ObservedHTMLParser()
            parser.feed(content.decode("utf-8"))
            parser.close()
            actual_evaluations = parser.evaluations
            actual_findings = [
                (rule_id, fingerprint, parser.evidence_counts[fingerprint])
                for rule_id, fingerprint in parser.findings
            ]
        else:
            raise MeasurementIncomplete("report format is unsupported")
    except MeasurementIncomplete:
        raise
    except (IndexError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise MeasurementIncomplete("installed target report is invalid") from exc
    if actual_evaluations != expected_evaluations or actual_findings != expected_findings:
        raise MeasurementIncomplete("installed target report semantics drifted")


def _run_child(
    *,
    python: Path,
    input_path: Path,
    output_path: Path,
    report_format: str,
    timeout_seconds: int,
) -> dict[str, object]:
    started = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            [
                str(python),
                "-I",
                "-B",
                "-c",
                _CHILD_PROGRAM,
                str(input_path),
                str(output_path),
                report_format,
                AS_OF,
            ],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MeasurementIncomplete("child process did not complete") from exc
    wall_time_ns = time.perf_counter_ns() - started
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 16 * 1024:
        raise MeasurementIncomplete("child process result is invalid")
    try:
        payload = json.loads(completed.stdout.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MeasurementIncomplete("child process result is invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {"environment", "metrics"}:
        raise MeasurementIncomplete("child process result is incomplete")
    environment = _validated_environment(payload["environment"])
    sample = _validated_metrics(payload["metrics"], environment)
    report = _read_report(output_path)
    _validate_report_contract(report_format, report, _load_manifest())
    sample.update(
        {
            "output_bytes": len(report),
            "output_sha256": _sha256(report),
            "wall_time_ns": wall_time_ns,
        }
    )
    return {"environment": environment, "sample": sample}


def _summary(values: list[int | float]) -> dict[str, int | float]:
    if not values:
        raise MeasurementIncomplete("measurement sample set is empty")
    ordered = sorted(values)
    p95_index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return {
        "max": max(ordered),
        "median": statistics.median(ordered),
        "min": min(ordered),
        "p95": ordered[p95_index],
    }


def _measure_format(
    *,
    python: Path,
    input_path: Path,
    directory: Path,
    report_format: str,
    warmups: int,
    samples: int,
    timeout_seconds: int,
) -> tuple[dict[str, object], dict[str, object]]:
    environment: dict[str, object] | None = None
    output_sha256: str | None = None
    output_bytes: int | None = None
    measured: list[dict[str, object]] = []
    total_runs = warmups + samples
    for run_index in range(total_runs):
        observation = _run_child(
            python=python,
            input_path=input_path,
            output_path=directory / f"{report_format}-{run_index + 1}.report",
            report_format=report_format,
            timeout_seconds=timeout_seconds,
        )
        current_environment = observation["environment"]
        sample = observation["sample"]
        if not isinstance(current_environment, dict) or not isinstance(sample, dict):
            raise MeasurementIncomplete("child observation is invalid")
        if environment is None:
            environment = current_environment
            output_sha256 = str(sample.get("output_sha256"))
            output_bytes = int(sample.get("output_bytes", 0))
        elif current_environment != environment:
            raise MeasurementIncomplete("child environment drifted within the series")
        if (
            sample.get("output_sha256") != output_sha256
            or sample.get("output_bytes") != output_bytes
        ):
            raise MeasurementIncomplete("child report drifted within the series")
        if run_index >= warmups:
            recorded = dict(sample)
            recorded["index"] = run_index - warmups + 1
            measured.append(recorded)

    if environment is None or output_sha256 is None or output_bytes is None:
        raise MeasurementIncomplete("measurement series is incomplete")
    metrics = (
        "wall_time_ns",
        "user_cpu_ns",
        "system_cpu_ns",
        "peak_rss_raw",
        "peak_rss_mib",
    )
    summary = {
        metric: _summary(
            [value for sample in measured if type(value := sample.get(metric)) in {int, float}]
        )
        for metric in metrics
    }
    return environment, {
        "expected_cli_exit_code": 1,
        "format": report_format,
        "output_bytes": output_bytes,
        "output_sha256": output_sha256,
        "samples": measured,
        "summary": summary,
    }


def _collect_measurement(
    *,
    python: Path,
    input_path: Path,
    warmups: int,
    samples: int,
    timeout_seconds: int,
) -> dict[str, object]:
    results: list[dict[str, object]] = []
    environment: dict[str, object] | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="erpsec-observed-performance-") as temporary_name:
            directory = Path(temporary_name)
            for report_format in REPORT_FORMATS:
                current_environment, result = _measure_format(
                    python=python,
                    input_path=input_path,
                    directory=directory,
                    report_format=report_format,
                    warmups=warmups,
                    samples=samples,
                    timeout_seconds=timeout_seconds,
                )
                if environment is None:
                    environment = current_environment
                elif current_environment != environment:
                    raise MeasurementIncomplete("child environment drifted across formats")
                results.append(result)
    except MeasurementIncomplete:
        raise
    except OSError as exc:
        raise MeasurementIncomplete("temporary measurement workspace failed") from exc
    if environment is None or len(results) != len(REPORT_FORMATS):
        raise MeasurementIncomplete("measurement result is incomplete")
    manifest = _load_manifest()
    return {
        "claims_boundary": (
            "Single-host synthetic observation; not an SLA, benchmark, security-capacity claim, "
            "or production workload."
        ),
        "environment": environment,
        "protocol": {
            "formats": list(REPORT_FORMATS),
            "fresh_process_per_run": True,
            "samples_per_format": samples,
            "statistics": "median and nearest-rank p95; warmups excluded",
            "timeout_seconds": timeout_seconds,
            "warmups_per_format": warmups,
        },
        "results": results,
        "scenario": {
            "as_of": AS_OF,
            "byte_count": manifest["byte_count"],
            "record_count": manifest["record_count"],
            "scenario_id": SCENARIO_ID,
            "selected_rules": list(RULE_IDS),
            "sha256": manifest["sha256"],
        },
        "schema_version": MEASUREMENT_SCHEMA_VERSION,
    }


def _measurement_bytes(document: dict[str, object]) -> bytes:
    content = (
        json.dumps(document, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")
    if len(content) > MAX_MEASUREMENT_BYTES:
        raise MeasurementIncomplete("measurement document exceeds its byte limit")
    return content


def _bounded_integer(value: str, *, minimum: int, maximum: int) -> int:
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid integer") from exc
    if not minimum <= result <= maximum:
        raise argparse.ArgumentTypeError("integer is outside the supported range")
    return result


def _warmup_count(value: str) -> int:
    return _bounded_integer(value, minimum=0, maximum=MAX_WARMUPS)


def _sample_count(value: str) -> int:
    return _bounded_integer(value, minimum=1, maximum=MAX_SAMPLES)


def _parser() -> _SafeArgumentParser:
    parser = _SafeArgumentParser(
        description="Generate, verify, or measure the synthetic observation scenario."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    generate = subcommands.add_parser("generate")
    generate.add_argument("--output", required=True, type=Path)
    check = subcommands.add_parser("check")
    check.add_argument("--input", required=True, type=Path)
    measure = subcommands.add_parser("measure")
    measure.add_argument("--python", required=True, type=Path)
    measure.add_argument("--input", required=True, type=Path)
    measure.add_argument("--output", required=True, type=Path)
    measure.add_argument("--warmups", default=3, type=_warmup_count)
    measure.add_argument("--samples", default=20, type=_sample_count)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        if arguments.command == "generate":
            _write_new_file(arguments.output, _scenario_bytes())
            print("synthetic measurement input generated")
        elif arguments.command == "check":
            _check_input(arguments.input)
            print("synthetic measurement input verified")
        else:
            _require_new_path(arguments.output)
            python = _validated_python(arguments.python)
            try:
                _check_input(arguments.input)
            except ScenarioMismatch as exc:
                raise MeasurementIncomplete("measurement input differs") from exc
            measurement = _collect_measurement(
                python=python,
                input_path=arguments.input,
                warmups=arguments.warmups,
                samples=arguments.samples,
                timeout_seconds=CHILD_TIMEOUT_SECONDS,
            )
            _write_new_file(arguments.output, _measurement_bytes(measurement))
            print("observed performance measurement recorded")
    except SystemExit:
        raise
    except MeasurementIncomplete:
        print("error: observed performance measurement incomplete", file=sys.stderr)
        return 1
    except ScenarioMismatch:
        print("error: synthetic measurement input mismatch", file=sys.stderr)
        return 1
    except ObservedPerformanceError:
        print("error: invalid observed-performance operation", file=sys.stderr)
        return 2
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        print("error: unexpected observed-performance failure", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
