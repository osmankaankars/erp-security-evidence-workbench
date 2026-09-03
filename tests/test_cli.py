from __future__ import annotations

import hashlib
import json
import socket
import stat
import subprocess
from pathlib import Path

import pytest

from erp_security_evidence_workbench import cli, reporting
from erp_security_evidence_workbench.cli import main
from erp_security_evidence_workbench.models import EvidenceBundle

INPUT_SCHEMA_VERSION = "erpsec.synthetic-control-state/v1"
REPORT_SCHEMA_VERSION = "erpsec.report/v1"


def _write_synthetic_control(path: Path, *, enabled: bool) -> bytes:
    payload = {
        "schema_version": INPUT_SCHEMA_VERSION,
        "dataset_classification": "synthetic",
        "record_type": "control_state",
        "record_id": "control-audit-logging",
        "control": "AUDIT_LOGGING",
        "enabled": enabled,
    }
    content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    path.write_bytes(content)
    return content


def _analyze(input_path: Path, output_path: Path) -> int:
    return main(
        [
            "analyze",
            str(input_path),
            "--as-of",
            "2026-09-01T03:00:00+03:00",
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )


def test_disabled_audit_logging_emits_traceable_deterministic_finding(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    input_bytes = _write_synthetic_control(input_path, enabled=False)

    exit_code = _analyze(input_path, output_path)

    assert exit_code == 1
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["schema_version"] == REPORT_SCHEMA_VERSION
    assert report["tool"] == {
        "name": "erp-security-evidence-workbench",
        "version": "0.2.0rc1",
    }
    assert report["run"] == {
        "as_of": "2026-09-01T00:00:00Z",
        "coverage": "complete",
        "input_count": 1,
        "result": "findings",
    }
    assert report["evaluations"] == [
        {
            "rule_id": "ERP001",
            "rule_version": "1.0.0",
            "status": "matched",
        }
    ]
    assert report["evidence_manifest"] == [
        {
            "record_id": "control-audit-logging",
            "record_type": "control_state",
            "source_ref": {
                "adapter": "erpsec.legacy-control-state-json/v1",
                "format": "json",
                "json_pointer": "",
                "path": "audit-disabled.json",
                "sha256": hashlib.sha256(input_bytes).hexdigest(),
            },
        }
    ]
    assert report["source_manifest"] == [
        {
            "adapter": "erpsec.legacy-control-state-json/v1",
            "byte_count": len(input_bytes),
            "format": "json",
            "path": "audit-disabled.json",
            "record_count": 1,
            "sha256": hashlib.sha256(input_bytes).hexdigest(),
        }
    ]

    fingerprint_material = {
        "record_ids": ["control-audit-logging"],
        "rule_id": "ERP001",
        "rule_version": "1.0.0",
    }
    expected_fingerprint = hashlib.sha256(
        json.dumps(
            fingerprint_material,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    assert report["findings"] == [
        {
            "rule_id": "ERP001",
            "rule_version": "1.0.0",
            "severity": "high",
            "severity_rationale": (
                "Disabled audit logging can materially reduce investigation and "
                "accountability evidence."
            ),
            "title": "Required audit logging is disabled",
            "description": (
                "The supplied control-state evidence explicitly marks required audit "
                "logging as disabled."
            ),
            "fingerprint": expected_fingerprint,
            "evidence_refs": [
                {
                    "record_id": "control-audit-logging",
                    "source_ref": {
                        "adapter": "erpsec.legacy-control-state-json/v1",
                        "format": "json",
                        "json_pointer": "/enabled",
                        "path": "audit-disabled.json",
                        "sha256": hashlib.sha256(input_bytes).hexdigest(),
                    },
                }
            ],
            "limitation": (
                "ERP001 evaluates only supplied synthetic control-state evidence; it does "
                "not verify a live system or prove logging coverage."
            ),
            "remediation": (
                "Review the audit logging configuration and enable the required control "
                "through an authorized change process."
            ),
            "required_evidence_types": ["control_state"],
        }
    ]
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_enabled_audit_logging_produces_complete_clean_report(tmp_path: Path) -> None:
    input_path = tmp_path / "audit-enabled.json"
    output_path = tmp_path / "report.json"
    input_bytes = _write_synthetic_control(input_path, enabled=True)

    assert _analyze(input_path, output_path) == 0
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["run"]["coverage"] == "complete"
    assert report["run"]["result"] == "no_findings"
    assert report["evaluations"] == [
        {
            "rule_id": "ERP001",
            "rule_version": "1.0.0",
            "status": "not_matched",
        }
    ]
    assert report["findings"] == []
    assert report["evidence_manifest"] == [
        {
            "record_id": "control-audit-logging",
            "record_type": "control_state",
            "source_ref": {
                "adapter": "erpsec.legacy-control-state-json/v1",
                "format": "json",
                "json_pointer": "",
                "path": "audit-enabled.json",
                "sha256": hashlib.sha256(input_bytes).hexdigest(),
            },
        }
    ]


def test_identical_inputs_and_options_produce_identical_report_bytes(tmp_path: Path) -> None:
    input_path = tmp_path / "audit-disabled.json"
    first_output = tmp_path / "first.json"
    second_output = tmp_path / "second.json"
    _write_synthetic_control(input_path, enabled=False)

    assert _analyze(input_path, first_output) == 1
    assert _analyze(input_path, second_output) == 1
    assert first_output.read_bytes() == second_output.read_bytes()


def test_semantic_fingerprint_ignores_source_layout_and_filename(tmp_path: Path) -> None:
    first_input = tmp_path / "first-layout.json"
    second_input = tmp_path / "second-layout.json"
    first_output = tmp_path / "first-report.json"
    second_output = tmp_path / "second-report.json"
    _write_synthetic_control(first_input, enabled=False)
    second_input.write_text(
        json.dumps(
            {
                "enabled": False,
                "control": "AUDIT_LOGGING",
                "record_id": "control-audit-logging",
                "record_type": "control_state",
                "dataset_classification": "synthetic",
                "schema_version": INPUT_SCHEMA_VERSION,
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )

    assert _analyze(first_input, first_output) == 1
    assert _analyze(second_input, second_output) == 1
    first_finding = json.loads(first_output.read_text(encoding="utf-8"))["findings"][0]
    second_finding = json.loads(second_output.read_text(encoding="utf-8"))["findings"][0]
    assert first_finding["fingerprint"] == second_finding["fingerprint"]


def test_analysis_does_not_modify_input_bytes_mode_or_mtime(tmp_path: Path) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    original_bytes = _write_synthetic_control(input_path, enabled=False)
    input_path.chmod(0o640)
    before = input_path.stat()

    assert _analyze(input_path, output_path) == 1

    after = input_path.stat()
    assert input_path.read_bytes() == original_bytes
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
    assert after.st_mtime_ns == before.st_mtime_ns


@pytest.mark.parametrize(
    "payload",
    [
        b"{not-json}\n",
        json.dumps(
            {
                "schema_version": INPUT_SCHEMA_VERSION,
                "dataset_classification": "internal",
                "record_type": "control_state",
                "record_id": "control-audit-logging",
                "control": "AUDIT_LOGGING",
                "enabled": False,
            }
        ).encode(),
        json.dumps(
            {
                "schema_version": INPUT_SCHEMA_VERSION,
                "dataset_classification": "synthetic",
                "record_type": "control_state",
                "record_id": "control-audit-logging",
                "control": "AUDIT_LOGGING",
            }
        ).encode(),
        json.dumps(
            {
                "schema_version": INPUT_SCHEMA_VERSION,
                "dataset_classification": "synthetic",
                "record_type": "control_state",
                "record_id": "control-audit-logging",
                "control": "AUDIT_LOGGING",
                "enabled": "false",
            }
        ).encode(),
        (
            "{"
            f'"schema_version":"{INPUT_SCHEMA_VERSION}",'
            '"dataset_classification":"synthetic",'
            '"record_type":"control_state",'
            '"record_id":"control-audit-logging",'
            '"control":"AUDIT_LOGGING",'
            '"enabled":false,"enabled":true}'
        ).encode(),
        (
            "{"
            f'"schema_version":"{INPUT_SCHEMA_VERSION}",'
            '"dataset_classification":"synthetic",'
            '"record_type":"control_state",'
            '"record_id":"control-audit-logging",'
            '"control":"AUDIT_LOGGING",'
            '"enabled":NaN}'
        ).encode(),
    ],
)
def test_malformed_incomplete_or_non_synthetic_input_fails_closed(
    tmp_path: Path, payload: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "invalid.json"
    output_path = tmp_path / "report.json"
    input_path.write_bytes(payload)

    assert _analyze(input_path, output_path) == 2
    assert not output_path.exists()
    assert capsys.readouterr().err.startswith("error: ")


def test_diagnostics_do_not_echo_secret_like_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "invalid.json"
    output_path = tmp_path / "report.json"
    secret_value = "ultra-sensitive-value"
    input_path.write_text(
        json.dumps(
            {
                "schema_version": INPUT_SCHEMA_VERSION,
                "dataset_classification": "synthetic",
                "record_type": "control_state",
                "record_id": "control-audit-logging",
                "control": "AUDIT_LOGGING",
                "enabled": False,
                "password": secret_value,
            }
        ),
        encoding="utf-8",
    )

    assert _analyze(input_path, output_path) == 2
    captured = capsys.readouterr()
    assert secret_value not in captured.err
    assert not output_path.exists()


@pytest.mark.parametrize("duplicate", [False, True])
def test_diagnostics_do_not_echo_hostile_field_names(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    duplicate: bool,
) -> None:
    input_path = tmp_path / "invalid.json"
    output_path = tmp_path / "report.json"
    hostile_key = "secret-token-ALPHA123\n\x1b[31m"
    if duplicate:
        payload = (
            "{"
            f'"schema_version":"{INPUT_SCHEMA_VERSION}",'
            '"dataset_classification":"synthetic",'
            '"record_type":"control_state",'
            '"record_id":"control-audit-logging",'
            '"control":"AUDIT_LOGGING",'
            '"enabled":false,'
            f"{json.dumps(hostile_key)}:1,{json.dumps(hostile_key)}:2"
            "}"
        )
    else:
        payload = json.dumps(
            {
                "schema_version": INPUT_SCHEMA_VERSION,
                "dataset_classification": "synthetic",
                "record_type": "control_state",
                "record_id": "control-audit-logging",
                "control": "AUDIT_LOGGING",
                "enabled": False,
                hostile_key: "not-for-diagnostics",
            }
        )
    input_path.write_text(payload, encoding="utf-8")

    assert _analyze(input_path, output_path) == 2
    error = capsys.readouterr().err
    assert hostile_key not in error
    assert "ALPHA123" not in error
    assert "\x1b" not in error
    assert error.count("\n") == 1


def test_diagnostics_do_not_echo_hostile_input_filename(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    hostile_name = "secret-token-ALPHA123\n\x1b[31m.json"
    input_path = tmp_path / hostile_name
    output_path = tmp_path / "report.json"

    assert _analyze(input_path, output_path) == 2
    error = capsys.readouterr().err
    assert "ALPHA123" not in error
    assert "\x1b" not in error
    assert error == "error: input filename is unsupported\n"


def test_oversized_json_integer_fails_closed_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "invalid.json"
    output_path = tmp_path / "report.json"
    digits = "9" * 5001
    payload = (
        "{"
        f'"schema_version":"{INPUT_SCHEMA_VERSION}",'
        '"dataset_classification":"synthetic",'
        '"record_type":"control_state",'
        '"record_id":"control-audit-logging",'
        '"control":"AUDIT_LOGGING",'
        f'"enabled":{digits}'
        "}"
    ).encode()
    input_path.write_bytes(payload)
    input_path.chmod(0o640)
    before = input_path.stat()

    assert _analyze(input_path, output_path) == 2
    after = input_path.stat()
    error = capsys.readouterr().err
    assert "Traceback" not in error
    assert digits not in error
    assert not output_path.exists()
    assert input_path.read_bytes() == payload
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
    assert after.st_mtime_ns == before.st_mtime_ns


def test_as_of_requires_an_explicit_timezone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    _write_synthetic_control(input_path, enabled=False)

    exit_code = main(
        [
            "analyze",
            str(input_path),
            "--as-of",
            "2026-09-01T00:00:00",
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 2
    assert not output_path.exists()
    assert "timezone" in capsys.readouterr().err.lower()


def test_as_of_rejects_fractional_seconds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    _write_synthetic_control(input_path, enabled=False)

    exit_code = main(
        [
            "analyze",
            str(input_path),
            "--as-of",
            "2026-09-01T00:00:00.123Z",
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 2
    assert not output_path.exists()
    assert "seconds precision" in capsys.readouterr().err.lower()


def test_json_format_is_explicitly_required(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    _write_synthetic_control(input_path, enabled=False)

    exit_code = main(
        [
            "analyze",
            str(input_path),
            "--as-of",
            "2026-09-01T00:00:00Z",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 2
    assert capsys.readouterr().err == "error: invalid command-line arguments\n"
    assert not output_path.exists()


@pytest.mark.parametrize("argument_kind", ["extra", "format", "option"])
def test_hostile_command_line_argument_is_not_echoed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    argument_kind: str,
) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    hostile_argument = "secret-token-ALPHA123\n\x1b[31m"
    _write_synthetic_control(input_path, enabled=False)

    arguments = [
        "analyze",
        str(input_path),
        "--as-of",
        "2026-09-01T00:00:00Z",
        "--format",
        hostile_argument if argument_kind == "format" else "json",
        "--output",
        str(output_path),
    ]
    if argument_kind in {"extra", "option"}:
        arguments.append(hostile_argument if argument_kind == "extra" else f"--{hostile_argument}")

    exit_code = main(arguments)

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == "error: invalid command-line arguments\n"
    assert "ALPHA123" not in captured.err
    assert "\x1b" not in captured.err
    assert not output_path.exists()


def test_equivalent_as_of_offsets_produce_identical_reports(tmp_path: Path) -> None:
    input_path = tmp_path / "audit-disabled.json"
    first_output = tmp_path / "first.json"
    second_output = tmp_path / "second.json"
    _write_synthetic_control(input_path, enabled=False)

    first_exit = main(
        [
            "analyze",
            str(input_path),
            "--as-of",
            "2026-09-01T03:00:00+03:00",
            "--format",
            "json",
            "--output",
            str(first_output),
        ]
    )
    second_exit = main(
        [
            "analyze",
            str(input_path),
            "--as-of",
            "2026-09-01T00:00:00Z",
            "--format",
            "json",
            "--output",
            str(second_output),
        ]
    )

    assert first_exit == second_exit == 1
    assert first_output.read_bytes() == second_output.read_bytes()


def test_existing_output_is_not_overwritten(tmp_path: Path) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    _write_synthetic_control(input_path, enabled=False)
    output_path.write_bytes(b"existing-report\n")

    assert _analyze(input_path, output_path) == 2
    assert output_path.read_bytes() == b"existing-report\n"


def test_output_error_does_not_echo_hostile_filename(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "secret-token-ALPHA123\n\x1b[31m.json"
    _write_synthetic_control(input_path, enabled=False)
    output_path.write_bytes(b"existing-report\n")

    assert _analyze(input_path, output_path) == 2
    error = capsys.readouterr().err
    assert error == "error: output filename is unsupported\n"
    assert "ALPHA123" not in error
    assert "\x1b" not in error
    assert output_path.read_bytes() == b"existing-report\n"


def test_output_cannot_alias_input(tmp_path: Path) -> None:
    input_path = tmp_path / "audit-disabled.json"
    original_bytes = _write_synthetic_control(input_path, enabled=False)

    assert _analyze(input_path, input_path) == 2
    assert input_path.read_bytes() == original_bytes


@pytest.mark.parametrize("alias_kind", ["hardlink", "symlink"])
def test_output_aliases_are_rejected(tmp_path: Path, alias_kind: str) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    original_bytes = _write_synthetic_control(input_path, enabled=False)
    if alias_kind == "hardlink":
        output_path.hardlink_to(input_path)
    else:
        output_path.symlink_to(input_path)

    assert _analyze(input_path, output_path) == 2
    assert input_path.read_bytes() == original_bytes


def test_failed_report_publication_leaves_no_output_or_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    _write_synthetic_control(input_path, enabled=False)

    def fail_link(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("injected publication failure")

    monkeypatch.setattr(reporting.os, "link", fail_link)

    assert _analyze(input_path, output_path) == 2
    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


@pytest.mark.parametrize("failure_point", ["write", "zero_write", "fsync"])
def test_report_write_failures_return_two_without_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure_point: str,
) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    _write_synthetic_control(input_path, enabled=False)

    if failure_point in {"write", "zero_write"}:

        def fail_write(descriptor: int, content: bytes) -> int:
            del descriptor, content
            if failure_point == "zero_write":
                return 0
            raise OSError("injected write failure")

        monkeypatch.setattr(reporting.os, "write", fail_write)
    else:

        def fail_fsync(descriptor: int) -> None:
            del descriptor
            raise OSError("injected fsync failure")

        monkeypatch.setattr(reporting.os, "fsync", fail_fsync)

    assert _analyze(input_path, output_path) == 2
    error = capsys.readouterr().err
    assert error == "error: report could not be written\n"
    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


def test_short_descriptor_writes_are_retried_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    _write_synthetic_control(input_path, enabled=False)
    real_write = reporting.os.write
    calls = 0

    def short_write(descriptor: int, content: bytes) -> int:
        nonlocal calls
        calls += 1
        limit = max(1, len(content) // 2)
        return real_write(descriptor, content[:limit])

    monkeypatch.setattr(reporting.os, "write", short_write)

    assert _analyze(input_path, output_path) == 1
    assert calls > 1
    assert output_path.exists()
    assert json.loads(output_path.read_text(encoding="utf-8"))["run"]["coverage"] == "complete"
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


def test_transient_temporary_cleanup_failure_is_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    _write_synthetic_control(input_path, enabled=False)
    real_unlink = reporting.os.unlink
    failed_once = False

    def fail_once(path: str, *, dir_fd: int | None = None) -> None:
        nonlocal failed_once
        if path.startswith(".erpsec-report.") and not failed_once:
            failed_once = True
            raise OSError("injected transient cleanup failure")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(reporting.os, "unlink", fail_once)

    assert _analyze(input_path, output_path) == 1
    assert output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


def test_persistent_temporary_cleanup_failure_preserves_committed_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    _write_synthetic_control(input_path, enabled=False)
    real_unlink = reporting.os.unlink
    unlink_attempts: list[str] = []

    def fail_temporary_cleanup(path: str, *, dir_fd: int | None = None) -> None:
        unlink_attempts.append(path)
        if path.startswith(".erpsec-report."):
            raise OSError("injected persistent cleanup failure")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(reporting.os, "unlink", fail_temporary_cleanup)

    assert _analyze(input_path, output_path) == 1
    assert capsys.readouterr().err == ""
    assert json.loads(output_path.read_text(encoding="utf-8"))["run"]["result"] == "findings"
    temporary_files = list(tmp_path.glob(".erpsec-report.*.tmp"))
    assert len(temporary_files) == 1
    assert stat.S_IMODE(temporary_files[0].stat().st_mode) == 0o600
    assert temporary_files[0].stat().st_ino == output_path.stat().st_ino
    assert output_path.name not in unlink_attempts


@pytest.mark.parametrize(
    ("enabled", "expected_exit", "expected_result"),
    [(False, 1, "findings"), (True, 0, "no_findings")],
)
def test_cleanup_failures_after_commit_never_report_an_unpublished_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    enabled: bool,
    expected_exit: int,
    expected_result: str,
) -> None:
    input_path = tmp_path / "audit.json"
    output_path = tmp_path / "report.json"
    _write_synthetic_control(input_path, enabled=enabled)
    unlink_attempts: list[str] = []

    def fail_all_cleanup(path: str, *, dir_fd: int | None = None) -> None:
        del dir_fd
        unlink_attempts.append(path)
        raise OSError("injected persistent cleanup failure")

    monkeypatch.setattr(reporting.os, "unlink", fail_all_cleanup)

    assert _analyze(input_path, output_path) == expected_exit
    assert capsys.readouterr().err == ""
    assert json.loads(output_path.read_text(encoding="utf-8"))["run"]["result"] == expected_result
    temporary_files = list(tmp_path.glob(".erpsec-report.*.tmp"))
    assert len(temporary_files) == 1
    assert stat.S_IMODE(temporary_files[0].stat().st_mode) == 0o600
    assert temporary_files[0].stat().st_ino == output_path.stat().st_ino
    assert temporary_files[0].read_bytes() == output_path.read_bytes()
    assert output_path.name not in unlink_attempts


def test_unexpected_runtime_failure_is_redacted_and_returns_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    input_path = tmp_path / "audit-enabled.json"
    output_path = tmp_path / "report.json"
    _write_synthetic_control(input_path, enabled=True)

    def fail_unexpectedly(path: Path) -> EvidenceBundle:
        del path
        raise RuntimeError("secret-token-ALPHA123")

    monkeypatch.setattr(cli, "load_control_state", fail_unexpectedly)

    assert _analyze(input_path, output_path) == 2
    assert capsys.readouterr().err == "error: unexpected internal failure\n"
    assert not output_path.exists()


@pytest.mark.parametrize("complete", [False, True])
def test_missing_evidence_cannot_produce_a_clean_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    complete: bool,
) -> None:
    input_path = tmp_path / "audit-enabled.json"
    output_path = tmp_path / "report.json"
    _write_synthetic_control(input_path, enabled=True)
    monkeypatch.setattr(
        cli,
        "load_control_state",
        lambda path: EvidenceBundle(records=(), complete=complete),
    )

    assert _analyze(input_path, output_path) == 2
    assert capsys.readouterr().err == "error: evidence coverage is incomplete\n"
    assert not output_path.exists()


def test_runtime_path_makes_no_network_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "audit-disabled.json"
    output_path = tmp_path / "report.json"
    _write_synthetic_control(input_path, enabled=False)

    def deny_network(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("runtime attempted a network connection")

    monkeypatch.setattr(socket, "socket", deny_network)
    monkeypatch.setattr(socket, "create_connection", deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)
    monkeypatch.setattr(subprocess, "Popen", deny_network)

    assert _analyze(input_path, output_path) == 1
