"""Generate, verify, and replay the deterministic synthetic scenario corpus."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

AS_OF = "2026-09-01T00:00:00Z"
CORPUS_SCHEMA_VERSION = "erpsec.synthetic-corpus-manifest/v1"
EVIDENCE_SCHEMA_VERSION = "erpsec.synthetic-evidence/v1"
GENERATOR_PATH = "scripts/synthetic_corpus.py"
GENERATOR_VERSION = "1.0.0"
ORIGIN = "first-principles deterministic generator"
RULE_IDS = ("ERP001", "ERP002", "ERP003", "ERP004", "ERP005", "ERP006")
ALLOWED_UNMANAGED_FILES = frozenset({"README.md"})
ADVERSARIAL_SENTINEL = "do-not-echo-fixture-sentinel-9f74c2</script>"


class CorpusError(Exception):
    """Base class for safely reportable corpus-tool failures."""


class CorpusUsageError(CorpusError):
    """The requested path or manifest is unsafe or invalid."""


class CorpusMismatchError(CorpusError):
    """Generated, committed, or replayed evidence differs from the contract."""


class _SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser whose failures do not echo user-controlled values."""

    def error(self, message: str) -> NoReturn:
        del message
        raise CorpusUsageError("invalid corpus-tool arguments")


@dataclass(frozen=True, slots=True)
class Fixture:
    """One deterministic managed fixture."""

    path: str
    format: str
    content: bytes
    intent: str
    record_count: int | None


def _record(record_type: str, record_id: str, **fields: object) -> dict[str, object]:
    return {
        "dataset_classification": "synthetic",
        "record_id": record_id,
        "record_type": record_type,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        **fields,
    }


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")


def _jsonl_bytes(records: tuple[dict[str, object], ...]) -> bytes:
    lines = (
        json.dumps(
            record,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        for record in records
    )
    return ("\n".join(lines) + "\n").encode("ascii")


def _csv_bytes(fieldnames: tuple[str, ...], records: tuple[dict[str, object], ...]) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=fieldnames,
        lineterminator="\n",
        extrasaction="raise",
    )
    writer.writeheader()
    writer.writerows(
        {
            key: ("true" if value is True else "false" if value is False else value)
            for key, value in record.items()
        }
        for record in records
    )
    return buffer.getvalue().encode("ascii")


def _fixture_specs() -> tuple[Fixture, ...]:
    principal_fields = (
        "schema_version",
        "dataset_classification",
        "record_type",
        "record_id",
        "principal_id",
        "principal_kind",
        "enabled",
        "last_active_at",
    )

    clean_principals = (
        _record(
            "principal",
            "principal.clean.user",
            principal_id="fixture-clean-user",
            principal_kind="human",
            enabled=True,
            last_active_at=AS_OF,
        ),
    )
    clean_permissions = (
        _record(
            "permission_assignment",
            "permission.clean.read",
            principal_id="fixture-clean-user",
            permission="READ_REPORT",
            assignment_mode="inherited",
            assigned_at="2026-01-01T00:00:00Z",
        ),
    )
    clean_events_controls = (
        _record(
            "control_state",
            "control.clean.audit",
            control="AUDIT_LOGGING",
            enabled=True,
        ),
        _record(
            "auth_event",
            "auth.clean.sign-in",
            principal_id="fixture-clean-user",
            action="SIGN_IN",
            outcome="success",
            occurred_at=AS_OF,
        ),
    )

    access_principals = (
        _record(
            "principal",
            "principal.access.boundary",
            principal_id="fixture-access-boundary",
            principal_kind="human",
            enabled=True,
            last_active_at="2026-06-03T00:00:00Z",
        ),
        _record(
            "principal",
            "principal.access.direct",
            principal_id="fixture-access-direct",
            principal_kind="human",
            enabled=True,
            last_active_at=AS_OF,
        ),
        _record(
            "principal",
            "principal.access.sod",
            principal_id="fixture-access-sod",
            principal_kind="human",
            enabled=True,
            last_active_at=AS_OF,
        ),
        _record(
            "principal",
            "principal.access.stale",
            principal_id="fixture-access-stale",
            principal_kind="human",
            enabled=True,
            last_active_at="2026-06-02T23:59:59Z",
        ),
    )
    access_permissions = (
        _record(
            "permission_assignment",
            "permission.access.approve-payment",
            principal_id="fixture-access-sod",
            permission="APPROVE_PAYMENT",
            assignment_mode="inherited",
            assigned_at="2026-01-01T00:00:00Z",
        ),
        _record(
            "permission_assignment",
            "permission.access.boundary-admin",
            principal_id="fixture-access-boundary",
            permission="ADMINISTER_SYSTEM",
            assignment_mode="inherited",
            assigned_at="2026-01-01T00:00:00Z",
        ),
        _record(
            "permission_assignment",
            "permission.access.create-vendor",
            principal_id="fixture-access-sod",
            permission="CREATE_VENDOR",
            assignment_mode="inherited",
            assigned_at="2026-01-01T00:00:00Z",
        ),
        _record(
            "permission_assignment",
            "permission.access.direct-admin",
            principal_id="fixture-access-direct",
            permission="ADMINISTER_SYSTEM",
            assignment_mode="direct",
            assigned_at="2026-01-01T00:00:00Z",
        ),
        _record(
            "permission_assignment",
            "permission.access.stale-admin",
            principal_id="fixture-access-stale",
            permission="ADMINISTER_SYSTEM",
            assignment_mode="inherited",
            assigned_at="2026-01-01T00:00:00Z",
        ),
    )

    auth_principals = (
        _record(
            "principal",
            "principal.auth.emergency",
            principal_id="fixture-auth-emergency",
            principal_kind="emergency",
            enabled=True,
            last_active_at=AS_OF,
        ),
        _record(
            "principal",
            "principal.auth.failure-clean",
            principal_id="fixture-auth-failure-clean",
            principal_kind="human",
            enabled=True,
            last_active_at=AS_OF,
        ),
        _record(
            "principal",
            "principal.auth.failure-match",
            principal_id="fixture-auth-failure-match",
            principal_kind="human",
            enabled=True,
            last_active_at=AS_OF,
        ),
    )
    auth_events = (
        _record(
            "auth_event",
            "auth.emergency.boundary-end",
            principal_id="fixture-auth-emergency",
            action="SIGN_IN",
            outcome="success",
            occurred_at=AS_OF,
        ),
        _record(
            "auth_event",
            "auth.emergency.boundary-start",
            principal_id="fixture-auth-emergency",
            action="SIGN_IN",
            outcome="success",
            occurred_at="2026-08-31T20:00:00Z",
        ),
        _record(
            "auth_event",
            "auth.emergency.outside",
            principal_id="fixture-auth-emergency",
            action="SIGN_IN",
            outcome="success",
            occurred_at="2026-08-31T19:59:59Z",
        ),
        *tuple(
            _record(
                "auth_event",
                f"auth.failure.match.{index}",
                principal_id="fixture-auth-failure-match",
                action="SIGN_IN",
                outcome="failure",
                occurred_at=timestamp,
            )
            for index, timestamp in enumerate(
                (
                    "2026-08-31T12:00:00Z",
                    "2026-08-31T12:03:00Z",
                    "2026-08-31T12:06:00Z",
                    "2026-08-31T12:09:00Z",
                    "2026-08-31T12:15:00Z",
                ),
                start=1,
            )
        ),
        *tuple(
            _record(
                "auth_event",
                f"auth.failure.clean.{index}",
                principal_id="fixture-auth-failure-clean",
                action="SIGN_IN",
                outcome="failure",
                occurred_at=timestamp,
            )
            for index, timestamp in enumerate(
                (
                    "2026-08-31T13:00:00Z",
                    "2026-08-31T13:03:00Z",
                    "2026-08-31T13:06:00Z",
                    "2026-08-31T13:09:00Z",
                    "2026-08-31T13:15:01Z",
                ),
                start=1,
            )
        ),
    )
    auth_control = (
        _record(
            "control_state",
            "control.auth.audit",
            control="AUDIT_LOGGING",
            enabled=False,
        ),
    )

    malformed_first_line = _jsonl_bytes(
        (
            _record(
                "control_state",
                "control.fixture.validation.malformed",
                control="AUDIT_LOGGING",
                enabled=False,
            ),
        )
    )
    incomplete_principal = (
        _record(
            "principal",
            "principal.fixture.validation.incomplete",
            principal_id="fixture-persona-incomplete",
            principal_kind="human",
            enabled=True,
            last_active_at=AS_OF,
        ),
    )
    adversarial_extra_field = _record(
        "control_state",
        "control.fixture.validation.adversarial",
        control="AUDIT_LOGGING",
        enabled=False,
        unexpected_sensitive_field=ADVERSARIAL_SENTINEL,
    )

    fixtures = (
        Fixture(
            path="clean-baseline/clean-principals.csv",
            format="csv",
            content=_csv_bytes(principal_fields, clean_principals),
            intent=(
                "Provide one fictional enabled human principal with current activity for the "
                "complete clean replay."
            ),
            record_count=len(clean_principals),
        ),
        Fixture(
            path="clean-baseline/clean-permissions.jsonl",
            format="jsonl",
            content=_jsonl_bytes(clean_permissions),
            intent=(
                "Provide one inherited, non-privileged generic permission for the clean replay."
            ),
            record_count=len(clean_permissions),
        ),
        Fixture(
            path="clean-baseline/clean-events-controls.json",
            format="json",
            content=_json_bytes(clean_events_controls),
            intent=(
                "Provide enabled audit logging and one successful sign-in by a non-emergency "
                "fictional principal."
            ),
            record_count=len(clean_events_controls),
        ),
        Fixture(
            path="access-governance/access-principals.csv",
            format="csv",
            content=_csv_bytes(principal_fields, access_principals),
            intent=(
                "Provide fictional principals on both sides of the inactivity cutoff plus active "
                "principals for direct-grant and toxic-pair evidence."
            ),
            record_count=len(access_principals),
        ),
        Fixture(
            path="access-governance/access-permissions.jsonl",
            format="jsonl",
            content=_jsonl_bytes(access_permissions),
            intent=(
                "Provide generic stale, exact-boundary, direct privileged, and configured "
                "toxic-pair assignments for the access-governance replay."
            ),
            record_count=len(access_permissions),
        ),
        Fixture(
            path="authentication-control/auth-principals.csv",
            format="csv",
            content=_csv_bytes(principal_fields, auth_principals),
            intent=(
                "Provide one fictional emergency principal and separate fictional principals for "
                "matching and just-outside failure windows."
            ),
            record_count=len(auth_principals),
        ),
        Fixture(
            path="authentication-control/auth-events.jsonl",
            format="jsonl",
            content=_jsonl_bytes(auth_events),
            intent=(
                "Provide one out-of-window emergency sign-in and one inclusive five-failure burst "
                "using fictional identifiers and fixed timestamps."
            ),
            record_count=len(auth_events),
        ),
        Fixture(
            path="authentication-control/auth-control.json",
            format="json",
            content=_json_bytes(auth_control),
            intent="Provide one explicitly disabled generic audit-logging control.",
            record_count=len(auth_control),
        ),
        Fixture(
            path="validation/malformed-tail.jsonl",
            format="jsonl",
            content=malformed_first_line + b'{"record_type":\n',
            intent=(
                "Verify that a malformed trailing JSONL record invalidates the complete source and "
                "publishes no report."
            ),
            record_count=None,
        ),
        Fixture(
            path="validation/incomplete-principal.json",
            format="json",
            content=_json_bytes(incomplete_principal),
            intent=(
                "Verify that a principal-only source cannot produce a clean audit-logging result."
            ),
            record_count=len(incomplete_principal),
        ),
        Fixture(
            path="validation/adversarial-extra-field.json",
            format="json",
            content=_json_bytes((adversarial_extra_field,)),
            intent=(
                "Verify that an unsupported field containing an injection-shaped sentinel fails "
                "closed without diagnostic echo or report publication."
            ),
            record_count=1,
        ),
    )
    return tuple(sorted(fixtures, key=lambda fixture: fixture.path))


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _source_ref(
    fixture: Fixture,
    locator: dict[str, int | str],
    *,
    field: str,
) -> dict[str, int | str]:
    reference: dict[str, int | str] = {
        "adapter": f"erpsec.{fixture.format}/v1",
        "format": fixture.format,
        "path": PurePosixPath(fixture.path).name,
        "sha256": _sha256(fixture.content),
    }
    if fixture.format == "json":
        pointer = locator["json_pointer"]
        assert isinstance(pointer, str)
        reference["json_pointer"] = f"{pointer}/{field}"
    else:
        reference.update(locator)
        reference["field"] = field
    return reference


def _evidence_ref(
    fixtures: dict[str, Fixture],
    path: str,
    record_id: str,
    locator: dict[str, int | str],
    field: str,
) -> dict[str, object]:
    return {
        "record_id": record_id,
        "source_ref": _source_ref(fixtures[path], locator, field=field),
    }


def _expected_record(
    record_type: str,
    record_id: str,
    path: str,
    locator: dict[str, int | str],
) -> dict[str, object]:
    return {
        "record_id": record_id,
        "record_type": record_type,
        "source": {
            "locator": locator,
            "path": PurePosixPath(path).name,
        },
    }


def _evaluation(rule_id: str, status: str) -> dict[str, str]:
    return {"rule_id": rule_id, "rule_version": "1.0.0", "status": status}


def _finding(
    rule_id: str,
    fingerprint: str,
    evidence_refs: tuple[dict[str, object], ...],
) -> dict[str, object]:
    return {
        "evidence_refs": list(evidence_refs),
        "fingerprint": fingerprint,
        "rule_id": rule_id,
        "rule_version": "1.0.0",
    }


def _scenario_contracts(fixtures: dict[str, Fixture]) -> list[dict[str, object]]:
    clean_principals = "clean-baseline/clean-principals.csv"
    clean_permissions = "clean-baseline/clean-permissions.jsonl"
    clean_events = "clean-baseline/clean-events-controls.json"
    clean_records = [
        _expected_record(
            "auth_event",
            "auth.clean.sign-in",
            clean_events,
            {"json_pointer": "/1"},
        ),
        _expected_record(
            "control_state",
            "control.clean.audit",
            clean_events,
            {"json_pointer": "/0"},
        ),
        _expected_record(
            "permission_assignment",
            "permission.clean.read",
            clean_permissions,
            {"line": 1},
        ),
        _expected_record(
            "principal",
            "principal.clean.user",
            clean_principals,
            {"row": 2},
        ),
    ]

    access_principals = "access-governance/access-principals.csv"
    access_permissions = "access-governance/access-permissions.jsonl"
    access_records = [
        _expected_record(
            "permission_assignment",
            "permission.access.approve-payment",
            access_permissions,
            {"line": 1},
        ),
        _expected_record(
            "permission_assignment",
            "permission.access.boundary-admin",
            access_permissions,
            {"line": 2},
        ),
        _expected_record(
            "permission_assignment",
            "permission.access.create-vendor",
            access_permissions,
            {"line": 3},
        ),
        _expected_record(
            "permission_assignment",
            "permission.access.direct-admin",
            access_permissions,
            {"line": 4},
        ),
        _expected_record(
            "permission_assignment",
            "permission.access.stale-admin",
            access_permissions,
            {"line": 5},
        ),
        _expected_record(
            "principal",
            "principal.access.boundary",
            access_principals,
            {"row": 2},
        ),
        _expected_record(
            "principal",
            "principal.access.direct",
            access_principals,
            {"row": 3},
        ),
        _expected_record(
            "principal",
            "principal.access.sod",
            access_principals,
            {"row": 4},
        ),
        _expected_record(
            "principal",
            "principal.access.stale",
            access_principals,
            {"row": 5},
        ),
    ]
    erp002_evidence = tuple(
        _evidence_ref(
            fixtures,
            access_permissions,
            "permission.access.stale-admin",
            {"line": 5},
            field,
        )
        for field in ("permission", "principal_id")
    ) + tuple(
        _evidence_ref(
            fixtures,
            access_principals,
            "principal.access.stale",
            {"row": 5},
            field,
        )
        for field in ("enabled", "last_active_at", "principal_id")
    )
    erp003_evidence = tuple(
        _evidence_ref(
            fixtures,
            access_permissions,
            "permission.access.direct-admin",
            {"line": 4},
            field,
        )
        for field in ("assignment_mode", "permission")
    )
    erp004_evidence = tuple(
        _evidence_ref(
            fixtures,
            access_permissions,
            record_id,
            {"line": line},
            field,
        )
        for record_id, line in (
            ("permission.access.approve-payment", 1),
            ("permission.access.create-vendor", 3),
        )
        for field in ("permission", "principal_id")
    )

    auth_principals = "authentication-control/auth-principals.csv"
    auth_events = "authentication-control/auth-events.jsonl"
    auth_control = "authentication-control/auth-control.json"
    auth_records = [
        _expected_record(
            "auth_event",
            "auth.emergency.boundary-end",
            auth_events,
            {"line": 1},
        ),
        _expected_record(
            "auth_event",
            "auth.emergency.boundary-start",
            auth_events,
            {"line": 2},
        ),
        _expected_record(
            "auth_event",
            "auth.emergency.outside",
            auth_events,
            {"line": 3},
        ),
        *[
            _expected_record(
                "auth_event",
                f"auth.failure.clean.{index}",
                auth_events,
                {"line": index + 8},
            )
            for index in range(1, 6)
        ],
        *[
            _expected_record(
                "auth_event",
                f"auth.failure.match.{index}",
                auth_events,
                {"line": index + 3},
            )
            for index in range(1, 6)
        ],
        _expected_record(
            "control_state",
            "control.auth.audit",
            auth_control,
            {"json_pointer": "/0"},
        ),
        _expected_record(
            "principal",
            "principal.auth.emergency",
            auth_principals,
            {"row": 2},
        ),
        _expected_record(
            "principal",
            "principal.auth.failure-clean",
            auth_principals,
            {"row": 3},
        ),
        _expected_record(
            "principal",
            "principal.auth.failure-match",
            auth_principals,
            {"row": 4},
        ),
    ]
    erp001_evidence = (
        _evidence_ref(
            fixtures,
            auth_control,
            "control.auth.audit",
            {"json_pointer": "/0"},
            "enabled",
        ),
    )
    erp005_evidence = tuple(
        _evidence_ref(
            fixtures,
            auth_events,
            "auth.emergency.outside",
            {"line": 3},
            field,
        )
        for field in ("action", "occurred_at", "outcome", "principal_id")
    ) + tuple(
        _evidence_ref(
            fixtures,
            auth_principals,
            "principal.auth.emergency",
            {"row": 2},
            field,
        )
        for field in ("principal_id", "principal_kind")
    )
    erp006_evidence = tuple(
        _evidence_ref(
            fixtures,
            auth_events,
            f"auth.failure.match.{index}",
            {"line": index + 3},
            field,
        )
        for index in range(1, 6)
        for field in ("action", "occurred_at", "outcome", "principal_id")
    )

    scenarios: list[dict[str, object]] = [
        {
            "expected": {
                "evaluations": [_evaluation(rule_id, "not_matched") for rule_id in RULE_IDS],
                "exit_code": 0,
                "findings": [],
                "output_present": True,
                "records": clean_records,
            },
            "input_paths": sorted((clean_principals, clean_permissions, clean_events)),
            "scenario_id": "clean-baseline",
            "selected_rules": list(RULE_IDS),
        },
        {
            "expected": {
                "evaluations": [
                    _evaluation("ERP002", "matched"),
                    _evaluation("ERP003", "matched"),
                    _evaluation("ERP004", "matched"),
                ],
                "exit_code": 1,
                "findings": [
                    _finding(
                        "ERP002",
                        "5fcaa53c2b2dfa4876d13b290bfe0466380b073950f65b30919f3c8037f5ef31",
                        erp002_evidence,
                    ),
                    _finding(
                        "ERP003",
                        "ea1222dbc95da3713f7aa4fc325417e90ad5c6de52c902177b5f44c0f9f46125",
                        erp003_evidence,
                    ),
                    _finding(
                        "ERP004",
                        "28cebe7564a901c9ace0646d74373bbd40af951f9ce4b73d72c4d0af8f7aea4e",
                        erp004_evidence,
                    ),
                ],
                "output_present": True,
                "records": access_records,
            },
            "input_paths": sorted((access_principals, access_permissions)),
            "scenario_id": "access-governance",
            "selected_rules": ["ERP002", "ERP003", "ERP004"],
        },
        {
            "expected": {
                "evaluations": [
                    _evaluation("ERP001", "matched"),
                    _evaluation("ERP005", "matched"),
                    _evaluation("ERP006", "matched"),
                ],
                "exit_code": 1,
                "findings": [
                    _finding(
                        "ERP001",
                        "5e8e54ccb2d8a4e08413e1c52c0938f2646bc01b767508ba383a8e4dca1eab53",
                        erp001_evidence,
                    ),
                    _finding(
                        "ERP005",
                        "d30f1e317f1680d2e7951e59098e2da7ee33dc5dd4ac46dc6880658dbe9bd7e1",
                        erp005_evidence,
                    ),
                    _finding(
                        "ERP006",
                        "847311517adac28d910ef1cf15a26dbed13a993b17d78eb3cbd15165ef0fb657",
                        erp006_evidence,
                    ),
                ],
                "output_present": True,
                "records": auth_records,
            },
            "input_paths": sorted((auth_principals, auth_events, auth_control)),
            "scenario_id": "authentication-control",
            "selected_rules": ["ERP001", "ERP005", "ERP006"],
        },
    ]
    return sorted(scenarios, key=lambda scenario: str(scenario["scenario_id"]))


def _validation_contracts() -> list[dict[str, object]]:
    validations: list[dict[str, object]] = [
        {
            "expected": {
                "diagnostic": "error: input contains malformed JSON\n",
                "diagnostic_excludes": [],
                "exit_code": 2,
                "output_present": False,
            },
            "input_paths": ["validation/malformed-tail.jsonl"],
            "selected_rules": ["ERP001"],
            "validation_id": "malformed-tail",
        },
        {
            "expected": {
                "diagnostic": "error: evidence coverage is incomplete\n",
                "diagnostic_excludes": [],
                "exit_code": 2,
                "output_present": False,
            },
            "input_paths": ["validation/incomplete-principal.json"],
            "selected_rules": ["ERP001"],
            "validation_id": "incomplete-principal",
        },
        {
            "expected": {
                "diagnostic": ("error: input record does not match the supported field contract\n"),
                "diagnostic_excludes": [ADVERSARIAL_SENTINEL],
                "exit_code": 2,
                "output_present": False,
            },
            "input_paths": ["validation/adversarial-extra-field.json"],
            "selected_rules": ["ERP001"],
            "validation_id": "adversarial-extra-field",
        },
    ]
    return sorted(validations, key=lambda validation: str(validation["validation_id"]))


def _expected_corpus() -> dict[str, bytes]:
    fixture_specs = _fixture_specs()
    fixtures = {fixture.path: fixture for fixture in fixture_specs}
    fixture_entries: list[dict[str, object]] = []
    for fixture in fixture_specs:
        entry: dict[str, object] = {
            "byte_count": len(fixture.content),
            "format": fixture.format,
            "intent": fixture.intent,
            "origin": ORIGIN,
            "path": fixture.path,
            "sha256": _sha256(fixture.content),
        }
        if fixture.record_count is not None:
            entry["record_count"] = fixture.record_count
        fixture_entries.append(entry)

    manifest = {
        "as_of": AS_OF,
        "dataset_classification": "synthetic",
        "fixtures": fixture_entries,
        "generator": {"path": GENERATOR_PATH, "version": GENERATOR_VERSION},
        "scenarios": _scenario_contracts(fixtures),
        "schema_version": CORPUS_SCHEMA_VERSION,
        "validation_cases": _validation_contracts(),
    }
    managed = {fixture.path: fixture.content for fixture in fixture_specs}
    managed["manifest.json"] = _json_bytes(manifest)
    checksum_lines = [f"{_sha256(content)}  {path}\n" for path, content in sorted(managed.items())]
    managed["SHA256SUMS"] = "".join(checksum_lines).encode("ascii")
    return dict(sorted(managed.items()))


def _safe_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise CorpusUsageError("managed corpus path is invalid")
    return path


def _validate_expected_paths(managed: dict[str, bytes]) -> None:
    for relative in managed:
        _safe_relative_path(relative)


def _validate_target_parent(target: Path) -> None:
    if target.name in {"", ".", ".."} or target.is_symlink():
        raise CorpusUsageError("corpus target is unsafe")
    parent = target.parent
    if parent.is_symlink() or not parent.is_dir():
        raise CorpusUsageError("corpus target parent is invalid")


def _prepare_empty_target(target: Path) -> None:
    _validate_target_parent(target)
    if target.exists():
        if not target.is_dir():
            raise CorpusUsageError("corpus target must be a directory")
        try:
            entries = tuple(target.iterdir())
            if any(
                entry.name not in ALLOWED_UNMANAGED_FILES
                or entry.is_symlink()
                or not entry.is_file()
                for entry in entries
            ):
                raise CorpusUsageError("corpus target must be empty")
        except OSError as exc:
            raise CorpusUsageError("corpus target could not be inspected") from exc
        return
    try:
        target.mkdir()
    except OSError as exc:
        raise CorpusUsageError("corpus target could not be created") from exc


def _write_managed_corpus(target: Path, managed: dict[str, bytes]) -> None:
    _prepare_empty_target(target)
    try:
        for relative, content in managed.items():
            destination = target.joinpath(*_safe_relative_path(relative).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.is_symlink():
                raise CorpusUsageError("managed corpus destination is unsafe")
            with destination.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
    except CorpusError:
        raise
    except OSError as exc:
        raise CorpusUsageError("managed corpus could not be written") from exc


def _actual_managed_paths(corpus: Path) -> set[str]:
    if corpus.is_symlink() or not corpus.is_dir():
        raise CorpusUsageError("corpus directory is invalid")
    paths: set[str] = set()
    try:
        for root, directories, files in os.walk(corpus, followlinks=False):
            root_path = Path(root)
            for directory in directories:
                if (root_path / directory).is_symlink():
                    raise CorpusUsageError("corpus contains an unsafe path")
            for filename in files:
                path = root_path / filename
                if path.is_symlink() or not path.is_file():
                    raise CorpusUsageError("corpus contains an unsafe path")
                relative = path.relative_to(corpus).as_posix()
                _safe_relative_path(relative)
                if relative not in ALLOWED_UNMANAGED_FILES:
                    paths.add(relative)
    except CorpusError:
        raise
    except OSError as exc:
        raise CorpusUsageError("corpus directory could not be inspected") from exc
    return paths


def _check_corpus(corpus: Path, managed: dict[str, bytes]) -> None:
    expected_paths = set(managed)
    if _actual_managed_paths(corpus) != expected_paths:
        raise CorpusMismatchError("corpus file set differs from the deterministic contract")
    try:
        for relative, expected in managed.items():
            path = corpus.joinpath(*_safe_relative_path(relative).parts)
            if path.stat().st_size != len(expected):
                raise CorpusMismatchError("corpus bytes differ from the deterministic contract")
            with path.open("rb") as handle:
                actual = handle.read(len(expected) + 1)
            if actual != expected:
                raise CorpusMismatchError("corpus bytes differ from the deterministic contract")
    except CorpusError:
        raise
    except OSError as exc:
        raise CorpusUsageError("corpus files could not be read") from exc


def _load_manifest(path: Path, *, expected: bytes) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.name != "manifest.json":
        raise CorpusUsageError("corpus manifest path is invalid")
    try:
        with path.open("rb") as handle:
            content = handle.read(len(expected) + 1)
        if content != expected:
            raise CorpusMismatchError("corpus manifest changed after integrity validation")
        value = json.loads(content.decode("ascii"))
    except CorpusError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CorpusUsageError("corpus manifest is invalid") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != CORPUS_SCHEMA_VERSION
        or value.get("dataset_classification") != "synthetic"
        or value.get("as_of") != AS_OF
        or not isinstance(value.get("fixtures"), list)
        or not isinstance(value.get("scenarios"), list)
        or not isinstance(value.get("validation_cases"), list)
    ):
        raise CorpusUsageError("corpus manifest is invalid")
    return value


def _cli_arguments(
    corpus: Path,
    input_paths: list[str],
    selected_rules: list[str],
    output: Path,
) -> list[str]:
    arguments = ["analyze"]
    for relative in input_paths:
        arguments.append(str(corpus.joinpath(*_safe_relative_path(relative).parts)))
    arguments.extend(("--as-of", AS_OF, "--format", "json", "--output", str(output)))
    for rule_id in selected_rules:
        if rule_id not in RULE_IDS:
            raise CorpusUsageError("corpus manifest contains an unsupported rule")
        arguments.extend(("--rule", rule_id))
    return arguments


def _invoke_cli(arguments: list[str]) -> tuple[int, str, str]:
    repository_root = Path(__file__).resolve().parents[1]
    source_root = repository_root / "src"
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))
    from erp_security_evidence_workbench.cli import main as cli_main

    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        exit_code = cli_main(arguments)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _report_records(report: dict[str, Any]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for item in report.get("evidence_manifest", []):
        source_ref = item["source_ref"]
        locator = {
            key: source_ref[key] for key in ("json_pointer", "row", "line") if key in source_ref
        }
        records.append(
            {
                "record_id": item["record_id"],
                "record_type": item["record_type"],
                "source": {"locator": locator, "path": source_ref["path"]},
            }
        )
    return records


def _report_findings(report: dict[str, Any]) -> list[dict[str, object]]:
    return [
        {
            "evidence_refs": finding["evidence_refs"],
            "fingerprint": finding["fingerprint"],
            "rule_id": finding["rule_id"],
            "rule_version": finding["rule_version"],
        }
        for finding in report.get("findings", [])
    ]


def _replay_success_scenario(corpus: Path, scenario: dict[str, Any]) -> None:
    expected = scenario.get("expected")
    input_paths = scenario.get("input_paths")
    selected_rules = scenario.get("selected_rules")
    if (
        not isinstance(expected, dict)
        or not isinstance(input_paths, list)
        or not all(isinstance(value, str) for value in input_paths)
        or not isinstance(selected_rules, list)
        or not all(isinstance(value, str) for value in selected_rules)
    ):
        raise CorpusUsageError("corpus scenario contract is invalid")

    report_bytes: list[bytes] = []
    with tempfile.TemporaryDirectory(prefix="erpsec-corpus-replay-") as temporary_name:
        for run_number in (1, 2):
            output = Path(temporary_name) / f"report-{run_number}.json"
            exit_code, stdout, stderr = _invoke_cli(
                _cli_arguments(corpus, input_paths, selected_rules, output)
            )
            output_present = output.is_file()
            if (
                stdout
                or stderr
                or exit_code != expected.get("exit_code")
                or output_present is not expected.get("output_present")
                or not output_present
            ):
                raise CorpusMismatchError("scenario replay differs from the expected outcome")
            try:
                report_bytes.append(output.read_bytes())
            except OSError as exc:
                raise CorpusMismatchError("scenario replay report is invalid") from exc

    if len(report_bytes) != 2 or report_bytes[0] != report_bytes[1]:
        raise CorpusMismatchError("scenario replay is not byte-deterministic")
    try:
        report = json.loads(report_bytes[0].decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CorpusMismatchError("scenario replay report is invalid") from exc

    if (
        report.get("evaluations") != expected.get("evaluations")
        or _report_records(report) != expected.get("records")
        or _report_findings(report) != expected.get("findings")
        or report.get("run", {}).get("coverage") != "complete"
        or report.get("run", {}).get("input_count") != len(expected.get("records", []))
    ):
        raise CorpusMismatchError("scenario replay report differs from the manifest")


def _replay_validation(corpus: Path, validation: dict[str, Any]) -> None:
    expected = validation.get("expected")
    input_paths = validation.get("input_paths")
    selected_rules = validation.get("selected_rules")
    if (
        not isinstance(expected, dict)
        or not isinstance(input_paths, list)
        or not all(isinstance(value, str) for value in input_paths)
        or not isinstance(selected_rules, list)
        or not all(isinstance(value, str) for value in selected_rules)
    ):
        raise CorpusUsageError("corpus validation contract is invalid")

    with tempfile.TemporaryDirectory(prefix="erpsec-corpus-validation-") as temporary_name:
        output = Path(temporary_name) / "report.json"
        exit_code, stdout, stderr = _invoke_cli(
            _cli_arguments(corpus, input_paths, selected_rules, output)
        )
        if (
            stdout
            or exit_code != expected.get("exit_code")
            or output.is_file() is not expected.get("output_present")
            or stderr != expected.get("diagnostic")
        ):
            raise CorpusMismatchError("validation replay differs from the expected outcome")
        exclusions = expected.get("diagnostic_excludes")
        if not isinstance(exclusions, list) or any(
            not isinstance(value, str) or value in stderr for value in exclusions
        ):
            raise CorpusMismatchError("validation diagnostic contains excluded input")


def _replay_manifest(manifest_path: Path, managed: dict[str, bytes]) -> None:
    corpus = manifest_path.parent
    _check_corpus(corpus, managed)
    manifest = _load_manifest(manifest_path, expected=managed["manifest.json"])
    scenarios = manifest["scenarios"]
    validations = manifest["validation_cases"]
    if not all(isinstance(value, dict) for value in (*scenarios, *validations)):
        raise CorpusUsageError("corpus manifest replay entries are invalid")
    for scenario in scenarios:
        _replay_success_scenario(corpus, scenario)
    for validation in validations:
        _replay_validation(corpus, validation)
    _check_corpus(corpus, managed)


def _parser() -> _SafeArgumentParser:
    parser = _SafeArgumentParser(description="Manage the deterministic synthetic scenario corpus.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    generate = subcommands.add_parser("generate")
    generate.add_argument("--output", required=True, type=Path)
    check = subcommands.add_parser("check")
    check.add_argument("--corpus", required=True, type=Path)
    replay = subcommands.add_parser("replay")
    replay.add_argument("--manifest", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        managed = _expected_corpus()
        _validate_expected_paths(managed)
        if arguments.command == "generate":
            _write_managed_corpus(arguments.output, managed)
            print("synthetic corpus generated")
        elif arguments.command == "check":
            _check_corpus(arguments.corpus, managed)
            print("synthetic corpus verified")
        else:
            _replay_manifest(arguments.manifest, managed)
            print("synthetic corpus replay verified")
    except CorpusMismatchError:
        print("error: synthetic corpus mismatch", file=sys.stderr)
        return 1
    except CorpusError:
        print("error: invalid synthetic corpus operation", file=sys.stderr)
        return 2
    except Exception:
        print("error: unexpected synthetic corpus failure", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
