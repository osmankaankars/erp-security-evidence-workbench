"""Strict normalization into the vendor-neutral evidence record model."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from erp_security_evidence_workbench.errors import InputValidationError
from erp_security_evidence_workbench.models import (
    AuthEvent,
    CanonicalRecord,
    ChangeEvent,
    ControlState,
    PermissionAssignment,
    Principal,
    RoleAssignment,
    SourceRef,
)
from erp_security_evidence_workbench.timestamps import normalize_rfc3339_seconds

INPUT_SCHEMA_VERSION = "erpsec.synthetic-evidence/v1"
LEGACY_INPUT_SCHEMA_VERSION = "erpsec.synthetic-control-state/v1"

RECORD_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
CAPABILITY_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,63}")

COMMON_REQUIRED_FIELDS = {
    "schema_version",
    "dataset_classification",
    "record_type",
}
TYPE_FIELDS: dict[str, frozenset[str]] = {
    "principal": frozenset({"principal_id", "principal_kind", "enabled", "last_active_at"}),
    "role_assignment": frozenset({"principal_id", "role_id", "assignment_mode", "assigned_at"}),
    "permission_assignment": frozenset(
        {"principal_id", "permission", "assignment_mode", "assigned_at"}
    ),
    "auth_event": frozenset({"principal_id", "action", "outcome", "occurred_at"}),
    "change_event": frozenset({"principal_id", "object_id", "action", "outcome", "occurred_at"}),
    "control_state": frozenset({"control", "enabled"}),
}


def expected_input_fields(record_type: str) -> tuple[frozenset[str], frozenset[str]]:
    """Return the accepted exact field sets, without and with an explicit ID."""
    type_fields = TYPE_FIELDS.get(record_type)
    if type_fields is None:
        raise InputValidationError("input record type is unsupported")
    without_id = frozenset(COMMON_REQUIRED_FIELDS) | type_fields
    return without_id, without_id | {"record_id"}


def normalize_payload(
    payload: dict[str, Any],
    source_ref: SourceRef,
    *,
    max_field_chars: int,
) -> CanonicalRecord:
    """Validate one exact synthetic record and return its typed canonical form."""
    if len(payload) > 32:
        raise InputValidationError("input record contains too many fields")

    schema_version = payload.get("schema_version")
    if schema_version != INPUT_SCHEMA_VERSION or type(schema_version) is not str:
        raise InputValidationError("input record schema version is unsupported")
    classification = payload.get("dataset_classification")
    if classification != "synthetic" or type(classification) is not str:
        raise InputValidationError("input record classification is unsupported")
    record_type = payload.get("record_type")
    if type(record_type) is not str or record_type not in TYPE_FIELDS:
        raise InputValidationError("input record type is unsupported")

    without_id, with_id = expected_input_fields(record_type)
    actual_fields = frozenset(payload)
    if actual_fields not in {without_id, with_id}:
        raise InputValidationError("input record does not match the supported field contract")

    semantic = _normalize_semantic_fields(
        record_type,
        payload,
        max_field_chars=max_field_chars,
    )
    if "record_id" not in payload:
        record_id = _generated_record_id(record_type, semantic)
    else:
        record_id = _safe_identifier(
            payload["record_id"],
            max_field_chars=min(max_field_chars, 128),
        )

    if record_type == "principal":
        return Principal(record_id=record_id, source_ref=source_ref, **semantic)
    if record_type == "role_assignment":
        return RoleAssignment(record_id=record_id, source_ref=source_ref, **semantic)
    if record_type == "permission_assignment":
        return PermissionAssignment(record_id=record_id, source_ref=source_ref, **semantic)
    if record_type == "auth_event":
        return AuthEvent(record_id=record_id, source_ref=source_ref, **semantic)
    if record_type == "change_event":
        return ChangeEvent(record_id=record_id, source_ref=source_ref, **semantic)
    return ControlState(record_id=record_id, source_ref=source_ref, **semantic)


def normalize_legacy_control_state(
    payload: dict[str, Any],
    source_ref: SourceRef,
    *,
    max_field_chars: int,
) -> ControlState:
    """Normalize the explicit compatibility object."""
    expected_fields = {
        "schema_version",
        "dataset_classification",
        "record_type",
        "record_id",
        "control",
        "enabled",
    }
    if set(payload) != expected_fields:
        raise InputValidationError("input record does not match the legacy field contract")
    if payload.get("schema_version") != LEGACY_INPUT_SCHEMA_VERSION:
        raise InputValidationError("input record schema version is unsupported")
    if payload.get("dataset_classification") != "synthetic":
        raise InputValidationError("input record classification is unsupported")
    if payload.get("record_type") != "control_state":
        raise InputValidationError("input record type is unsupported")
    if payload.get("control") != "AUDIT_LOGGING":
        raise InputValidationError("legacy input control is unsupported")
    if type(payload.get("enabled")) is not bool:
        raise InputValidationError("input Boolean field is invalid")

    return ControlState(
        record_id=_safe_identifier(
            payload.get("record_id"),
            max_field_chars=min(max_field_chars, 128),
        ),
        control="AUDIT_LOGGING",
        enabled=payload["enabled"],
        source_ref=source_ref,
    )


def _normalize_semantic_fields(
    record_type: str,
    payload: dict[str, Any],
    *,
    max_field_chars: int,
) -> dict[str, Any]:
    if record_type == "principal":
        return {
            "principal_id": _safe_identifier(
                payload["principal_id"], max_field_chars=max_field_chars
            ),
            "principal_kind": _literal(
                payload["principal_kind"],
                {"human", "service", "emergency"},
                max_field_chars=max_field_chars,
            ),
            "enabled": _boolean(payload["enabled"]),
            "last_active_at": _timestamp(
                payload["last_active_at"], max_field_chars=max_field_chars
            ),
        }
    if record_type == "role_assignment":
        return {
            "principal_id": _safe_identifier(
                payload["principal_id"], max_field_chars=max_field_chars
            ),
            "role_id": _safe_identifier(payload["role_id"], max_field_chars=max_field_chars),
            "assignment_mode": _literal(
                payload["assignment_mode"],
                {"direct", "inherited"},
                max_field_chars=max_field_chars,
            ),
            "assigned_at": _timestamp(payload["assigned_at"], max_field_chars=max_field_chars),
        }
    if record_type == "permission_assignment":
        return {
            "principal_id": _safe_identifier(
                payload["principal_id"], max_field_chars=max_field_chars
            ),
            "permission": _capability(payload["permission"], max_field_chars=max_field_chars),
            "assignment_mode": _literal(
                payload["assignment_mode"],
                {"direct", "inherited"},
                max_field_chars=max_field_chars,
            ),
            "assigned_at": _timestamp(payload["assigned_at"], max_field_chars=max_field_chars),
        }
    if record_type == "auth_event":
        return {
            "principal_id": _safe_identifier(
                payload["principal_id"], max_field_chars=max_field_chars
            ),
            "action": _capability(payload["action"], max_field_chars=max_field_chars),
            "outcome": _literal(
                payload["outcome"],
                {"success", "failure", "denied"},
                max_field_chars=max_field_chars,
            ),
            "occurred_at": _timestamp(payload["occurred_at"], max_field_chars=max_field_chars),
        }
    if record_type == "change_event":
        return {
            "principal_id": _safe_identifier(
                payload["principal_id"], max_field_chars=max_field_chars
            ),
            "object_id": _safe_identifier(payload["object_id"], max_field_chars=max_field_chars),
            "action": _capability(payload["action"], max_field_chars=max_field_chars),
            "outcome": _literal(
                payload["outcome"],
                {"success", "failure", "denied"},
                max_field_chars=max_field_chars,
            ),
            "occurred_at": _timestamp(payload["occurred_at"], max_field_chars=max_field_chars),
        }
    return {
        "control": _capability(payload["control"], max_field_chars=max_field_chars),
        "enabled": _boolean(payload["enabled"]),
    }


def _generated_record_id(record_type: str, semantic: dict[str, Any]) -> str:
    identity_material = {
        "schema_version": INPUT_SCHEMA_VERSION,
        "record_type": record_type,
        **semantic,
    }
    canonical_bytes = json.dumps(
        identity_material,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"auto:{record_type}:{hashlib.sha256(canonical_bytes).hexdigest()}"


def _safe_identifier(value: object, *, max_field_chars: int) -> str:
    if type(value) is not str or len(value) > max_field_chars:
        raise InputValidationError("input identifier is invalid")
    if IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise InputValidationError("input identifier is invalid")
    return value


def _capability(value: object, *, max_field_chars: int) -> str:
    if type(value) is not str or len(value) > max_field_chars:
        raise InputValidationError("input capability is invalid")
    if CAPABILITY_PATTERN.fullmatch(value) is None:
        raise InputValidationError("input capability is invalid")
    return value


def _literal(value: object, accepted: set[str], *, max_field_chars: int) -> str:
    if type(value) is not str or len(value) > max_field_chars or value not in accepted:
        raise InputValidationError("input enumerated field is invalid")
    return value


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise InputValidationError("input Boolean field is invalid")
    return value


def _timestamp(value: object, *, max_field_chars: int) -> str:
    if type(value) is not str or len(value) > max_field_chars:
        raise InputValidationError("input timestamp is invalid")
    try:
        return normalize_rfc3339_seconds(value)
    except ValueError as exc:
        raise InputValidationError("input timestamp is invalid") from exc
