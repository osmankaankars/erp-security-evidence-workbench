"""Canonical, vendor-neutral evidence and provenance contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

EVIDENCE_RECORD_SCHEMA_VERSION = "erpsec.synthetic-evidence/v1"
SourceFormat = Literal["csv", "json", "jsonl"]

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_INVALID_POINTER_ESCAPE = re.compile(r"~(?![01])")
_DEFAULT_ADAPTERS: dict[SourceFormat, str] = {
    "csv": "erpsec.csv/v1",
    "json": "erpsec.json/v1",
    "jsonl": "erpsec.jsonl/v1",
}


def _pointer_token(value: str) -> str:
    """Encode one JSON Pointer token according to RFC 6901."""
    return value.replace("~", "~0").replace("/", "~1")


def _is_positive_int(value: int | None) -> bool:
    return value is not None and type(value) is int and value > 0


@dataclass(frozen=True, slots=True)
class SourceRef:
    """Minimized provenance for exactly one normalized input record."""

    sha256: str
    path: str
    format: SourceFormat = "json"
    adapter: str = ""
    json_pointer: str | None = ""
    row: int | None = None
    line: int | None = None

    def __post_init__(self) -> None:
        if _SHA256_PATTERN.fullmatch(self.sha256) is None:
            raise ValueError("sha256 must be a lowercase hexadecimal SHA-256 digest")
        if not self.path or self.path in {".", ".."} or "/" in self.path or "\\" in self.path:
            raise ValueError("source path must contain a basename only")
        if self.format not in _DEFAULT_ADAPTERS:
            raise ValueError("unsupported source format")
        if not self.adapter:
            object.__setattr__(self, "adapter", _DEFAULT_ADAPTERS[self.format])

        locators = (self.json_pointer is not None, self.row is not None, self.line is not None)
        if sum(locators) != 1:
            raise ValueError("source reference must contain exactly one record locator")

        if self.format == "json":
            if self.json_pointer is None or self.row is not None or self.line is not None:
                raise ValueError("JSON source locator must be a JSON Pointer")
            if self.json_pointer and not self.json_pointer.startswith("/"):
                raise ValueError("JSON source locator must be an RFC 6901 pointer")
            if _INVALID_POINTER_ESCAPE.search(self.json_pointer) is not None:
                raise ValueError("JSON source locator must be an RFC 6901 pointer")
        elif self.format == "csv":
            if (
                not _is_positive_int(self.row)
                or self.json_pointer is not None
                or self.line is not None
            ):
                raise ValueError("CSV source locator must be a positive row number")
        elif self.format == "jsonl":
            if (
                not _is_positive_int(self.line)
                or self.json_pointer is not None
                or self.row is not None
            ):
                raise ValueError("JSONL source locator must be a positive line number")
        else:
            raise ValueError("unsupported source format")

    def to_dict(self, *, field: str | None = None) -> dict[str, str | int]:
        """Serialize record provenance, optionally refined to one evaluated field."""
        if field is not None and not field:
            raise ValueError("source field must not be empty")

        result: dict[str, str | int] = {
            "adapter": self.adapter,
            "format": self.format,
            "path": self.path,
            "sha256": self.sha256,
        }
        if self.format == "json":
            assert self.json_pointer is not None
            pointer = self.json_pointer
            if field is not None:
                terminal = f"/{_pointer_token(field)}"
                if pointer != terminal and not pointer.endswith(terminal):
                    pointer = f"{pointer}{terminal}"
            result["json_pointer"] = pointer
        elif self.format == "csv":
            assert self.row is not None
            result["row"] = self.row
            if field is not None:
                result["field"] = field
        else:
            assert self.line is not None
            result["line"] = self.line
            if field is not None:
                result["field"] = field
        return result


@dataclass(frozen=True, slots=True)
class Principal:
    """One synthetic ERP principal."""

    record_id: str
    principal_id: str
    principal_kind: Literal["human", "service", "emergency"]
    enabled: bool
    last_active_at: str
    source_ref: SourceRef
    record_type: Literal["principal"] = "principal"
    schema_version: str = EVIDENCE_RECORD_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class RoleAssignment:
    """One role-to-principal relationship."""

    record_id: str
    principal_id: str
    role_id: str
    assignment_mode: Literal["direct", "inherited"]
    assigned_at: str
    source_ref: SourceRef
    record_type: Literal["role_assignment"] = "role_assignment"
    schema_version: str = EVIDENCE_RECORD_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class PermissionAssignment:
    """One direct or inherited permission assignment."""

    record_id: str
    principal_id: str
    permission: str
    assignment_mode: Literal["direct", "inherited"]
    assigned_at: str
    source_ref: SourceRef
    record_type: Literal["permission_assignment"] = "permission_assignment"
    schema_version: str = EVIDENCE_RECORD_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """One authentication or authorization event."""

    record_id: str
    principal_id: str
    action: str
    outcome: Literal["success", "failure", "denied"]
    occurred_at: str
    source_ref: SourceRef
    record_type: Literal["auth_event"] = "auth_event"
    schema_version: str = EVIDENCE_RECORD_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class ChangeEvent:
    """One auditable change event against a generic ERP object."""

    record_id: str
    principal_id: str
    object_id: str
    action: str
    outcome: Literal["success", "failure", "denied"]
    occurred_at: str
    source_ref: SourceRef
    record_type: Literal["change_event"] = "change_event"
    schema_version: str = EVIDENCE_RECORD_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class ControlState:
    """Vendor-neutral state of one synthetic security control."""

    # Keep the first four fields unchanged for constructor compatibility.
    record_id: str
    control: str
    enabled: bool
    source_ref: SourceRef
    record_type: Literal["control_state"] = "control_state"
    schema_version: str = EVIDENCE_RECORD_SCHEMA_VERSION


CanonicalRecord = (
    Principal | RoleAssignment | PermissionAssignment | AuthEvent | ChangeEvent | ControlState
)


@dataclass(frozen=True, slots=True)
class FindingEvidence:
    """One canonical record field that directly supports a finding."""

    record: CanonicalRecord
    field: str

    def __post_init__(self) -> None:
        if not self.field or self.field == "source_ref" or not hasattr(self.record, self.field):
            raise ValueError("finding evidence field is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record.record_id,
            "source_ref": self.record.source_ref.to_dict(field=self.field),
        }


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    """Deterministic outcome for one conclusively evaluated rule."""

    rule_id: str
    rule_version: str
    status: Literal["matched", "not_matched"]

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class SourceArtifact:
    """One bounded source file represented in the evidence manifest."""

    sha256: str
    path: str
    format: SourceFormat
    adapter: str
    byte_count: int
    record_count: int

    def to_dict(self) -> dict[str, str | int]:
        return {
            "adapter": self.adapter,
            "byte_count": self.byte_count,
            "format": self.format,
            "path": self.path,
            "record_count": self.record_count,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    """Validated evidence, source artifacts, and completeness state."""

    records: tuple[CanonicalRecord, ...]
    schema_version: str = "erpsec.evidence-bundle/v1"
    complete: bool = True
    sources: tuple[SourceArtifact, ...] = ()
    diagnostics: tuple[str, ...] = ()


def canonical_record_data(record: CanonicalRecord) -> dict[str, Any]:
    """Return canonical semantic data while excluding source provenance."""
    common: dict[str, Any] = {
        "schema_version": record.schema_version,
        "record_type": record.record_type,
        "record_id": record.record_id,
    }
    if isinstance(record, Principal):
        common.update(
            {
                "principal_id": record.principal_id,
                "principal_kind": record.principal_kind,
                "enabled": record.enabled,
                "last_active_at": record.last_active_at,
            }
        )
    elif isinstance(record, RoleAssignment):
        common.update(
            {
                "principal_id": record.principal_id,
                "role_id": record.role_id,
                "assignment_mode": record.assignment_mode,
                "assigned_at": record.assigned_at,
            }
        )
    elif isinstance(record, PermissionAssignment):
        common.update(
            {
                "principal_id": record.principal_id,
                "permission": record.permission,
                "assignment_mode": record.assignment_mode,
                "assigned_at": record.assigned_at,
            }
        )
    elif isinstance(record, AuthEvent):
        common.update(
            {
                "principal_id": record.principal_id,
                "action": record.action,
                "outcome": record.outcome,
                "occurred_at": record.occurred_at,
            }
        )
    elif isinstance(record, ChangeEvent):
        common.update(
            {
                "principal_id": record.principal_id,
                "object_id": record.object_id,
                "action": record.action,
                "outcome": record.outcome,
                "occurred_at": record.occurred_at,
            }
        )
    else:
        common.update({"control": record.control, "enabled": record.enabled})
    return common


@dataclass(frozen=True, slots=True)
class Finding:
    """One deterministic finding supported by exact evidence references."""

    rule_id: str
    rule_version: str
    severity: str
    severity_rationale: str
    title: str
    description: str
    fingerprint: str
    evidence_record: ControlState | None
    limitation: str
    remediation: str
    required_evidence_types: tuple[str, ...]
    supporting_evidence: tuple[FindingEvidence, ...] = ()

    def __post_init__(self) -> None:
        if self.evidence_record is None and not self.supporting_evidence:
            raise ValueError("finding must contain supporting evidence")
        if self.evidence_record is not None and self.supporting_evidence:
            raise ValueError("finding evidence must use one compatibility representation")

        if self.supporting_evidence:
            deduplicated = {
                (item.record.record_type, item.record.record_id, item.field): item
                for item in self.supporting_evidence
            }
            object.__setattr__(
                self,
                "supporting_evidence",
                tuple(deduplicated[key] for key in sorted(deduplicated)),
            )

    def to_dict(self) -> dict[str, Any]:
        if self.supporting_evidence:
            evidence_refs = [item.to_dict() for item in self.supporting_evidence]
        else:
            assert self.evidence_record is not None
            evidence_refs = [
                {
                    "record_id": self.evidence_record.record_id,
                    "source_ref": self.evidence_record.source_ref.to_dict(field="enabled"),
                }
            ]
        return {
            "description": self.description,
            "evidence_refs": evidence_refs,
            "fingerprint": self.fingerprint,
            "limitation": self.limitation,
            "remediation": self.remediation,
            "required_evidence_types": list(self.required_evidence_types),
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "severity": self.severity,
            "severity_rationale": self.severity_rationale,
            "title": self.title,
        }
