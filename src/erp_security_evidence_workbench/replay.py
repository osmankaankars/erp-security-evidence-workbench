"""Fail-closed loading for pinned, synthetic, offline replay manifests."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from erp_security_evidence_workbench.adapters import (
    DEFAULT_LIMITS,
    IngestLimits,
    LocatedPayload,
    ParsedSource,
    parse_source,
)
from erp_security_evidence_workbench.errors import InputValidationError
from erp_security_evidence_workbench.models import (
    CanonicalRecord,
    EvidenceBundle,
    ObservedEvent,
    ReplayMetadata,
    SourceArtifact,
    SourceRef,
    ThreatIndicator,
)
from erp_security_evidence_workbench.normalization import normalize_payload
from erp_security_evidence_workbench.timestamps import normalize_rfc3339_seconds

REPLAY_MANIFEST_SCHEMA_VERSION = "erpsec.synthetic-replay-manifest/v1"
HONEYPOT_ADAPTER = "erpsec.synthetic-honeypot/v1"
THREAT_INTEL_ADAPTER = "erpsec.synthetic-threat-intel/v1"
CANONICAL_EVIDENCE_ADAPTER = "erpsec.synthetic-evidence/v1"
HONEYPOT_EVENT_SCHEMA_VERSION = "erpsec.synthetic-honeypot-event/v1"
THREAT_INDICATOR_SCHEMA_VERSION = "erpsec.synthetic-threat-indicator/v1"
SUPPORTED_REPLAY_ADAPTERS = (
    CANONICAL_EVIDENCE_ADAPTER,
    HONEYPOT_ADAPTER,
    THREAT_INTEL_ADAPTER,
)

_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_CAPABILITY_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
    )
)


@dataclass(frozen=True, slots=True)
class ReplaySourceContract:
    """One digest-pinned source declared by the replay manifest."""

    source_id: str
    path: str
    adapter: str
    sha256: str


def load_replay_manifest(
    path: Path,
    *,
    limits: IngestLimits = DEFAULT_LIMITS,
) -> EvidenceBundle:
    """Load one multi-source synthetic replay without network or source mutation."""
    if not isinstance(path, Path):
        raise InputValidationError("replay manifest must be a filesystem path")
    manifest = parse_source(path, limits=limits)
    if manifest.format != "json" or len(manifest.payloads) != 1:
        raise InputValidationError("replay manifest must contain exactly one JSON record")

    replay_id, contracts = _manifest_contract(manifest.payloads[0].payload, limits=limits)
    manifest_identity = (manifest.device, manifest.inode)
    identities = {manifest_identity}
    record_ids: set[str] = set()
    records: list[CanonicalRecord] = []
    sources: list[SourceArtifact] = []
    total_bytes = manifest.byte_count

    for contract in contracts:
        source_path = path.parent / contract.path
        parsed = parse_source(source_path, limits=limits)
        identity = (parsed.device, parsed.inode)
        if identity in identities:
            raise InputValidationError("replay sources must refer to distinct regular files")
        identities.add(identity)
        if parsed.sha256 != contract.sha256:
            raise InputValidationError("replay source digest does not match the manifest")
        _validate_adapter_format(contract.adapter, parsed)

        total_bytes += parsed.byte_count
        if total_bytes > limits.max_total_bytes:
            raise InputValidationError("replay inputs exceed the aggregate byte limit")

        source_records = tuple(
            _normalize_replay_payload(
                located,
                parsed=parsed,
                contract=contract,
                limits=limits,
            )
            for located in parsed.payloads
        )
        for record in source_records:
            if record.record_id in record_ids:
                raise InputValidationError("replay input contains a duplicate record identifier")
            record_ids.add(record.record_id)
        records.extend(source_records)
        if len(records) > limits.max_records:
            raise InputValidationError("replay inputs exceed the aggregate record limit")
        sources.append(
            SourceArtifact(
                adapter=contract.adapter,
                byte_count=parsed.byte_count,
                format=parsed.format,
                path=parsed.path,
                record_count=len(source_records),
                sha256=parsed.sha256,
                source_id=contract.source_id,
            )
        )

    return EvidenceBundle(
        records=tuple(sorted(records, key=lambda item: (item.record_type, item.record_id))),
        schema_version="erpsec.evidence-bundle/v2",
        sources=tuple(sorted(sources, key=lambda item: (item.source_id or "", item.path))),
        replay=ReplayMetadata(
            replay_id=replay_id,
            manifest_path=manifest.path,
            manifest_sha256=manifest.sha256,
        ),
    )


def replay_input_paths(manifest_path: Path, bundle: EvidenceBundle) -> tuple[Path, ...]:
    """Return manifest and declared source paths for no-overwrite alias checks."""
    return (manifest_path, *(manifest_path.parent / source.path for source in bundle.sources))


def _manifest_contract(
    payload: dict[str, Any],
    *,
    limits: IngestLimits,
) -> tuple[str, tuple[ReplaySourceContract, ...]]:
    if set(payload) != {
        "dataset_classification",
        "replay_id",
        "schema_version",
        "sources",
    }:
        raise InputValidationError("replay manifest does not match the supported contract")
    if payload.get("schema_version") != REPLAY_MANIFEST_SCHEMA_VERSION:
        raise InputValidationError("replay manifest schema version is unsupported")
    if payload.get("dataset_classification") != "synthetic":
        raise InputValidationError("replay manifest classification is unsupported")
    replay_id = _identifier(payload.get("replay_id"), "replay identifier")
    raw_sources = payload.get("sources")
    if (
        not isinstance(raw_sources, list)
        or len(raw_sources) < 2
        or len(raw_sources) > limits.max_sources
    ):
        raise InputValidationError("replay manifest source count is outside the allowed range")

    contracts: list[ReplaySourceContract] = []
    source_ids: set[str] = set()
    paths: set[str] = set()
    for source in raw_sources:
        if not isinstance(source, dict) or set(source) != {
            "adapter",
            "path",
            "sha256",
            "source_id",
        }:
            raise InputValidationError("replay source does not match the supported contract")
        source_id = _identifier(source.get("source_id"), "replay source identifier")
        source_path = _basename(source.get("path"))
        adapter = source.get("adapter")
        digest = source.get("sha256")
        if adapter not in SUPPORTED_REPLAY_ADAPTERS or type(adapter) is not str:
            raise InputValidationError("replay source adapter is unsupported")
        if type(digest) is not str or _SHA256_PATTERN.fullmatch(digest) is None:
            raise InputValidationError("replay source digest is invalid")
        if source_id in source_ids or source_path in paths:
            raise InputValidationError("replay source identifiers and paths must be unique")
        source_ids.add(source_id)
        paths.add(source_path)
        contracts.append(ReplaySourceContract(source_id, source_path, adapter, digest))
    return replay_id, tuple(contracts)


def _normalize_replay_payload(
    located: LocatedPayload,
    *,
    parsed: ParsedSource,
    contract: ReplaySourceContract,
    limits: IngestLimits,
) -> CanonicalRecord:
    source_ref = SourceRef(
        sha256=parsed.sha256,
        path=parsed.path,
        format=parsed.format,
        adapter=contract.adapter,
        row=located.row,
        line=located.line,
        json_pointer=located.json_pointer,
    )
    if contract.adapter == CANONICAL_EVIDENCE_ADAPTER:
        return normalize_payload(
            located.payload,
            source_ref,
            max_field_chars=limits.max_field_chars,
        )
    if contract.adapter == HONEYPOT_ADAPTER:
        return _normalize_honeypot_event(located.payload, source_ref, contract.source_id)
    return _normalize_threat_indicator(located.payload, source_ref, contract.source_id)


def _normalize_honeypot_event(
    payload: dict[str, Any],
    source_ref: SourceRef,
    source_id: str,
) -> ObservedEvent:
    expected = {
        "action",
        "dataset_classification",
        "event_id",
        "occurred_at",
        "outcome",
        "principal_id",
        "schema_version",
        "sensor_id",
        "source_address",
    }
    if set(payload) != expected:
        raise InputValidationError("synthetic honeypot event does not match the adapter contract")
    if payload.get("schema_version") != HONEYPOT_EVENT_SCHEMA_VERSION:
        raise InputValidationError("synthetic honeypot event schema version is unsupported")
    _require_synthetic(payload)
    action = _capability(payload.get("action"))
    if action != "SIGN_IN":
        raise InputValidationError("synthetic honeypot action is unsupported")
    return ObservedEvent(
        record_id=_identifier(payload.get("event_id"), "synthetic event identifier"),
        source_id=source_id,
        sensor_id=_identifier(payload.get("sensor_id"), "synthetic sensor identifier"),
        principal_id=_identifier(payload.get("principal_id"), "synthetic principal identifier"),
        source_address=_documentation_address(payload.get("source_address")),
        action=action,
        outcome=_outcome(payload.get("outcome")),
        occurred_at=_timestamp(payload.get("occurred_at")),
        source_ref=source_ref,
    )


def _normalize_threat_indicator(
    payload: dict[str, Any],
    source_ref: SourceRef,
    source_id: str,
) -> ThreatIndicator:
    expected = {
        "confidence",
        "dataset_classification",
        "indicator_id",
        "indicator_type",
        "schema_version",
        "valid_from",
        "valid_until",
        "value",
    }
    if set(payload) != expected:
        raise InputValidationError("synthetic indicator does not match the adapter contract")
    if payload.get("schema_version") != THREAT_INDICATOR_SCHEMA_VERSION:
        raise InputValidationError("synthetic indicator schema version is unsupported")
    _require_synthetic(payload)
    if payload.get("indicator_type") != "ip":
        raise InputValidationError("synthetic indicator type is unsupported")
    confidence = _confidence(payload.get("confidence"))
    valid_from = _timestamp(payload.get("valid_from"))
    valid_until = _timestamp(payload.get("valid_until"))
    if valid_from > valid_until:
        raise InputValidationError("synthetic indicator validity interval is invalid")
    indicator_id = _identifier(payload.get("indicator_id"), "synthetic indicator identifier")
    return ThreatIndicator(
        record_id=indicator_id,
        source_id=source_id,
        indicator_id=indicator_id,
        indicator_type="ip",
        value=_documentation_address(payload.get("value")),
        valid_from=valid_from,
        valid_until=valid_until,
        confidence=confidence,
        source_ref=source_ref,
    )


def _validate_adapter_format(adapter: str, parsed: ParsedSource) -> None:
    if adapter != CANONICAL_EVIDENCE_ADAPTER and parsed.format == "csv":
        raise InputValidationError("replay adapter does not support CSV input")


def _require_synthetic(payload: dict[str, Any]) -> None:
    if payload.get("dataset_classification") != "synthetic":
        raise InputValidationError("replay input classification is unsupported")


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise InputValidationError(f"{label} is invalid")
    return value


def _basename(value: object) -> str:
    if type(value) is not str or not value or value in {".", ".."} or "/" in value or "\\" in value:
        raise InputValidationError("replay source path must contain a basename only")
    return value


def _capability(value: object) -> str:
    if type(value) is not str or _CAPABILITY_PATTERN.fullmatch(value) is None:
        raise InputValidationError("replay event capability is invalid")
    return value


def _outcome(value: object) -> Literal["success", "failure", "denied"]:
    if value not in {"success", "failure", "denied"} or type(value) is not str:
        raise InputValidationError("replay event outcome is invalid")
    return value


def _confidence(value: object) -> Literal["low", "medium", "high"]:
    if value not in {"low", "medium", "high"} or type(value) is not str:
        raise InputValidationError("synthetic indicator confidence is invalid")
    return value


def _timestamp(value: object) -> str:
    if type(value) is not str:
        raise InputValidationError("replay timestamp is invalid")
    try:
        return normalize_rfc3339_seconds(value)
    except ValueError as exc:
        raise InputValidationError("replay timestamp is invalid") from exc


def _documentation_address(value: object) -> str:
    if type(value) is not str:
        raise InputValidationError("replay IP address is invalid")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise InputValidationError("replay IP address is invalid") from exc
    if str(address) != value or not any(address in network for network in _DOCUMENTATION_NETWORKS):
        raise InputValidationError("replay IP address must use a documentation range")
    return value


__all__ = [
    "CANONICAL_EVIDENCE_ADAPTER",
    "HONEYPOT_ADAPTER",
    "REPLAY_MANIFEST_SCHEMA_VERSION",
    "SUPPORTED_REPLAY_ADAPTERS",
    "THREAT_INTEL_ADAPTER",
    "load_replay_manifest",
    "replay_input_paths",
]
