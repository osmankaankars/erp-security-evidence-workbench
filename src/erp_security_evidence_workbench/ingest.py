"""Transactional multi-format ingestion for synthetic evidence."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from erp_security_evidence_workbench.adapters import (
    DEFAULT_LIMITS,
    HARD_MAX_SOURCE_BYTES,
    IngestLimits,
    parse_source,
)
from erp_security_evidence_workbench.errors import InputValidationError
from erp_security_evidence_workbench.models import (
    CanonicalRecord,
    EvidenceBundle,
    SourceArtifact,
    SourceRef,
)
from erp_security_evidence_workbench.normalization import (
    INPUT_SCHEMA_VERSION,
    LEGACY_INPUT_SCHEMA_VERSION,
    normalize_legacy_control_state,
    normalize_payload,
)

# Compatibility export retained for callers of the initial ingestion API.
MAX_INPUT_BYTES = HARD_MAX_SOURCE_BYTES


def load_evidence(
    paths: Sequence[Path],
    *,
    limits: IngestLimits = DEFAULT_LIMITS,
) -> EvidenceBundle:
    """Load every source atomically into one deterministic evidence bundle."""
    input_paths = tuple(paths)
    if not input_paths:
        raise InputValidationError("at least one input source is required")
    if len(input_paths) > limits.max_sources:
        raise InputValidationError("input source count exceeds the allowed limit")

    basenames: set[str] = set()
    identities: set[tuple[int, int]] = set()
    record_ids: set[str] = set()
    records: list[CanonicalRecord] = []
    sources: list[SourceArtifact] = []
    total_bytes = 0

    for path in input_paths:
        if not isinstance(path, Path):
            raise InputValidationError("input sources must be filesystem paths")
        if path.name in basenames:
            raise InputValidationError("input source basenames must be unique")
        basenames.add(path.name)

        parsed = parse_source(path, limits=limits)
        identity = (parsed.device, parsed.inode)
        if identity in identities:
            raise InputValidationError("input sources must refer to distinct files")
        identities.add(identity)

        total_bytes += parsed.byte_count
        if total_bytes > limits.max_total_bytes:
            raise InputValidationError("inputs exceed the aggregate byte limit")

        source_records: list[CanonicalRecord] = []
        for located in parsed.payloads:
            source_ref = SourceRef(
                sha256=parsed.sha256,
                path=parsed.path,
                format=parsed.format,
                adapter=parsed.adapter,
                row=located.row,
                line=located.line,
                json_pointer=located.json_pointer,
            )
            record: CanonicalRecord
            if located.legacy:
                record = normalize_legacy_control_state(
                    located.payload,
                    source_ref,
                    max_field_chars=limits.max_field_chars,
                )
            else:
                record = normalize_payload(
                    located.payload,
                    source_ref,
                    max_field_chars=limits.max_field_chars,
                )

            if record.record_id in record_ids:
                raise InputValidationError("input contains a duplicate record identifier")
            record_ids.add(record.record_id)
            source_records.append(record)
            if len(records) + len(source_records) > limits.max_records:
                raise InputValidationError("inputs exceed the aggregate record limit")

        records.extend(source_records)
        sources.append(
            SourceArtifact(
                adapter=parsed.adapter,
                byte_count=parsed.byte_count,
                format=parsed.format,
                path=parsed.path,
                record_count=len(source_records),
                sha256=parsed.sha256,
            )
        )

    return EvidenceBundle(
        records=tuple(sorted(records, key=lambda item: (item.record_type, item.record_id))),
        sources=tuple(
            sorted(
                sources,
                key=lambda source: (source.path, source.format, source.sha256),
            )
        ),
    )


def load_control_state(path: Path) -> EvidenceBundle:
    """Compatibility wrapper for the original single-input public Python seam."""
    return load_evidence((path,))


__all__ = [
    "DEFAULT_LIMITS",
    "INPUT_SCHEMA_VERSION",
    "IngestLimits",
    "LEGACY_INPUT_SCHEMA_VERSION",
    "MAX_INPUT_BYTES",
    "load_control_state",
    "load_evidence",
]
