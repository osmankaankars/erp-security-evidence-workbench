from __future__ import annotations

import hashlib
import json
from itertools import permutations
from pathlib import Path
from typing import Any

import pytest

from erp_security_evidence_workbench import ingest, models, rules
from erp_security_evidence_workbench.errors import (
    IncompleteEvidenceError,
    InputValidationError,
)

INPUT_SCHEMA_VERSION = "erpsec.synthetic-evidence/v1"
CONTROL_ID = "control.audit.disabled"
CONTROL_PAYLOAD: dict[str, object] = {
    "schema_version": INPUT_SCHEMA_VERSION,
    "dataset_classification": "synthetic",
    "record_type": "control_state",
    "record_id": CONTROL_ID,
    "control": "AUDIT_LOGGING",
    "enabled": False,
}
EXPECTED_CONTROL: dict[str, object] = {
    "schema_version": INPUT_SCHEMA_VERSION,
    "record_type": "control_state",
    "record_id": CONTROL_ID,
    "control": "AUDIT_LOGGING",
    "enabled": False,
}


def _compact_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _write(path: Path, content: bytes) -> bytes:
    path.write_bytes(content)
    return content


def _source_locator(source_ref: object) -> dict[str, object]:
    source = source_ref.to_dict()  # type: ignore[attr-defined]
    locator_keys = ("json_pointer", "row", "line")
    return {key: source[key] for key in locator_keys if key in source}


def test_equivalent_json_csv_and_jsonl_normalize_to_one_literal_contract(
    tmp_path: Path,
) -> None:
    json_path = tmp_path / "control.json"
    csv_path = tmp_path / "control.csv"
    jsonl_path = tmp_path / "control.jsonl"
    raw_inputs = {
        json_path: _write(json_path, _compact_json([CONTROL_PAYLOAD])),
        csv_path: _write(
            csv_path,
            (
                "schema_version,dataset_classification,record_type,record_id,control,enabled\n"
                f"{INPUT_SCHEMA_VERSION},synthetic,control_state,{CONTROL_ID},"
                "AUDIT_LOGGING,false\n"
            ).encode(),
        ),
        jsonl_path: _write(jsonl_path, _compact_json(CONTROL_PAYLOAD)),
    }
    expected_provenance = {
        json_path: ("json", {"json_pointer": "/0"}),
        csv_path: ("csv", {"row": 2}),
        jsonl_path: ("jsonl", {"line": 1}),
    }

    for path, raw_content in raw_inputs.items():
        bundle = ingest.load_evidence([path])

        assert bundle.complete is True
        assert len(bundle.records) == 1
        record = bundle.records[0]
        assert models.canonical_record_data(record) == EXPECTED_CONTROL

        source = record.source_ref.to_dict()
        expected_format, expected_locator = expected_provenance[path]
        assert source["format"] == expected_format
        assert source["path"] == path.name
        assert source["sha256"] == hashlib.sha256(raw_content).hexdigest()
        assert _source_locator(record.source_ref) == expected_locator


def test_missing_record_id_uses_source_independent_canonical_digest(tmp_path: Path) -> None:
    payload = {key: value for key, value in CONTROL_PAYLOAD.items() if key != "record_id"}
    input_path = tmp_path / "generated-id.json"
    _write(input_path, _compact_json([payload]))
    identity_material = {
        "schema_version": INPUT_SCHEMA_VERSION,
        "record_type": "control_state",
        "control": "AUDIT_LOGGING",
        "enabled": False,
    }
    identity_digest = hashlib.sha256(
        json.dumps(
            identity_material,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()

    record = ingest.load_evidence([input_path]).records[0]

    assert models.canonical_record_data(record) == {
        **identity_material,
        "record_id": f"auto:control_state:{identity_digest}",
    }


def test_malformed_trailing_jsonl_record_rejects_the_whole_source(tmp_path: Path) -> None:
    input_path = tmp_path / "truncated.jsonl"
    input_path.write_bytes(_compact_json(CONTROL_PAYLOAD) + b'{"schema_version":')

    with pytest.raises(InputValidationError):
        ingest.load_evidence([input_path])


def test_duplicate_record_ids_across_sources_fail_closed(tmp_path: Path) -> None:
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    _write(first_path, _compact_json([CONTROL_PAYLOAD]))
    _write(second_path, _compact_json([CONTROL_PAYLOAD]))

    with pytest.raises(InputValidationError):
        ingest.load_evidence([first_path, second_path])


def test_principal_only_bundle_is_incomplete_for_audit_logging_rule(tmp_path: Path) -> None:
    input_path = tmp_path / "principal.json"
    principal = {
        "schema_version": INPUT_SCHEMA_VERSION,
        "dataset_classification": "synthetic",
        "record_type": "principal",
        "record_id": "principal.fixture-persona-alpha",
        "principal_id": "fixture-persona-alpha",
        "principal_kind": "human",
        "enabled": True,
        "last_active_at": "2026-09-01T00:00:00Z",
    }
    _write(input_path, _compact_json([principal]))

    bundle = ingest.load_evidence([input_path])

    assert [models.canonical_record_data(record) for record in bundle.records] == [
        {
            "schema_version": INPUT_SCHEMA_VERSION,
            "record_type": "principal",
            "record_id": "principal.fixture-persona-alpha",
            "principal_id": "fixture-persona-alpha",
            "principal_kind": "human",
            "enabled": True,
            "last_active_at": "2026-09-01T00:00:00Z",
        }
    ]
    with pytest.raises(IncompleteEvidenceError):
        rules.evaluate(bundle)


def test_input_order_does_not_change_sorted_records_or_sources(tmp_path: Path) -> None:
    a_path = tmp_path / "a-source.json"
    z_path = tmp_path / "z-source.json"
    record_from_a = {**CONTROL_PAYLOAD, "record_id": "record.z"}
    record_from_z = {**CONTROL_PAYLOAD, "record_id": "record.a"}
    _write(a_path, _compact_json([record_from_a]))
    _write(z_path, _compact_json([record_from_z]))

    forward = ingest.load_evidence([z_path, a_path])
    reverse = ingest.load_evidence([a_path, z_path])

    forward_records = [models.canonical_record_data(record) for record in forward.records]
    reverse_records = [models.canonical_record_data(record) for record in reverse.records]
    assert forward_records == reverse_records
    assert [record["record_id"] for record in forward_records] == ["record.a", "record.z"]

    def source_projection(bundle: Any) -> list[tuple[str, str, str]]:
        return [(source.path, source.format, source.sha256) for source in bundle.sources]

    assert source_projection(forward) == source_projection(reverse)
    assert [source.path for source in forward.sources] == ["a-source.json", "z-source.json"]


def test_every_permutation_of_three_sources_has_one_canonical_order(tmp_path: Path) -> None:
    paths = [tmp_path / f"source-{index}.json" for index in range(3)]
    for index, path in enumerate(paths):
        payload = {**CONTROL_PAYLOAD, "record_id": f"record.{2 - index}"}
        _write(path, _compact_json([payload]))

    projections = []
    for ordered_paths in permutations(paths):
        bundle = ingest.load_evidence(ordered_paths)
        projections.append(
            (
                [models.canonical_record_data(record) for record in bundle.records],
                [source.to_dict() for source in bundle.sources],
            )
        )

    assert all(projection == projections[0] for projection in projections)
