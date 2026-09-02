from __future__ import annotations

import json
import os
import stat
import tracemalloc
from collections.abc import Sequence
from pathlib import Path

import pytest

from erp_security_evidence_workbench.adapters import DEFAULT_LIMITS, IngestLimits
from erp_security_evidence_workbench.errors import InputValidationError
from erp_security_evidence_workbench.ingest import load_evidence

INPUT_SCHEMA_VERSION = "erpsec.synthetic-evidence/v1"
HOSTILE_VALUE = "do-not-echo-this-sensitive-value"
CSV_HEADER = "schema_version,dataset_classification,record_type,record_id,control,enabled\n"


def _control(index: int, **changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": INPUT_SCHEMA_VERSION,
        "dataset_classification": "synthetic",
        "record_type": "control_state",
        "record_id": f"control.audit.{index}",
        "control": "AUDIT_LOGGING",
        "enabled": False,
    }
    payload.update(changes)
    return payload


def _principal(*, last_active_at: str) -> dict[str, object]:
    return {
        "schema_version": INPUT_SCHEMA_VERSION,
        "dataset_classification": "synthetic",
        "record_type": "principal",
        "record_id": "principal.fixture-persona-alpha",
        "principal_id": "fixture-persona-alpha",
        "principal_kind": "human",
        "enabled": True,
        "last_active_at": last_active_at,
    }


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode()


def _snapshot(paths: Sequence[Path]) -> dict[Path, tuple[bytes, int, int]]:
    return {
        path: (
            path.read_bytes(),
            stat.S_IMODE(path.stat().st_mode),
            path.stat().st_mtime_ns,
        )
        for path in paths
    }


def _assert_rejected_without_source_mutation(
    paths: Sequence[Path],
    *,
    limits: IngestLimits | None = None,
    secrets: Sequence[str] = (),
) -> str:
    before = _snapshot(paths)

    with pytest.raises(InputValidationError) as exc_info:
        if limits is None:
            load_evidence(paths)
        else:
            load_evidence(paths, limits=limits)

    message = str(exc_info.value)
    for secret in secrets:
        assert secret not in message
    assert _snapshot(paths) == before
    return message


def _corrupt_record(payload: dict[str, object], case: str) -> None:
    if case == "unknown-field":
        payload["unexpected_sensitive_field"] = HOSTILE_VALUE
    elif case == "unknown-type":
        payload["record_type"] = HOSTILE_VALUE
    elif case == "unknown-schema":
        payload["schema_version"] = HOSTILE_VALUE
    elif case == "unknown-classification":
        payload["dataset_classification"] = HOSTILE_VALUE
    else:  # pragma: no cover - test-data programming error
        raise AssertionError(f"unknown corruption case: {case}")


def test_invalid_timestamp_fails_closed_without_echo_or_mutation(tmp_path: Path) -> None:
    input_path = tmp_path / "invalid-timestamp.json"
    input_path.write_bytes(_json_bytes([_principal(last_active_at=HOSTILE_VALUE)]))

    _assert_rejected_without_source_mutation(
        [input_path],
        secrets=[HOSTILE_VALUE],
    )


@pytest.mark.parametrize("source_format", ["json", "jsonl"])
def test_explicit_null_record_id_is_not_treated_as_missing(
    tmp_path: Path,
    source_format: str,
) -> None:
    payload = _control(1, record_id=None)
    input_path = tmp_path / f"null-id.{source_format}"
    input_path.write_bytes(
        _json_bytes([payload]) if source_format == "json" else _json_bytes(payload)
    )

    _assert_rejected_without_source_mutation([input_path])


@pytest.mark.parametrize(
    "case",
    ["unknown-field", "unknown-type", "unknown-schema", "unknown-classification"],
)
@pytest.mark.parametrize("position", [0, 1, 2], ids=["first", "middle", "last"])
def test_invalid_record_anywhere_rejects_the_entire_json_source(
    tmp_path: Path,
    case: str,
    position: int,
) -> None:
    records = [_control(index) for index in range(3)]
    _corrupt_record(records[position], case)
    input_path = tmp_path / f"{case}-{position}.json"
    input_path.write_bytes(_json_bytes(records))

    _assert_rejected_without_source_mutation(
        [input_path],
        secrets=[HOSTILE_VALUE],
    )


def test_malformed_trailing_jsonl_rejects_valid_prefix_atomically(tmp_path: Path) -> None:
    input_path = tmp_path / "malformed-tail.jsonl"
    input_path.write_bytes(
        _json_bytes(_control(1)) + b'{"schema_version":"do-not-echo-this-sensitive-value"'
    )

    _assert_rejected_without_source_mutation(
        [input_path],
        secrets=[HOSTILE_VALUE],
    )


def test_blank_jsonl_physical_line_is_rejected(tmp_path: Path) -> None:
    input_path = tmp_path / "blank-line.jsonl"
    input_path.write_bytes(_json_bytes(_control(1)) + b"\n" + _json_bytes(_control(2)))

    _assert_rejected_without_source_mutation([input_path])


def test_duplicate_json_object_keys_are_rejected(tmp_path: Path) -> None:
    input_path = tmp_path / "duplicate-key.json"
    input_path.write_bytes(
        (
            "[{"
            f'"schema_version":"{INPUT_SCHEMA_VERSION}",'
            '"dataset_classification":"synthetic",'
            '"record_type":"control_state",'
            '"record_id":"control.audit.1",'
            '"control":"AUDIT_LOGGING",'
            '"enabled":false,"enabled":true}]\n'
        ).encode()
    )

    _assert_rejected_without_source_mutation([input_path])


@pytest.mark.parametrize(
    ("case", "content"),
    [
        (
            "duplicate-header",
            (
                "schema_version,dataset_classification,record_type,record_id,control,"
                "enabled,enabled\n"
                f"{INPUT_SCHEMA_VERSION},synthetic,control_state,control.audit.1,"
                "AUDIT_LOGGING,false,true\n"
            ).encode(),
        ),
        (
            "ragged-short",
            (
                CSV_HEADER + f"{INPUT_SCHEMA_VERSION},synthetic,control_state,control.audit.1,"
                "AUDIT_LOGGING\n"
            ).encode(),
        ),
        (
            "ragged-long",
            (
                CSV_HEADER + f"{INPUT_SCHEMA_VERSION},synthetic,control_state,control.audit.1,"
                "AUDIT_LOGGING,false,extra\n"
            ).encode(),
        ),
        ("header-only", CSV_HEADER.encode()),
        (
            "mixed-type",
            (
                CSV_HEADER + f"{INPUT_SCHEMA_VERSION},synthetic,control_state,control.audit.1,"
                "AUDIT_LOGGING,false\n"
                + f"{INPUT_SCHEMA_VERSION},synthetic,principal,control.audit.2,"
                "AUDIT_LOGGING,false\n"
            ).encode(),
        ),
        (
            "blank-row",
            (
                CSV_HEADER + f"{INPUT_SCHEMA_VERSION},synthetic,control_state,control.audit.1,"
                "AUDIT_LOGGING,false\n\n"
            ).encode(),
        ),
        (
            "multiline-field",
            (
                CSV_HEADER
                + f'{INPUT_SCHEMA_VERSION},synthetic,control_state,control.audit.1,"AUDIT\n'
                'LOGGING",false\n'
            ).encode(),
        ),
    ],
)
def test_malformed_or_ambiguous_csv_is_rejected_without_mutation(
    tmp_path: Path,
    case: str,
    content: bytes,
) -> None:
    input_path = tmp_path / f"{case}.csv"
    input_path.write_bytes(content)

    _assert_rejected_without_source_mutation([input_path])


@pytest.mark.parametrize(
    ("suffix", "content"),
    [
        (".json", b"\xef\xbb\xbf" + _json_bytes([_control(1)])),
        (".jsonl", _json_bytes(_control(1)) + b"\x00\n"),
        (
            ".csv",
            CSV_HEADER.encode()
            + f"{INPUT_SCHEMA_VERSION},synthetic,control_state,control.audit.1,".encode()
            + b"\xff,false\n",
        ),
    ],
    ids=["utf8-bom", "nul-byte", "malformed-utf8"],
)
def test_unsupported_encodings_are_rejected(
    tmp_path: Path,
    suffix: str,
    content: bytes,
) -> None:
    input_path = tmp_path / f"unsupported-encoding{suffix}"
    input_path.write_bytes(content)

    _assert_rejected_without_source_mutation([input_path])


def test_jsonl_byte_limits_accept_exact_boundary_and_reject_one_byte_over(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "bounded.jsonl"
    line = _json_bytes(_control(1))
    input_path.write_bytes(line)
    before = _snapshot([input_path])
    exact_limits = IngestLimits(
        max_source_bytes=len(line),
        max_total_bytes=len(line),
        max_record_bytes=len(line),
    )

    bundle = load_evidence([input_path], limits=exact_limits)

    assert len(bundle.records) == 1
    assert _snapshot([input_path]) == before
    _assert_rejected_without_source_mutation(
        [input_path],
        limits=IngestLimits(max_record_bytes=len(line) - 1),
    )
    _assert_rejected_without_source_mutation(
        [input_path],
        limits=IngestLimits(max_source_bytes=len(line) - 1),
    )


def test_aggregate_record_limit_accepts_exact_boundary_and_rejects_plus_one(
    tmp_path: Path,
) -> None:
    paths = [tmp_path / f"source-{index}.json" for index in range(3)]
    for index, path in enumerate(paths):
        path.write_bytes(_json_bytes([_control(index)]))
    limits = IngestLimits(max_records=2)
    before = _snapshot(paths)

    exact_bundle = load_evidence(paths[:2], limits=limits)

    assert len(exact_bundle.records) == 2
    _assert_rejected_without_source_mutation(paths, limits=limits)
    assert _snapshot(paths) == before


def test_per_source_record_limit_rejects_limit_plus_one(tmp_path: Path) -> None:
    input_path = tmp_path / "two-records.jsonl"
    input_path.write_bytes(_json_bytes(_control(1)) + _json_bytes(_control(2)))

    _assert_rejected_without_source_mutation(
        [input_path],
        limits=IngestLimits(max_source_records=1),
    )


def test_aggregate_byte_and_source_count_limits_are_enforced(tmp_path: Path) -> None:
    paths = [tmp_path / f"bounded-{index}.json" for index in range(2)]
    for index, path in enumerate(paths):
        path.write_bytes(_json_bytes([_control(index)]))
    total_bytes = sum(path.stat().st_size for path in paths)

    assert len(load_evidence(paths, limits=IngestLimits(max_total_bytes=total_bytes)).records) == 2
    _assert_rejected_without_source_mutation(
        paths,
        limits=IngestLimits(max_total_bytes=total_bytes - 1),
    )
    _assert_rejected_without_source_mutation(
        paths,
        limits=IngestLimits(max_sources=1),
    )


def test_jsonl_adapter_uses_bounded_incremental_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_path = tmp_path / "streamed.jsonl"
    input_path.write_bytes(_json_bytes(_control(1)) + _json_bytes(_control(2)))
    original_open = open

    class GuardedReader:
        def __init__(self, handle: object) -> None:
            self.handle = handle

        def __enter__(self) -> GuardedReader:
            return self

        def __exit__(self, *args: object) -> None:
            self.handle.close()  # type: ignore[attr-defined]

        def fileno(self) -> int:
            return self.handle.fileno()  # type: ignore[attr-defined,no-any-return]

        def readline(self, size: int = -1) -> bytes:
            assert 0 < size <= 64 * 1024 + 1
            return self.handle.readline(size)  # type: ignore[attr-defined,no-any-return]

        def read(self, size: int = -1) -> bytes:
            del size
            raise AssertionError("JSONL adapter attempted a full-file read")

    def guarded_open(path: object, *args: object, **kwargs: object) -> object:
        handle = original_open(path, *args, **kwargs)  # type: ignore[arg-type]
        if isinstance(path, int) and args and args[0] == "rb":
            return GuardedReader(handle)
        return handle

    monkeypatch.setattr("builtins.open", guarded_open)

    bundle = load_evidence([input_path])

    assert len(bundle.records) == 2


def test_default_frozen_source_and_record_boundaries(tmp_path: Path) -> None:
    assert DEFAULT_LIMITS.max_sources == 32
    assert DEFAULT_LIMITS.max_source_bytes == 1024 * 1024
    assert DEFAULT_LIMITS.max_total_bytes == 32 * 1024 * 1024
    assert DEFAULT_LIMITS.max_source_records == 1000
    assert DEFAULT_LIMITS.max_records == 5000

    small_sources = [tmp_path / f"small-{index}.json" for index in range(33)]
    for index, path in enumerate(small_sources):
        path.write_bytes(_json_bytes([_control(index)]))
    assert len(load_evidence(small_sources[:32]).sources) == 32
    _assert_rejected_without_source_mutation(small_sources)

    full_sources = [tmp_path / f"full-{source_index}.jsonl" for source_index in range(5)]
    for source_index, path in enumerate(full_sources):
        start = source_index * 1000
        path.write_bytes(b"".join(_json_bytes(_control(start + index)) for index in range(1000)))
    assert len(load_evidence(full_sources).records) == 5000

    aggregate_overflow = tmp_path / "aggregate-overflow.jsonl"
    aggregate_overflow.write_bytes(_json_bytes(_control(5000)))
    _assert_rejected_without_source_mutation([*full_sources, aggregate_overflow])

    source_overflow = tmp_path / "source-overflow.jsonl"
    source_overflow.write_bytes(
        b"".join(_json_bytes(_control(6000 + index)) for index in range(1001))
    )
    _assert_rejected_without_source_mutation([source_overflow])


def test_jsonl_peak_memory_stays_bounded_for_maximum_record_count(tmp_path: Path) -> None:
    input_path = tmp_path / "memory-bound.jsonl"
    input_path.write_bytes(b"".join(_json_bytes(_control(index)) for index in range(1000)))

    tracemalloc.start()
    try:
        bundle = load_evidence([input_path])
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert len(bundle.records) == 1000
    assert peak_bytes < 16 * 1024 * 1024


@pytest.mark.parametrize("generated", [False, True], ids=["explicit", "generated"])
def test_duplicate_record_identifiers_within_one_source_are_rejected(
    tmp_path: Path,
    generated: bool,
) -> None:
    first = _control(1)
    second = _control(2)
    if generated:
        first.pop("record_id")
        second.pop("record_id")
    else:
        second["record_id"] = first["record_id"]
    input_path = tmp_path / f"duplicate-id-{generated}.json"
    input_path.write_bytes(_json_bytes([first, second]))

    _assert_rejected_without_source_mutation([input_path])


def test_repeating_the_same_input_path_is_rejected(tmp_path: Path) -> None:
    input_path = tmp_path / "same.json"
    input_path.write_bytes(_json_bytes([_control(1)]))

    message = _assert_rejected_without_source_mutation([input_path, input_path])

    assert "basenames" in message


def test_hardlinked_inputs_are_rejected_as_the_same_file(tmp_path: Path) -> None:
    original = tmp_path / "original.json"
    alias = tmp_path / "alias.json"
    original.write_bytes(_json_bytes([_control(1)]))
    os.link(original, alias)

    message = _assert_rejected_without_source_mutation([original, alias])

    assert "distinct files" in message


def test_same_basename_from_different_directories_is_rejected(tmp_path: Path) -> None:
    first = tmp_path / "first" / "evidence.json"
    second = tmp_path / "second" / "evidence.json"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_bytes(_json_bytes([_control(1)]))
    second.write_bytes(_json_bytes([_control(2)]))

    message = _assert_rejected_without_source_mutation([first, second])

    assert "basenames" in message


def test_unsupported_suffix_is_rejected(tmp_path: Path) -> None:
    input_path = tmp_path / "evidence.txt"
    input_path.write_bytes(_json_bytes([_control(1)]))

    _assert_rejected_without_source_mutation([input_path])


def test_symbolic_link_input_is_rejected_without_mutating_its_target(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    input_path = tmp_path / "alias.json"
    target.write_bytes(_json_bytes([_control(1)]))
    input_path.symlink_to(target)

    _assert_rejected_without_source_mutation([target, input_path])
