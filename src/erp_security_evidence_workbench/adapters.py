"""Bounded, explicit file-format adapters for synthetic evidence."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import signal
import stat
import unicodedata
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Literal, NoReturn

from erp_security_evidence_workbench.errors import InputValidationError
from erp_security_evidence_workbench.normalization import (
    LEGACY_INPUT_SCHEMA_VERSION,
    expected_input_fields,
)

SourceFormat = Literal["csv", "json", "jsonl"]

HARD_MAX_SOURCES = 32
HARD_MAX_SOURCE_BYTES = 1024 * 1024
HARD_MAX_TOTAL_BYTES = HARD_MAX_SOURCES * HARD_MAX_SOURCE_BYTES
HARD_MAX_SOURCE_RECORDS = 1000
HARD_MAX_RECORDS = 5000
HARD_MAX_RECORD_BYTES = 64 * 1024
HARD_MAX_FIELD_CHARS = 4096
HARD_MAX_JSON_DEPTH = 8
HARD_MAX_OBJECT_FIELDS = 32


@dataclass(frozen=True, slots=True)
class IngestLimits:
    """Injectable lower bounds capped by the supported safety ceiling."""

    max_sources: int = HARD_MAX_SOURCES
    max_source_bytes: int = HARD_MAX_SOURCE_BYTES
    max_total_bytes: int = HARD_MAX_TOTAL_BYTES
    max_source_records: int = HARD_MAX_SOURCE_RECORDS
    max_records: int = HARD_MAX_RECORDS
    max_record_bytes: int = HARD_MAX_RECORD_BYTES
    max_field_chars: int = HARD_MAX_FIELD_CHARS
    max_json_depth: int = HARD_MAX_JSON_DEPTH
    max_object_fields: int = HARD_MAX_OBJECT_FIELDS

    def __post_init__(self) -> None:
        values_and_ceilings = (
            (self.max_sources, HARD_MAX_SOURCES),
            (self.max_source_bytes, HARD_MAX_SOURCE_BYTES),
            (self.max_total_bytes, HARD_MAX_TOTAL_BYTES),
            (self.max_source_records, HARD_MAX_SOURCE_RECORDS),
            (self.max_records, HARD_MAX_RECORDS),
            (self.max_record_bytes, HARD_MAX_RECORD_BYTES),
            (self.max_field_chars, HARD_MAX_FIELD_CHARS),
            (self.max_json_depth, HARD_MAX_JSON_DEPTH),
            (self.max_object_fields, HARD_MAX_OBJECT_FIELDS),
        )
        if any(
            type(value) is not int or value <= 0 or value > ceiling
            for value, ceiling in values_and_ceilings
        ):
            raise ValueError("ingest limits must be positive and may only lower hard ceilings")


DEFAULT_LIMITS = IngestLimits()


@dataclass(frozen=True, slots=True)
class LocatedPayload:
    """A temporary parsed payload plus its exact record-level locator."""

    payload: dict[str, Any]
    row: int | None = None
    line: int | None = None
    json_pointer: str | None = None
    legacy: bool = False


@dataclass(frozen=True, slots=True)
class ParsedSource:
    """Fully consumed source metadata and temporary parsed records."""

    path: str
    format: SourceFormat
    adapter: str
    sha256: str
    byte_count: int
    device: int
    inode: int
    payloads: tuple[LocatedPayload, ...]


@dataclass(slots=True)
class _OwnedDescriptor:
    descriptor: int = -1


def parse_source(path: Path, *, limits: IngestLimits = DEFAULT_LIMITS) -> ParsedSource:
    """Consume one stable regular file through an anchored parent descriptor.

    SIGINT cleanup semantics assume the project's single-threaded POSIX CLI and
    Python's default SIGINT-to-KeyboardInterrupt handler.
    """
    parent = _OwnedDescriptor()
    source = _OwnedDescriptor()
    previous_signal_mask = _block_sigint()
    try:
        return _parse_source_owned(
            path,
            limits=limits,
            parent=parent,
            source=source,
            honor_sigint=(
                signal.SIGINT not in previous_signal_mask
                and signal.getsignal(signal.SIGINT) is signal.default_int_handler
            ),
        )
    finally:
        try:
            _close_owned_descriptors(source, parent)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)


def _parse_source_owned(
    path: Path,
    *,
    limits: IngestLimits,
    parent: _OwnedDescriptor,
    source: _OwnedDescriptor,
    honor_sigint: bool,
) -> ParsedSource:
    source_format: SourceFormat
    try:
        _validate_source_name(path.name)
        _validate_source_path(path)
        resolved_parent = path.parent.resolve(strict=True)
        _acquire_descriptor(
            parent,
            lambda: os.open(resolved_parent, _directory_open_flags()),
        )
        _raise_if_sigint_pending(enabled=honor_sigint)
        parent_stat = os.fstat(parent.descriptor)
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise InputValidationError("input must be a regular file")

        try:
            initial_stat = os.stat(
                path.name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError as exc:
            raise InputValidationError("input must be a regular file") from exc
        if not stat.S_ISREG(initial_stat.st_mode):
            if stat.S_ISLNK(initial_stat.st_mode):
                raise InputValidationError("input must not be a symbolic link")
            raise InputValidationError("input must be a regular file")
        if initial_stat.st_size > limits.max_source_bytes:
            raise InputValidationError("input exceeds the per-source byte limit")
        source_format = _source_format(path)

        _acquire_descriptor(
            source,
            lambda: os.open(
                path.name,
                _source_open_flags(),
                dir_fd=parent.descriptor,
            ),
        )
        _raise_if_sigint_pending(enabled=honor_sigint)
        opened_stat = os.fstat(source.descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise InputValidationError("input must be a regular file")
        if not _same_source_state(initial_stat, opened_stat):
            raise InputValidationError("input changed before it could be read")

        with open(source.descriptor, "rb", closefd=False) as handle:
            opened_stat = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened_stat.st_mode):
                raise InputValidationError("input must be a regular file")
            payloads, digest, byte_count = _parse_open_source(
                handle,
                source_format=source_format,
                limits=limits,
            )
            _raise_if_sigint_pending(enabled=honor_sigint)
            final_descriptor_stat = os.fstat(handle.fileno())
            final_path_stat = os.stat(
                path.name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
            second_final_descriptor_stat = os.fstat(handle.fileno())
            if (
                not _same_source_state(opened_stat, final_descriptor_stat)
                or not _same_source_state(opened_stat, final_path_stat)
                or not _same_source_state(opened_stat, second_final_descriptor_stat)
            ):
                raise InputValidationError("input changed during read")

        if not _directory_path_matches(path.parent, parent_stat):
            raise InputValidationError("input changed during read")
    except InputValidationError:
        raise
    except ValueError as exc:
        raise InputValidationError("input path is unsupported") from exc
    except OSError as exc:
        raise InputValidationError("input could not be read") from exc

    adapter = (
        "erpsec.legacy-control-state-json/v1"
        if any(payload.legacy for payload in payloads)
        else f"erpsec.{source_format}/v1"
    )
    return ParsedSource(
        path=path.name,
        format=source_format,
        adapter=adapter,
        sha256=digest,
        byte_count=byte_count,
        device=opened_stat.st_dev,
        inode=opened_stat.st_ino,
        payloads=payloads,
    )


def _close_owned_descriptors(*ownerships: _OwnedDescriptor) -> None:
    for ownership in ownerships:
        if ownership.descriptor >= 0:
            with suppress(OSError):
                os.close(ownership.descriptor)
            ownership.descriptor = -1


def _block_sigint() -> set[int]:
    previous_signal_mask = _current_signal_mask()
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
    except BaseException:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)
        raise
    return previous_signal_mask


def _raise_if_sigint_pending(*, enabled: bool) -> None:
    if enabled and signal.SIGINT in signal.sigpending():
        raise KeyboardInterrupt


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _source_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _acquire_descriptor(
    ownership: _OwnedDescriptor,
    operation: Callable[[], int],
) -> None:
    descriptor = -1
    previous_signal_mask: set[int] | None = None
    try:
        previous_signal_mask = _current_signal_mask()
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        try:
            descriptor = operation()
            ownership.descriptor = descriptor
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)
    except BaseException:
        try:
            if previous_signal_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)
        finally:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
                if ownership.descriptor == descriptor:
                    ownership.descriptor = -1
        raise


def _current_signal_mask() -> set[int]:
    return {int(member) for member in signal.pthread_sigmask(signal.SIG_BLOCK, set())}


def _same_source_state(first: os.stat_result, second: os.stat_result) -> bool:
    """Compare identity and mutation-sensitive state while deliberately excluding atime."""
    return (
        stat.S_ISREG(first.st_mode)
        and stat.S_ISREG(second.st_mode)
        and first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and first.st_mode == second.st_mode
        and first.st_uid == second.st_uid
        and first.st_gid == second.st_gid
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
    )


def _directory_path_matches(path: Path, expected: os.stat_result) -> bool:
    try:
        current = path.resolve(strict=True).stat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(current.st_mode)
        and current.st_dev == expected.st_dev
        and current.st_ino == expected.st_ino
    )


def _parse_open_source(
    handle: BinaryIO,
    *,
    source_format: SourceFormat,
    limits: IngestLimits,
) -> tuple[tuple[LocatedPayload, ...], str, int]:
    if source_format == "json":
        return _parse_json(handle, limits=limits)
    if source_format == "jsonl":
        return _parse_jsonl(handle, limits=limits)
    return _parse_csv(handle, limits=limits)


def _parse_json(
    handle: BinaryIO, *, limits: IngestLimits
) -> tuple[tuple[LocatedPayload, ...], str, int]:
    content = handle.read(limits.max_source_bytes + 1)
    if len(content) > limits.max_source_bytes:
        raise InputValidationError("input exceeds the per-source byte limit")
    digest = hashlib.sha256(content).hexdigest()
    payload = _decode_json(content, limits=limits)

    located: tuple[LocatedPayload, ...]
    if isinstance(payload, dict):
        if payload.get("schema_version") != LEGACY_INPUT_SCHEMA_VERSION:
            raise InputValidationError("JSON input must be an array of supported records")
        located = (LocatedPayload(payload=payload, json_pointer="", legacy=True),)
    elif isinstance(payload, list):
        if not payload or len(payload) > limits.max_source_records:
            raise InputValidationError("JSON input record count is outside the allowed range")
        located_records: list[LocatedPayload] = []
        for index, item in enumerate(payload):
            if not isinstance(item, dict):
                raise InputValidationError("JSON array items must be record objects")
            located_records.append(LocatedPayload(payload=item, json_pointer=f"/{index}"))
        located = tuple(located_records)
    else:
        raise InputValidationError("JSON input must use a supported top-level shape")

    return located, digest, len(content)


def _parse_jsonl(
    handle: BinaryIO, *, limits: IngestLimits
) -> tuple[tuple[LocatedPayload, ...], str, int]:
    digest = hashlib.sha256()
    located: list[LocatedPayload] = []
    byte_count = 0
    line_number = 0

    while True:
        raw_line = handle.readline(limits.max_record_bytes + 1)
        if not raw_line:
            break
        line_number += 1
        if len(raw_line) > limits.max_record_bytes:
            raise InputValidationError("JSONL record exceeds the record byte limit")
        byte_count += len(raw_line)
        if byte_count > limits.max_source_bytes:
            raise InputValidationError("input exceeds the per-source byte limit")
        digest.update(raw_line)
        if raw_line in {b"\n", b"\r\n"} or not raw_line.strip(b"\r\n"):
            raise InputValidationError("JSONL input contains a blank physical line")
        item = _decode_json(raw_line, limits=limits)
        if not isinstance(item, dict):
            raise InputValidationError("JSONL lines must contain record objects")
        located.append(LocatedPayload(payload=item, line=line_number))
        if len(located) > limits.max_source_records:
            raise InputValidationError("input exceeds the record count limit")

    if not located:
        raise InputValidationError("JSONL input must contain at least one record")
    return tuple(located), digest.hexdigest(), byte_count


def _parse_csv(
    handle: BinaryIO, *, limits: IngestLimits
) -> tuple[tuple[LocatedPayload, ...], str, int]:
    digest = hashlib.sha256()
    located: list[LocatedPayload] = []
    header: list[str] | None = None
    byte_count = 0
    physical_row = 0
    homogeneous_type: str | None = None

    while True:
        raw_row = handle.readline(limits.max_record_bytes + 1)
        if not raw_row:
            break
        physical_row += 1
        if len(raw_row) > limits.max_record_bytes:
            raise InputValidationError("CSV row exceeds the record byte limit")
        byte_count += len(raw_row)
        if byte_count > limits.max_source_bytes:
            raise InputValidationError("input exceeds the per-source byte limit")
        digest.update(raw_row)
        if raw_row in {b"\n", b"\r\n"} or not raw_row.strip(b"\r\n"):
            raise InputValidationError("CSV input contains a blank physical row")

        text = _decode_utf8(raw_row)
        try:
            parsed_rows = list(csv.reader([text], dialect="excel", strict=True))
        except csv.Error as exc:
            raise InputValidationError("CSV input is malformed") from exc
        if len(parsed_rows) != 1:
            raise InputValidationError("CSV input contains an unsupported logical row")
        row = parsed_rows[0]
        if any("\n" in field or "\r" in field for field in row):
            raise InputValidationError("CSV input contains an embedded newline")
        for field in row:
            _validate_text(field, max_chars=limits.max_field_chars)

        if header is None:
            header = row
            if (
                not header
                or len(header) > limits.max_object_fields
                or any(not field for field in header)
                or len(set(header)) != len(header)
            ):
                raise InputValidationError("CSV header is invalid")
            if any(len(field) > limits.max_field_chars for field in header):
                raise InputValidationError("CSV header is invalid")
            continue

        if len(row) != len(header):
            raise InputValidationError("CSV row does not match the header")
        payload = dict(zip(header, row, strict=True))
        record_type = payload.get("record_type")
        if record_type is None:
            raise InputValidationError("CSV record type is missing")
        if homogeneous_type is None:
            homogeneous_type = record_type
            accepted_headers = expected_input_fields(record_type)
            if frozenset(header) not in accepted_headers:
                raise InputValidationError("CSV header does not match the record type")
        elif record_type != homogeneous_type:
            raise InputValidationError("CSV source must contain one record type")

        converted = _convert_csv_payload(payload)
        located.append(LocatedPayload(payload=converted, row=physical_row))
        if len(located) > limits.max_source_records:
            raise InputValidationError("input exceeds the record count limit")

    if header is None or not located:
        raise InputValidationError("CSV input must contain a header and at least one record")
    return tuple(located), digest.hexdigest(), byte_count


def _convert_csv_payload(payload: dict[str, str]) -> dict[str, Any]:
    converted: dict[str, Any] = dict(payload)
    if converted.get("record_id") == "":
        converted.pop("record_id")
    if "enabled" in converted:
        enabled = converted["enabled"]
        if enabled == "true":
            converted["enabled"] = True
        elif enabled == "false":
            converted["enabled"] = False
        else:
            raise InputValidationError("CSV Boolean field is invalid")
    if any(value == "" for value in converted.values()):
        raise InputValidationError("CSV fields must not be empty")
    return converted


def _decode_json(content: bytes, *, limits: IngestLimits) -> Any:
    text = _decode_utf8(content)
    try:
        payload = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_number,
            parse_float=_reject_json_number,
            parse_int=_reject_json_number,
        )
    except InputValidationError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise InputValidationError("input contains malformed JSON") from exc
    _validate_json_structure(payload, depth=0, limits=limits)
    return payload


def _decode_utf8(content: bytes) -> str:
    if content.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")) or b"\x00" in content:
        raise InputValidationError("input encoding is unsupported")
    try:
        return content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InputValidationError("input encoding is unsupported") from exc


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputValidationError("input contains duplicate fields")
        result[key] = value
    return result


def _reject_json_number(value: str) -> NoReturn:
    del value
    raise InputValidationError("numeric JSON values are unsupported")


def _validate_json_structure(value: Any, *, depth: int, limits: IngestLimits) -> None:
    if depth > limits.max_json_depth:
        raise InputValidationError("JSON input exceeds the nesting limit")
    if isinstance(value, dict):
        if len(value) > limits.max_object_fields:
            raise InputValidationError("JSON object contains too many fields")
        for key, item in value.items():
            _validate_text(key, max_chars=limits.max_field_chars)
            _validate_json_structure(item, depth=depth + 1, limits=limits)
    elif isinstance(value, list):
        if len(value) > limits.max_records:
            raise InputValidationError("JSON array exceeds the record count limit")
        for item in value:
            _validate_json_structure(item, depth=depth + 1, limits=limits)
    elif isinstance(value, str):
        _validate_text(value, max_chars=limits.max_field_chars)
    elif value is not None and type(value) is not bool:
        raise InputValidationError("JSON scalar type is unsupported")


def _validate_text(value: str, *, max_chars: int) -> None:
    if len(value) > max_chars:
        raise InputValidationError("input scalar exceeds the character limit")
    if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in value):
        raise InputValidationError("input contains unsupported control characters")


def _validate_source_name(name: str) -> None:
    if not name or len(name) > 255 or "/" in name or "\\" in name:
        raise InputValidationError("input filename is unsupported")
    if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in name):
        raise InputValidationError("input filename is unsupported")


def _validate_source_path(path: Path) -> None:
    if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in os.fspath(path)):
        raise InputValidationError("input path is unsupported")


def _source_format(path: Path) -> SourceFormat:
    suffix = path.suffix
    if suffix == ".csv":
        return "csv"
    if suffix == ".json":
        return "json"
    if suffix == ".jsonl":
        return "jsonl"
    raise InputValidationError("input file extension is unsupported")
