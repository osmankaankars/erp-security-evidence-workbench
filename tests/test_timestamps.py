"""Contract tests for canonical evidence timestamps."""

from __future__ import annotations

import pytest

from erp_security_evidence_workbench.timestamps import normalize_rfc3339_seconds


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-09-01T12:34:56Z", "2026-09-01T12:34:56Z"),
        ("2026-09-01T15:34:56+03:00", "2026-09-01T12:34:56Z"),
        ("2026-09-01T07:04:56-05:30", "2026-09-01T12:34:56Z"),
    ],
)
def test_normalize_rfc3339_seconds_converts_to_utc(raw: str, expected: str) -> None:
    assert normalize_rfc3339_seconds(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "2026-09-01T12:34:56",
        "2026-09-01T12:34:56.000Z",
        "2026-09-01 12:34:56Z",
        "2026-09-01T12:34:56z",
        "2026-09-01T12:34:56+0300",
        "2026-09-01T12:34:56+24:00",
        "2026-02-30T12:34:56Z",
    ],
)
def test_normalize_rfc3339_seconds_rejects_noncanonical_input(raw: str) -> None:
    with pytest.raises(ValueError, match="RFC 3339"):
        normalize_rfc3339_seconds(raw)
