"""Strict canonicalization for evidence timestamps."""

from __future__ import annotations

import re
from datetime import UTC, datetime

_RFC3339_SECONDS_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})")


def normalize_rfc3339_seconds(value: str) -> str:
    """Validate a seconds-precision RFC 3339 timestamp and normalize it to UTC ``Z``."""
    if not isinstance(value, str) or _RFC3339_SECONDS_PATTERN.fullmatch(value) is None:
        raise ValueError("timestamp must be seconds-precision RFC 3339 with a timezone")

    iso_value = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(iso_value)
    except (OverflowError, ValueError) as exc:
        raise ValueError("timestamp must be a valid RFC 3339 value") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must be seconds-precision RFC 3339 with a timezone")
    try:
        return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError) as exc:
        raise ValueError("timestamp must be a valid RFC 3339 value") from exc


def parse_rfc3339_seconds(value: str) -> str:
    """Compatibility spelling for callers that treat normalization as parsing."""
    return normalize_rfc3339_seconds(value)
