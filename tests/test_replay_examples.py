"""Committed synthetic replay scenarios and report reproducibility."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from erp_security_evidence_workbench.cli import main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPLAY_ROOT = PROJECT_ROOT / "examples" / "replay"
AS_OF = "2026-09-01T12:45:00Z"


def test_replay_example_checksum_manifests_cover_every_committed_artifact() -> None:
    for scenario in ("clean-baseline", "detection-correlation"):
        root = REPLAY_ROOT / scenario
        entries = {}
        for line in (root / "SHA256SUMS").read_text(encoding="ascii").splitlines():
            digest, name = line.split("  ", 1)
            entries[name] = digest
        actual_names = {path.name for path in root.iterdir() if path.name != "SHA256SUMS"}
        assert set(entries) == actual_names
        assert {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in entries
        } == entries


@pytest.mark.parametrize(
    ("scenario", "expected_exit"),
    [("clean-baseline", 0), ("detection-correlation", 1)],
)
@pytest.mark.parametrize("report_format", ["html", "json", "sarif"])
def test_replay_examples_match_the_real_cli_byte_for_byte(
    tmp_path: Path,
    scenario: str,
    expected_exit: int,
    report_format: str,
) -> None:
    root = REPLAY_ROOT / scenario
    output = tmp_path / f"{scenario}.{report_format}"

    assert (
        main(
            [
                "replay",
                str(root / "replay-manifest.json"),
                "--as-of",
                AS_OF,
                "--format",
                report_format,
                "--output",
                str(output),
                "--rule",
                "all",
            ]
        )
        == expected_exit
    )
    assert output.read_bytes() == (root / f"report.{report_format}").read_bytes()
