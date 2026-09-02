"""Deterministic committed example-report generation and verification contracts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from slice6_report_oracles import (
    ALL_RULE_IDS,
    analyze_cli,
    assert_html_is_self_contained,
    assert_sarif_21_structure,
    json_finding_projection,
    parse_html_report,
    sarif_document,
    sarif_finding_projection,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOL = PROJECT_ROOT / "scripts" / "example_reports.py"
REPORTS_ROOT = PROJECT_ROOT / "examples" / "reports"
AS_OF = "2026-09-01T00:00:00Z"
CHECKSUM_NAME = "SHA256SUMS"
MANIFEST_NAME = "manifest.json"
REPORT_FORMATS = ("html", "json", "sarif")
SCENARIO_EXPECTATIONS = {
    "clean-baseline": {
        "exit_code": 0,
        "input_paths": (
            "examples/scenarios/clean-baseline/clean-events-controls.json",
            "examples/scenarios/clean-baseline/clean-permissions.jsonl",
            "examples/scenarios/clean-baseline/clean-principals.csv",
        ),
        "result": "no_findings",
    },
    "rule-pack-findings": {
        "exit_code": 1,
        "input_paths": ("examples/rule-pack-findings.json",),
        "result": "findings",
    },
}
REPORT_NAMES = frozenset(
    f"{scenario_id}.{report_format}"
    for scenario_id in SCENARIO_EXPECTATIONS
    for report_format in REPORT_FORMATS
)
MANAGED_NAMES = REPORT_NAMES | {MANIFEST_NAME, CHECKSUM_NAME}


def _run_tool(
    *arguments: str,
    expected_exit: int = 0,
) -> subprocess.CompletedProcess[str]:
    assert TOOL.is_file(), "example-report tool has not been implemented"
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, str(TOOL), *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=120,
    )
    assert completed.returncode == expected_exit, completed.stderr
    return completed


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.iterdir())
        if path.is_file() and not path.is_symlink()
    }


def _metadata_snapshot(root: Path) -> dict[str, tuple[int, int, int, int]]:
    paths = (root, *sorted(root.iterdir()))
    return {
        "." if path == root else path.name: (
            stat.S_IMODE(path.lstat().st_mode),
            path.lstat().st_ino,
            path.lstat().st_size,
            path.lstat().st_mtime_ns,
        )
        for path in paths
    }


def _checksums(root: Path) -> dict[str, str]:
    raw = (root / CHECKSUM_NAME).read_bytes()
    assert raw.endswith(b"\n") and b"\r" not in raw
    result: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        assert match is not None, f"invalid checksum line: {line!r}"
        digest, relative = match.groups()
        path = PurePosixPath(relative)
        assert not path.is_absolute()
        assert all(part not in {"", ".", ".."} for part in path.parts)
        assert relative == path.as_posix() and relative not in result
        result[relative] = digest
    assert list(result) == sorted(result)
    return result


def _manifest(root: Path = REPORTS_ROOT) -> dict[str, Any]:
    value = json.loads((root / MANIFEST_NAME).read_text(encoding="ascii"))
    assert isinstance(value, dict)
    return value


def test_two_generations_are_byte_identical_to_the_committed_tree(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"

    _run_tool("generate", "--output", str(first))
    second.mkdir()
    _run_tool("generate", "--output", str(second))

    assert set(_snapshot(first)) == set(_snapshot(second)) == MANAGED_NAMES
    assert _snapshot(first) == _snapshot(second) == _snapshot(REPORTS_ROOT)


@pytest.mark.parametrize("scenario_id", sorted(SCENARIO_EXPECTATIONS))
@pytest.mark.parametrize("report_format", REPORT_FORMATS)
def test_committed_bytes_and_exit_codes_match_the_real_cli(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    scenario_id: str,
    report_format: str,
) -> None:
    expected = SCENARIO_EXPECTATIONS[scenario_id]
    output = tmp_path / f"{scenario_id}.{report_format}"
    inputs = tuple(PROJECT_ROOT / relative for relative in expected["input_paths"])

    exit_code = analyze_cli(
        inputs,
        output,
        report_format=report_format,
        rule_ids=ALL_RULE_IDS,
    )

    assert exit_code == expected["exit_code"]
    assert output.read_bytes() == (REPORTS_ROOT / output.name).read_bytes()
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_manifest_pins_provenance_options_outcomes_and_report_bytes() -> None:
    manifest = _manifest()
    checksums = _checksums(REPORTS_ROOT)

    assert set(manifest) == {
        "as_of",
        "dataset_classification",
        "generator",
        "scenarios",
        "schema_version",
    }
    assert manifest["schema_version"] == "erpsec.example-reports-manifest/v1"
    assert manifest["dataset_classification"] == "synthetic"
    assert manifest["as_of"] == AS_OF
    assert manifest["generator"] == {
        "path": "scripts/example_reports.py",
        "version": "1.0.0",
    }
    assert set(checksums) == REPORT_NAMES | {MANIFEST_NAME}

    scenarios = manifest["scenarios"]
    assert [scenario["scenario_id"] for scenario in scenarios] == sorted(SCENARIO_EXPECTATIONS)
    for scenario in scenarios:
        scenario_id = scenario["scenario_id"]
        expected = SCENARIO_EXPECTATIONS[scenario_id]
        assert set(scenario) == {
            "artifacts",
            "expected",
            "options",
            "provenance",
            "scenario_id",
        }
        assert scenario["options"] == {
            "as_of": AS_OF,
            "selected_rules": ["all"],
        }
        assert scenario["expected"] == {
            "exit_code": expected["exit_code"],
            "result": expected["result"],
        }
        provenance = scenario["provenance"]
        assert provenance["dataset_classification"] == "synthetic"
        assert provenance["origin"] == "in-repository fictional fixture"
        inputs = provenance["inputs"]
        assert [item["path"] for item in inputs] == list(expected["input_paths"])
        for item in inputs:
            assert set(item) == {"byte_count", "path", "sha256"}
            source = PROJECT_ROOT / item["path"]
            assert source.is_file() and not source.is_symlink()
            assert item["byte_count"] == source.stat().st_size
            assert item["sha256"] == _sha256(source)

        artifacts = scenario["artifacts"]
        assert [item["format"] for item in artifacts] == list(REPORT_FORMATS)
        for item in artifacts:
            assert set(item) == {"byte_count", "format", "path", "sha256"}
            assert item["path"] == f"{scenario_id}.{item['format']}"
            report = REPORTS_ROOT / item["path"]
            assert report.is_file() and not report.is_symlink()
            assert item["byte_count"] == report.stat().st_size
            assert item["sha256"] == checksums[item["path"]] == _sha256(report)

    assert checksums[MANIFEST_NAME] == _sha256(REPORTS_ROOT / MANIFEST_NAME)


@pytest.mark.parametrize("scenario_id", sorted(SCENARIO_EXPECTATIONS))
def test_committed_formats_have_matching_finding_semantics(scenario_id: str) -> None:
    json_document = json.loads((REPORTS_ROOT / f"{scenario_id}.json").read_text(encoding="ascii"))
    html = parse_html_report((REPORTS_ROOT / f"{scenario_id}.html").read_bytes())
    sarif = sarif_document((REPORTS_ROOT / f"{scenario_id}.sarif").read_bytes())

    assert_html_is_self_contained(html)
    assert_sarif_21_structure(sarif)
    expected_result = SCENARIO_EXPECTATIONS[scenario_id]["result"]
    assert json_document["run"]["result"] == html.run_result == expected_result
    assert sarif["runs"][0]["properties"]["erpsec.result"] == expected_result
    assert (
        json_finding_projection(json_document)
        == html.finding_projection()
        == sarif_finding_projection(sarif)
    )


def test_generate_accepts_empty_but_never_overwrites_or_follows_symlink(
    tmp_path: Path,
) -> None:
    output = tmp_path / "empty"
    output.mkdir()
    _run_tool("generate", "--output", str(output))
    before = _snapshot(output)

    _run_tool("generate", "--output", str(output), expected_exit=2)
    assert _snapshot(output) == before

    non_empty = tmp_path / "non-empty"
    non_empty.mkdir()
    sentinel = non_empty / "keep.txt"
    sentinel.write_text("keep", encoding="ascii")
    _run_tool("generate", "--output", str(non_empty), expected_exit=2)
    assert sentinel.read_text(encoding="ascii") == "keep"

    symlink = tmp_path / "linked-output"
    symlink.symlink_to(non_empty, target_is_directory=True)
    _run_tool("generate", "--output", str(symlink), expected_exit=2)
    assert set(non_empty.iterdir()) == {sentinel}


def test_check_is_read_only_and_detects_drift_or_manifest_external_files(
    tmp_path: Path,
) -> None:
    before_bytes = _snapshot(REPORTS_ROOT)
    before_metadata = _metadata_snapshot(REPORTS_ROOT)

    _run_tool("check", "--reports", str(REPORTS_ROOT))

    assert _snapshot(REPORTS_ROOT) == before_bytes
    assert _metadata_snapshot(REPORTS_ROOT) == before_metadata

    drifted = tmp_path / "drifted"
    _run_tool("generate", "--output", str(drifted))
    changed = drifted / "clean-baseline.json"
    changed.write_bytes(changed.read_bytes() + b" ")
    _run_tool("check", "--reports", str(drifted), expected_exit=1)

    external = tmp_path / "external"
    _run_tool("generate", "--output", str(external))
    (external / "not-in-manifest.txt").write_text("unexpected", encoding="ascii")
    _run_tool("check", "--reports", str(external), expected_exit=1)


def test_check_refuses_directory_or_entry_symlinks(tmp_path: Path) -> None:
    generated = tmp_path / "generated"
    _run_tool("generate", "--output", str(generated))

    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(generated, target_is_directory=True)
    _run_tool("check", "--reports", str(linked_root), expected_exit=2)

    linked_entry = generated / "external-link"
    linked_entry.symlink_to(generated / "manifest.json")
    _run_tool("check", "--reports", str(generated), expected_exit=2)
