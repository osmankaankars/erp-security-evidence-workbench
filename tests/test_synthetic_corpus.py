"""Deterministic synthetic-corpus generation and provenance contracts."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from scripts import synthetic_corpus

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = PROJECT_ROOT / "examples" / "scenarios"
CORPUS_TOOL = PROJECT_ROOT / "scripts" / "synthetic_corpus.py"
CHECKSUM_NAME = "SHA256SUMS"
README_NAME = "README.md"

SCENARIO_CONTRACTS: dict[str, tuple[int, tuple[str, ...], dict[str, str]]] = {
    "clean-baseline": (
        4,
        ("ERP001", "ERP002", "ERP003", "ERP004", "ERP005", "ERP006"),
        {},
    ),
    "access-governance": (
        9,
        ("ERP002", "ERP003", "ERP004"),
        {
            "ERP002": "5fcaa53c2b2dfa4876d13b290bfe0466380b073950f65b30919f3c8037f5ef31",
            "ERP003": "ea1222dbc95da3713f7aa4fc325417e90ad5c6de52c902177b5f44c0f9f46125",
            "ERP004": "28cebe7564a901c9ace0646d74373bbd40af951f9ce4b73d72c4d0af8f7aea4e",
        },
    ),
    "authentication-control": (
        17,
        ("ERP001", "ERP005", "ERP006"),
        {
            "ERP001": "5e8e54ccb2d8a4e08413e1c52c0938f2646bc01b767508ba383a8e4dca1eab53",
            "ERP005": "d30f1e317f1680d2e7951e59098e2da7ee33dc5dd4ac46dc6880658dbe9bd7e1",
            "ERP006": "847311517adac28d910ef1cf15a26dbed13a993b17d78eb3cbd15165ef0fb657",
        },
    ),
}
VALIDATION_IDS = (
    "adversarial-extra-field",
    "incomplete-principal",
    "malformed-tail",
)


def _run_tool(*arguments: str) -> subprocess.CompletedProcess[str]:
    assert CORPUS_TOOL.is_file(), "synthetic corpus tool has not been implemented"
    return subprocess.run(
        [sys.executable, str(CORPUS_TOOL), *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative_files(root: Path) -> tuple[str, ...]:
    return tuple(
        sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
    )


def _snapshot(root: Path) -> dict[str, bytes]:
    return {relative: (root / relative).read_bytes() for relative in _relative_files(root)}


def _checksums(root: Path) -> dict[str, str]:
    checksum_path = root / CHECKSUM_NAME
    assert checksum_path.is_file(), "generated corpus must include SHA256SUMS"
    raw = checksum_path.read_bytes()
    assert raw.endswith(b"\n")
    assert b"\r" not in raw

    lines = raw.decode("ascii").splitlines()
    assert lines
    result: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        assert match is not None, f"invalid checksum line: {line!r}"
        digest, relative = match.groups()
        path = PurePosixPath(relative)
        assert not path.is_absolute()
        assert relative == path.as_posix()
        assert all(part not in {"", ".", ".."} for part in path.parts)
        assert relative not in {CHECKSUM_NAME, README_NAME}
        assert relative not in result
        result[relative] = digest

    assert list(result) == sorted(result)
    return result


def _manifest(root: Path = CORPUS_ROOT) -> dict[str, Any]:
    value = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_generator_reproduces_committed_tree_and_expected_checksums(tmp_path: Path) -> None:
    generated = tmp_path / "generated"

    result = _run_tool("generate", "--output", str(generated))

    assert result.returncode == 0, result.stderr
    committed_checksums = _checksums(CORPUS_ROOT)
    generated_checksums = _checksums(generated)
    assert generated_checksums == committed_checksums
    assert _relative_files(generated) == tuple(sorted((*generated_checksums, CHECKSUM_NAME)))
    assert _relative_files(CORPUS_ROOT) == tuple(
        sorted((*committed_checksums, CHECKSUM_NAME, README_NAME))
    )

    for relative, expected_digest in committed_checksums.items():
        committed_path = CORPUS_ROOT / relative
        generated_path = generated / relative
        assert _sha256(committed_path) == expected_digest
        assert _sha256(generated_path) == expected_digest
        assert generated_path.read_bytes() == committed_path.read_bytes()
    assert (generated / CHECKSUM_NAME).read_bytes() == (CORPUS_ROOT / CHECKSUM_NAME).read_bytes()


def test_generation_is_repeatable_and_refuses_nonempty_targets(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"

    first_result = _run_tool("generate", "--output", str(first))
    second.mkdir()
    second_result = _run_tool("generate", "--output", str(second))

    assert first_result.returncode == second_result.returncode == 0
    assert _snapshot(first) == _snapshot(second)
    before = _snapshot(first)

    repeated = _run_tool("generate", "--output", str(first))

    assert repeated.returncode == 2
    assert _snapshot(first) == before


def test_check_accepts_committed_corpus_and_rejects_byte_drift(tmp_path: Path) -> None:
    accepted = _run_tool("check", "--corpus", str(CORPUS_ROOT))
    assert accepted.returncode == 0, accepted.stderr

    drifted = tmp_path / "drifted"
    generated = _run_tool("generate", "--output", str(drifted))
    assert generated.returncode == 0, generated.stderr
    checksums = _checksums(drifted)
    fixture = next(relative for relative in checksums if relative != "manifest.json")
    fixture_path = drifted / fixture
    fixture_path.write_bytes(fixture_path.read_bytes() + b"\n")

    rejected = _run_tool("check", "--corpus", str(drifted))

    assert rejected.returncode == 1


def test_oversized_fixture_is_rejected_before_content_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    generated = tmp_path / "generated"
    result = _run_tool("generate", "--output", str(generated))
    assert result.returncode == 0, result.stderr
    managed = synthetic_corpus._expected_corpus()
    relative = "access-governance/access-permissions.jsonl"
    oversized = generated / relative
    oversized.write_bytes(managed[relative] + b"x")
    original_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object) -> object:
        if path == oversized and args and args[0] == "rb":
            raise AssertionError("oversized fixture content must not be opened")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    with pytest.raises(synthetic_corpus.CorpusMismatchError):
        synthetic_corpus._check_corpus(generated, managed)


def test_oversized_manifest_is_rejected_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    generated = tmp_path / "generated"
    result = _run_tool("generate", "--output", str(generated))
    assert result.returncode == 0, result.stderr
    managed = synthetic_corpus._expected_corpus()
    manifest_path = generated / "manifest.json"
    manifest_path.write_bytes(managed["manifest.json"] + b" ")

    def unexpected_load(*args: object, **kwargs: object) -> dict[str, Any]:
        del args, kwargs
        raise AssertionError("unverified manifest must not be parsed")

    monkeypatch.setattr(synthetic_corpus, "_load_manifest", unexpected_load)

    with pytest.raises(synthetic_corpus.CorpusMismatchError):
        synthetic_corpus._replay_manifest(manifest_path, managed)


def test_manifest_pins_fixture_provenance_and_scenario_contracts() -> None:
    manifest = _manifest()

    assert set(manifest) == {
        "as_of",
        "dataset_classification",
        "fixtures",
        "generator",
        "scenarios",
        "schema_version",
        "validation_cases",
    }
    assert manifest["schema_version"] == "erpsec.synthetic-corpus-manifest/v1"
    assert manifest["dataset_classification"] == "synthetic"
    assert manifest["as_of"] == "2026-09-01T00:00:00Z"
    assert manifest["generator"]["path"] == "scripts/synthetic_corpus.py"
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", manifest["generator"]["version"])

    checksums = _checksums(CORPUS_ROOT)
    expected_fixture_paths = set(checksums) - {"manifest.json"}
    fixtures = manifest["fixtures"]
    assert isinstance(fixtures, list)
    assert [fixture["path"] for fixture in fixtures] == sorted(expected_fixture_paths)
    fixture_by_path = {fixture["path"]: fixture for fixture in fixtures}
    assert set(fixture_by_path) == expected_fixture_paths

    for relative, fixture in fixture_by_path.items():
        expected_keys = {"byte_count", "format", "intent", "origin", "path", "sha256"}
        if relative != "validation/malformed-tail.jsonl":
            expected_keys.add("record_count")
        assert set(fixture) == expected_keys
        source_path = CORPUS_ROOT / relative
        assert fixture["format"] == source_path.suffix.removeprefix(".")
        assert fixture["byte_count"] == source_path.stat().st_size
        assert fixture["sha256"] == checksums[relative] == _sha256(source_path)
        assert isinstance(fixture["origin"], str) and fixture["origin"].strip()
        assert isinstance(fixture["intent"], str) and fixture["intent"].strip()
        if "record_count" in fixture:
            assert type(fixture["record_count"]) is int and fixture["record_count"] > 0

    scenarios = manifest["scenarios"]
    assert isinstance(scenarios, list)
    assert [scenario["scenario_id"] for scenario in scenarios] == sorted(SCENARIO_CONTRACTS)
    for scenario in scenarios:
        record_count, selected_rules, fingerprints = SCENARIO_CONTRACTS[scenario["scenario_id"]]
        assert set(scenario) == {"expected", "input_paths", "scenario_id", "selected_rules"}
        assert scenario["input_paths"] == sorted(scenario["input_paths"])
        assert set(scenario["input_paths"]) <= expected_fixture_paths
        assert tuple(scenario["selected_rules"]) == selected_rules
        expected = scenario["expected"]
        assert set(expected) == {
            "evaluations",
            "exit_code",
            "findings",
            "output_present",
            "records",
        }
        assert len(expected["records"]) == record_count
        assert expected["exit_code"] == (0 if scenario["scenario_id"] == "clean-baseline" else 1)
        assert expected["output_present"] is True
        assert {
            finding["rule_id"]: finding["fingerprint"] for finding in expected["findings"]
        } == fingerprints

    validation_cases = manifest["validation_cases"]
    assert isinstance(validation_cases, list)
    assert [case["validation_id"] for case in validation_cases] == list(VALIDATION_IDS)
    for case in validation_cases:
        assert set(case) == {"expected", "input_paths", "selected_rules", "validation_id"}
        assert set(case["input_paths"]) <= expected_fixture_paths
        assert tuple(case["selected_rules"]) == ("ERP001",)
        assert case["expected"]["exit_code"] == 2
        assert case["expected"]["output_present"] is False
        assert isinstance(case["expected"]["diagnostic"], str)
        assert isinstance(case["expected"]["diagnostic_excludes"], list)


def test_fixture_corpus_contains_only_explicitly_synthetic_generic_material() -> None:
    manifest = _manifest()
    fixture_paths = [CORPUS_ROOT / fixture["path"] for fixture in manifest["fixtures"]]
    prohibited_literals = (
        b"@",
        b"http://",
        b"https://",
        b"exampleproduct",
        b"oracle",
        b"password",
        b"sap",
        b"fictionalcorp",
        b"token",
    )
    ipv4 = re.compile(rb"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")

    for path in fixture_paths:
        content = path.read_bytes()
        lowered = content.lower()
        assert b"synthetic" in lowered
        assert all(literal not in lowered for literal in prohibited_literals)
        assert ipv4.search(content) is None
