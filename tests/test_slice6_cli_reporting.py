"""Red-first CLI parity, escaping, and fatal-publication contracts."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

import pytest
from slice6_report_oracles import (
    AUTH_INPUTS,
    AUTH_RULE_IDS,
    EXPECTED_AUTH_FINDINGS,
    analyze_cli,
    assert_sarif_21_structure,
    json_finding_projection,
    parse_html_report,
    sarif_document,
    sarif_finding_projection,
)

from erp_security_evidence_workbench import reporting

PROJECT_ROOT = Path(__file__).resolve().parents[1]
HOSTILE_BASENAME = "evidence-\"><img src=x onerror=ERPSEC_SENTINEL> & 'quoted'.json"


def test_cli_json_html_and_sarif_have_exact_finding_parity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    outputs = {name: tmp_path / f"report.{name}" for name in ("json", "html", "sarif")}

    exit_codes = {
        name: analyze_cli(
            AUTH_INPUTS,
            output,
            report_format=name,
            rule_ids=AUTH_RULE_IDS,
        )
        for name, output in outputs.items()
    }

    assert exit_codes == {"json": 1, "html": 1, "sarif": 1}
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    json_projection = json_finding_projection(
        json.loads(outputs["json"].read_text(encoding="utf-8"))
    )
    html_projection = parse_html_report(outputs["html"].read_bytes()).finding_projection()
    sarif_value = sarif_document(outputs["sarif"].read_bytes())
    assert_sarif_21_structure(sarif_value)
    sarif_projection = sarif_finding_projection(sarif_value)
    assert json_projection == html_projection == sarif_projection == EXPECTED_AUTH_FINDINGS


@pytest.mark.parametrize("report_format", ["html", "sarif"])
def test_hostile_accepted_basename_is_escaped_without_losing_provenance(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    report_format: str,
) -> None:
    input_path = tmp_path / HOSTILE_BASENAME
    input_path.write_bytes((PROJECT_ROOT / "examples" / "audit-logging-disabled.json").read_bytes())
    output_path = tmp_path / f"hostile.{report_format}"

    assert (
        analyze_cli(
            (input_path,),
            output_path,
            report_format=report_format,
            rule_ids=("ERP001",),
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""

    if report_format == "html":
        content = output_path.read_bytes()
        parsed = parse_html_report(content)
        assert HOSTILE_BASENAME in parsed.source_paths
        assert "img" not in {tag for tag, _ in parsed.start_tags}
        assert not any(
            name.startswith("on") for _, attributes in parsed.start_tags for name in attributes
        )
        assert b"<img src=x onerror=ERPSEC_SENTINEL>" not in content
    else:
        document = sarif_document(output_path.read_bytes())
        assert_sarif_21_structure(document)
        locations = document["runs"][0]["results"][0]["locations"]
        uris = {location["physicalLocation"]["artifactLocation"]["uri"] for location in locations}
        assert uris == {quote(HOSTILE_BASENAME, safe="-._~")}


@pytest.mark.parametrize("report_format", ["json", "html", "sarif"])
@pytest.mark.parametrize(
    ("relative_input", "expected_error"),
    [
        ("validation/incomplete-principal.json", "error: evidence coverage is incomplete\n"),
        ("validation/malformed-tail.jsonl", "error: input contains malformed JSON\n"),
    ],
)
def test_incomplete_and_fatal_runs_publish_no_artifact(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    report_format: str,
    relative_input: str,
    expected_error: str,
) -> None:
    input_path = PROJECT_ROOT / "examples" / "scenarios" / relative_input
    output_path = tmp_path / f"fatal.{report_format}"

    assert (
        analyze_cli(
            (input_path,),
            output_path,
            report_format=report_format,
            rule_ids=("ERP001",),
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == expected_error
    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


@pytest.mark.parametrize("report_format", ["html", "sarif"])
def test_renderer_internal_failure_is_redacted_and_leaves_no_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    report_format: str,
) -> None:
    output_path = tmp_path / f"failure.{report_format}"

    def fail_validation(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("secret-renderer-sentinel")

    monkeypatch.setattr(reporting, "_validated_results", fail_validation)

    assert (
        analyze_cli(
            AUTH_INPUTS,
            output_path,
            report_format=report_format,
            rule_ids=AUTH_RULE_IDS,
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: unexpected internal failure\n"
    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


@pytest.mark.parametrize("report_format", ["json", "html", "sarif"])
def test_existing_output_is_never_overwritten(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    report_format: str,
) -> None:
    output_path = tmp_path / f"existing.{report_format}"
    output_path.write_bytes(b"existing-report\n")

    assert (
        analyze_cli(
            AUTH_INPUTS,
            output_path,
            report_format=report_format,
            rule_ids=AUTH_RULE_IDS,
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: output already exists\n"
    assert output_path.read_bytes() == b"existing-report\n"
