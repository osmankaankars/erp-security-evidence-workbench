"""Red-first direct contracts for the HTML and SARIF renderers."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator
from slice6_report_oracles import (
    ALL_RULE_IDS,
    AS_OF,
    AUTH_INPUTS,
    AUTH_RULE_IDS,
    CLEAN_INPUTS,
    EXPECTED_AUTH_FINDINGS,
    assert_html_is_self_contained,
    assert_sarif_21_structure,
    build_direct_report,
    load_rule_run,
    parse_html_report,
    sarif_document,
    sarif_finding_projection,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SARIF_SCHEMA_PATH = (
    PROJECT_ROOT / "tests" / "schemas" / "oasis" / "sarif" / "2.1.0" / "sarif-schema-2.1.0.json"
)
SARIF_SCHEMA_SHA256 = "ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25"


def test_html_has_exact_finding_semantics_and_no_external_resources() -> None:
    bundle, findings, evaluations = load_rule_run(AUTH_INPUTS, AUTH_RULE_IDS)

    parsed = parse_html_report(build_direct_report("html", bundle, findings, evaluations))

    assert parsed.run_result == "findings"
    assert parsed.finding_projection() == EXPECTED_AUTH_FINDINGS
    assert parsed.evaluations == {rule_id: "matched" for rule_id in AUTH_RULE_IDS}
    assert AS_OF in parsed.visible_text
    assert "synthetic" in parsed.visible_text.casefold()
    assert "reference project" in parsed.visible_text.casefold()
    assert_html_is_self_contained(parsed)
    sections = [
        attributes["id"]
        for tag, attributes in parsed.start_tags
        if tag == "section" and attributes.get("id") is not None
    ]
    assert sections == [
        "scope",
        "summary",
        "rule-evaluations",
        "skipped-evaluations",
        "findings",
        "evidence",
        "rule-details",
        "limitations",
        "run-metadata",
    ]
    style = "".join(parsed.style_chunks)
    style_digest = base64.b64encode(hashlib.sha256(style.encode()).digest()).decode()
    metadata = [attributes for tag, attributes in parsed.start_tags if tag == "meta"]
    assert any(
        attributes.get("name") == "referrer" and attributes.get("content") == "no-referrer"
        for attributes in metadata
    )
    csp = next(
        attributes["content"]
        for attributes in metadata
        if attributes.get("http-equiv") == "Content-Security-Policy"
    )
    assert csp == (
        "default-src 'none'; "
        f"style-src 'sha256-{style_digest}'; "
        "base-uri 'none'; form-action 'none'"
    )


def test_sarif_has_exact_rules_severities_and_locations() -> None:
    bundle, findings, evaluations = load_rule_run(AUTH_INPUTS, AUTH_RULE_IDS)

    document = sarif_document(build_direct_report("sarif", bundle, findings, evaluations))

    assert_sarif_21_structure(document)
    assert sarif_finding_projection(document) == EXPECTED_AUTH_FINDINGS
    rules = document["runs"][0]["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == list(AUTH_RULE_IDS)


def test_sarif_validates_offline_against_hash_pinned_official_schema() -> None:
    schema_bytes = SARIF_SCHEMA_PATH.read_bytes()
    assert hashlib.sha256(schema_bytes).hexdigest() == SARIF_SCHEMA_SHA256
    schema = json.loads(schema_bytes)
    assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert all(reference.startswith("#") for reference in _schema_references(schema))
    Draft7Validator.check_schema(schema)

    bundle, findings, evaluations = load_rule_run(AUTH_INPUTS, AUTH_RULE_IDS)
    document = sarif_document(build_direct_report("sarif", bundle, findings, evaluations))
    errors = sorted(
        Draft7Validator(schema).iter_errors(document),
        key=lambda error: tuple(str(item) for item in error.absolute_path),
    )

    assert errors == []


@pytest.mark.parametrize("report_format", ["html", "sarif"])
def test_clean_reports_are_complete_and_distinct(report_format: str) -> None:
    bundle, findings, evaluations = load_rule_run(CLEAN_INPUTS, ALL_RULE_IDS)

    content = build_direct_report(report_format, bundle, findings, evaluations)

    if report_format == "html":
        parsed = parse_html_report(content)
        assert parsed.run_result == "no_findings"
        assert parsed.finding_projection() == {}
        assert parsed.evaluations == {rule_id: "not_matched" for rule_id in ALL_RULE_IDS}
        lowered = parsed.visible_text.casefold()
        assert "no findings" in lowered and "complete" in lowered
        assert not {"compliant", "secure", "safe"} & set(lowered.split())
        assert_html_is_self_contained(parsed)
    else:
        document = sarif_document(content)
        assert_sarif_21_structure(document)
        run = document["runs"][0]
        assert run["results"] == []
        assert run["properties"]["erpsec.result"] == "no_findings"
        assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == list(ALL_RULE_IDS)


@pytest.mark.parametrize("report_format", ["html", "sarif"])
def test_renderer_bytes_are_stable_when_source_order_changes(report_format: str) -> None:
    first = load_rule_run(AUTH_INPUTS, AUTH_RULE_IDS)
    second = load_rule_run(tuple(reversed(AUTH_INPUTS)), AUTH_RULE_IDS)

    assert build_direct_report(report_format, *first) == build_direct_report(report_format, *second)


def _schema_references(value: Any) -> list[str]:
    if isinstance(value, dict):
        references = [value["$ref"]] if isinstance(value.get("$ref"), str) else []
        return references + [
            reference for nested in value.values() for reference in _schema_references(nested)
        ]
    if isinstance(value, list):
        return [reference for nested in value for reference in _schema_references(nested)]
    return []
