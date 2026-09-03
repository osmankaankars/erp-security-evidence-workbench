"""Independent report expectations and standard-library parsers."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from erp_security_evidence_workbench import reporting
from erp_security_evidence_workbench.cli import main
from erp_security_evidence_workbench.ingest import load_evidence
from erp_security_evidence_workbench.models import (
    EvidenceBundle,
    Finding,
    RuleEvaluation,
)
from erp_security_evidence_workbench.rules import evaluate_rules

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = PROJECT_ROOT / "examples" / "scenarios"
AS_OF = "2026-09-01T00:00:00Z"

ALL_RULE_IDS = ("ERP001", "ERP002", "ERP003", "ERP004", "ERP005", "ERP006")
ACCESS_RULE_IDS = ("ERP002", "ERP003", "ERP004")
AUTH_RULE_IDS = ("ERP001", "ERP005", "ERP006")

CLEAN_INPUTS = (
    CORPUS_ROOT / "clean-baseline" / "clean-principals.csv",
    CORPUS_ROOT / "clean-baseline" / "clean-permissions.jsonl",
    CORPUS_ROOT / "clean-baseline" / "clean-events-controls.json",
)
ACCESS_INPUTS = (
    CORPUS_ROOT / "access-governance" / "access-permissions.jsonl",
    CORPUS_ROOT / "access-governance" / "access-principals.csv",
)
AUTH_INPUTS = (
    CORPUS_ROOT / "authentication-control" / "auth-control.json",
    CORPUS_ROOT / "authentication-control" / "auth-events.jsonl",
    CORPUS_ROOT / "authentication-control" / "auth-principals.csv",
)

FINGERPRINT_PROPERTY = "erpsec/v1"
SEVERITY_PROPERTY = "erpsec.severity"
RULE_SEVERITIES = {
    "ERP001": "high",
    "ERP002": "high",
    "ERP003": "high",
    "ERP004": "high",
    "ERP005": "high",
    "ERP006": "medium",
}
SARIF_LEVELS = {"high": "error", "medium": "warning"}


@dataclass(frozen=True, slots=True)
class EvidenceLocation:
    """One independently expected finding-evidence location."""

    record_id: str
    path: str
    source_format: str
    locator_kind: str
    locator_value: str
    field: str


@dataclass(frozen=True, slots=True)
class FindingProjection:
    """Format-neutral finding projection used as the parity oracle."""

    rule_id: str
    severity: str
    locations: frozenset[EvidenceLocation]


def _locations(
    *,
    records: Sequence[tuple[str, int]],
    path: str,
    source_format: str,
    locator_kind: str,
    fields: Sequence[str],
) -> frozenset[EvidenceLocation]:
    return frozenset(
        EvidenceLocation(
            record_id=record_id,
            path=path,
            source_format=source_format,
            locator_kind=locator_kind,
            locator_value=str(locator),
            field=field,
        )
        for record_id, locator in records
        for field in fields
    )


EXPECTED_ACCESS_FINDINGS: dict[str, FindingProjection] = {
    "5fcaa53c2b2dfa4876d13b290bfe0466380b073950f65b30919f3c8037f5ef31": (
        FindingProjection(
            rule_id="ERP002",
            severity="high",
            locations=(
                _locations(
                    records=(("permission.access.stale-admin", 5),),
                    path="access-permissions.jsonl",
                    source_format="jsonl",
                    locator_kind="line",
                    fields=("permission", "principal_id"),
                )
                | _locations(
                    records=(("principal.access.stale", 5),),
                    path="access-principals.csv",
                    source_format="csv",
                    locator_kind="row",
                    fields=("enabled", "last_active_at", "principal_id"),
                )
            ),
        )
    ),
    "ea1222dbc95da3713f7aa4fc325417e90ad5c6de52c902177b5f44c0f9f46125": (
        FindingProjection(
            rule_id="ERP003",
            severity="high",
            locations=_locations(
                records=(("permission.access.direct-admin", 4),),
                path="access-permissions.jsonl",
                source_format="jsonl",
                locator_kind="line",
                fields=("assignment_mode", "permission"),
            ),
        )
    ),
    "28cebe7564a901c9ace0646d74373bbd40af951f9ce4b73d72c4d0af8f7aea4e": (
        FindingProjection(
            rule_id="ERP004",
            severity="high",
            locations=_locations(
                records=(
                    ("permission.access.approve-payment", 1),
                    ("permission.access.create-vendor", 3),
                ),
                path="access-permissions.jsonl",
                source_format="jsonl",
                locator_kind="line",
                fields=("permission", "principal_id"),
            ),
        )
    ),
}

EXPECTED_AUTH_FINDINGS: dict[str, FindingProjection] = {
    "5e8e54ccb2d8a4e08413e1c52c0938f2646bc01b767508ba383a8e4dca1eab53": (
        FindingProjection(
            rule_id="ERP001",
            severity="high",
            locations=frozenset(
                {
                    EvidenceLocation(
                        record_id="control.auth.audit",
                        path="auth-control.json",
                        source_format="json",
                        locator_kind="json_pointer",
                        locator_value="/0/enabled",
                        field="enabled",
                    )
                }
            ),
        )
    ),
    "d30f1e317f1680d2e7951e59098e2da7ee33dc5dd4ac46dc6880658dbe9bd7e1": (
        FindingProjection(
            rule_id="ERP005",
            severity="high",
            locations=(
                _locations(
                    records=(("auth.emergency.outside", 3),),
                    path="auth-events.jsonl",
                    source_format="jsonl",
                    locator_kind="line",
                    fields=("action", "occurred_at", "outcome", "principal_id"),
                )
                | _locations(
                    records=(("principal.auth.emergency", 2),),
                    path="auth-principals.csv",
                    source_format="csv",
                    locator_kind="row",
                    fields=("principal_id", "principal_kind"),
                )
            ),
        )
    ),
    "847311517adac28d910ef1cf15a26dbed13a993b17d78eb3cbd15165ef0fb657": (
        FindingProjection(
            rule_id="ERP006",
            severity="medium",
            locations=_locations(
                records=(
                    ("auth.failure.match.1", 4),
                    ("auth.failure.match.2", 5),
                    ("auth.failure.match.3", 6),
                    ("auth.failure.match.4", 7),
                    ("auth.failure.match.5", 8),
                ),
                path="auth-events.jsonl",
                source_format="jsonl",
                locator_kind="line",
                fields=("action", "occurred_at", "outcome", "principal_id"),
            ),
        )
    ),
}


def load_rule_run(
    inputs: Sequence[Path],
    rule_ids: tuple[str, ...],
) -> tuple[EvidenceBundle, tuple[Finding, ...], tuple[RuleEvaluation, ...]]:
    bundle = load_evidence(tuple(inputs))
    run = evaluate_rules(bundle, as_of=AS_OF, selected_rule_ids=rule_ids)
    return bundle, run.findings, run.evaluations


def build_direct_report(
    report_format: str,
    bundle: EvidenceBundle,
    findings: tuple[Finding, ...],
    evaluations: tuple[RuleEvaluation, ...],
) -> bytes:
    builder_name = f"build_{report_format}_report"
    builder = getattr(reporting, builder_name, None)
    assert callable(builder), f"renderer reporting.{builder_name} is missing"
    typed_builder: Callable[..., bytes] = builder
    content = typed_builder(bundle, findings, as_of=AS_OF, evaluations=evaluations)
    assert type(content) is bytes
    return content


def analyze_cli(
    inputs: Sequence[Path],
    output: Path,
    *,
    report_format: str,
    rule_ids: tuple[str, ...],
) -> int:
    arguments = [
        "analyze",
        *(str(path) for path in inputs),
        "--as-of",
        AS_OF,
        "--format",
        report_format,
        "--output",
        str(output),
    ]
    if rule_ids == ALL_RULE_IDS:
        arguments.extend(("--rule", "all"))
    else:
        for rule_id in rule_ids:
            arguments.extend(("--rule", rule_id))
    return main(arguments)


def _pointer_field(pointer: str) -> str:
    token = pointer.rsplit("/", 1)[-1]
    return token.replace("~1", "/").replace("~0", "~")


def json_finding_projection(document: dict[str, Any]) -> dict[str, FindingProjection]:
    result: dict[str, FindingProjection] = {}
    for finding in document["findings"]:
        locations: set[EvidenceLocation] = set()
        for evidence in finding["evidence_refs"]:
            source = evidence["source_ref"]
            if "json_pointer" in source:
                locator_kind = "json_pointer"
                locator_value = str(source["json_pointer"])
                field = _pointer_field(locator_value)
            elif "row" in source:
                locator_kind = "row"
                locator_value = str(source["row"])
                field = str(source["field"])
            else:
                locator_kind = "line"
                locator_value = str(source["line"])
                field = str(source["field"])
            locations.add(
                EvidenceLocation(
                    record_id=str(evidence["record_id"]),
                    path=str(source["path"]),
                    source_format=str(source["format"]),
                    locator_kind=locator_kind,
                    locator_value=locator_value,
                    field=field,
                )
            )
        fingerprint = str(finding["fingerprint"])
        assert fingerprint not in result
        result[fingerprint] = FindingProjection(
            rule_id=str(finding["rule_id"]),
            severity=str(finding["severity"]),
            locations=frozenset(locations),
        )
    return result


class ERPSECHTMLParser(HTMLParser):
    """Collect stable semantic report hooks while retaining security-relevant markup."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.declarations: list[str] = []
        self.start_tags: list[tuple[str, dict[str, str | None]]] = []
        self.text_chunks: list[str] = []
        self.style_chunks: list[str] = []
        self.run_result: str | None = None
        self.findings: dict[str, tuple[str, str]] = {}
        self.evidence: dict[str, set[EvidenceLocation]] = defaultdict(set)
        self.evaluations: dict[str, str] = {}
        self.source_paths: set[str] = set()
        self._style_depth = 0

    def handle_decl(self, decl: str) -> None:
        self.declarations.append(decl)

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = dict(attrs)
        self.start_tags.append((tag, attributes))
        if tag == "style":
            self._style_depth += 1
        if tag == "body":
            self.run_result = attributes.get("data-run-result")

        role = attributes.get("data-erpsec-role")
        if role == "finding":
            fingerprint = _required_attribute(attributes, "data-fingerprint")
            assert fingerprint not in self.findings, "finding rendered more than once"
            self.findings[fingerprint] = (
                _required_attribute(attributes, "data-rule-id"),
                _required_attribute(attributes, "data-severity"),
            )
        elif role == "evidence":
            fingerprint = _required_attribute(attributes, "data-fingerprint")
            path = _required_attribute(attributes, "data-source-path")
            self.source_paths.add(path)
            self.evidence[fingerprint].add(
                EvidenceLocation(
                    record_id=_required_attribute(attributes, "data-record-id"),
                    path=path,
                    source_format=_required_attribute(attributes, "data-source-format"),
                    locator_kind=_required_attribute(attributes, "data-locator-kind"),
                    locator_value=_required_attribute(attributes, "data-locator-value"),
                    field=_required_attribute(attributes, "data-field"),
                )
            )
        elif role == "evaluation":
            rule_id = _required_attribute(attributes, "data-rule-id")
            assert rule_id not in self.evaluations, "evaluation rendered more than once"
            self.evaluations[rule_id] = _required_attribute(attributes, "data-status")

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag == "style":
            self._style_depth -= 1

    def handle_data(self, data: str) -> None:
        self.text_chunks.append(data)
        if self._style_depth:
            self.style_chunks.append(data)

    @property
    def visible_text(self) -> str:
        return " ".join(" ".join(self.text_chunks).split())

    def finding_projection(self) -> dict[str, FindingProjection]:
        assert set(self.evidence) <= set(self.findings)
        return {
            fingerprint: FindingProjection(
                rule_id=rule_id,
                severity=severity,
                locations=frozenset(self.evidence.get(fingerprint, set())),
            )
            for fingerprint, (rule_id, severity) in self.findings.items()
        }


def _required_attribute(attributes: dict[str, str | None], name: str) -> str:
    value = attributes.get(name)
    assert value is not None and value != "", f"HTML report omitted {name}"
    return value


def parse_html_report(content: bytes) -> ERPSECHTMLParser:
    parser = ERPSECHTMLParser()
    parser.feed(content.decode("utf-8"))
    parser.close()
    return parser


def assert_html_is_self_contained(parser: ERPSECHTMLParser) -> None:
    forbidden_tags = {
        "audio",
        "base",
        "embed",
        "form",
        "frame",
        "iframe",
        "img",
        "link",
        "object",
        "script",
        "source",
        "svg",
        "track",
        "video",
    }
    url_attributes = {
        "action",
        "background",
        "cite",
        "formaction",
        "href",
        "poster",
        "src",
        "srcset",
    }
    assert [item.lower() for item in parser.declarations] == ["doctype html"]
    observed_tags = {tag for tag, _ in parser.start_tags}
    assert {"html", "head", "body", "style"} <= observed_tags
    assert not observed_tags & forbidden_tags

    for tag, attributes in parser.start_tags:
        assert not any(name.lower().startswith("on") for name in attributes)
        if tag == "meta":
            assert attributes.get("http-equiv", "").lower() != "refresh"
        for name, value in attributes.items():
            if name.lower() not in url_attributes:
                continue
            assert name.lower() == "href" and value is not None and value.startswith("#")
        inline_style = attributes.get("style", "") or ""
        assert not _contains_external_css(inline_style)

    assert not _contains_external_css("".join(parser.style_chunks))


def _contains_external_css(value: str) -> bool:
    lowered = value.casefold()
    return any(token in lowered for token in ("@import", "@font-face", "url("))


def sarif_document(content: bytes) -> dict[str, Any]:
    document = json.loads(content.decode("utf-8"))
    assert isinstance(document, dict)
    return document


def assert_sarif_21_structure(document: dict[str, Any]) -> None:
    """Validate the selected project subset, not the full official SARIF schema."""
    schema_uri = document.get("$schema")
    assert isinstance(schema_uri, str)
    assert schema_uri.endswith("/sarif-schema-2.1.0.json")
    assert document.get("version") == "2.1.0"
    runs = document.get("runs")
    assert isinstance(runs, list) and len(runs) == 1
    run = runs[0]
    assert isinstance(run, dict)

    driver = run.get("tool", {}).get("driver")
    assert isinstance(driver, dict)
    assert driver.get("name") == "erp-security-evidence-workbench"
    assert driver.get("version") == "0.2.0rc1"
    rules = driver.get("rules")
    assert isinstance(rules, list)
    rule_ids = [rule.get("id") for rule in rules if isinstance(rule, dict)]
    assert len(rule_ids) == len(rules) == len(set(rule_ids))
    for rule in rules:
        assert isinstance(rule, dict)
        rule_id = rule.get("id")
        assert rule_id in RULE_SEVERITIES
        assert _message_text(rule.get("shortDescription"))
        assert _message_text(rule.get("fullDescription"))
        configuration = rule.get("defaultConfiguration")
        assert isinstance(configuration, dict)
        assert configuration.get("level") == SARIF_LEVELS[RULE_SEVERITIES[rule_id]]

    properties = run.get("properties")
    assert isinstance(properties, dict)
    assert properties.get("erpsec.asOf") == AS_OF
    assert properties.get("erpsec.coverage") == "complete"
    assert type(properties.get("erpsec.inputCount")) is int
    assert properties.get("erpsec.result") in {"findings", "no_findings"}

    results = run.get("results")
    assert isinstance(results, list)
    assert properties["erpsec.result"] == ("findings" if results else "no_findings")
    for result in results:
        assert isinstance(result, dict)
        rule_id = result.get("ruleId")
        rule_index = result.get("ruleIndex")
        assert type(rule_index) is int and 0 <= rule_index < len(rules)
        assert rule_ids[rule_index] == rule_id
        assert result.get("level") == SARIF_LEVELS[RULE_SEVERITIES[rule_id]]
        assert _message_text(result.get("message"))

        fingerprints = result.get("fingerprints")
        assert isinstance(fingerprints, dict)
        fingerprint = fingerprints.get(FINGERPRINT_PROPERTY)
        assert isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", fingerprint)
        result_properties = result.get("properties")
        assert isinstance(result_properties, dict)
        assert result_properties.get(SEVERITY_PROPERTY) == RULE_SEVERITIES[rule_id]

        locations = result.get("locations")
        assert isinstance(locations, list) and locations
        for location in locations:
            _assert_sarif_location(location)


def _message_text(value: object) -> str:
    assert isinstance(value, dict)
    text = value.get("text")
    assert isinstance(text, str) and text.strip()
    return text


def _assert_sarif_location(location: object) -> None:
    assert isinstance(location, dict)
    properties = location.get("properties")
    assert isinstance(properties, dict)
    required_properties = {
        "erpsec.recordId",
        "erpsec.sourceFormat",
        "erpsec.locatorKind",
        "erpsec.locatorValue",
        "erpsec.field",
    }
    assert required_properties <= set(properties)
    assert all(isinstance(properties[key], str) for key in required_properties)

    physical = location.get("physicalLocation")
    assert isinstance(physical, dict)
    artifact = physical.get("artifactLocation")
    assert isinstance(artifact, dict)
    uri = artifact.get("uri")
    assert isinstance(uri, str) and uri
    parsed = urlsplit(uri)
    assert parsed.scheme == parsed.netloc == ""
    assert not unquote(parsed.path).startswith("/")
    assert "/" not in unquote(parsed.path)

    locator_kind = properties["erpsec.locatorKind"]
    locator_value = properties["erpsec.locatorValue"]
    source_format = properties["erpsec.sourceFormat"]
    if locator_kind == "json_pointer":
        assert source_format == "json"
        assert locator_value.startswith("/")
        assert "region" not in physical
    else:
        assert locator_kind in {"row", "line"}
        assert source_format == ("csv" if locator_kind == "row" else "jsonl")
        region = physical.get("region")
        assert isinstance(region, dict)
        assert region.get("startLine") == int(locator_value)


def sarif_finding_projection(document: dict[str, Any]) -> dict[str, FindingProjection]:
    results = document["runs"][0]["results"]
    projection: dict[str, FindingProjection] = {}
    for result in results:
        fingerprint = str(result["fingerprints"][FINGERPRINT_PROPERTY])
        assert fingerprint not in projection
        locations = frozenset(_sarif_location_projection(item) for item in result["locations"])
        projection[fingerprint] = FindingProjection(
            rule_id=str(result["ruleId"]),
            severity=str(result["properties"][SEVERITY_PROPERTY]),
            locations=locations,
        )
    return projection


def _sarif_location_projection(location: dict[str, Any]) -> EvidenceLocation:
    properties = location["properties"]
    uri = location["physicalLocation"]["artifactLocation"]["uri"]
    return EvidenceLocation(
        record_id=str(properties["erpsec.recordId"]),
        path=unquote(str(uri)),
        source_format=str(properties["erpsec.sourceFormat"]),
        locator_kind=str(properties["erpsec.locatorKind"]),
        locator_value=str(properties["erpsec.locatorValue"]),
        field=str(properties["erpsec.field"]),
    )
