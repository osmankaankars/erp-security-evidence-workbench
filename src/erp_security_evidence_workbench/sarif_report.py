"""Deterministic SARIF 2.1.0 rendering for validated reports."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any
from urllib.parse import quote

from erp_security_evidence_workbench.errors import OutputError
from erp_security_evidence_workbench.rules import RuleDefinition

SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
)
_LEVELS = {"high": "error", "medium": "warning"}


def render_sarif_report(
    report: dict[str, Any],
    definitions: Sequence[RuleDefinition],
) -> bytes:
    """Render one already validated report as SARIF 2.1.0."""
    run = _mapping(report["run"])
    tool = _mapping(report["tool"])
    findings = _mapping_sequence(report["findings"])
    evaluations = _mapping_sequence(report["evaluations"])
    artifacts, artifact_indexes = _artifacts(report, findings)
    rules = [_rule_descriptor(definition) for definition in definitions]
    rule_indexes = {definition.rule_id: index for index, definition in enumerate(definitions)}
    results = [
        _result(finding, rule_indexes=rule_indexes, artifact_indexes=artifact_indexes)
        for finding in findings
    ]
    run_properties: dict[str, Any] = {
        "erpsec.asOf": run["as_of"],
        "erpsec.coverage": run["coverage"],
        "erpsec.evaluations": evaluations,
        "erpsec.inputCount": run["input_count"],
        "erpsec.reportSchemaVersion": report["schema_version"],
        "erpsec.result": run["result"],
        "erpsec.syntheticEvidenceOnly": True,
    }
    if "correlations" in report:
        run_properties["erpsec.correlations"] = report["correlations"]
        run_properties["erpsec.replay"] = report["replay"]

    document: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "runs": [
            {
                "artifacts": artifacts,
                "invocations": [{"executionSuccessful": True}],
                "properties": run_properties,
                "results": results,
                "tool": {
                    "driver": {
                        "name": tool["name"],
                        "rules": rules,
                        "version": tool["version"],
                    }
                },
            }
        ],
        "version": "2.1.0",
    }
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _rule_descriptor(definition: RuleDefinition) -> dict[str, Any]:
    level = _level(definition.severity)
    return {
        "defaultConfiguration": {"level": level},
        "fullDescription": {"text": definition.severity_rationale},
        "help": {"text": f"{definition.limitation} Remediation: {definition.remediation}"},
        "id": definition.rule_id,
        "properties": {
            "erpsec.fixedConditions": [
                condition.to_dict() for condition in definition.fixed_conditions
            ],
            "erpsec.parameters": [parameter.to_dict() for parameter in definition.parameters],
            "erpsec.requiredEvidenceTypes": list(definition.required_evidence_types),
            "erpsec.ruleVersion": definition.rule_version,
            "erpsec.severity": definition.severity,
        },
        "shortDescription": {"text": definition.title},
    }


def _result(
    finding: dict[str, Any],
    *,
    rule_indexes: dict[str, int],
    artifact_indexes: dict[tuple[str, str], int],
) -> dict[str, Any]:
    rule_id = _string(finding["rule_id"])
    severity = _string(finding["severity"])
    fingerprint = _string(finding["fingerprint"])
    if rule_id not in rule_indexes:
        raise OutputError("report rule reference is inconsistent")
    properties: dict[str, Any] = {
        "erpsec.findingId": fingerprint,
        "erpsec.limitation": finding["limitation"],
        "erpsec.remediation": finding["remediation"],
        "erpsec.requiredEvidenceTypes": finding["required_evidence_types"],
        "erpsec.ruleVersion": finding["rule_version"],
        "erpsec.severity": severity,
    }
    if "correlation_id" in finding:
        properties["erpsec.correlationId"] = finding["correlation_id"]
    return {
        "fingerprints": {"erpsec/v1": fingerprint},
        "level": _level(severity),
        "locations": [
            _location(evidence, artifact_indexes=artifact_indexes)
            for evidence in _mapping_sequence(finding["evidence_refs"])
        ],
        "message": {"text": _string(finding["description"])},
        "properties": properties,
        "ruleId": rule_id,
        "ruleIndex": rule_indexes[rule_id],
    }


def _artifacts(
    report: dict[str, Any],
    findings: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], int]]:
    sources = _mapping_sequence(report["source_manifest"])
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for source in sources:
        key = (_string(source["path"]), _string(source["sha256"]))
        if key not in by_key:
            by_key[key] = source
            order.append(key)
    missing: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        for evidence in _mapping_sequence(finding["evidence_refs"]):
            source = _mapping(evidence["source_ref"])
            key = (_string(source["path"]), _string(source["sha256"]))
            if key not in by_key:
                missing.setdefault(key, source)
    order.extend(sorted(missing))
    by_key.update(missing)

    artifacts: list[dict[str, Any]] = []
    indexes: dict[tuple[str, str], int] = {}
    for index, key in enumerate(order):
        source = by_key[key]
        path, sha256 = key
        artifact: dict[str, Any] = {
            "hashes": {"sha-256": sha256},
            "location": {"index": index, "uri": _uri(path)},
            "properties": {
                "erpsec.adapter": source.get("adapter", ""),
                "erpsec.format": source.get("format", ""),
            },
            "roles": ["analysisTarget"],
        }
        if "byte_count" in source:
            artifact["length"] = source["byte_count"]
        if "record_count" in source:
            artifact["properties"]["erpsec.recordCount"] = source["record_count"]
        artifacts.append(artifact)
        indexes[key] = index
    return artifacts, indexes


def _location(
    evidence: dict[str, Any],
    *,
    artifact_indexes: dict[tuple[str, str], int],
) -> dict[str, Any]:
    source = _mapping(evidence["source_ref"])
    path = _string(source["path"])
    sha256 = _string(source["sha256"])
    key = (path, sha256)
    if key not in artifact_indexes:
        raise OutputError("report artifact reference is inconsistent")
    locator_kind, locator_value, field = _locator(source)
    physical: dict[str, Any] = {
        "artifactLocation": {
            "index": artifact_indexes[key],
            "uri": _uri(path),
        }
    }
    if locator_kind in {"row", "line"}:
        physical["region"] = {"startLine": int(locator_value)}
    return {
        "message": {"text": f"Evidence record {_string(evidence['record_id'])}"},
        "physicalLocation": physical,
        "properties": {
            "erpsec.adapter": source["adapter"],
            "erpsec.field": field,
            "erpsec.locatorKind": locator_kind,
            "erpsec.locatorValue": locator_value,
            "erpsec.recordId": evidence["record_id"],
            "erpsec.sourceFormat": source["format"],
            "erpsec.sourceSha256": sha256,
        },
    }


def _locator(source: dict[str, Any]) -> tuple[str, str, str]:
    if "json_pointer" in source:
        pointer = _string(source["json_pointer"])
        token = pointer.rsplit("/", 1)[-1]
        return "json_pointer", pointer, token.replace("~1", "/").replace("~0", "~")
    if "row" in source:
        return "row", str(source["row"]), _string(source["field"])
    return "line", str(source["line"]), _string(source["field"])


def _uri(path: str) -> str:
    return quote(path, safe="-._~")


def _level(severity: str) -> str:
    try:
        return _LEVELS[severity]
    except KeyError as exc:
        raise OutputError("report contains an unsupported severity") from exc


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError("report mapping is invalid")
    return value


def _mapping_sequence(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise TypeError("report sequence is invalid")
    return value


def _string(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("report string is invalid")
    return value
