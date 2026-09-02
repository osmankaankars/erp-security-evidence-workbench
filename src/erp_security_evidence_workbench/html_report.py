"""Deterministic, self-contained HTML rendering for validated reports."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Sequence
from html import escape
from typing import Any

from erp_security_evidence_workbench.rules import RuleDefinition

_STYLE = (
    "body{margin:0;background:#f4f7f9;color:#17212b;"
    "font:15px/1.5 system-ui,sans-serif}"
    "main{max-width:1080px;margin:auto;padding:32px}"
    "h1,h2,h3{line-height:1.2}"
    "section{background:#fff;border:1px solid #d8e0e6;border-radius:10px;"
    "margin:16px 0;padding:20px}"
    ".scope{border-left:5px solid #176b87}"
    ".summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}"
    ".metric{background:#edf4f7;border-radius:8px;padding:12px}"
    ".finding{border-left:5px solid #a03c2f}"
    ".severity-high{color:#8e2d22}.severity-medium{color:#765500}"
    "table{border-collapse:collapse;width:100%}"
    "th,td{border-bottom:1px solid #d8e0e6;padding:9px;"
    "text-align:left;vertical-align:top}"
    "code{overflow-wrap:anywhere}dt{font-weight:700}dd{margin:0 0 10px}"
    ".muted{color:#52616b}.state{font-weight:700}"
)
_STYLE_HASH = base64.b64encode(hashlib.sha256(_STYLE.encode("utf-8")).digest()).decode("ascii")
_CSP = f"default-src 'none'; style-src 'sha256-{_STYLE_HASH}'; base-uri 'none'; form-action 'none'"
_BIDI_CONTROLS = frozenset(
    {
        0x061C,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
    }
)


def render_html_report(
    report: dict[str, Any],
    definitions: Sequence[RuleDefinition],
) -> bytes:
    """Render one already validated report as static, escaped HTML."""
    run = _mapping(report["run"])
    tool = _mapping(report["tool"])
    evaluations = _mapping_sequence(report["evaluations"])
    findings = _mapping_sequence(report["findings"])
    result = _string(run["result"])
    severity_counts = _severity_counts(findings)

    parts = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{_attribute(_CSP)}">',
        '<meta name="referrer" content="no-referrer">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>ERP Security Evidence Report</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        f'<body data-run-result="{_attribute(result)}">',
        "<main>",
        "<h1>ERP Security Evidence Report</h1>",
        '<section id="scope" class="scope">',
        "<h2>Scope</h2>",
        (
            "<p>This offline reference project analyzes supplied synthetic evidence only. "
            "It does not inspect a live system, establish compliance, or replace human review.</p>"
        ),
        "</section>",
        '<section id="summary">',
        "<h2>Summary</h2>",
        '<div class="summary">',
        f'<div class="metric"><strong>Result</strong><br>{_text(result)}</div>',
        f'<div class="metric"><strong>Findings</strong><br>{len(findings)}</div>',
        f'<div class="metric"><strong>Selected rules</strong><br>{len(evaluations)}</div>',
        (
            '<div class="metric"><strong>Coverage</strong><br>'
            f"{_text(_string(run['coverage']))}</div>"
        ),
        "</div>",
        _summary_state(result),
        (
            "<p>Severity summary: "
            f"high={severity_counts.get('high', 0)}, "
            f"medium={severity_counts.get('medium', 0)}.</p>"
        ),
        "</section>",
        '<section id="rule-evaluations">',
        "<h2>Rule evaluations</h2>",
        "<table><thead><tr><th>Rule</th><th>Version</th><th>Status</th></tr></thead><tbody>",
    ]
    for evaluation in evaluations:
        rule_id = _string(evaluation["rule_id"])
        status = _string(evaluation["status"])
        parts.extend(
            [
                (
                    '<tr data-erpsec-role="evaluation" '
                    f'data-rule-id="{_attribute(rule_id)}" '
                    f'data-status="{_attribute(status)}">'
                ),
                f"<td><code>{_text(rule_id)}</code></td>",
                f"<td>{_text(_string(evaluation['rule_version']))}</td>",
                f"<td>{_text(status)}</td></tr>",
            ]
        )
    parts.extend(
        [
            "</tbody></table>",
            "</section>",
            '<section id="skipped-evaluations">',
            "<h2>Skipped evaluations</h2>",
            (
                "<p>None. This version fails the complete run when selected-rule evidence is "
                "insufficient and does not publish a report.</p>"
            ),
            "</section>",
            '<section id="findings">',
            "<h2>Findings</h2>",
        ]
    )
    if not findings:
        parts.append('<p class="muted">No finding records were emitted.</p>')
    for finding in findings:
        fingerprint = _string(finding["fingerprint"])
        rule_id = _string(finding["rule_id"])
        rule_version = _string(finding["rule_version"])
        severity = _string(finding["severity"])
        parts.extend(
            [
                (
                    f'<article id="finding-{_attribute(fingerprint)}" class="finding" '
                    'data-erpsec-role="finding" '
                    f'data-fingerprint="{_attribute(fingerprint)}" '
                    f'data-rule-id="{_attribute(rule_id)}" '
                    f'data-rule-version="{_attribute(rule_version)}" '
                    f'data-severity="{_attribute(severity)}">'
                ),
                f"<h3>{_text(_string(finding['title']))}</h3>",
                (
                    f'<p class="severity-{_attribute(severity)}"><strong>'
                    f"{_text(rule_id)} · {_text(severity)}</strong></p>"
                ),
                f"<p>{_text(_string(finding['description']))}</p>",
                f"<p><strong>Finding ID:</strong> <code>{_text(fingerprint)}</code></p>",
                f"<p><strong>Limitation:</strong> {_text(_string(finding['limitation']))}</p>",
                f"<p><strong>Remediation:</strong> {_text(_string(finding['remediation']))}</p>",
                "</article>",
            ]
        )
    parts.extend(
        [
            "</section>",
            '<section id="evidence">',
            "<h2>Finding-linked evidence</h2>",
        ]
    )
    if findings:
        parts.append(
            "<table><thead><tr><th>Rule</th><th>Record</th><th>Source</th>"
            "<th>Format</th><th>Locator</th><th>Field</th></tr></thead><tbody>"
        )
        for finding in findings:
            parts.extend(_evidence_rows(finding))
        parts.append("</tbody></table>")
    else:
        parts.append('<p class="muted">No finding-linked evidence.</p>')
    parts.extend(
        [
            "</section>",
            '<section id="rule-details">',
            "<h2>Rule details</h2>",
        ]
    )
    for definition in definitions:
        parts.extend(
            [
                f'<article id="rule-{_attribute(definition.rule_id.casefold())}">',
                f"<h3>{_text(definition.rule_id)} · {_text(definition.title)}</h3>",
                f"<p>{_text(definition.severity_rationale)}</p>",
                (
                    "<p><strong>Required evidence:</strong> "
                    f"{_text(', '.join(definition.required_evidence_types))}</p>"
                ),
                f"<p><strong>Limitation:</strong> {_text(definition.limitation)}</p>",
                f"<p><strong>Remediation:</strong> {_text(definition.remediation)}</p>",
                "</article>",
            ]
        )
    parts.extend(
        [
            "</section>",
            '<section id="limitations">',
            "<h2>Limitations</h2>",
            (
                "<p>Coverage is complete only for the supplied files and selected rules. A clean "
                "result does not prove absence of risk or source-system completeness.</p>"
            ),
            "</section>",
            '<section id="run-metadata">',
            "<h2>Run metadata</h2>",
            "<dl>",
            f"<dt>Analysis time</dt><dd>{_text(_string(run['as_of']))}</dd>",
            f"<dt>Input records</dt><dd>{_text(str(run['input_count']))}</dd>",
            f"<dt>Report schema</dt><dd>{_text(_string(report['schema_version']))}</dd>",
            (
                f"<dt>Tool</dt><dd>{_text(_string(tool['name']))} "
                f"{_text(_string(tool['version']))}</dd>"
            ),
            "</dl>",
            "</section>",
            "</main>",
            "</body>",
            "</html>",
        ]
    )
    return ("\n".join(parts) + "\n").encode("utf-8")


def _summary_state(result: str) -> str:
    if result == "findings":
        return '<p class="state">Findings in supplied evidence.</p>'
    return (
        '<p class="state">No findings in supplied evidence.</p>'
        "<p>This does not prove absence of risk or source-system completeness.</p>"
    )


def _severity_counts(findings: Sequence[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = _string(finding["severity"])
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _evidence_rows(finding: dict[str, Any]) -> list[str]:
    fingerprint = _string(finding["fingerprint"])
    rule_id = _string(finding["rule_id"])
    rows: list[str] = []
    for evidence in _mapping_sequence(finding["evidence_refs"]):
        source = _mapping(evidence["source_ref"])
        locator_kind, locator_value, field = _locator(source)
        record_id = _string(evidence["record_id"])
        path = _string(source["path"])
        source_format = _string(source["format"])
        rows.extend(
            [
                (
                    '<tr data-erpsec-role="evidence" '
                    f'data-fingerprint="{_attribute(fingerprint)}" '
                    f'data-record-id="{_attribute(record_id)}" '
                    f'data-source-path="{_attribute(path)}" '
                    f'data-source-format="{_attribute(source_format)}" '
                    f'data-locator-kind="{_attribute(locator_kind)}" '
                    f'data-locator-value="{_attribute(locator_value)}" '
                    f'data-field="{_attribute(field)}">'
                ),
                f"<td><code>{_text(rule_id)}</code></td>",
                f"<td><code>{_text(record_id)}</code></td>",
                f"<td>{_text(path)}</td>",
                f"<td>{_text(source_format)}</td>",
                f"<td>{_text(locator_kind)} {_text(locator_value)}</td>",
                f"<td>{_text(field)}</td></tr>",
            ]
        )
    return rows


def _locator(source: dict[str, Any]) -> tuple[str, str, str]:
    if "json_pointer" in source:
        pointer = _string(source["json_pointer"])
        token = pointer.rsplit("/", 1)[-1]
        field = token.replace("~1", "/").replace("~0", "~")
        return "json_pointer", pointer, field
    if "row" in source:
        return "row", str(source["row"]), _string(source["field"])
    return "line", str(source["line"]), _string(source["field"])


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


def _display(value: str) -> str:
    rendered: list[str] = []
    for character in value:
        codepoint = ord(character)
        if codepoint < 0x20 or 0x7F <= codepoint <= 0x9F or codepoint in _BIDI_CONTROLS:
            rendered.append(f"\\u{codepoint:04X}")
        else:
            rendered.append(character)
    return "".join(rendered)


def _text(value: str) -> str:
    return escape(_display(value), quote=True)


def _attribute(value: str) -> str:
    return escape(_display(value), quote=True)
