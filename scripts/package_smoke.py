"""Build and exercise the installed wheel without package-index access."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DISTRIBUTION_NAME = "erp-security-evidence-workbench"
COMMAND_TIMEOUT_SECONDS = 60
AUDIT_GUARD = (
    "import sys\n"
    "def _deny_runtime_access(event, arguments):\n"
    "    del arguments\n"
    "    denied_events = {\n"
    "        'os.posix_spawn',\n"
    "        'os.posix_spawnp',\n"
    "        'os.system',\n"
    "        'subprocess.Popen',\n"
    "    }\n"
    "    if event.startswith('socket.') or event in denied_events:\n"
    "        raise RuntimeError('runtime network or process access denied')\n"
    "sys.addaudithook(_deny_runtime_access)\n"
)
CLI_MAIN_RUNNER = AUDIT_GUARD + (
    "from erp_security_evidence_workbench.cli import main\nraise SystemExit(main(sys.argv[1:]))\n"
)
CONSOLE_SCRIPT_RUNNER = AUDIT_GUARD + (
    "import runpy\n"
    "script_path = sys.argv[1]\n"
    "sys.argv = [script_path, *sys.argv[2:]]\n"
    "runpy.run_path(script_path, run_name='__main__')\n"
)
MODULE_RUNNER = AUDIT_GUARD + (
    "import runpy\n"
    "sys.argv = ['erp_security_evidence_workbench', *sys.argv[1:]]\n"
    "runpy.run_module('erp_security_evidence_workbench', run_name='__main__')\n"
)
COPY_IGNORE = shutil.ignore_patterns(
    ".DS_Store",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "*.egg-info",
    "__pycache__",
    "build",
    "dist",
)

EvidenceLocation = tuple[str, str, str, str, str, str]
FindingProjection = tuple[str, str, str, frozenset[EvidenceLocation]]


@dataclass(frozen=True, slots=True)
class _ReportProjection:
    """Format-neutral installed-report semantics anchored to canonical JSON."""

    result: str
    as_of: str
    coverage: str
    input_count: int
    evaluations: tuple[tuple[str, str, str], ...]
    findings: dict[str, FindingProjection]


class _InstalledHTMLParser(HTMLParser):
    """Collect the stable HTML semantic hooks and self-containment surface."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.declarations: list[str] = []
        self.start_tags: list[tuple[str, dict[str, str | None]]] = []
        self.text_chunks: list[str] = []
        self.style_chunks: list[str] = []
        self.run_result: str | None = None
        self.findings: dict[str, tuple[str, str, str]] = {}
        self.evidence: dict[str, set[EvidenceLocation]] = {}
        self.evaluations: list[tuple[str, str]] = []
        self._evaluation_ids: set[str] = set()
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
            fingerprint = _required_html_attribute(attributes, "data-fingerprint")
            if fingerprint in self.findings:
                raise RuntimeError("installed HTML report repeated a finding")
            self.findings[fingerprint] = (
                _required_html_attribute(attributes, "data-rule-id"),
                _required_html_attribute(attributes, "data-rule-version"),
                _required_html_attribute(attributes, "data-severity"),
            )
        elif role == "evidence":
            fingerprint = _required_html_attribute(attributes, "data-fingerprint")
            self.evidence.setdefault(fingerprint, set()).add(
                (
                    _required_html_attribute(attributes, "data-record-id"),
                    _required_html_attribute(attributes, "data-source-path"),
                    _required_html_attribute(attributes, "data-source-format"),
                    _required_html_attribute(attributes, "data-locator-kind"),
                    _required_html_attribute(attributes, "data-locator-value"),
                    _required_html_attribute(attributes, "data-field"),
                )
            )
        elif role == "evaluation":
            rule_id = _required_html_attribute(attributes, "data-rule-id")
            if rule_id in self._evaluation_ids:
                raise RuntimeError("installed HTML report repeated a rule evaluation")
            self._evaluation_ids.add(rule_id)
            self.evaluations.append((rule_id, _required_html_attribute(attributes, "data-status")))

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
        if not set(self.evidence) <= set(self.findings):
            raise RuntimeError("installed HTML report emitted orphan finding evidence")
        return {
            fingerprint: (
                rule_id,
                rule_version,
                severity,
                frozenset(self.evidence.get(fingerprint, set())),
            )
            for fingerprint, (rule_id, rule_version, severity) in self.findings.items()
        }


def _clean_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for key in tuple(environment):
        if key.upper().startswith("PYTHON"):
            environment.pop(key)
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    expected_exit: int = 0,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            check=False,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"command exceeded the {COMMAND_TIMEOUT_SECONDS}-second verification limit"
        ) from exc
    if completed.returncode != expected_exit:
        rendered_command = " ".join(command)
        raise RuntimeError(
            f"command exited {completed.returncode}, expected {expected_exit}: "
            f"{rendered_command}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def _run_installed_cli(
    installed_python: Path,
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    expected_exit: int = 0,
) -> subprocess.CompletedProcess[str]:
    return _run(
        [str(installed_python), "-I", "-c", CLI_MAIN_RUNNER, *arguments],
        cwd=cwd,
        environment=environment,
        expected_exit=expected_exit,
    )


def _venv_python(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _console_script(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "erpsec.exe"
    return venv / "bin" / "erpsec"


def _required_html_attribute(attributes: dict[str, str | None], name: str) -> str:
    value = attributes.get(name)
    if value is None or not value:
        raise RuntimeError(f"installed HTML report omitted {name}")
    return value


def _parse_evaluations(value: object) -> tuple[tuple[str, str, str], ...]:
    if not isinstance(value, list):
        raise RuntimeError("installed report omitted rule evaluations")
    result: list[tuple[str, str, str]] = []
    for evaluation in value:
        if not isinstance(evaluation, dict):
            raise RuntimeError("installed report emitted an invalid rule evaluation")
        rule_id = evaluation.get("rule_id")
        rule_version = evaluation.get("rule_version")
        status = evaluation.get("status")
        if not all(isinstance(item, str) and item for item in (rule_id, rule_version, status)):
            raise RuntimeError("installed report emitted an incomplete rule evaluation")
        result.append((rule_id, rule_version, status))
    if len({rule_id for rule_id, _, _ in result}) != len(result):
        raise RuntimeError("installed report repeated a rule evaluation")
    return tuple(result)


def _pointer_field(pointer: str) -> str:
    token = pointer.rsplit("/", 1)[-1]
    return token.replace("~1", "/").replace("~0", "~")


def _json_evidence_location(evidence: object) -> EvidenceLocation:
    if not isinstance(evidence, dict) or not isinstance(evidence.get("source_ref"), dict):
        raise RuntimeError("installed JSON report emitted invalid finding evidence")
    source = evidence["source_ref"]
    record_id = evidence.get("record_id")
    path = source.get("path")
    source_format = source.get("format")
    if not all(isinstance(item, str) and item for item in (record_id, path, source_format)):
        raise RuntimeError("installed JSON report emitted incomplete finding evidence")

    locator_kind: str
    locator_value: str
    field: object
    if "json_pointer" in source:
        locator_kind = "json_pointer"
        locator_value = str(source["json_pointer"])
        field = _pointer_field(locator_value)
    elif "row" in source:
        locator_kind = "row"
        locator_value = str(source["row"])
        field = source.get("field")
    elif "line" in source:
        locator_kind = "line"
        locator_value = str(source["line"])
        field = source.get("field")
    else:
        raise RuntimeError("installed JSON report omitted an evidence locator")
    if not isinstance(field, str) or not field:
        raise RuntimeError("installed JSON report omitted an evidence field")
    return record_id, path, source_format, locator_kind, locator_value, field


def _json_report_projection(report_path: Path) -> _ReportProjection:
    document = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema_version") != "erpsec.report/v1":
        raise RuntimeError("installed CLI emitted an unexpected JSON report schema")
    run = document.get("run")
    if not isinstance(run, dict):
        raise RuntimeError("installed JSON report omitted run metadata")
    result = run.get("result")
    as_of = run.get("as_of")
    coverage = run.get("coverage")
    input_count = run.get("input_count")
    if (
        result not in {"findings", "no_findings"}
        or not isinstance(as_of, str)
        or not isinstance(coverage, str)
        or type(input_count) is not int
    ):
        raise RuntimeError("installed JSON report emitted invalid run metadata")

    findings_value = document.get("findings")
    if not isinstance(findings_value, list):
        raise RuntimeError("installed JSON report omitted findings")
    findings: dict[str, FindingProjection] = {}
    for finding in findings_value:
        if not isinstance(finding, dict) or not isinstance(finding.get("evidence_refs"), list):
            raise RuntimeError("installed JSON report emitted an invalid finding")
        fingerprint = finding.get("fingerprint")
        rule_id = finding.get("rule_id")
        rule_version = finding.get("rule_version")
        severity = finding.get("severity")
        if not all(
            isinstance(item, str) and item
            for item in (fingerprint, rule_id, rule_version, severity)
        ):
            raise RuntimeError("installed JSON report emitted an incomplete finding")
        if fingerprint in findings:
            raise RuntimeError("installed JSON report repeated a finding")
        evidence = frozenset(_json_evidence_location(item) for item in finding["evidence_refs"])
        if not evidence:
            raise RuntimeError("installed JSON report emitted an unsupported evidence-free finding")
        findings[fingerprint] = (rule_id, rule_version, severity, evidence)

    if result != ("findings" if findings else "no_findings"):
        raise RuntimeError("installed JSON report result disagrees with its findings")
    return _ReportProjection(
        result=result,
        as_of=as_of,
        coverage=coverage,
        input_count=input_count,
        evaluations=_parse_evaluations(document.get("evaluations")),
        findings=findings,
    )


def _assert_html_is_self_contained(parser: _InstalledHTMLParser) -> None:
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
    if [item.casefold() for item in parser.declarations] != ["doctype html"]:
        raise RuntimeError("installed HTML report omitted the HTML5 doctype")
    observed_tags = {tag for tag, _ in parser.start_tags}
    if not {"html", "head", "body", "style"} <= observed_tags:
        raise RuntimeError("installed HTML report omitted required document structure")
    if observed_tags & forbidden_tags:
        raise RuntimeError("installed HTML report contains an external-resource-capable element")

    content_security_policies: list[str] = []
    for tag, attributes in parser.start_tags:
        if any(name.casefold().startswith("on") for name in attributes):
            raise RuntimeError("installed HTML report contains an event-handler attribute")
        if tag == "meta":
            http_equiv = (attributes.get("http-equiv") or "").casefold()
            if http_equiv == "refresh":
                raise RuntimeError("installed HTML report contains a refresh directive")
            if http_equiv == "content-security-policy":
                policy = attributes.get("content")
                if isinstance(policy, str):
                    content_security_policies.append(policy)
        for name, value in attributes.items():
            if name.casefold() not in url_attributes:
                continue
            if name.casefold() != "href" or value is None or not value.startswith("#"):
                raise RuntimeError("installed HTML report contains a non-local URL")
        inline_style = attributes.get("style") or ""
        if _contains_external_css(inline_style):
            raise RuntimeError("installed HTML report contains external inline CSS")

    if (
        len(content_security_policies) != 1
        or "default-src 'none'" not in (content_security_policies[0])
    ):
        raise RuntimeError("installed HTML report omitted its restrictive content policy")
    if _contains_external_css("".join(parser.style_chunks)):
        raise RuntimeError("installed HTML report contains external stylesheet references")


def _contains_external_css(value: str) -> bool:
    lowered = value.casefold()
    return any(token in lowered for token in ("@import", "@font-face", "url("))


def _assert_html_report(report_path: Path, expected: _ReportProjection) -> None:
    parser = _InstalledHTMLParser()
    parser.feed(report_path.read_text(encoding="utf-8"))
    parser.close()
    _assert_html_is_self_contained(parser)

    if parser.run_result != expected.result:
        raise RuntimeError("installed HTML report emitted an unexpected run result")
    expected_evaluations = tuple((rule_id, status) for rule_id, _, status in expected.evaluations)
    if tuple(parser.evaluations) != expected_evaluations:
        raise RuntimeError("installed HTML report evaluations differ from JSON")
    if parser.finding_projection() != expected.findings:
        raise RuntimeError("installed HTML report findings differ from JSON")

    visible_text = parser.visible_text.casefold()
    if "synthetic" not in visible_text or "reference project" not in visible_text:
        raise RuntimeError("installed HTML report omitted its scope boundary")
    if expected.as_of not in parser.visible_text or "complete" not in visible_text:
        raise RuntimeError("installed HTML report omitted deterministic run metadata")
    if expected.result == "no_findings" and "no findings" not in visible_text:
        raise RuntimeError("installed HTML report omitted its clean-state language")


def _sarif_location(location: object) -> EvidenceLocation:
    if not isinstance(location, dict):
        raise RuntimeError("installed SARIF report emitted an invalid location")
    properties = location.get("properties")
    physical = location.get("physicalLocation")
    if not isinstance(properties, dict) or not isinstance(physical, dict):
        raise RuntimeError("installed SARIF report emitted an incomplete location")
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("uri"), str):
        raise RuntimeError("installed SARIF report omitted an artifact URI")
    uri = artifact["uri"]
    parsed_uri = urlsplit(uri)
    decoded_path = unquote(parsed_uri.path)
    if (
        parsed_uri.scheme
        or parsed_uri.netloc
        or parsed_uri.query
        or parsed_uri.fragment
        or decoded_path.startswith("/")
        or "/" in decoded_path
    ):
        raise RuntimeError("installed SARIF report emitted a non-relative source URI")

    property_names = (
        "erpsec.recordId",
        "erpsec.sourceFormat",
        "erpsec.locatorKind",
        "erpsec.locatorValue",
        "erpsec.field",
    )
    property_values = tuple(properties.get(name) for name in property_names)
    if not all(isinstance(value, str) and value for value in property_values):
        raise RuntimeError("installed SARIF report omitted evidence-location properties")
    record_id, source_format, locator_kind, locator_value, field = property_values
    if locator_kind == "json_pointer":
        if source_format != "json" or not locator_value.startswith("/") or "region" in physical:
            raise RuntimeError("installed SARIF report emitted an invalid JSON location")
    else:
        expected_format = "csv" if locator_kind == "row" else "jsonl"
        region = physical.get("region")
        if (
            locator_kind not in {"row", "line"}
            or source_format != expected_format
            or not isinstance(region, dict)
            or region.get("startLine") != int(locator_value)
        ):
            raise RuntimeError("installed SARIF report emitted an invalid line location")
    return record_id, decoded_path, source_format, locator_kind, locator_value, field


def _assert_sarif_report(report_path: Path, expected: _ReportProjection) -> None:
    document = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise RuntimeError("installed SARIF report is not a JSON object")
    schema = document.get("$schema")
    runs = document.get("runs")
    if (
        not isinstance(schema, str)
        or not schema.endswith("/sarif-schema-2.1.0.json")
        or document.get("version") != "2.1.0"
        or not isinstance(runs, list)
        or len(runs) != 1
        or not isinstance(runs[0], dict)
    ):
        raise RuntimeError("installed CLI emitted an unexpected SARIF envelope")
    run = runs[0]
    driver = run.get("tool", {}).get("driver")
    if not isinstance(driver, dict) or driver.get("name") != DISTRIBUTION_NAME:
        raise RuntimeError("installed SARIF report emitted unexpected tool metadata")
    rules = driver.get("rules")
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        raise RuntimeError("installed SARIF report omitted its rule definitions")
    rule_ids = [rule.get("id") for rule in rules]
    expected_rule_ids = [rule_id for rule_id, _, _ in expected.evaluations]
    if rule_ids != expected_rule_ids or len(set(rule_ids)) != len(rule_ids):
        raise RuntimeError("installed SARIF report rule definitions differ from JSON")

    severity_levels = {"high": "error", "medium": "warning"}
    severity_by_rule = {
        rule_id: severity for _, (rule_id, _, severity, _) in expected.findings.items()
    }
    for rule in rules:
        rule_id = rule["id"]
        configuration = rule.get("defaultConfiguration")
        rule_properties = rule.get("properties")
        if not isinstance(rule_properties, dict):
            raise RuntimeError("installed SARIF report omitted rule properties")
        rule_severity = rule_properties.get("erpsec.severity")
        if (
            rule_severity not in severity_levels
            or not isinstance(configuration, dict)
            or configuration.get("level") != severity_levels[rule_severity]
        ):
            raise RuntimeError("installed SARIF report emitted invalid rule severity")
        expected_severity = severity_by_rule.get(rule_id)
        if expected_severity is not None and expected_severity != rule_severity:
            raise RuntimeError("installed SARIF rule severity differs from JSON")

    properties = run.get("properties")
    if not isinstance(properties, dict):
        raise RuntimeError("installed SARIF report omitted run properties")
    if (
        properties.get("erpsec.reportSchemaVersion") != "erpsec.report/v1"
        or properties.get("erpsec.asOf") != expected.as_of
        or properties.get("erpsec.coverage") != expected.coverage
        or properties.get("erpsec.inputCount") != expected.input_count
        or properties.get("erpsec.result") != expected.result
        or _parse_evaluations(properties.get("erpsec.evaluations")) != expected.evaluations
    ):
        raise RuntimeError("installed SARIF report run metadata differs from JSON")

    results = run.get("results")
    if not isinstance(results, list):
        raise RuntimeError("installed SARIF report omitted results")
    findings: dict[str, FindingProjection] = {}
    for result in results:
        if not isinstance(result, dict):
            raise RuntimeError("installed SARIF report emitted an invalid result")
        rule_id = result.get("ruleId")
        rule_index = result.get("ruleIndex")
        message = result.get("message")
        fingerprints = result.get("fingerprints")
        result_properties = result.get("properties")
        locations = result.get("locations")
        if (
            not isinstance(rule_id, str)
            or type(rule_index) is not int
            or not 0 <= rule_index < len(rule_ids)
            or rule_ids[rule_index] != rule_id
            or not isinstance(message, dict)
            or not isinstance(message.get("text"), str)
            or not message["text"].strip()
            or not isinstance(fingerprints, dict)
            or not isinstance(result_properties, dict)
            or not isinstance(locations, list)
            or not locations
        ):
            raise RuntimeError("installed SARIF report emitted an incomplete result")
        fingerprint = fingerprints.get("erpsec/v1")
        severity = result_properties.get("erpsec.severity")
        rule_version = result_properties.get("erpsec.ruleVersion")
        if (
            not isinstance(fingerprint, str)
            or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
            or not isinstance(rule_version, str)
            or not rule_version
            or severity not in severity_levels
            or result.get("level") != severity_levels[severity]
        ):
            raise RuntimeError(
                "installed SARIF report emitted invalid finding identity or severity"
            )
        if fingerprint in findings:
            raise RuntimeError("installed SARIF report repeated a finding")
        findings[fingerprint] = (
            rule_id,
            rule_version,
            severity,
            frozenset(_sarif_location(location) for location in locations),
        )
    if findings != expected.findings:
        raise RuntimeError("installed SARIF report findings differ from JSON")


def _assert_finding_report(report_path: Path) -> None:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    findings = report.get("findings")
    if report.get("schema_version") != "erpsec.report/v1":
        raise RuntimeError("installed CLI emitted an unexpected report schema")
    if not isinstance(findings, list) or len(findings) != 1:
        raise RuntimeError("installed CLI did not emit exactly one finding")
    if findings[0].get("rule_id") != "ERP001":
        raise RuntimeError("installed CLI emitted an unexpected rule identifier")


def _assert_clean_report(report_path: Path) -> None:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("schema_version") != "erpsec.report/v1":
        raise RuntimeError("installed CLI emitted an unexpected clean-report schema")
    if report.get("findings") != []:
        raise RuntimeError("installed CLI emitted a finding for clean evidence")
    run = report.get("run")
    if not isinstance(run, dict) or run.get("result") != "no_findings":
        raise RuntimeError("installed CLI emitted an unexpected clean result")


def _assert_source_adapter(report_path: Path, expected_adapter: str) -> None:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    source_manifest = report.get("source_manifest")
    if not isinstance(source_manifest, list) or len(source_manifest) != 1:
        raise RuntimeError("installed CLI emitted an unexpected source manifest")
    if source_manifest[0].get("adapter") != expected_adapter:
        raise RuntimeError("installed CLI emitted an unexpected source adapter")


def _assert_rule_catalog(output: str) -> None:
    catalog = json.loads(output)
    rules = catalog.get("rules")
    if catalog.get("schema_version") != "erpsec.rule-catalog/v1":
        raise RuntimeError("installed CLI emitted an unexpected rule catalog schema")
    if not isinstance(rules, list) or [rule.get("rule_id") for rule in rules] != [
        "ERP001",
        "ERP002",
        "ERP003",
        "ERP004",
        "ERP005",
        "ERP006",
        "ERP007",
        "ERP008",
        "ERP009",
    ]:
        raise RuntimeError("installed CLI emitted an unexpected rule catalog")


def _assert_full_rule_pack(report_path: Path) -> None:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    evaluations = report.get("evaluations")
    findings = report.get("findings")
    if not isinstance(evaluations, list) or [
        evaluation.get("rule_id") for evaluation in evaluations
    ] != ["ERP001", "ERP002", "ERP003", "ERP004", "ERP005", "ERP006"]:
        raise RuntimeError("installed CLI did not evaluate the complete rule pack")
    if not isinstance(findings, list) or {finding.get("rule_id") for finding in findings} != {
        "ERP001",
        "ERP002",
        "ERP003",
        "ERP004",
        "ERP005",
        "ERP006",
    }:
        raise RuntimeError("installed CLI emitted an unexpected full rule-pack finding set")


def _assert_scenario_report(
    report_path: Path,
    *,
    expected_evaluations: tuple[tuple[str, str], ...],
    expected_finding_ids: tuple[str, ...],
    expected_record_count: int,
) -> None:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("schema_version") != "erpsec.report/v1":
        raise RuntimeError("installed CLI emitted an unexpected scenario-report schema")

    evaluations = report.get("evaluations")
    if (
        not isinstance(evaluations, list)
        or tuple(
            (evaluation.get("rule_id"), evaluation.get("status")) for evaluation in evaluations
        )
        != expected_evaluations
    ):
        raise RuntimeError("installed CLI emitted unexpected scenario evaluations")

    findings = report.get("findings")
    if (
        not isinstance(findings, list)
        or tuple(finding.get("rule_id") for finding in findings) != expected_finding_ids
    ):
        raise RuntimeError("installed CLI emitted unexpected scenario findings")

    run = report.get("run")
    expected_result = "findings" if expected_finding_ids else "no_findings"
    if (
        not isinstance(run, dict)
        or run.get("result") != expected_result
        or run.get("input_count") != expected_record_count
    ):
        raise RuntimeError("installed CLI emitted unexpected scenario run metadata")


def _assert_replay_report(report_path: Path) -> None:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("schema_version") != "erpsec.report/v2":
        raise RuntimeError("installed replay emitted an unexpected report schema")
    replay = report.get("replay")
    if not isinstance(replay, dict) or replay.get("replay_id") != (
        "scenario-detection-correlation"
    ):
        raise RuntimeError("installed replay omitted its manifest identity")
    evaluations = report.get("evaluations")
    if not isinstance(evaluations, list) or [item.get("rule_id") for item in evaluations] != [
        "ERP007",
        "ERP008",
        "ERP009",
    ]:
        raise RuntimeError("installed replay emitted unexpected evaluations")
    correlations = report.get("correlations")
    findings = report.get("findings")
    if (
        not isinstance(correlations, list)
        or not isinstance(findings, list)
        or len(correlations) != 3
        or len(findings) != 3
        or {item.get("correlation_id") for item in correlations}
        != {item.get("correlation_id") for item in findings}
    ):
        raise RuntimeError("installed replay emitted inconsistent correlations")


def main() -> None:
    environment = _clean_environment()
    with tempfile.TemporaryDirectory(prefix="erpsec-package-smoke-") as temporary_name:
        temporary_root = Path(temporary_name)
        source_copy = temporary_root / "source"
        wheelhouse = temporary_root / "wheelhouse"
        install_venv = temporary_root / "installed"
        finding_report_path = temporary_root / "finding-report.json"
        finding_html_report_path = temporary_root / "finding-report.html"
        finding_sarif_report_path = temporary_root / "finding-report.sarif"
        clean_report_path = temporary_root / "clean-report.json"
        clean_html_report_path = temporary_root / "clean-report.html"
        clean_sarif_report_path = temporary_root / "clean-report.sarif"
        invalid_input_path = temporary_root / "invalid.json"
        invalid_report_path = temporary_root / "invalid-report.json"
        csv_report_path = temporary_root / "csv-report.json"
        jsonl_report_path = temporary_root / "jsonl-report.json"
        malformed_jsonl_path = temporary_root / "malformed.jsonl"
        malformed_jsonl_report_path = temporary_root / "malformed-jsonl-report.json"
        duplicate_report_path = temporary_root / "duplicate-report.json"
        full_pack_report_path = temporary_root / "full-pack-report.json"
        clean_scenario_report_path = temporary_root / "clean-scenario-report.json"
        access_scenario_report_path = temporary_root / "access-scenario-report.json"
        auth_scenario_report_path = temporary_root / "auth-scenario-report.json"
        replay_report_path = temporary_root / "replay-report.json"

        shutil.copytree(PROJECT_ROOT, source_copy, ignore=COPY_IGNORE)
        wheelhouse.mkdir()

        _run(
            [
                sys.executable,
                "-m",
                "pip",
                "--isolated",
                "--disable-pip-version-check",
                "wheel",
                "--no-index",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(wheelhouse),
                str(source_copy),
            ],
            cwd=temporary_root,
            environment=environment,
        )
        wheels = sorted(wheelhouse.glob("*.whl"))
        if len(wheels) != 1:
            raise RuntimeError(f"expected one project wheel, found {len(wheels)}")

        _run(
            [sys.executable, "-m", "venv", str(install_venv)],
            cwd=temporary_root,
            environment=environment,
        )
        installed_python = _venv_python(install_venv)
        _run(
            [
                str(installed_python),
                "-m",
                "pip",
                "--isolated",
                "--disable-pip-version-check",
                "install",
                "--no-index",
                "--no-deps",
                str(wheels[0]),
            ],
            cwd=temporary_root,
            environment=environment,
        )

        audit_guard_probe = AUDIT_GUARD + (
            "import socket\n"
            "import subprocess\n"
            "for operation in (lambda: socket.socket(), lambda: subprocess.run(['false'])):\n"
            "    try:\n"
            "        operation()\n"
            "    except RuntimeError as error:\n"
            "        assert str(error) == 'runtime network or process access denied'\n"
            "    else:\n"
            "        raise RuntimeError('runtime audit guard did not deny an operation')\n"
        )
        _run(
            [str(installed_python), "-I", "-c", audit_guard_probe],
            cwd=temporary_root,
            environment=environment,
        )

        metadata_probe = AUDIT_GUARD + (
            "from importlib.metadata import version\n"
            "from pathlib import Path\n"
            "import erp_security_evidence_workbench as package\n"
            f"assert version('{DISTRIBUTION_NAME}') == package.__version__\n"
            "assert Path(package.__file__).resolve().is_relative_to("
            "Path(sys.prefix).resolve())\n"
        )
        _run(
            [str(installed_python), "-I", "-c", metadata_probe],
            cwd=temporary_root,
            environment=environment,
        )

        console_script = _console_script(install_venv)
        help_result = _run(
            [
                str(installed_python),
                "-I",
                "-c",
                CONSOLE_SCRIPT_RUNNER,
                str(console_script),
                "--help",
            ],
            cwd=temporary_root,
            environment=environment,
        )
        if not {"analyze", "replay"} <= set(help_result.stdout.split()):
            raise RuntimeError("installed console-script help omitted a required command")

        module_help_result = _run(
            [
                str(installed_python),
                "-I",
                "-c",
                MODULE_RUNNER,
                "--help",
            ],
            cwd=temporary_root,
            environment=environment,
        )
        if not {"analyze", "replay"} <= set(module_help_result.stdout.split()):
            raise RuntimeError("installed module help omitted a required command")

        catalog_result = _run_installed_cli(
            installed_python,
            ["rules"],
            cwd=temporary_root,
            environment=environment,
        )
        _assert_rule_catalog(catalog_result.stdout)

        _run_installed_cli(
            installed_python,
            [
                "analyze",
                str(source_copy / "examples" / "rule-pack-findings.json"),
                "--as-of",
                "2026-09-01T00:00:00Z",
                "--format",
                "json",
                "--output",
                str(full_pack_report_path),
                "--rule",
                "all",
            ],
            cwd=temporary_root,
            environment=environment,
            expected_exit=1,
        )
        _assert_full_rule_pack(full_pack_report_path)

        scenario_root = source_copy / "examples" / "scenarios"
        _run_installed_cli(
            installed_python,
            [
                "analyze",
                str(scenario_root / "clean-baseline" / "clean-principals.csv"),
                str(scenario_root / "clean-baseline" / "clean-permissions.jsonl"),
                str(scenario_root / "clean-baseline" / "clean-events-controls.json"),
                "--as-of",
                "2026-09-01T00:00:00Z",
                "--format",
                "json",
                "--output",
                str(clean_scenario_report_path),
                "--rule",
                "all",
            ],
            cwd=temporary_root,
            environment=environment,
        )
        _assert_scenario_report(
            clean_scenario_report_path,
            expected_evaluations=(
                ("ERP001", "not_matched"),
                ("ERP002", "not_matched"),
                ("ERP003", "not_matched"),
                ("ERP004", "not_matched"),
                ("ERP005", "not_matched"),
                ("ERP006", "not_matched"),
            ),
            expected_finding_ids=(),
            expected_record_count=4,
        )

        _run_installed_cli(
            installed_python,
            [
                "analyze",
                str(scenario_root / "access-governance" / "access-principals.csv"),
                str(scenario_root / "access-governance" / "access-permissions.jsonl"),
                "--as-of",
                "2026-09-01T00:00:00Z",
                "--format",
                "json",
                "--output",
                str(access_scenario_report_path),
                "--rule",
                "ERP002",
                "--rule",
                "ERP003",
                "--rule",
                "ERP004",
            ],
            cwd=temporary_root,
            environment=environment,
            expected_exit=1,
        )
        _assert_scenario_report(
            access_scenario_report_path,
            expected_evaluations=(
                ("ERP002", "matched"),
                ("ERP003", "matched"),
                ("ERP004", "matched"),
            ),
            expected_finding_ids=("ERP002", "ERP003", "ERP004"),
            expected_record_count=9,
        )

        _run_installed_cli(
            installed_python,
            [
                "analyze",
                str(scenario_root / "authentication-control" / "auth-principals.csv"),
                str(scenario_root / "authentication-control" / "auth-events.jsonl"),
                str(scenario_root / "authentication-control" / "auth-control.json"),
                "--as-of",
                "2026-09-01T00:00:00Z",
                "--format",
                "json",
                "--output",
                str(auth_scenario_report_path),
                "--rule",
                "ERP001",
                "--rule",
                "ERP005",
                "--rule",
                "ERP006",
            ],
            cwd=temporary_root,
            environment=environment,
            expected_exit=1,
        )
        _assert_scenario_report(
            auth_scenario_report_path,
            expected_evaluations=(
                ("ERP001", "matched"),
                ("ERP005", "matched"),
                ("ERP006", "matched"),
            ),
            expected_finding_ids=("ERP001", "ERP005", "ERP006"),
            expected_record_count=17,
        )

        _run_installed_cli(
            installed_python,
            [
                "replay",
                str(
                    source_copy
                    / "examples"
                    / "replay"
                    / "detection-correlation"
                    / "replay-manifest.json"
                ),
                "--as-of",
                "2026-09-01T12:45:00Z",
                "--format",
                "json",
                "--output",
                str(replay_report_path),
                "--rule",
                "all",
            ],
            cwd=temporary_root,
            environment=environment,
            expected_exit=1,
        )
        _assert_replay_report(replay_report_path)

        _run_installed_cli(
            installed_python,
            [
                "analyze",
                str(source_copy / "examples" / "audit-logging-disabled.json"),
                "--as-of",
                "2026-09-01T00:00:00Z",
                "--format",
                "json",
                "--output",
                str(finding_report_path),
            ],
            cwd=temporary_root,
            environment=environment,
            expected_exit=1,
        )
        _assert_finding_report(finding_report_path)
        _assert_source_adapter(
            finding_report_path,
            "erpsec.legacy-control-state-json/v1",
        )

        _run_installed_cli(
            installed_python,
            [
                "analyze",
                str(source_copy / "examples" / "audit-logging-enabled.json"),
                "--as-of",
                "2026-09-01T00:00:00Z",
                "--format",
                "json",
                "--output",
                str(clean_report_path),
            ],
            cwd=temporary_root,
            environment=environment,
        )
        _assert_clean_report(clean_report_path)

        finding_projection = _json_report_projection(finding_report_path)
        clean_projection = _json_report_projection(clean_report_path)
        report_variants = (
            (
                "html",
                _assert_html_report,
                finding_html_report_path,
                clean_html_report_path,
            ),
            (
                "sarif",
                _assert_sarif_report,
                finding_sarif_report_path,
                clean_sarif_report_path,
            ),
        )
        for report_format, validator, finding_output, clean_output in report_variants:
            for source_name, output_path, projection, expected_exit in (
                ("audit-logging-disabled.json", finding_output, finding_projection, 1),
                ("audit-logging-enabled.json", clean_output, clean_projection, 0),
            ):
                completed = _run_installed_cli(
                    installed_python,
                    [
                        "analyze",
                        str(source_copy / "examples" / source_name),
                        "--as-of",
                        "2026-09-01T00:00:00Z",
                        "--format",
                        report_format,
                        "--output",
                        str(output_path),
                    ],
                    cwd=temporary_root,
                    environment=environment,
                    expected_exit=expected_exit,
                )
                if completed.stdout or completed.stderr:
                    raise RuntimeError(
                        f"installed CLI emitted unexpected {report_format} command output"
                    )
                validator(output_path, projection)

        _run_installed_cli(
            installed_python,
            [
                "analyze",
                str(source_copy / "examples" / "audit-logging-disabled.csv"),
                "--as-of",
                "2026-09-01T00:00:00Z",
                "--format",
                "json",
                "--output",
                str(csv_report_path),
            ],
            cwd=temporary_root,
            environment=environment,
            expected_exit=1,
        )
        _assert_finding_report(csv_report_path)
        _assert_source_adapter(csv_report_path, "erpsec.csv/v1")

        _run_installed_cli(
            installed_python,
            [
                "analyze",
                str(source_copy / "examples" / "audit-logging-disabled.jsonl"),
                "--as-of",
                "2026-09-01T00:00:00Z",
                "--format",
                "json",
                "--output",
                str(jsonl_report_path),
            ],
            cwd=temporary_root,
            environment=environment,
            expected_exit=1,
        )
        _assert_finding_report(jsonl_report_path)
        _assert_source_adapter(jsonl_report_path, "erpsec.jsonl/v1")

        malformed_jsonl_path.write_bytes(
            (source_copy / "examples" / "audit-logging-disabled.jsonl").read_bytes()
            + b'{"schema_version":'
        )
        malformed_jsonl_result = _run_installed_cli(
            installed_python,
            [
                "analyze",
                str(malformed_jsonl_path),
                "--as-of",
                "2026-09-01T00:00:00Z",
                "--format",
                "json",
                "--output",
                str(malformed_jsonl_report_path),
            ],
            cwd=temporary_root,
            environment=environment,
            expected_exit=2,
        )
        if malformed_jsonl_report_path.exists():
            raise RuntimeError("installed CLI published a partial JSONL report")
        if "Traceback" in malformed_jsonl_result.stderr:
            raise RuntimeError("installed CLI exposed a JSONL validation traceback")

        duplicate_result = _run_installed_cli(
            installed_python,
            [
                "analyze",
                str(source_copy / "examples" / "audit-logging-disabled.csv"),
                str(source_copy / "examples" / "audit-logging-disabled.jsonl"),
                "--as-of",
                "2026-09-01T00:00:00Z",
                "--format",
                "json",
                "--output",
                str(duplicate_report_path),
            ],
            cwd=temporary_root,
            environment=environment,
            expected_exit=2,
        )
        if duplicate_report_path.exists():
            raise RuntimeError("installed CLI published a report with duplicate record IDs")
        if "Traceback" in duplicate_result.stderr:
            raise RuntimeError("installed CLI exposed a duplicate-record traceback")

        invalid_input_path.write_bytes(b"{not-json}\n")
        invalid_result = _run_installed_cli(
            installed_python,
            [
                "analyze",
                str(invalid_input_path),
                "--as-of",
                "2026-09-01T00:00:00Z",
                "--format",
                "json",
                "--output",
                str(invalid_report_path),
            ],
            cwd=temporary_root,
            environment=environment,
            expected_exit=2,
        )
        if invalid_report_path.exists():
            raise RuntimeError("installed CLI published a report for malformed evidence")
        if not invalid_result.stderr.startswith("error: ") or "Traceback" in invalid_result.stderr:
            raise RuntimeError("installed CLI emitted an unsafe malformed-input diagnostic")

    print(
        "index-disabled build/install and network-denied JSON/HTML/SARIF "
        "installed-runtime smoke passed"
    )


if __name__ == "__main__":
    main()
