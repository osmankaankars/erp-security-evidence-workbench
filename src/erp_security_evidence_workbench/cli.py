from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

from erp_security_evidence_workbench.errors import InputValidationError, WorkbenchError
from erp_security_evidence_workbench.ingest import load_control_state, load_evidence
from erp_security_evidence_workbench.replay import load_replay_manifest, replay_input_paths
from erp_security_evidence_workbench.reporting import (
    REPLAY_REPORT_SCHEMA_VERSION,
    REPORT_FORMATS,
    build_report,
    write_new_report,
)
from erp_security_evidence_workbench.rules import (
    ALL_RULE_IDS,
    DETECTION_RULE_IDS,
    RULE_ID,
    build_rule_catalog,
    evaluate_rules,
)

RFC3339_SECONDS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})")


class _SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser whose failures never echo untrusted argument values."""

    def error(self, message: str) -> NoReturn:
        del message
        raise InputValidationError("invalid command-line arguments")


def _parser() -> _SafeArgumentParser:
    parser = _SafeArgumentParser(
        prog="erpsec",
        description="Analyze synthetic ERP security evidence offline and read-only.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    analyze = subcommands.add_parser("analyze", help="analyze synthetic evidence files")
    analyze.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="explicit synthetic CSV, JSON, or JSONL evidence files",
    )
    analyze.add_argument("--as-of", required=True, help="timezone-aware ISO 8601 analysis time")
    analyze.add_argument("--format", required=True, choices=REPORT_FORMATS, help="report format")
    analyze.add_argument("--output", required=True, type=Path, help="new report path")
    analyze.add_argument(
        "--rule",
        action="append",
        choices=(*ALL_RULE_IDS, "all"),
        dest="selected_rules",
        help="rule ID to evaluate; repeat for multiple rules or use 'all'",
    )
    replay = subcommands.add_parser(
        "replay",
        help="replay a digest-pinned synthetic multi-source manifest",
    )
    replay.add_argument("manifest", type=Path, help="synthetic replay manifest")
    replay.add_argument("--as-of", required=True, help="timezone-aware ISO 8601 analysis time")
    replay.add_argument("--format", required=True, choices=REPORT_FORMATS, help="report format")
    replay.add_argument("--output", required=True, type=Path, help="new report path")
    replay.add_argument(
        "--rule",
        action="append",
        choices=(*DETECTION_RULE_IDS, "all"),
        dest="selected_rules",
        help="replay rule ID; repeat for multiple rules or use 'all'",
    )
    subcommands.add_parser("rules", help="print the deterministic JSON rule catalog")
    return parser


def _canonical_as_of(value: str) -> str:
    if "." in value:
        raise InputValidationError("as-of must use seconds precision")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", value):
        raise InputValidationError("as-of must include an explicit timezone")
    if RFC3339_SECONDS.fullmatch(value) is None:
        raise InputValidationError("as-of must be a seconds-precision RFC 3339 timestamp")

    parseable = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(parseable)
    except ValueError as exc:
        raise InputValidationError("as-of must be a valid ISO 8601 timestamp") from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InputValidationError("as-of must include an explicit timezone")

    utc_value = parsed.astimezone(UTC).isoformat(timespec="seconds")
    return utc_value.replace("+00:00", "Z")


def _paths_alias(input_path: Path, output_path: Path) -> bool:
    try:
        if output_path.exists() and input_path.samefile(output_path):
            return True
        return input_path.resolve(strict=True) == output_path.resolve(strict=False)
    except (OSError, ValueError):
        return False


def _selected_rule_ids(values: list[str] | None) -> tuple[str, ...]:
    if values is None:
        return (RULE_ID,)
    selected = tuple(values)
    if "all" in selected:
        if selected != ("all",):
            raise InputValidationError("'all' cannot be combined with individual rules")
        return ALL_RULE_IDS
    if len(set(selected)) != len(selected):
        raise InputValidationError("rule selections must be unique")
    selected_set = set(selected)
    return tuple(rule_id for rule_id in ALL_RULE_IDS if rule_id in selected_set)


def _selected_replay_rule_ids(values: list[str] | None) -> tuple[str, ...]:
    if values is None:
        return DETECTION_RULE_IDS
    selected = tuple(values)
    if "all" in selected:
        if selected != ("all",):
            raise InputValidationError("'all' cannot be combined with individual rules")
        return DETECTION_RULE_IDS
    if len(set(selected)) != len(selected):
        raise InputValidationError("rule selections must be unique")
    selected_set = set(selected)
    return tuple(rule_id for rule_id in DETECTION_RULE_IDS if rule_id in selected_set)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface."""
    try:
        arguments = _parser().parse_args(argv)
        if arguments.command == "rules":
            sys.stdout.write(build_rule_catalog().decode("ascii"))
            return 0

        as_of = _canonical_as_of(arguments.as_of)
        report_schema_version = "erpsec.report/v1"
        if arguments.command == "replay":
            if _paths_alias(arguments.manifest, arguments.output):
                raise InputValidationError("input and output must be different paths")
            bundle = load_replay_manifest(arguments.manifest)
            if any(
                _paths_alias(input_path, arguments.output)
                for input_path in replay_input_paths(arguments.manifest, bundle)
            ):
                raise InputValidationError("input and output must be different paths")
            selected_rule_ids = _selected_replay_rule_ids(arguments.selected_rules)
            report_schema_version = REPLAY_REPORT_SCHEMA_VERSION
        else:
            inputs = tuple(arguments.inputs)
            if any(_paths_alias(input_path, arguments.output) for input_path in inputs):
                raise InputValidationError("input and output must be different paths")
            bundle = load_control_state(inputs[0]) if len(inputs) == 1 else load_evidence(inputs)
            selected_rule_ids = _selected_rule_ids(arguments.selected_rules)
        rule_run = evaluate_rules(
            bundle,
            as_of=as_of,
            selected_rule_ids=selected_rule_ids,
        )
        findings = rule_run.findings
        report = build_report(
            arguments.format,
            bundle,
            findings,
            as_of=as_of,
            evaluations=rule_run.evaluations,
            schema_version=report_schema_version,
        )
        write_new_report(arguments.output, report)
    except WorkbenchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print("error: unexpected internal failure", file=sys.stderr)
        return 2

    return 1 if findings else 0


def entrypoint() -> None:
    """Console-script entry point."""
    raise SystemExit(main())
