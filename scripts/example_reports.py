"""Generate and byte-check deterministic example reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, TypedDict

sys.dont_write_bytecode = True

AS_OF = "2026-09-01T00:00:00Z"
MANIFEST_SCHEMA_VERSION = "erpsec.example-reports-manifest/v1"
GENERATOR_PATH = "scripts/example_reports.py"
GENERATOR_VERSION = "1.0.0"
MANIFEST_NAME = "manifest.json"
CHECKSUM_NAME = "SHA256SUMS"
REPORT_FORMATS = ("html", "json", "sarif")
PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ExampleReportsError(Exception):
    """Base class for safely reportable example-report failures."""


class ExampleReportsUsageError(ExampleReportsError):
    """A requested filesystem operation is invalid or unsafe."""


class ExampleReportsMismatchError(ExampleReportsError):
    """Committed bytes differ from the deterministic report contract."""


class _SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser whose diagnostics do not echo user-controlled paths."""

    def error(self, message: str) -> NoReturn:
        del message
        raise ExampleReportsUsageError("invalid example-report arguments")


@dataclass(frozen=True, slots=True)
class Scenario:
    """One fixed synthetic report scenario."""

    scenario_id: str
    input_paths: tuple[str, ...]
    expected_exit: int
    expected_result: str


class SourceEntry(TypedDict):
    """One committed input identity embedded in the report manifest."""

    byte_count: int
    path: str
    sha256: str


SCENARIOS = (
    Scenario(
        scenario_id="clean-baseline",
        input_paths=(
            "examples/scenarios/clean-baseline/clean-events-controls.json",
            "examples/scenarios/clean-baseline/clean-permissions.jsonl",
            "examples/scenarios/clean-baseline/clean-principals.csv",
        ),
        expected_exit=0,
        expected_result="no_findings",
    ),
    Scenario(
        scenario_id="rule-pack-findings",
        input_paths=("examples/rule-pack-findings.json",),
        expected_exit=1,
        expected_result="findings",
    ),
)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _source_entries(scenario: Scenario) -> list[SourceEntry]:
    entries: list[SourceEntry] = []
    try:
        for relative in scenario.input_paths:
            path = PROJECT_ROOT / relative
            if path.is_symlink() or not path.is_file():
                raise ExampleReportsUsageError("example-report input is invalid")
            content = path.read_bytes()
            entries.append(
                {
                    "byte_count": len(content),
                    "path": relative,
                    "sha256": _sha256(content),
                }
            )
    except ExampleReportsError:
        raise
    except OSError as exc:
        raise ExampleReportsUsageError("example-report input could not be read") from exc
    return entries


def _build_scenario_reports(scenario: Scenario) -> dict[str, bytes]:
    source_root = PROJECT_ROOT / "src"
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))

    from erp_security_evidence_workbench.ingest import load_control_state, load_evidence
    from erp_security_evidence_workbench.reporting import build_report
    from erp_security_evidence_workbench.rules import ALL_RULE_IDS, evaluate_rules

    input_paths = tuple(PROJECT_ROOT / relative for relative in scenario.input_paths)
    bundle = (
        load_control_state(input_paths[0]) if len(input_paths) == 1 else load_evidence(input_paths)
    )
    run = evaluate_rules(bundle, as_of=AS_OF, selected_rule_ids=ALL_RULE_IDS)
    result = "findings" if run.findings else "no_findings"
    exit_code = 1 if run.findings else 0
    if result != scenario.expected_result or exit_code != scenario.expected_exit:
        raise ExampleReportsMismatchError(
            "example-report scenario differs from the expected outcome"
        )

    reports = {
        report_format: build_report(
            report_format,
            bundle,
            run.findings,
            as_of=AS_OF,
            evaluations=run.evaluations,
        )
        for report_format in REPORT_FORMATS
    }
    json_report = json.loads(reports["json"].decode("ascii"))
    if json_report.get("run", {}).get("result") != scenario.expected_result:
        raise ExampleReportsMismatchError(
            "example-report content differs from the expected outcome"
        )
    expected_sources = {
        Path(entry["path"]).name: entry["sha256"] for entry in _source_entries(scenario)
    }
    actual_sources = {
        source["path"]: source["sha256"] for source in json_report.get("source_manifest", [])
    }
    if actual_sources != expected_sources:
        raise ExampleReportsMismatchError(
            "example-report provenance differs from the input fixtures"
        )
    return reports


def _expected_tree() -> dict[str, bytes]:
    managed: dict[str, bytes] = {}
    manifest_scenarios: list[dict[str, object]] = []
    for scenario in SCENARIOS:
        before_sources = _source_entries(scenario)
        reports = _build_scenario_reports(scenario)
        after_sources = _source_entries(scenario)
        if before_sources != after_sources:
            raise ExampleReportsMismatchError("example-report inputs changed during generation")

        artifacts: list[dict[str, object]] = []
        for report_format in REPORT_FORMATS:
            path = f"{scenario.scenario_id}.{report_format}"
            content = reports[report_format]
            managed[path] = content
            artifacts.append(
                {
                    "byte_count": len(content),
                    "format": report_format,
                    "path": path,
                    "sha256": _sha256(content),
                }
            )
        manifest_scenarios.append(
            {
                "artifacts": artifacts,
                "expected": {
                    "exit_code": scenario.expected_exit,
                    "result": scenario.expected_result,
                },
                "options": {
                    "as_of": AS_OF,
                    "selected_rules": ["all"],
                },
                "provenance": {
                    "dataset_classification": "synthetic",
                    "inputs": before_sources,
                    "origin": "in-repository fictional fixture",
                },
                "scenario_id": scenario.scenario_id,
            }
        )

    manifest = {
        "as_of": AS_OF,
        "dataset_classification": "synthetic",
        "generator": {"path": GENERATOR_PATH, "version": GENERATOR_VERSION},
        "scenarios": manifest_scenarios,
        "schema_version": MANIFEST_SCHEMA_VERSION,
    }
    managed[MANIFEST_NAME] = _json_bytes(manifest)
    managed[CHECKSUM_NAME] = "".join(
        f"{_sha256(content)}  {path}\n" for path, content in sorted(managed.items())
    ).encode("ascii")
    return dict(sorted(managed.items()))


def _directory_open_flags() -> int:
    return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW


def _validate_output_path(target: Path) -> None:
    if target.name in {"", ".", ".."} or target.is_symlink():
        raise ExampleReportsUsageError("example-report output directory is unsafe")
    parent = target.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ExampleReportsUsageError("example-report output parent is invalid")


def _open_output_directory(target: Path) -> int:
    _validate_output_path(target)
    descriptor: int | None = None
    try:
        if target.exists():
            if not target.is_dir():
                raise ExampleReportsUsageError("example-report output must be a directory")
        else:
            target.mkdir()
        descriptor = os.open(target, _directory_open_flags())
        if os.listdir(descriptor):
            raise ExampleReportsUsageError("example-report output directory must be new or empty")
        return descriptor
    except ExampleReportsError:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        raise ExampleReportsUsageError(
            "example-report output directory could not be prepared"
        ) from exc


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _write_tree(target: Path, managed: dict[str, bytes]) -> None:
    directory_descriptor = _open_output_directory(target)
    try:
        for name, content in managed.items():
            if "/" in name or name in {"", ".", ".."}:
                raise ExampleReportsUsageError("managed report path is invalid")
            flags = os.O_WRONLY | os.O_CLOEXEC | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            descriptor = os.open(
                name,
                flags,
                0o644,
                dir_fd=directory_descriptor,
            )
            try:
                _write_all(descriptor, content)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(directory_descriptor)
    except ExampleReportsError:
        raise
    except OSError as exc:
        raise ExampleReportsUsageError("example reports could not be written") from exc
    finally:
        os.close(directory_descriptor)


def _read_bounded(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _open_reports_directory(reports: Path) -> int:
    if reports.name in {"", ".", ".."} or reports.is_symlink() or not reports.is_dir():
        raise ExampleReportsUsageError("example-report directory is invalid")
    try:
        return os.open(reports, _directory_open_flags())
    except OSError as exc:
        raise ExampleReportsUsageError("example-report directory could not be opened") from exc


def _check_tree(reports: Path, managed: dict[str, bytes]) -> None:
    directory_descriptor = _open_reports_directory(reports)
    try:
        names = os.listdir(directory_descriptor)
        for name in names:
            metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise ExampleReportsUsageError("example-report directory contains an unsafe entry")
        if set(names) != set(managed):
            raise ExampleReportsMismatchError(
                "example-report file set differs from the deterministic contract"
            )

        for name, expected in managed.items():
            metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            if metadata.st_size != len(expected):
                raise ExampleReportsMismatchError(
                    "example-report bytes differ from the deterministic contract"
                )
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_descriptor,
            )
            try:
                opened_metadata = os.fstat(descriptor)
                if not stat.S_ISREG(opened_metadata.st_mode):
                    raise ExampleReportsUsageError(
                        "example-report directory contains an unsafe entry"
                    )
                actual = _read_bounded(descriptor, len(expected) + 1)
            finally:
                os.close(descriptor)
            if actual != expected:
                raise ExampleReportsMismatchError(
                    "example-report bytes differ from the deterministic contract"
                )
    except ExampleReportsError:
        raise
    except OSError as exc:
        raise ExampleReportsUsageError("example reports could not be read") from exc
    finally:
        os.close(directory_descriptor)


def _parser() -> _SafeArgumentParser:
    parser = _SafeArgumentParser(description="Manage deterministic example reports.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    generate = subcommands.add_parser("generate")
    generate.add_argument("--output", required=True, type=Path)
    check = subcommands.add_parser("check")
    check.add_argument("--reports", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the development-only example-report helper."""
    try:
        arguments = _parser().parse_args(argv)
        managed = _expected_tree()
        if arguments.command == "generate":
            _write_tree(arguments.output, managed)
            print("example reports generated")
        else:
            _check_tree(arguments.reports, managed)
            print("example reports verified")
    except ExampleReportsMismatchError:
        print("error: example report mismatch", file=sys.stderr)
        return 1
    except ExampleReportsError:
        print("error: invalid example report operation", file=sys.stderr)
        return 2
    except Exception:
        print("error: unexpected example report failure", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
