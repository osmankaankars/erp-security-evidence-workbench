"""Deterministic multi-format reporting with no-overwrite publication."""

from __future__ import annotations

import json
import os
import secrets
import signal
import stat
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from erp_security_evidence_workbench import __version__
from erp_security_evidence_workbench.errors import (
    IncompleteEvidenceError,
    InputValidationError,
    OutputError,
)
from erp_security_evidence_workbench.models import EvidenceBundle, Finding, RuleEvaluation
from erp_security_evidence_workbench.rules import (
    DEFAULT_RULE_PARAMETERS,
    RULE_ID,
    RULE_REGISTRY,
    RuleDefinition,
    RuleParameters,
    evaluate_rules,
)
from erp_security_evidence_workbench.timestamps import normalize_rfc3339_seconds

REPORT_SCHEMA_VERSION = "erpsec.report/v1"
REPORT_FORMATS = ("json", "html", "sarif")
_TEMPORARY_NAME_ATTEMPTS = 16


@dataclass(slots=True)
class _OwnedFile:
    descriptor: int = -1
    name: str | None = None


@dataclass(slots=True)
class _PublicationState:
    committed: bool = False


def build_json_report(
    bundle: EvidenceBundle,
    findings: tuple[Finding, ...],
    *,
    as_of: str,
    evaluations: tuple[RuleEvaluation, ...] | None = None,
    parameters: RuleParameters = DEFAULT_RULE_PARAMETERS,
) -> bytes:
    """Build canonical report bytes for identical inputs and options."""
    report, _ = _prepare_report(
        bundle,
        findings,
        as_of=as_of,
        evaluations=evaluations,
        parameters=parameters,
    )
    return _canonical_json(report)


def build_html_report(
    bundle: EvidenceBundle,
    findings: tuple[Finding, ...],
    *,
    as_of: str,
    evaluations: tuple[RuleEvaluation, ...] | None = None,
    parameters: RuleParameters = DEFAULT_RULE_PARAMETERS,
) -> bytes:
    """Build deterministic self-contained HTML from validated results."""
    from erp_security_evidence_workbench.html_report import render_html_report

    report, definitions = _prepare_report(
        bundle,
        findings,
        as_of=as_of,
        evaluations=evaluations,
        parameters=parameters,
    )
    return render_html_report(report, definitions)


def build_sarif_report(
    bundle: EvidenceBundle,
    findings: tuple[Finding, ...],
    *,
    as_of: str,
    evaluations: tuple[RuleEvaluation, ...] | None = None,
    parameters: RuleParameters = DEFAULT_RULE_PARAMETERS,
) -> bytes:
    """Build deterministic SARIF 2.1.0 from validated results."""
    from erp_security_evidence_workbench.sarif_report import render_sarif_report

    report, definitions = _prepare_report(
        bundle,
        findings,
        as_of=as_of,
        evaluations=evaluations,
        parameters=parameters,
    )
    return render_sarif_report(report, definitions)


def build_report(
    report_format: str,
    bundle: EvidenceBundle,
    findings: tuple[Finding, ...],
    *,
    as_of: str,
    evaluations: tuple[RuleEvaluation, ...] | None = None,
    parameters: RuleParameters = DEFAULT_RULE_PARAMETERS,
) -> bytes:
    """Build the explicitly selected report format through one validation seam."""
    report, definitions = _prepare_report(
        bundle,
        findings,
        as_of=as_of,
        evaluations=evaluations,
        parameters=parameters,
    )
    if report_format == "json":
        return _canonical_json(report)
    if report_format == "html":
        from erp_security_evidence_workbench.html_report import render_html_report

        return render_html_report(report, definitions)
    if report_format == "sarif":
        from erp_security_evidence_workbench.sarif_report import render_sarif_report

        return render_sarif_report(report, definitions)
    raise InputValidationError("report format is invalid")


def _prepare_report(
    bundle: EvidenceBundle,
    findings: tuple[Finding, ...],
    *,
    as_of: str,
    evaluations: tuple[RuleEvaluation, ...] | None,
    parameters: RuleParameters,
) -> tuple[dict[str, Any], tuple[RuleDefinition, ...]]:
    """Create one engine-coherent document shared by every serializer."""
    if not bundle.complete or not bundle.records:
        raise IncompleteEvidenceError("evidence coverage is incomplete")

    findings, evaluations = _validated_results(
        bundle,
        findings,
        as_of=as_of,
        evaluations=evaluations,
        parameters=parameters,
    )
    matched = bool(findings)
    try:
        canonical_as_of = normalize_rfc3339_seconds(as_of)
    except ValueError as exc:
        raise InputValidationError("analysis time is invalid") from exc
    report: dict[str, Any] = {
        "evidence_manifest": [
            {
                "record_id": record.record_id,
                "record_type": record.record_type,
                "source_ref": record.source_ref.to_dict(),
            }
            for record in sorted(
                bundle.records,
                key=lambda item: (
                    item.record_type,
                    item.record_id,
                    item.source_ref.sha256,
                    item.source_ref.path,
                ),
            )
        ],
        "source_manifest": [source.to_dict() for source in bundle.sources],
        "evaluations": [evaluation.to_dict() for evaluation in evaluations],
        "findings": [finding.to_dict() for finding in findings],
        "run": {
            "as_of": canonical_as_of,
            "coverage": "complete",
            "input_count": len(bundle.records),
            "result": "findings" if matched else "no_findings",
        },
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {
            "name": "erp-security-evidence-workbench",
            "version": __version__,
        },
    }
    definitions_by_id = {definition.rule_id: definition for definition in RULE_REGISTRY}
    definitions = tuple(definitions_by_id[evaluation.rule_id] for evaluation in evaluations)
    return report, definitions


def _canonical_json(document: dict[str, Any]) -> bytes:
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


def _validated_results(
    bundle: EvidenceBundle,
    findings: tuple[Finding, ...],
    *,
    as_of: str,
    evaluations: tuple[RuleEvaluation, ...] | None,
    parameters: RuleParameters,
) -> tuple[tuple[Finding, ...], tuple[RuleEvaluation, ...]]:
    """Re-evaluate selected rules and accept only an engine-coherent result."""
    registry_versions = {
        definition.rule_id: definition.rule_version for definition in RULE_REGISTRY
    }
    registry_order = {definition.rule_id: index for index, definition in enumerate(RULE_REGISTRY)}
    selected_rule_ids: tuple[str, ...]
    supplied_evaluations: tuple[RuleEvaluation, ...] | None
    if evaluations is None:
        selected_rule_ids = (RULE_ID,)
        supplied_evaluations = None
    else:
        if not evaluations:
            raise InputValidationError("rule evaluation results are inconsistent")
        evaluations_by_id: dict[str, RuleEvaluation] = {}
        for evaluation in evaluations:
            if (
                evaluation.rule_id in evaluations_by_id
                or registry_versions.get(evaluation.rule_id) != evaluation.rule_version
                or evaluation.status not in {"matched", "not_matched"}
            ):
                raise InputValidationError("rule evaluation results are inconsistent")
            evaluations_by_id[evaluation.rule_id] = evaluation
        supplied_evaluations = tuple(
            sorted(evaluations, key=lambda item: registry_order[item.rule_id])
        )
        selected_rule_ids = tuple(evaluation.rule_id for evaluation in supplied_evaluations)

    expected = evaluate_rules(
        bundle,
        as_of=as_of,
        selected_rule_ids=selected_rule_ids,
        parameters=parameters,
    )
    supplied_findings = tuple(sorted(findings, key=lambda item: (item.rule_id, item.fingerprint)))
    if supplied_findings != expected.findings:
        raise InputValidationError("rule evaluation results are inconsistent")
    if supplied_evaluations is not None and supplied_evaluations != expected.evaluations:
        raise InputValidationError("rule evaluation results are inconsistent")

    return expected.findings, expected.evaluations


def write_new_report(path: Path, content: bytes) -> None:
    """Publish a bounded report through one descriptor-anchored directory.

    The exclusive hard link plus identity and parent checks form the publication
    commit point. Cleanup of the private temporary hard link remains best effort
    after that point so an already-published report is never described as absent.
    SIGINT cleanup semantics assume the project's single-threaded POSIX CLI and
    Python's default SIGINT-to-KeyboardInterrupt handler.
    """
    if type(content) is not bytes:
        raise OutputError("report content is invalid")
    _validate_output_name(path.name)
    _validate_output_path(path)

    parent = _OwnedFile()
    temporary = _OwnedFile()
    state = _PublicationState()
    previous_signal_mask = _block_sigint()
    try:
        _publish_new_report(
            path,
            content,
            parent=parent,
            temporary=temporary,
            state=state,
            honor_sigint=(
                signal.SIGINT not in previous_signal_mask
                and signal.getsignal(signal.SIGINT) is signal.default_int_handler
            ),
        )
    finally:
        try:
            _cleanup_publication(
                path,
                parent=parent,
                temporary=temporary,
                committed=state.committed,
            )
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)


def _publish_new_report(
    path: Path,
    content: bytes,
    *,
    parent: _OwnedFile,
    temporary: _OwnedFile,
    state: _PublicationState,
    honor_sigint: bool,
) -> None:
    stage = "write"
    try:
        try:
            resolved_parent = path.parent.resolve(strict=True)
            _acquire_descriptor(
                parent,
                lambda: os.open(resolved_parent, _directory_open_flags()),
            )
            _raise_if_sigint_pending(enabled=honor_sigint)
            parent_stat = os.fstat(parent.descriptor)
            if not stat.S_ISDIR(parent_stat.st_mode):
                raise OSError("output parent is not a directory")
        except ValueError as exc:
            raise OutputError("output path is unsupported") from exc
        except OSError as exc:
            raise OutputError("output parent directory does not exist") from exc
        parent_mode = stat.S_IMODE(parent_stat.st_mode)
        shared_write_bits = stat.S_IWGRP | stat.S_IWOTH
        if parent_mode & shared_write_bits and not parent_mode & stat.S_ISVTX:
            raise OutputError("output parent directory permissions are unsafe")

        try:
            os.stat(
                path.name,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise OutputError("output already exists")

        _create_private_temporary_file(parent.descriptor, temporary)
        _raise_if_sigint_pending(enabled=honor_sigint)
        os.fchmod(temporary.descriptor, 0o600)
        _write_temporary_report(temporary.descriptor, content)
        _raise_if_sigint_pending(enabled=honor_sigint)
        temporary_stat = os.fstat(temporary.descriptor)
        named_temporary_stat = os.stat(
            _owned_name(temporary),
            dir_fd=parent.descriptor,
            follow_symlinks=False,
        )
        if not _same_private_regular_file(temporary_stat, named_temporary_stat):
            raise OSError("temporary report identity changed")

        stage = "link"
        link_exception: BaseException | None = None
        try:
            _raise_if_sigint_pending(enabled=honor_sigint)
            os.link(
                _owned_name(temporary),
                path.name,
                src_dir_fd=parent.descriptor,
                dst_dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
        except BaseException as exc:
            if not _name_matches_private_file(
                path.name,
                temporary.descriptor,
                parent.descriptor,
            ):
                raise
            link_exception = exc
        stage = "verify"
        final_stat = os.stat(
            path.name,
            dir_fd=parent.descriptor,
            follow_symlinks=False,
        )
        if not _same_private_regular_file(
            temporary_stat, final_stat
        ) or not _directory_path_matches(path.parent, parent_stat):
            raise OutputError("output parent directory changed")
        _raise_if_sigint_pending(enabled=honor_sigint)
        state.committed = True
        if link_exception is not None and not isinstance(link_exception, OSError):
            raise link_exception
    except FileExistsError as exc:
        raise OutputError("output already exists") from exc
    except OutputError:
        raise
    except OSError as exc:
        if stage == "write":
            raise OutputError("report could not be written") from exc
        if stage == "link":
            raise OutputError("final report could not be created") from exc
        raise OutputError("final report could not be verified") from exc


def _cleanup_publication(
    path: Path,
    *,
    parent: _OwnedFile,
    temporary: _OwnedFile,
    committed: bool,
) -> None:
    if not committed:
        _remove_if_same_file(path.name, temporary.descriptor, parent.descriptor)
    if temporary.name is not None:
        _remove_if_open_file(temporary.name, temporary.descriptor, parent.descriptor)
    if temporary.descriptor >= 0:
        with suppress(OSError):
            os.close(temporary.descriptor)
        temporary.descriptor = -1
    if parent.descriptor >= 0:
        with suppress(OSError):
            os.close(parent.descriptor)
        parent.descriptor = -1


def _block_sigint() -> set[int]:
    previous_signal_mask = _current_signal_mask()
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
    except BaseException:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)
        raise
    return previous_signal_mask


def _raise_if_sigint_pending(*, enabled: bool) -> None:
    if enabled and signal.SIGINT in signal.sigpending():
        raise KeyboardInterrupt


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _validate_output_name(name: str) -> None:
    has_control_character = any(ord(character) < 32 or ord(character) == 127 for character in name)
    if not name or name in {".", ".."} or len(name) > 255 or "\\" in name or has_control_character:
        raise OutputError("output filename is unsupported")


def _validate_output_path(path: Path) -> None:
    raw_path = os.fspath(path)
    if any(ord(character) < 32 or ord(character) == 127 for character in raw_path):
        raise OutputError("output path is unsupported")


def _create_private_temporary_file(
    parent_descriptor: int,
    ownership: _OwnedFile,
) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for _ in range(_TEMPORARY_NAME_ATTEMPTS):
        name = f".erpsec-report.{secrets.token_hex(16)}.tmp"
        descriptor = -1
        previous_signal_mask: set[int] | None = None
        collision = False
        creation_error: OSError | None = None
        try:
            previous_signal_mask = _current_signal_mask()
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
            try:
                try:
                    descriptor = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
                except FileExistsError:
                    collision = True
                except OSError as exc:
                    creation_error = exc
                else:
                    ownership.descriptor = descriptor
                    ownership.name = name
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)
        except BaseException as exc:
            try:
                if previous_signal_mask is not None:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)
            finally:
                if descriptor >= 0:
                    try:
                        _remove_if_open_file(name, descriptor, parent_descriptor)
                    finally:
                        with suppress(OSError):
                            os.close(descriptor)
                    if ownership.descriptor == descriptor:
                        ownership.descriptor = -1
                        ownership.name = None
            if isinstance(exc, OSError):
                raise OutputError("temporary report could not be created") from exc
            raise
        if collision:
            continue
        if creation_error is not None:
            raise OutputError("temporary report could not be created") from creation_error
        return
    raise OutputError("temporary report could not be created")


def _write_temporary_report(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("short report write")
        offset += written
    os.fsync(descriptor)


def _acquire_descriptor(ownership: _OwnedFile, operation: Callable[[], int]) -> None:
    descriptor = -1
    previous_signal_mask: set[int] | None = None
    try:
        previous_signal_mask = _current_signal_mask()
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        try:
            descriptor = operation()
            ownership.descriptor = descriptor
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)
    except BaseException:
        try:
            if previous_signal_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)
        finally:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
                if ownership.descriptor == descriptor:
                    ownership.descriptor = -1
        raise


def _current_signal_mask() -> set[int]:
    return {int(member) for member in signal.pthread_sigmask(signal.SIG_BLOCK, set())}


def _owned_name(ownership: _OwnedFile) -> str:
    if ownership.name is None:
        raise OutputError("temporary report could not be created")
    return ownership.name


def _same_private_regular_file(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        stat.S_ISREG(first.st_mode)
        and stat.S_ISREG(second.st_mode)
        and first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and stat.S_IMODE(first.st_mode) == 0o600
        and stat.S_IMODE(second.st_mode) == 0o600
        and first.st_size == second.st_size
    )


def _directory_path_matches(path: Path, expected: os.stat_result) -> bool:
    try:
        current = path.resolve(strict=True).stat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(current.st_mode)
        and current.st_dev == expected.st_dev
        and current.st_ino == expected.st_ino
    )


def _remove_if_same_file(name: str, descriptor: int, parent_descriptor: int) -> bool:
    if not _name_matches_private_file(name, descriptor, parent_descriptor):
        return False
    return _remove_file(name, parent_descriptor)


def _remove_if_open_file(name: str, descriptor: int, parent_descriptor: int) -> bool:
    """Remove a just-created name only when it still identifies its open inode."""
    try:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError:
        return False
    if not (
        stat.S_ISREG(opened.st_mode)
        and stat.S_ISREG(named.st_mode)
        and opened.st_dev == named.st_dev
        and opened.st_ino == named.st_ino
    ):
        return False
    return _remove_file(name, parent_descriptor)


def _name_matches_private_file(name: str, descriptor: int, parent_descriptor: int) -> bool:
    if descriptor < 0 or parent_descriptor < 0:
        return False
    try:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError:
        return False
    return _same_private_regular_file(opened, named)


def _remove_file(name: str, parent_descriptor: int) -> bool:
    """Best-effort bounded descriptor-relative cleanup."""
    for _ in range(2):
        try:
            os.unlink(name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            return True
        except OSError:
            continue
        else:
            return True
    return False
