"""Filesystem identity and interruption contracts."""

from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from erp_security_evidence_workbench import adapters, reporting
from erp_security_evidence_workbench.errors import InputValidationError, OutputError
from erp_security_evidence_workbench.ingest import load_control_state

SCHEMA = "erpsec.synthetic-control-state/v1"


def _control_bytes(record_id: str, *, enabled: bool = False) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": SCHEMA,
                "dataset_classification": "synthetic",
                "record_type": "control_state",
                "record_id": record_id,
                "control": "AUDIT_LOGGING",
                "enabled": enabled,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _descriptor_is_closed(descriptor: int) -> bool:
    try:
        os.fstat(descriptor)
    except OSError:
        return True
    return False


@pytest.mark.parametrize("module", [adapters, reporting])
def test_interrupted_initial_sigint_block_restores_prior_mask(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
) -> None:
    initial_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    real_sigmask = signal.pthread_sigmask
    injected = False

    def block_then_interrupt(how: int, mask: Any) -> set[signal.Signals | int]:
        nonlocal injected
        previous = real_sigmask(how, mask)
        if how == signal.SIG_BLOCK and signal.SIGINT in mask and not injected:
            injected = True
            raise KeyboardInterrupt
        return previous

    monkeypatch.setattr(module.signal, "pthread_sigmask", block_then_interrupt)

    try:
        with pytest.raises(KeyboardInterrupt):
            module._block_sigint()
        final_signal_mask = real_sigmask(signal.SIG_BLOCK, set())
    finally:
        real_sigmask(signal.SIG_SETMASK, initial_signal_mask)

    assert injected
    assert final_signal_mask == initial_signal_mask


def test_input_final_component_swap_is_refused_without_following_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_path = tmp_path / "victim.json"
    replacement = tmp_path / "replacement.json"
    input_path.write_bytes(_control_bytes("control.original"))
    replacement.write_bytes(_control_bytes("control.replacement", enabled=True))

    real_path_open = Path.open
    real_os_open = os.open
    swapped = False

    def swap_final_component() -> None:
        nonlocal swapped
        if swapped:
            return
        swapped = True
        input_path.unlink()
        input_path.symlink_to(replacement)

    def controlled_path_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == input_path:
            swap_final_component()
        return real_path_open(path, *args, **kwargs)

    def controlled_os_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if dir_fd is not None and os.fsdecode(path) == input_path.name:
            swap_final_component()
        return real_os_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(Path, "open", controlled_path_open)
    monkeypatch.setattr(adapters.os, "open", controlled_os_open)

    with pytest.raises(InputValidationError, match="input could not be read"):
        load_control_state(input_path)

    assert swapped
    assert replacement.read_bytes() == _control_bytes("control.replacement", enabled=True)


def test_input_changed_after_read_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_path = tmp_path / "changing.json"
    original = _control_bytes("control.original")
    replacement = _control_bytes("control.replaced")
    assert len(original) == len(replacement)
    input_path.write_bytes(original)
    initial_mtime_ns = input_path.stat().st_mtime_ns
    real_parse = adapters._parse_open_source

    def parse_then_mutate(*args: Any, **kwargs: Any) -> Any:
        parsed = real_parse(*args, **kwargs)
        input_path.write_bytes(replacement)
        os.utime(
            input_path,
            ns=(input_path.stat().st_atime_ns, initial_mtime_ns + 1_000_000_000),
        )
        return parsed

    monkeypatch.setattr(adapters, "_parse_open_source", parse_then_mutate)

    with pytest.raises(InputValidationError, match="input changed during read"):
        load_control_state(input_path)


def test_sigint_at_owned_input_try_boundary_still_closes_descriptors(
    tmp_path: Path,
) -> None:
    initial_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    if signal.SIGINT in initial_signal_mask:
        pytest.skip("SIGINT is already blocked by the test environment")

    input_path = tmp_path / "input.json"
    input_path.write_bytes(_control_bytes("control.original"))
    previous_trace = sys.gettrace()
    opened_descriptors: list[int] = []
    fired = False

    def interrupt_at_owned_boundary(frame: Any, event: str, argument: Any) -> Any:
        nonlocal fired
        del argument
        if (
            event == "line"
            and not fired
            and frame.f_code is adapters._parse_source_owned.__code__
            and frame.f_lineno == 148
        ):
            parent = frame.f_locals.get("parent")
            source = frame.f_locals.get("source")
            if (
                isinstance(parent, adapters._OwnedDescriptor)
                and isinstance(source, adapters._OwnedDescriptor)
                and parent.descriptor >= 0
                and source.descriptor < 0
            ):
                opened_descriptors.append(parent.descriptor)
                fired = True
                os.kill(os.getpid(), signal.SIGINT)
        return interrupt_at_owned_boundary

    implementation_closed_descriptors = False
    sys.settrace(interrupt_at_owned_boundary)
    try:
        with pytest.raises(KeyboardInterrupt):
            adapters.parse_source(input_path)
        assert opened_descriptors
        implementation_closed_descriptors = all(
            _descriptor_is_closed(descriptor) for descriptor in opened_descriptors
        )
    finally:
        sys.settrace(previous_trace)
        for descriptor in opened_descriptors:
            if not _descriptor_is_closed(descriptor):
                with suppress(OSError):
                    os.close(descriptor)
        final_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        signal.pthread_sigmask(signal.SIG_SETMASK, initial_signal_mask)

    assert fired
    assert implementation_closed_descriptors
    assert final_signal_mask == initial_signal_mask


@pytest.mark.parametrize("acquisition", ["parent", "source"])
def test_sigint_during_input_descriptor_acquisition_closes_owned_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    acquisition: str,
) -> None:
    initial_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    if signal.SIGINT in initial_signal_mask:
        pytest.skip("SIGINT is already blocked by the test environment")

    input_path = tmp_path / "input.json"
    input_path.write_bytes(_control_bytes("control.original"))
    real_open = os.open
    opened_descriptor: int | None = None
    signaled = False

    def open_then_signal(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal opened_descriptor, signaled
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        is_parent = dir_fd is None and bool(flags & getattr(os, "O_DIRECTORY", 0))
        is_source = dir_fd is not None and os.fsdecode(path) == input_path.name
        if not signaled and (
            (acquisition == "parent" and is_parent) or (acquisition == "source" and is_source)
        ):
            opened_descriptor = descriptor
            signaled = True
            os.kill(os.getpid(), signal.SIGINT)
        return descriptor

    monkeypatch.setattr(adapters.os, "open", open_then_signal)

    implementation_closed_descriptor = False
    try:
        with pytest.raises(KeyboardInterrupt):
            adapters.parse_source(input_path)
        assert opened_descriptor is not None
        try:
            os.fstat(opened_descriptor)
        except OSError:
            implementation_closed_descriptor = True
    finally:
        if opened_descriptor is not None and not implementation_closed_descriptor:
            with suppress(OSError):
                os.close(opened_descriptor)
        final_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        signal.pthread_sigmask(signal.SIG_SETMASK, initial_signal_mask)

    assert signaled
    assert implementation_closed_descriptor
    assert final_signal_mask == initial_signal_mask


@pytest.mark.parametrize("operation", ["input", "publication"])
def test_preblocked_sigint_policy_is_preserved_without_synthesized_interrupt(
    tmp_path: Path,
    operation: str,
) -> None:
    path = tmp_path / ("input.json" if operation == "input" else "report.json")
    if operation == "input":
        path.write_bytes(_control_bytes("control.original"))

    project_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(project_root / "src")
    script = """
import os
import signal
import sys
from pathlib import Path

from erp_security_evidence_workbench import adapters, reporting

operation = sys.argv[1]
path = Path(sys.argv[2])
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
os.kill(os.getpid(), signal.SIGINT)
assert signal.SIGINT in signal.sigpending()
if operation == "input":
    parsed = adapters.parse_source(path)
    assert parsed.path == path.name
else:
    reporting.write_new_report(path, b'{"complete":true}\\n')
current_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
assert signal.SIGINT in current_mask
assert signal.SIGINT in signal.sigpending()
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, operation, str(path)],
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    if operation == "publication":
        assert path.read_bytes() == b'{"complete":true}\n'


def test_output_parent_replacement_cannot_publish_forged_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "reports"
    displaced = tmp_path / "reports-displaced"
    parent.mkdir()
    output_path = parent / "report.json"
    trusted_content = b'{"trusted":true}\n'
    forged_content = b'{"trusted":false}\n'
    real_link = os.link
    replaced = False

    def replace_parent_then_link(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        nonlocal replaced
        if not replaced:
            replaced = True
            parent.rename(displaced)
            parent.mkdir()
            forged_temporary = parent / Path(os.fsdecode(source)).name
            forged_temporary.write_bytes(forged_content)
            try:
                real_link(source, destination, *args, **kwargs)
            finally:
                forged_temporary.unlink(missing_ok=True)
            return
        real_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(reporting.os, "link", replace_parent_then_link)

    with pytest.raises(OutputError, match="output parent directory changed"):
        reporting.write_new_report(output_path, trusted_content)

    assert replaced
    assert not output_path.exists()
    assert not (displaced / output_path.name).exists()
    assert list(displaced.glob(".erpsec-report.*.tmp")) == []


@pytest.mark.parametrize("failure_point", ["fsync", "link"])
def test_precommit_keyboard_interrupt_removes_private_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    output_path = tmp_path / "report.json"

    def interrupt(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise KeyboardInterrupt

    monkeypatch.setattr(reporting.os, failure_point, interrupt)

    with pytest.raises(KeyboardInterrupt):
        reporting.write_new_report(output_path, b'{"complete":true}\n')

    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


def test_sigint_at_owned_publication_try_boundary_cleans_private_state(
    tmp_path: Path,
) -> None:
    initial_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    if signal.SIGINT in initial_signal_mask:
        pytest.skip("SIGINT is already blocked by the test environment")

    output_path = tmp_path / "report.json"
    previous_trace = sys.gettrace()
    opened_descriptors: list[int] = []
    fired = False

    def interrupt_at_owned_boundary(frame: Any, event: str, argument: Any) -> Any:
        nonlocal fired
        del argument
        if (
            event == "line"
            and not fired
            and frame.f_code is reporting._publish_new_report.__code__
            and frame.f_lineno == 348
        ):
            parent = frame.f_locals.get("parent")
            temporary = frame.f_locals.get("temporary")
            if (
                isinstance(parent, reporting._OwnedFile)
                and isinstance(temporary, reporting._OwnedFile)
                and parent.descriptor >= 0
                and temporary.descriptor >= 0
            ):
                opened_descriptors.extend((parent.descriptor, temporary.descriptor))
                fired = True
                os.kill(os.getpid(), signal.SIGINT)
        return interrupt_at_owned_boundary

    implementation_closed_descriptors = False
    implementation_removed_names = False
    sys.settrace(interrupt_at_owned_boundary)
    try:
        with pytest.raises(KeyboardInterrupt):
            reporting.write_new_report(output_path, b'{"complete":true}\n')
        assert opened_descriptors
        implementation_closed_descriptors = all(
            _descriptor_is_closed(descriptor) for descriptor in opened_descriptors
        )
        implementation_removed_names = (
            not output_path.exists() and list(tmp_path.glob(".erpsec-report.*.tmp")) == []
        )
    finally:
        sys.settrace(previous_trace)
        for descriptor in opened_descriptors:
            if not _descriptor_is_closed(descriptor):
                with suppress(OSError):
                    os.close(descriptor)
        for residual in tmp_path.glob(".erpsec-report.*.tmp"):
            residual.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)
        final_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        signal.pthread_sigmask(signal.SIG_SETMASK, initial_signal_mask)

    assert fired
    assert implementation_closed_descriptors
    assert implementation_removed_names
    assert final_signal_mask == initial_signal_mask


def test_sigint_during_normal_publication_cleanup_finishes_cleanup_first(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    if signal.SIGINT in initial_signal_mask:
        pytest.skip("SIGINT is already blocked by the test environment")

    output_path = tmp_path / "report.json"
    content = b'{"complete":true}\n'
    real_open = os.open
    real_remove = reporting._remove_if_open_file
    opened_descriptors: list[int] = []
    fired = False

    def record_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        opened_descriptors.append(descriptor)
        return descriptor

    def signal_then_remove(name: str, descriptor: int, parent_descriptor: int) -> bool:
        nonlocal fired
        if not fired:
            fired = True
            os.kill(os.getpid(), signal.SIGINT)
        return real_remove(name, descriptor, parent_descriptor)

    monkeypatch.setattr(reporting.os, "open", record_open)
    monkeypatch.setattr(reporting, "_remove_if_open_file", signal_then_remove)

    implementation_closed_descriptors = False
    implementation_removed_temporary = False
    try:
        with pytest.raises(KeyboardInterrupt):
            reporting.write_new_report(output_path, content)
        implementation_closed_descriptors = all(
            _descriptor_is_closed(descriptor) for descriptor in opened_descriptors
        )
        implementation_removed_temporary = list(tmp_path.glob(".erpsec-report.*.tmp")) == []
    finally:
        for descriptor in opened_descriptors:
            if not _descriptor_is_closed(descriptor):
                with suppress(OSError):
                    os.close(descriptor)
        for residual in tmp_path.glob(".erpsec-report.*.tmp"):
            residual.unlink(missing_ok=True)
        final_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        signal.pthread_sigmask(signal.SIG_SETMASK, initial_signal_mask)

    assert fired
    assert output_path.read_bytes() == content
    assert implementation_closed_descriptors
    assert implementation_removed_temporary
    assert final_signal_mask == initial_signal_mask


@pytest.mark.parametrize("exception", [OSError("late failure"), KeyboardInterrupt()])
def test_completed_link_is_reconciled_without_invalidating_published_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exception: BaseException,
) -> None:
    output_path = tmp_path / "report.json"
    content = b'{"complete":true}\n'
    real_link = os.link

    def link_then_raise(*args: Any, **kwargs: Any) -> None:
        real_link(*args, **kwargs)
        raise exception

    monkeypatch.setattr(reporting.os, "link", link_then_raise)

    if isinstance(exception, KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            reporting.write_new_report(output_path, content)
    else:
        reporting.write_new_report(output_path, content)

    assert output_path.read_bytes() == content
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


def test_interrupt_immediately_after_link_return_removes_unverified_final(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "report.json"
    content = b'{"complete":true}\n'
    previous_trace = sys.gettrace()

    def interrupt_after_link_return(frame: Any, event: str, argument: Any) -> Any:
        del argument
        if (
            event == "line"
            and frame.f_code is reporting._publish_new_report.__code__
            and frame.f_locals.get("stage") == "link"
            and isinstance(frame.f_locals.get("state"), reporting._PublicationState)
            and frame.f_locals["state"].committed is False
            and output_path.exists()
        ):
            raise KeyboardInterrupt
        return interrupt_after_link_return

    sys.settrace(interrupt_after_link_return)
    try:
        with pytest.raises(KeyboardInterrupt):
            reporting.write_new_report(output_path, content)
    finally:
        sys.settrace(previous_trace)

    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


def test_interrupt_after_temporary_open_before_helper_return_cleans_up(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "report.json"
    previous_trace = sys.gettrace()
    initial_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

    def interrupt_after_temporary_open(frame: Any, event: str, argument: Any) -> Any:
        del argument
        if (
            event == "line"
            and frame.f_code is reporting._create_private_temporary_file.__code__
            and frame.f_locals.get("descriptor", -1) >= 0
        ):
            raise KeyboardInterrupt
        return interrupt_after_temporary_open

    sys.settrace(interrupt_after_temporary_open)
    try:
        with pytest.raises(KeyboardInterrupt):
            reporting.write_new_report(output_path, b'{"complete":true}\n')
    finally:
        sys.settrace(previous_trace)
        final_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        signal.pthread_sigmask(signal.SIG_SETMASK, initial_signal_mask)

    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []
    assert final_signal_mask == initial_signal_mask


def test_sigint_during_temporary_open_is_deferred_until_descriptor_is_owned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    if signal.SIGINT in initial_signal_mask:
        pytest.skip("SIGINT is already blocked by the test environment")

    output_path = tmp_path / "report.json"
    real_open = os.open
    opened_descriptor: int | None = None

    def open_then_signal(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal opened_descriptor
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if dir_fd is not None and os.fsdecode(path).startswith(".erpsec-report."):
            opened_descriptor = descriptor
            os.kill(os.getpid(), signal.SIGINT)
        return descriptor

    monkeypatch.setattr(reporting.os, "open", open_then_signal)

    implementation_closed_descriptor = False
    try:
        with pytest.raises(KeyboardInterrupt):
            reporting.write_new_report(output_path, b'{"complete":true}\n')
        assert opened_descriptor is not None
        try:
            os.fstat(opened_descriptor)
        except OSError:
            implementation_closed_descriptor = True
    finally:
        if opened_descriptor is not None and not implementation_closed_descriptor:
            with suppress(OSError):
                os.close(opened_descriptor)
        final_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        signal.pthread_sigmask(signal.SIG_SETMASK, initial_signal_mask)

    assert opened_descriptor is not None
    assert implementation_closed_descriptor
    assert final_signal_mask == initial_signal_mask
    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


def test_sigint_during_parent_open_closes_owned_directory_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    if signal.SIGINT in initial_signal_mask:
        pytest.skip("SIGINT is already blocked by the test environment")

    output_path = tmp_path / "report.json"
    real_open = os.open
    opened_descriptor: int | None = None

    def open_then_signal(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal opened_descriptor
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if dir_fd is None and flags & getattr(os, "O_DIRECTORY", 0):
            opened_descriptor = descriptor
            os.kill(os.getpid(), signal.SIGINT)
        return descriptor

    monkeypatch.setattr(reporting.os, "open", open_then_signal)

    implementation_closed_descriptor = False
    try:
        with pytest.raises(KeyboardInterrupt):
            reporting.write_new_report(output_path, b'{"complete":true}\n')
        assert opened_descriptor is not None
        try:
            os.fstat(opened_descriptor)
        except OSError:
            implementation_closed_descriptor = True
    finally:
        if opened_descriptor is not None and not implementation_closed_descriptor:
            with suppress(OSError):
                os.close(opened_descriptor)
        final_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        signal.pthread_sigmask(signal.SIG_SETMASK, initial_signal_mask)

    assert implementation_closed_descriptor
    assert final_signal_mask == initial_signal_mask
    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


def test_sigint_during_descriptor_write_cleans_owned_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    if signal.SIGINT in initial_signal_mask:
        pytest.skip("SIGINT is already blocked by the test environment")

    output_path = tmp_path / "report.json"
    real_write = os.write
    opened_descriptor: int | None = None
    signaled = False

    def write_then_signal(descriptor: int, content: bytes) -> int:
        nonlocal opened_descriptor, signaled
        written = real_write(descriptor, content)
        if not signaled:
            opened_descriptor = descriptor
            signaled = True
            os.kill(os.getpid(), signal.SIGINT)
        return written

    monkeypatch.setattr(reporting.os, "write", write_then_signal)

    implementation_closed_descriptor = False
    try:
        with pytest.raises(KeyboardInterrupt):
            reporting.write_new_report(output_path, b'{"complete":true}\n')
        assert opened_descriptor is not None
        try:
            os.fstat(opened_descriptor)
        except OSError:
            implementation_closed_descriptor = True
    finally:
        if opened_descriptor is not None and not implementation_closed_descriptor:
            with suppress(OSError):
                os.close(opened_descriptor)
        final_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        signal.pthread_sigmask(signal.SIG_SETMASK, initial_signal_mask)

    assert implementation_closed_descriptor
    assert final_signal_mask == initial_signal_mask
    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


def test_sigint_before_fchmod_cleans_temporary_with_narrower_umask_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    if signal.SIGINT in initial_signal_mask:
        pytest.skip("SIGINT is already blocked by the test environment")

    output_path = tmp_path / "report.json"
    real_open = os.open
    real_fchmod = os.fchmod
    opened_descriptor: int | None = None

    def record_temporary_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal opened_descriptor
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if dir_fd is not None and os.fsdecode(path).startswith(".erpsec-report."):
            opened_descriptor = descriptor
        return descriptor

    def signal_before_fchmod(descriptor: int, mode: int) -> None:
        os.kill(os.getpid(), signal.SIGINT)
        real_fchmod(descriptor, mode)

    monkeypatch.setattr(reporting.os, "open", record_temporary_open)
    monkeypatch.setattr(reporting.os, "fchmod", signal_before_fchmod)

    implementation_closed_descriptor = False
    previous_umask = os.umask(0o777)
    try:
        with pytest.raises(KeyboardInterrupt):
            reporting.write_new_report(output_path, b'{"complete":true}\n')
        assert opened_descriptor is not None
        try:
            os.fstat(opened_descriptor)
        except OSError:
            implementation_closed_descriptor = True
    finally:
        os.umask(previous_umask)
        if opened_descriptor is not None and not implementation_closed_descriptor:
            with suppress(OSError):
                os.close(opened_descriptor)
        final_signal_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        signal.pthread_sigmask(signal.SIG_SETMASK, initial_signal_mask)

    assert implementation_closed_descriptor
    assert final_signal_mask == initial_signal_mask
    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


def test_file_exists_during_mask_restoration_is_not_treated_as_name_collision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_path = tmp_path / "report.json"
    real_open = os.open
    real_sigmask = signal.pthread_sigmask
    opened_descriptor: int | None = None
    temporary_opened = False
    injected = False
    initial_signal_mask = real_sigmask(signal.SIG_BLOCK, set())

    def record_temporary_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal opened_descriptor, temporary_opened
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if dir_fd is not None and os.fsdecode(path).startswith(".erpsec-report."):
            opened_descriptor = descriptor
            temporary_opened = True
        return descriptor

    def fail_first_temporary_restore(how: int, mask: Any) -> set[signal.Signals | int]:
        nonlocal injected
        if temporary_opened and how == signal.SIG_SETMASK and not injected:
            injected = True
            raise FileExistsError("injected restoration failure")
        return real_sigmask(how, mask)

    monkeypatch.setattr(reporting.os, "open", record_temporary_open)
    monkeypatch.setattr(reporting.signal, "pthread_sigmask", fail_first_temporary_restore)

    implementation_closed_descriptor = False
    try:
        with pytest.raises(OutputError, match="temporary report could not be created"):
            reporting.write_new_report(output_path, b'{"complete":true}\n')
        assert opened_descriptor is not None
        try:
            os.fstat(opened_descriptor)
        except OSError:
            implementation_closed_descriptor = True
    finally:
        if opened_descriptor is not None and not implementation_closed_descriptor:
            with suppress(OSError):
                os.close(opened_descriptor)
        final_signal_mask = real_sigmask(signal.SIG_BLOCK, set())
        real_sigmask(signal.SIG_SETMASK, initial_signal_mask)

    assert injected
    assert implementation_closed_descriptor
    assert final_signal_mask == initial_signal_mask
    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []


def test_successful_report_mode_is_exactly_private_under_restrictive_umask(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "report.json"
    previous_umask = os.umask(0o777)
    try:
        reporting.write_new_report(output_path, b'{"complete":true}\n')
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600


def test_output_filename_with_control_character_is_rejected(tmp_path: Path) -> None:
    output_path = tmp_path / "report\x00.json"

    with pytest.raises(OutputError, match="output filename is unsupported"):
        reporting.write_new_report(output_path, b'{"complete":true}\n')

    assert list(tmp_path.iterdir()) == []


def test_output_parent_with_nul_character_is_rejected(tmp_path: Path) -> None:
    output_path = tmp_path / "invalid\x00parent" / "report.json"

    with pytest.raises(OutputError, match="output path is unsupported"):
        reporting.write_new_report(output_path, b'{"complete":true}\n')

    assert list(tmp_path.iterdir()) == []


def test_cli_maps_control_character_output_name_to_expected_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from erp_security_evidence_workbench import cli

    input_path = tmp_path / "input.json"
    input_path.write_bytes(_control_bytes("control.original"))
    output_path = tmp_path / "report\x00.json"

    exit_code = cli.main(
        [
            "analyze",
            str(input_path),
            "--as-of",
            "2026-09-01T00:00:00Z",
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 2
    assert capsys.readouterr().err == "error: output filename is unsupported\n"


def test_cli_maps_nul_in_output_parent_to_expected_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from erp_security_evidence_workbench import cli

    input_path = tmp_path / "input.json"
    input_path.write_bytes(_control_bytes("control.original"))
    output_path = tmp_path / "invalid\x00parent" / "report.json"

    exit_code = cli.main(
        [
            "analyze",
            str(input_path),
            "--as-of",
            "2026-09-01T00:00:00Z",
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 2
    assert capsys.readouterr().err == "error: output path is unsupported\n"


def test_input_parent_with_nul_character_is_rejected(tmp_path: Path) -> None:
    input_path = tmp_path / "invalid\x00parent" / "input.json"

    with pytest.raises(InputValidationError, match="input path is unsupported"):
        adapters.parse_source(input_path)

    assert list(tmp_path.iterdir()) == []


def test_cli_maps_nul_in_input_parent_to_expected_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from erp_security_evidence_workbench import cli

    input_path = tmp_path / "invalid\x00parent" / "input.json"
    output_path = tmp_path / "report.json"

    exit_code = cli.main(
        [
            "analyze",
            str(input_path),
            "--as-of",
            "2026-09-01T00:00:00Z",
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 2
    assert capsys.readouterr().err == "error: input path is unsupported\n"
    assert not output_path.exists()


def test_input_filename_with_path_separator_lookalike_is_rejected_as_validation_error(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "synthetic\\evidence.json"
    input_path.write_bytes(_control_bytes("control.original"))

    with pytest.raises(InputValidationError, match="input filename is unsupported"):
        load_control_state(input_path)


def test_symlinked_output_parent_is_resolved_once_and_supported(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-reports"
    alias_parent = tmp_path / "reports-alias"
    real_parent.mkdir()
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    output_path = alias_parent / "report.json"
    content = b'{"complete":true}\n'

    reporting.write_new_report(output_path, content)

    assert output_path.read_bytes() == content
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600


def test_world_writable_non_sticky_output_parent_is_rejected(tmp_path: Path) -> None:
    output_parent = tmp_path / "unsafe-reports"
    output_parent.mkdir()
    output_parent.chmod(0o777)

    with pytest.raises(OutputError, match="output parent directory permissions are unsafe"):
        reporting.write_new_report(output_parent / "report.json", b'{"complete":true}\n')

    assert list(output_parent.iterdir()) == []


def test_group_writable_non_sticky_output_parent_is_rejected_before_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_parent = tmp_path / "shared-reports"
    output_parent.mkdir()
    output_parent.chmod(0o770)

    def unexpected_stage(*args: object, **kwargs: object) -> tuple[int, str]:
        del args, kwargs
        pytest.fail("unsafe output parent must be rejected before staging")

    monkeypatch.setattr(reporting, "_create_private_temporary_file", unexpected_stage)

    with pytest.raises(OutputError, match="output parent directory permissions are unsafe"):
        reporting.write_new_report(output_parent / "report.json", b'{"complete":true}\n')

    assert list(output_parent.iterdir()) == []


def test_cleanup_does_not_unlink_a_replaced_temporary_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_path = tmp_path / "report.json"
    forged_content = b'{"unrelated":true}\n'
    real_fsync = os.fsync
    replaced_name: Path | None = None

    def replace_name_then_fail(descriptor: int) -> None:
        nonlocal replaced_name
        real_fsync(descriptor)
        staged = list(tmp_path.glob(".erpsec-report.*.tmp"))
        assert len(staged) == 1
        replaced_name = staged[0]
        replaced_name.unlink()
        replaced_name.write_bytes(forged_content)
        raise OSError("simulated post-write failure")

    monkeypatch.setattr(reporting.os, "fsync", replace_name_then_fail)

    with pytest.raises(OutputError, match="report could not be written"):
        reporting.write_new_report(output_path, b'{"complete":true}\n')

    assert not output_path.exists()
    assert replaced_name is not None
    assert replaced_name.read_bytes() == forged_content


def test_world_writable_sticky_output_parent_is_supported(tmp_path: Path) -> None:
    output_parent = tmp_path / "sticky-reports"
    output_parent.mkdir()
    output_parent.chmod(0o1777)
    output_path = output_parent / "report.json"

    reporting.write_new_report(output_path, b'{"complete":true}\n')

    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600


def test_renderer_interrupt_still_creates_no_publication_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "report.json"
    input_path.write_bytes(_control_bytes("control.original"))

    from erp_security_evidence_workbench import cli

    def interrupt_renderer(*args: object, **kwargs: object) -> bytes:
        del args, kwargs
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "build_report", interrupt_renderer)

    argv = [
        "analyze",
        str(input_path),
        "--as-of",
        "2026-09-01T00:00:00Z",
        "--format",
        "json",
        "--output",
        str(output_path),
    ]
    with pytest.raises(KeyboardInterrupt):
        cli.main(argv)

    assert not output_path.exists()
    assert list(tmp_path.glob(".erpsec-report.*.tmp")) == []
