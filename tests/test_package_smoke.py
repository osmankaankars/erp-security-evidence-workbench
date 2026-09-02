from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts import package_smoke


def test_child_timeout_is_bounded_and_safely_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_timeout: float | None = None

    def time_out(
        command: object,
        *,
        cwd: Path,
        env: dict[str, str],
        capture_output: bool,
        check: bool,
        text: bool,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        del cwd, env, capture_output, check, text
        nonlocal observed_timeout
        observed_timeout = timeout
        raise subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr(package_smoke.subprocess, "run", time_out)

    with pytest.raises(RuntimeError, match="60-second verification limit"):
        package_smoke._run(
            ["verification-child"],
            cwd=tmp_path,
            environment={},
        )

    assert observed_timeout == package_smoke.COMMAND_TIMEOUT_SECONDS


def test_clean_environment_removes_ambient_python_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYTHONPATH", "/untrusted/path")
    monkeypatch.setenv("PythonWarnings", "error")
    monkeypatch.setenv("PYTHONHASHSEED", "random")

    environment = package_smoke._clean_environment()

    assert environment["PYTHONNOUSERSITE"] == "1"
    assert all(
        not key.upper().startswith("PYTHON") or key == "PYTHONNOUSERSITE" for key in environment
    )
