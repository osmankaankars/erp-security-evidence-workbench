"""Reproducible release-candidate build checks."""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts import build_release

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "build_release.py"
RELEASE_SCRIPT = PROJECT_ROOT / "scripts" / "release_artifacts.py"
WHEEL_NAME = "erp_security_evidence_workbench-0.2.0rc1-py3-none-any.whl"
SDIST_NAME = "erp_security_evidence_workbench-0.2.0rc1.tar.gz"


def _run(*arguments: str, expected_exit: int = 0) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=120,
    )
    assert completed.returncode == expected_exit, completed.stderr
    return completed


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_release(*arguments: str) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        [sys.executable, str(RELEASE_SCRIPT), *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    return completed


def test_two_rc_builds_are_byte_identical(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"

    _run("build", "--output", str(first), "--source-date-epoch", "1788307200")
    _run("build", "--output", str(second), "--source-date-epoch", "1788307200")

    expected_names = {WHEEL_NAME, SDIST_NAME, "build-manifest.json"}
    assert {path.name for path in first.iterdir()} == expected_names
    assert {path.name for path in second.iterdir()} == expected_names
    assert {name: _sha256(first / name) for name in expected_names} == {
        name: _sha256(second / name) for name in expected_names
    }

    manifest = json.loads((first / "build-manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "erpsec.build-manifest/v1"
    assert manifest["package"] == {
        "distribution": "erp-security-evidence-workbench",
        "version": "0.2.0rc1",
    }
    assert manifest["source"]["vcs_revision"] is None
    assert manifest["source"]["vcs_state"] == "unavailable"
    expected_source_entries = []
    for relative in sorted(
        (
            *build_release.BUILD_FILES,
            *(
                path.relative_to(PROJECT_ROOT).as_posix()
                for path in build_release.PACKAGE_ROOT.rglob("*.py")
            ),
        )
    ):
        content = (PROJECT_ROOT / relative).read_bytes()
        expected_source_entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    assert manifest["source"]["files"] == expected_source_entries
    source_commitment = json.dumps(
        expected_source_entries,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    assert manifest["source"]["tree_sha256"] == hashlib.sha256(source_commitment).hexdigest()
    assert manifest["source_date_epoch"] == 1788307200
    assert manifest["build_environment"] == {
        "implementation": "CPython",
        "machine": platform.machine(),
        "operating_system": platform.system(),
        "operating_system_release": platform.release(),
        "python": platform.python_version(),
        "tools": {
            "build": "1.6.0",
            "setuptools": "84.0.0",
            "wheel": "0.48.0",
        },
    }
    assert manifest["artifacts"] == [
        {
            "filename": SDIST_NAME,
            "sha256": _sha256(first / SDIST_NAME),
            "size": (first / SDIST_NAME).stat().st_size,
        },
        {
            "filename": WHEEL_NAME,
            "sha256": _sha256(first / WHEEL_NAME),
            "size": (first / WHEEL_NAME).stat().st_size,
        },
    ]
    assert "/Users/" not in (first / "build-manifest.json").read_text(encoding="utf-8")

    with zipfile.ZipFile(first / WHEEL_NAME) as wheel:
        assert wheel.infolist()
        metadata = wheel.read("erp_security_evidence_workbench-0.2.0rc1.dist-info/METADATA").decode(
            "utf-8"
        )
        assert "License-Expression: MIT\n" in metadata
        assert "License-File: LICENSE\n" in metadata
        assert (
            wheel.read("erp_security_evidence_workbench-0.2.0rc1.dist-info/licenses/LICENSE")
            == (PROJECT_ROOT / "LICENSE").read_bytes()
        )
        for member in wheel.infolist():
            encoded_mode = member.external_attr >> 16
            assert stat.S_IFMT(encoded_mode) == stat.S_IFREG
            assert stat.S_IMODE(encoded_mode) == 0o644

    with tarfile.open(first / SDIST_NAME, "r:gz") as sdist:
        assert sdist.getmembers()
        license_member = sdist.extractfile("erp_security_evidence_workbench-0.2.0rc1/LICENSE")
        assert license_member is not None
        assert license_member.read() == (PROJECT_ROOT / "LICENSE").read_bytes()
        for member in sdist.getmembers():
            assert member.uid == member.gid == 0
            assert member.uname == member.gname == ""
            assert member.mtime == 1788307200
            assert member.mode == (0o755 if member.isdir() else 0o644)
            assert member.isdir() or member.isfile()

    for kind, archive_name, policy_name in (
        ("wheel", WHEEL_NAME, "wheel-members.txt"),
        ("sdist", SDIST_NAME, "sdist-members.txt"),
    ):
        inspected = _run_release(
            "inspect",
            "--kind",
            kind,
            "--archive",
            str(first / archive_name),
            "--policy",
            str(PROJECT_ROOT / "release" / policy_name),
        )
        inspection = json.loads(inspected.stdout)
        assert inspection["status"] == "accepted"
        assert inspection["red_flags"] == []


def test_build_refuses_a_non_empty_or_symlink_output(tmp_path: Path) -> None:
    non_empty = tmp_path / "non-empty"
    non_empty.mkdir()
    (non_empty / "keep.txt").write_text("keep", encoding="utf-8")
    symlink = tmp_path / "linked-output"
    symlink.symlink_to(non_empty, target_is_directory=True)

    non_empty_result = _run("build", "--output", str(non_empty), expected_exit=2)
    symlink_result = _run("build", "--output", str(symlink), expected_exit=2)

    assert "output directory must be new or empty" in non_empty_result.stderr
    assert "symbolic link" in symlink_result.stderr
    assert (non_empty / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_build_environment_ignores_contaminated_parent_pythonpath(tmp_path: Path) -> None:
    fake_distribution = tmp_path / "fake-site" / "build-999.0.dist-info"
    fake_distribution.mkdir(parents=True)
    (fake_distribution / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: build\nVersion: 999.0\n",
        encoding="ascii",
    )
    output = tmp_path / "output"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(fake_distribution.parent)

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "build",
            "--output",
            str(output),
            "--source-date-epoch",
            "1788307200",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=120,
    )

    assert completed.returncode == 0, completed.stderr
    manifest = json.loads((output / "build-manifest.json").read_text(encoding="ascii"))
    assert manifest["build_environment"]["tools"]["build"] == "1.6.0"


def test_source_commitment_preserves_file_boundaries() -> None:
    first_contents = (("a", b"X"), ("b", b"Y\0b\0Z"))
    second_contents = (("a", b"X\0b\0Y"), ("b", b"Z"))

    def legacy_commitment(items: tuple[tuple[str, bytes], ...]) -> str:
        digest = hashlib.sha256()
        for name, content in items:
            digest.update(name.encode("utf-8"))
            digest.update(b"\0")
            digest.update(content)
            digest.update(b"\0")
        return digest.hexdigest()

    def canonical_entries(
        items: tuple[tuple[str, bytes], ...],
    ) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "path": name,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
            for name, content in items
        )

    assert legacy_commitment(first_contents) == legacy_commitment(second_contents)
    assert build_release._source_tree_digest(
        canonical_entries(first_contents)
    ) != build_release._source_tree_digest(canonical_entries(second_contents))


def test_publication_failure_removes_owned_partial_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "output"
    original_write = build_release._write_exclusive_at
    calls = 0

    def fail_second_write(directory_descriptor: int, name: str, content: bytes) -> tuple[int, int]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected publication failure")
        return original_write(directory_descriptor, name, content)

    monkeypatch.setattr(build_release, "_write_exclusive_at", fail_second_write)

    with pytest.raises(build_release.BuildError):
        build_release._publish_release_bundle(output, {"a.txt": b"a", "b.txt": b"b"})

    assert not output.exists() or list(output.iterdir()) == []


def test_publication_detects_output_directory_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "output"
    moved = tmp_path / "moved"
    original_write = build_release._write_exclusive_at
    calls = 0

    def replace_after_first_write(
        directory_descriptor: int, name: str, content: bytes
    ) -> tuple[int, int]:
        nonlocal calls
        calls += 1
        identity = original_write(directory_descriptor, name, content)
        if calls == 1:
            output.rename(moved)
            output.mkdir()
        return identity

    monkeypatch.setattr(build_release, "_write_exclusive_at", replace_after_first_write)

    with pytest.raises(build_release.BuildError):
        build_release._publish_release_bundle(output, {"a.txt": b"a", "b.txt": b"b"})

    assert list(output.iterdir()) == []
    assert list(moved.iterdir()) == []


@pytest.mark.parametrize("name", (".", "./a", "a/./b", "a//b", "a/"))
def test_archive_normalizer_rejects_noncanonical_aliases(name: str) -> None:
    assert not build_release._safe_archive_name(name)


@pytest.mark.parametrize("name", (".", "./a", "a/./b", "a//b", "a/"))
def test_wheel_normalizer_rejects_noncanonical_aliases(tmp_path: Path, name: str) -> None:
    wheel = tmp_path / "candidate.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(name, b"content")

    with pytest.raises(build_release.BuildError, match="unsafe or duplicate path"):
        build_release._normalize_wheel(wheel, 1788307200)


@pytest.mark.parametrize("name", (".", "./a", "a/./b", "a//b", "a/"))
def test_sdist_normalizer_rejects_noncanonical_aliases(tmp_path: Path, name: str) -> None:
    sdist = tmp_path / "candidate.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        member = tarfile.TarInfo(name)
        member.size = len(b"content")
        archive.addfile(member, io.BytesIO(b"content"))

    with pytest.raises(build_release.BuildError, match="unsafe or duplicate path"):
        build_release._normalize_source_distribution(sdist, 1788307200)
