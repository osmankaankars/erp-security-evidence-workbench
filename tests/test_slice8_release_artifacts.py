"""Release-artifact safety and metadata checks."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts import release_artifacts

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "release_artifacts.py"
WHEEL_POLICY = PROJECT_ROOT / "release" / "wheel-members.txt"
SDIST_POLICY = PROJECT_ROOT / "release" / "sdist-members.txt"
DIST_INFO = "erp_security_evidence_workbench-0.2.0rc1.dist-info"
SDIST_ROOT = "erp_security_evidence_workbench-0.2.0rc1"
WHEEL_NAME = "erp_security_evidence_workbench-0.2.0rc1-py3-none-any.whl"
SECRET_CANARY = "ghp_SYNTHETIC_CREDENTIAL_CANARY_1234567890"
PROJECT_DEV_REQUIREMENTS = (
    'build==1.6.0; extra == "dev"',
    'jsonschema==4.26.0; extra == "dev"',
    'mypy==2.3.1; extra == "dev"',
    'pytest==9.1.1; extra == "dev"',
    'ruff==0.16.5; extra == "dev"',
    'setuptools==84.0.0; extra == "dev"',
    'wheel==0.48.0; extra == "dev"',
)


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
        timeout=30,
    )
    assert completed.returncode == expected_exit, completed.stderr
    return completed


def _initialize_git_repository(
    source: Path,
    files: dict[str, str],
) -> tuple[dict[str, str], str]:
    environment = {
        **os.environ,
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_AUTHOR_NAME": "Release Test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "Release Test",
    }
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(source)],
        check=True,
        capture_output=True,
        env=environment,
    )
    for relative, content in files.items():
        destination = source / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(source), "add", "."],
        check=True,
        capture_output=True,
        env=environment,
    )
    subprocess.run(
        ["git", "-C", str(source), "commit", "-m", "test fixture"],
        check=True,
        capture_output=True,
        env=environment,
    )
    revision = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        env=environment,
        text=True,
    ).stdout.strip()
    return environment, revision


def _zip_member(
    name: str,
    data: bytes,
    *,
    mode: int = 0o644,
    file_type: int = stat.S_IFREG,
) -> tuple[zipfile.ZipInfo, bytes]:
    information = zipfile.ZipInfo(name, date_time=(2026, 9, 2, 0, 0, 0))
    information.create_system = 3
    information.compress_type = zipfile.ZIP_DEFLATED
    information.external_attr = (file_type | mode) << 16
    return information, data


def _write_wheel(
    path: Path,
    members: list[tuple[zipfile.ZipInfo, bytes]],
) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for information, data in members:
            archive.writestr(information, data)


def _write_policy(path: Path, names: list[str]) -> None:
    path.write_text("\n".join(names) + "\n", encoding="utf-8")


def _safe_wheel(path: Path) -> tuple[Path, list[str]]:
    names = ["sample/__init__.py", "sample-1.0.dist-info/METADATA"]
    _write_wheel(
        path,
        [
            _zip_member(names[0], b'__version__ = "1.0"\n'),
            _zip_member(names[1], b"Metadata-Version: 2.4\nName: sample\nVersion: 1.0\n"),
        ],
    )
    return path, names


def _project_wheel(
    path: Path,
    *,
    requires_dist: tuple[str, ...] = (),
    license_expression: str | None = "MIT",
    license_file: str | None = "LICENSE",
    license_content: bytes | None = None,
) -> tuple[Path, list[str]]:
    names = [
        line
        for line in WHEEL_POLICY.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    metadata = b"Metadata-Version: 2.4\nName: erp-security-evidence-workbench\nVersion: 0.2.0rc1\n"
    if license_expression is not None:
        metadata += f"License-Expression: {license_expression}\n".encode()
    if license_file is not None:
        metadata += f"License-File: {license_file}\n".encode()
    for requirement in requires_dist:
        metadata += f"Requires-Dist: {requirement}\n".encode()
    expected_license_content = (
        (PROJECT_ROOT / "LICENSE").read_bytes() if license_content is None else license_content
    )
    _write_wheel(
        path,
        [
            _zip_member(
                name,
                (
                    metadata
                    if name == f"{DIST_INFO}/METADATA"
                    else expected_license_content
                    if name == f"{DIST_INFO}/licenses/LICENSE"
                    else b"safe\n"
                ),
            )
            for name in names
        ],
    )
    return path, names


def test_inspect_accepts_only_the_exact_wheel_policy(tmp_path: Path) -> None:
    wheel, names = _safe_wheel(tmp_path / "sample-1.0-py3-none-any.whl")
    policy = tmp_path / "wheel-members.txt"
    _write_policy(policy, names)

    completed = _run(
        "inspect",
        "--kind",
        "wheel",
        "--archive",
        str(wheel),
        "--policy",
        str(policy),
    )

    result = json.loads(completed.stdout)
    assert result == {
        "archive": wheel.name,
        "archive_kind": "wheel",
        "member_count": 2,
        "red_flags": [],
        "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "status": "accepted",
    }
    assert str(tmp_path) not in completed.stdout


@pytest.mark.parametrize(
    ("file_type", "data", "diagnostic"),
    [
        (stat.S_IFLNK, b"sample/__init__.py", "link red flag"),
        (stat.S_IFIFO, b"", "special-file red flag"),
        (stat.S_IFREG, b"", "special-file red flag"),
        (stat.S_IFDIR, SECRET_CANARY.encode(), "special-file red flag"),
    ],
)
def test_inspect_rejects_trailing_slash_entries_with_inconsistent_zip_metadata(
    tmp_path: Path,
    file_type: int,
    data: bytes,
    diagnostic: str,
) -> None:
    wheel, names = _safe_wheel(tmp_path / "sample-1.0-py3-none-any.whl")
    with zipfile.ZipFile(wheel, "a") as archive:
        information, content = _zip_member(
            "sample/",
            data,
            mode=0o755,
            file_type=file_type,
        )
        archive.writestr(information, content)
    policy = tmp_path / "wheel-members.txt"
    _write_policy(policy, names)

    completed = _run(
        "inspect",
        "--kind",
        "wheel",
        "--archive",
        str(wheel),
        "--policy",
        str(policy),
        expected_exit=2,
    )

    assert diagnostic in completed.stderr
    assert SECRET_CANARY not in completed.stderr
    assert completed.stdout == ""


def test_inspect_accepts_empty_directory_with_consistent_zip_metadata(tmp_path: Path) -> None:
    wheel, names = _safe_wheel(tmp_path / "sample-1.0-py3-none-any.whl")
    with zipfile.ZipFile(wheel, "a") as archive:
        information, data = _zip_member(
            "sample/",
            b"",
            mode=0o755,
            file_type=stat.S_IFDIR,
        )
        archive.writestr(information, data)
    policy = tmp_path / "wheel-members.txt"
    _write_policy(policy, names)

    completed = _run(
        "inspect",
        "--kind",
        "wheel",
        "--archive",
        str(wheel),
        "--policy",
        str(policy),
    )

    assert json.loads(completed.stdout)["status"] == "accepted"


@pytest.mark.parametrize(
    ("unsafe_member", "unsafe_data", "mode", "file_type", "diagnostic"),
    [
        ("../escape.py", b"safe\n", 0o644, stat.S_IFREG, "path traversal red flag"),
        ("/absolute.py", b"safe\n", 0o644, stat.S_IFREG, "absolute path red flag"),
        (
            r"C:\\Users\\operator\\escape.py",
            b"safe\n",
            0o644,
            stat.S_IFREG,
            "absolute path red flag",
        ),
        ("pkg/__pycache__/module.pyc", b"safe\n", 0o644, stat.S_IFREG, "cache red flag"),
        (
            "docs/PRIVATE_GO_NO_GO.md",
            b"safe\n",
            0o644,
            stat.S_IFREG,
            "private document red flag",
        ),
        (
            "docs/CLAIMS_POLICY.md",
            b"safe\n",
            0o644,
            stat.S_IFREG,
            "private document red flag",
        ),
        (
            "docs/PROVENANCE.md",
            b"safe\n",
            0o644,
            stat.S_IFREG,
            "private document red flag",
        ),
        (
            "extra.txt",
            b"workspace = /Users/operator/project\n",
            0o644,
            stat.S_IFREG,
            "local path red flag",
        ),
        ("extra.txt", SECRET_CANARY.encode(), 0o644, stat.S_IFREG, "secret-canary red flag"),
        (
            f"pkg/{SECRET_CANARY}.txt",
            b"safe\n",
            0o644,
            stat.S_IFREG,
            "secret-canary red flag",
        ),
        ("extra.txt", b"safe\n", 0o666, stat.S_IFREG, "unsafe mode red flag"),
        ("extra.txt", b"sample/__init__.py", 0o777, stat.S_IFLNK, "link red flag"),
        ("extra.txt", b"safe\n", 0o644, stat.S_IFREG, "unexpected member red flag"),
    ],
)
def test_inspect_rejects_wheel_red_flags_without_echoing_values(
    tmp_path: Path,
    unsafe_member: str,
    unsafe_data: bytes,
    mode: int,
    file_type: int,
    diagnostic: str,
) -> None:
    wheel, names = _safe_wheel(tmp_path / "sample-1.0-py3-none-any.whl")
    with zipfile.ZipFile(wheel, "a") as archive:
        information, data = _zip_member(
            unsafe_member,
            unsafe_data,
            mode=mode,
            file_type=file_type,
        )
        archive.writestr(information, data)
    policy = tmp_path / "wheel-members.txt"
    _write_policy(policy, names)

    completed = _run(
        "inspect",
        "--kind",
        "wheel",
        "--archive",
        str(wheel),
        "--policy",
        str(policy),
        expected_exit=2,
    )

    assert diagnostic in completed.stderr
    assert SECRET_CANARY not in completed.stderr
    assert SECRET_CANARY not in completed.stdout


def test_inspect_rejects_missing_members_and_tar_links(tmp_path: Path) -> None:
    wheel, names = _safe_wheel(tmp_path / "sample-1.0-py3-none-any.whl")
    wheel_policy = tmp_path / "wheel-members.txt"
    _write_policy(wheel_policy, [*names, "sample/missing.py"])

    missing = _run(
        "inspect",
        "--kind",
        "wheel",
        "--archive",
        str(wheel),
        "--policy",
        str(wheel_policy),
        expected_exit=2,
    )
    assert "missing expected member red flag" in missing.stderr

    sdist = tmp_path / "sample-1.0.tar.gz"
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        regular = tarfile.TarInfo("sample-1.0/file.txt")
        regular.mode = 0o644
        regular.size = 5
        archive.addfile(regular, io.BytesIO(b"safe\n"))
        linked = tarfile.TarInfo("sample-1.0/linked.txt")
        linked.type = tarfile.LNKTYPE
        linked.mode = 0o644
        linked.linkname = "sample-1.0/file.txt"
        archive.addfile(linked)
    sdist_policy = tmp_path / "sdist-members.txt"
    _write_policy(sdist_policy, ["sample-1.0/file.txt"])

    hardlink = _run(
        "inspect",
        "--kind",
        "sdist",
        "--archive",
        str(sdist),
        "--policy",
        str(sdist_policy),
        expected_exit=2,
    )
    assert "link red flag" in hardlink.stderr


def test_spdx_sbom_is_deterministic_for_actual_dependency_free_policy(
    tmp_path: Path,
) -> None:
    wheel, _ = _project_wheel(tmp_path / WHEEL_NAME)
    first = tmp_path / "first.spdx.json"
    second = tmp_path / "second.spdx.json"

    for output in (first, second):
        _run(
            "sbom",
            "--wheel",
            str(wheel),
            "--policy",
            str(WHEEL_POLICY),
            "--output",
            str(output),
            "--source-date-epoch",
            "1788307200",
        )

    assert first.read_bytes() == second.read_bytes()
    document = json.loads(first.read_text(encoding="utf-8"))
    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["dataLicense"] == "CC0-1.0"
    assert document["creationInfo"]["created"] == "2026-09-02T00:00:00Z"
    assert len(document["packages"]) == 1
    package = document["packages"][0]
    assert package["name"] == "erp-security-evidence-workbench"
    assert package["versionInfo"] == "0.2.0rc1"
    assert package["filesAnalyzed"] is False
    assert package["licenseConcluded"] == "NOASSERTION"
    assert package["licenseDeclared"] == "MIT"
    assert "no Requires-Dist entries" in package["comment"]
    assert "private" not in package["comment"].lower()
    assert package["checksums"] == [
        {
            "algorithm": "SHA256",
            "checksumValue": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        }
    ]
    assert document["relationships"] == [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package",
        }
    ]
    assert "DEPENDS_ON" not in first.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("license_expression", "license_file", "license_content"),
    (
        (None, "LICENSE", None),
        ("Apache-2.0", "LICENSE", None),
        ("MIT", None, None),
        ("MIT", "COPYING", None),
        ("MIT", "LICENSE", b"not the project license\n"),
    ),
)
def test_spdx_sbom_rejects_inconsistent_project_license_metadata(
    tmp_path: Path,
    license_expression: str | None,
    license_file: str | None,
    license_content: bytes | None,
) -> None:
    wheel, _ = _project_wheel(
        tmp_path / WHEEL_NAME,
        license_expression=license_expression,
        license_file=license_file,
        license_content=license_content,
    )
    output = tmp_path / "package.spdx.json"

    completed = _run(
        "sbom",
        "--wheel",
        str(wheel),
        "--policy",
        str(WHEEL_POLICY),
        "--output",
        str(output),
        "--source-date-epoch",
        "1788307200",
        expected_exit=2,
    )

    assert "license" in completed.stderr.lower()
    assert not output.exists()


def test_spdx_sbom_models_unconditional_requires_dist_deterministically(
    tmp_path: Path,
) -> None:
    requirement = "sample-runtime>=1"
    wheel, _ = _project_wheel(tmp_path / WHEEL_NAME, requires_dist=(requirement,))
    output = tmp_path / "package.spdx.json"

    _run(
        "sbom",
        "--wheel",
        str(wheel),
        "--policy",
        str(WHEEL_POLICY),
        "--output",
        str(output),
        "--source-date-epoch",
        "1788307200",
    )

    document = json.loads(output.read_text(encoding="utf-8"))
    requirement_id = f"SPDXRef-Requirement-{hashlib.sha256(requirement.encode()).hexdigest()}"
    assert document["packages"][1] == {
        "SPDXID": requirement_id,
        "comment": ("Exact unresolved wheel METADATA Requires-Dist declaration: sample-runtime>=1"),
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "name": "sample-runtime",
        "primaryPackagePurpose": "LIBRARY",
        "supplier": "NOASSERTION",
    }
    assert document["relationships"][1] == {
        "relatedSpdxElement": requirement_id,
        "relationshipType": "DEPENDS_ON",
        "spdxElementId": "SPDXRef-Package",
    }


def test_spdx_sbom_models_actual_optional_dev_requirements_without_calling_them_runtime(
    tmp_path: Path,
) -> None:
    wheel, _ = _project_wheel(tmp_path / WHEEL_NAME, requires_dist=PROJECT_DEV_REQUIREMENTS)
    output = tmp_path / "package.spdx.json"

    _run(
        "sbom",
        "--wheel",
        str(wheel),
        "--policy",
        str(WHEEL_POLICY),
        "--output",
        str(output),
        "--source-date-epoch",
        "1788307200",
    )

    document = json.loads(output.read_text(encoding="utf-8"))
    assert len(document["packages"]) == 1 + len(PROJECT_DEV_REQUIREMENTS)
    dependency_relationships = document["relationships"][1:]
    assert len(dependency_relationships) == len(PROJECT_DEV_REQUIREMENTS)
    assert {relationship["relationshipType"] for relationship in dependency_relationships} == {
        "OPTIONAL_DEPENDENCY_OF"
    }
    assert all(
        relationship["relatedSpdxElement"] == "SPDXRef-Package"
        for relationship in dependency_relationships
    )
    assert "DEPENDS_ON" not in output.read_text(encoding="utf-8")
    rendered_requirements = {
        package["comment"].partition("declaration: ")[2] for package in document["packages"][1:]
    }
    assert rendered_requirements == set(PROJECT_DEV_REQUIREMENTS)


def test_spdx_sbom_rejects_an_unsafe_requires_dist_without_writing_output(
    tmp_path: Path,
) -> None:
    wheel, _ = _project_wheel(tmp_path / WHEEL_NAME, requires_dist=(":invalid",))
    output = tmp_path / "package.spdx.json"

    completed = _run(
        "sbom",
        "--wheel",
        str(wheel),
        "--policy",
        str(WHEEL_POLICY),
        "--output",
        str(output),
        "--source-date-epoch",
        "1788307200",
        expected_exit=2,
    )

    assert "unsupported Requires-Dist entry" in completed.stderr
    assert ":invalid" not in completed.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    "requirement",
    (
        'sample-runtime; extra != "dev"',
        'sample-runtime; extra == "dev" or python_version < "3.12"',
        'sample-runtime; python_version < "3.12"',
    ),
)
def test_spdx_sbom_rejects_markers_it_cannot_classify_exactly(
    tmp_path: Path,
    requirement: str,
) -> None:
    wheel, _ = _project_wheel(tmp_path / WHEEL_NAME, requires_dist=(requirement,))
    output = tmp_path / "package.spdx.json"

    completed = _run(
        "sbom",
        "--wheel",
        str(wheel),
        "--policy",
        str(WHEEL_POLICY),
        "--output",
        str(output),
        "--source-date-epoch",
        "1788307200",
        expected_exit=2,
    )

    assert "unsupported Requires-Dist marker" in completed.stderr
    assert requirement not in completed.stderr
    assert not output.exists()


def test_sdist_reader_streams_without_getmembers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdist = tmp_path / "sample-1.0.tar.gz"
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("sample-1.0/file.txt")
        member.mode = 0o644
        member.size = 5
        archive.addfile(member, io.BytesIO(b"safe\n"))

    def fail_getmembers(_archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
        raise AssertionError("sdist reader must not materialize all member headers")

    monkeypatch.setattr(tarfile.TarFile, "getmembers", fail_getmembers)

    members = release_artifacts._read_sdist(sdist)

    assert [(member.name, member.data) for member in members] == [
        ("sample-1.0/file.txt", b"safe\n")
    ]


def test_wheel_member_count_is_bounded_before_zipfile_materializes_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "sample-1.0-py3-none-any.whl"
    _write_wheel(
        wheel,
        [
            _zip_member("sample/first.py", b"first\n"),
            _zip_member("sample/second.py", b"second\n"),
        ],
    )
    monkeypatch.setattr(release_artifacts, "MAX_MEMBERS", 1)

    def fail_zipfile(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("over-limit central directory must fail before ZipFile construction")

    monkeypatch.setattr(zipfile.ZipFile, "__init__", fail_zipfile)

    with pytest.raises(release_artifacts.ReleaseArtifactError, match="member-count limit"):
        release_artifacts._read_wheel(wheel)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_archive_member_reads_are_chunk_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    monkeypatch.setattr(release_artifacts, "READ_CHUNK_BYTES", 2)
    observed_sizes: list[int] = []
    if kind == "wheel":
        archive_path, _ = _safe_wheel(tmp_path / "sample-1.0-py3-none-any.whl")
        original_read = zipfile.ZipExtFile.read

        def bounded_zip_read(handle: zipfile.ZipExtFile, size: int = -1) -> bytes:
            observed_sizes.append(size)
            assert 0 <= size <= 2
            return original_read(handle, size)

        monkeypatch.setattr(zipfile.ZipExtFile, "read", bounded_zip_read)
        release_artifacts._read_wheel(archive_path)
    else:
        archive_path = tmp_path / "sample-1.0.tar.gz"
        with tarfile.open(archive_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            member = tarfile.TarInfo("sample-1.0/file.txt")
            member.mode = 0o644
            member.size = 5
            archive.addfile(member, io.BytesIO(b"safe\n"))
        original_read = tarfile.ExFileObject.read

        def bounded_tar_read(handle: tarfile.ExFileObject, size: int = -1) -> bytes:
            observed_sizes.append(size)
            assert 0 <= size <= 2
            return original_read(handle, size)

        monkeypatch.setattr(tarfile.ExFileObject, "read", bounded_tar_read)
        release_artifacts._read_sdist(archive_path)

    assert observed_sizes
    assert max(observed_sizes) <= 2


def test_sdist_member_count_limit_stops_before_reading_the_excess_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdist = tmp_path / "sample-1.0.tar.gz"
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name in ("first.txt", "second.txt"):
            member = tarfile.TarInfo(f"sample-1.0/{name}")
            member.mode = 0o644
            member.size = 5
            archive.addfile(member, io.BytesIO(b"safe\n"))
    monkeypatch.setattr(release_artifacts, "MAX_MEMBERS", 1)
    original_extractfile = tarfile.TarFile.extractfile
    extracted: list[str] = []

    def observed_extractfile(
        archive: tarfile.TarFile,
        member: tarfile.TarInfo,
    ) -> tarfile.ExFileObject | None:
        extracted.append(member.name)
        return original_extractfile(archive, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", observed_extractfile)

    with pytest.raises(release_artifacts.ReleaseArtifactError, match="member-count limit"):
        release_artifacts._read_sdist(sdist)

    assert extracted == ["sample-1.0/first.txt"]


def test_sdist_declared_and_total_size_limits_stop_before_excess_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdist = tmp_path / "sample-1.0.tar.gz"
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name in ("first.txt", "second.txt"):
            member = tarfile.TarInfo(f"sample-1.0/{name}")
            member.mode = 0o644
            member.size = 5
            archive.addfile(member, io.BytesIO(b"safe\n"))
    monkeypatch.setattr(release_artifacts, "MAX_MEMBER_BYTES", 5)
    monkeypatch.setattr(release_artifacts, "MAX_TOTAL_MEMBER_BYTES", 7)
    original_extractfile = tarfile.TarFile.extractfile
    extracted: list[str] = []

    def observed_extractfile(
        archive: tarfile.TarFile,
        member: tarfile.TarInfo,
    ) -> tarfile.ExFileObject | None:
        extracted.append(member.name)
        return original_extractfile(archive, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", observed_extractfile)

    with pytest.raises(release_artifacts.ReleaseArtifactError, match="expanded-size limit"):
        release_artifacts._read_sdist(sdist)

    assert extracted == ["sample-1.0/first.txt"]


def test_sdist_declared_member_size_limit_stops_before_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdist = tmp_path / "sample-1.0.tar.gz"
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("sample-1.0/file.txt")
        member.mode = 0o644
        member.size = 5
        archive.addfile(member, io.BytesIO(b"safe\n"))
    monkeypatch.setattr(release_artifacts, "MAX_MEMBER_BYTES", 4)

    def fail_extractfile(
        _archive: tarfile.TarFile,
        _member: tarfile.TarInfo,
    ) -> tarfile.ExFileObject | None:
        raise AssertionError("an over-limit member must not be decompressed")

    monkeypatch.setattr(tarfile.TarFile, "extractfile", fail_extractfile)

    with pytest.raises(release_artifacts.ReleaseArtifactError, match="size limit"):
        release_artifacts._read_sdist(sdist)


def test_bounded_member_reader_rejects_data_beyond_declared_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(release_artifacts, "READ_CHUNK_BYTES", 2)

    with pytest.raises(release_artifacts.ReleaseArtifactError, match="inconsistent size"):
        release_artifacts._read_bounded_member(
            io.BytesIO(b"12345"),
            declared_size=4,
            member_number=1,
        )


def test_bounded_member_reader_rejects_a_negative_declared_size_before_reading() -> None:
    class NoRead:
        def read(self, _size: int = -1) -> bytes:
            raise AssertionError("an invalid declared size must fail before a read")

    with pytest.raises(release_artifacts.ReleaseArtifactError, match="size limit"):
        release_artifacts._read_bounded_member(
            NoRead(),  # type: ignore[arg-type]
            declared_size=-1,
            member_number=1,
        )


def test_sdist_reader_enforces_compressed_input_size_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdist = tmp_path / "sample-1.0.tar.gz"
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("sample-1.0/file.txt")
        member.mode = 0o644
        member.size = 5
        archive.addfile(member, io.BytesIO(b"safe\n"))
    monkeypatch.setattr(release_artifacts, "MAX_ARCHIVE_BYTES", sdist.stat().st_size - 1)

    with pytest.raises(release_artifacts.ReleaseArtifactError, match="file-size limit"):
        release_artifacts._read_sdist(sdist)


def test_release_artifact_script_imports_only_the_standard_library() -> None:
    module = ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))
    imported_roots: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_roots.add(node.module.partition(".")[0])
    assert imported_roots <= sys.stdlib_module_names


def test_sha256sums_is_sorted_reproducible_and_excludes_itself(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "z.whl").write_bytes(b"wheel\n")
    (artifacts / "a.tar.gz").write_bytes(b"sdist\n")
    (artifacts / "package.spdx.json").write_bytes(b"{}\n")
    (artifacts / "SHA256SUMS").write_text("stale\n", encoding="utf-8")

    _run("checksums", "--artifact-dir", str(artifacts))
    first = (artifacts / "SHA256SUMS").read_bytes()
    _run("checksums", "--artifact-dir", str(artifacts))

    assert (artifacts / "SHA256SUMS").read_bytes() == first
    lines = first.decode("utf-8").splitlines()
    assert [line.split("  ", 1)[1] for line in lines] == [
        "a.tar.gz",
        "package.spdx.json",
        "z.whl",
    ]
    for line in lines:
        digest, name = line.split("  ", 1)
        assert digest == hashlib.sha256((artifacts / name).read_bytes()).hexdigest()
    assert "SHA256SUMS" not in lines


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is required for source snapshots")
def test_source_snapshot_rejects_an_unborn_head_without_output(tmp_path: Path) -> None:
    source = tmp_path / "source"
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(source)],
        check=True,
        capture_output=True,
    )
    (source / "private.txt").write_text("must not be inventoried\n", encoding="utf-8")
    output = tmp_path / "source-snapshot.json"

    rejected = _run(
        "source-snapshot",
        "--source-root",
        str(source),
        "--output",
        str(output),
        expected_exit=2,
    )

    assert "resolvable committed HEAD" in rejected.stderr
    assert not output.exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is required for source snapshots")
def test_source_snapshot_rejects_a_non_git_directory_without_output(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "private.txt").write_text("must not be inventoried\n", encoding="utf-8")
    output = tmp_path / "source-snapshot.json"

    rejected = _run(
        "source-snapshot",
        "--source-root",
        str(source),
        "--output",
        str(output),
        expected_exit=2,
    )

    assert "resolvable committed HEAD" in rejected.stderr
    assert not output.exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is required for commit-bound snapshot")
def test_source_snapshot_uses_only_clean_tracked_files_for_a_commit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    environment = {
        **os.environ,
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_AUTHOR_NAME": "Release Test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "Release Test",
    }

    subprocess.run(
        ["git", "init", "--initial-branch=main", str(source)],
        check=True,
        capture_output=True,
        env=environment,
    )
    (source / ".gitignore").write_text(
        "internal.txt\ndocs/PRIVATE_GO_NO_GO.md\n",
        encoding="utf-8",
    )
    (source / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(source), "add", ".gitignore", "tracked.txt"],
        check=True,
        capture_output=True,
        env=environment,
    )
    subprocess.run(
        ["git", "-C", str(source), "commit", "-m", "test fixture"],
        check=True,
        capture_output=True,
        env=environment,
    )
    (source / "internal.txt").write_text("must stay local\n", encoding="utf-8")
    (source / "docs").mkdir()
    (source / "docs" / "PRIVATE_GO_NO_GO.md").write_text(
        "must stay local\n",
        encoding="utf-8",
    )
    output = tmp_path / "source-snapshot.json"

    _run("source-snapshot", "--source-root", str(source), "--output", str(output))

    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert [entry["path"] for entry in manifest["files"]] == [
        ".gitignore",
        "tracked.txt",
    ]
    revision = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert manifest["vcs_revision"] == revision
    tracked_blob = subprocess.run(
        ["git", "-C", str(source), "show", f"{revision}:tracked.txt"],
        check=True,
        capture_output=True,
    ).stdout
    tracked_entry = next(entry for entry in manifest["files"] if entry["path"] == "tracked.txt")
    assert tracked_entry["sha256"] == hashlib.sha256(tracked_blob).hexdigest()
    assert tracked_entry["size"] == len(tracked_blob)
    assert "internal.txt" not in output.read_text(encoding="utf-8")
    assert "PRIVATE_GO_NO_GO" not in output.read_text(encoding="utf-8")

    (source / "tracked.txt").write_text("dirty\n", encoding="utf-8")
    rejected = _run(
        "source-snapshot",
        "--source-root",
        str(source),
        "--output",
        str(tmp_path / "rejected.json"),
        expected_exit=2,
    )
    assert "clean tracked worktree" in rejected.stderr

    subprocess.run(
        ["git", "-C", str(source), "add", "tracked.txt"],
        check=True,
        capture_output=True,
        env=environment,
    )
    staged_output = tmp_path / "staged-rejected.json"
    rejected_staged = _run(
        "source-snapshot",
        "--source-root",
        str(source),
        "--output",
        str(staged_output),
        expected_exit=2,
    )
    assert "clean tracked worktree" in rejected_staged.stderr
    assert not staged_output.exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is required for source snapshots")
def test_source_snapshot_supports_a_clean_linked_worktree(tmp_path: Path) -> None:
    source = tmp_path / "source"
    environment, revision = _initialize_git_repository(
        source,
        {
            ".gitignore": ("docs/CLAIMS_POLICY.md\ndocs/PRIVATE_GO_NO_GO.md\ndocs/PROVENANCE.md\n"),
            "tracked.txt": "tracked\n",
        },
    )
    linked = tmp_path / "linked"
    subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "worktree",
            "add",
            "-b",
            "snapshot-linked",
            str(linked),
        ],
        check=True,
        capture_output=True,
        env=environment,
    )
    (linked / "docs").mkdir()
    for name in ("CLAIMS_POLICY.md", "PRIVATE_GO_NO_GO.md", "PROVENANCE.md"):
        (linked / "docs" / name).write_text("must stay local\n", encoding="utf-8")
    output = tmp_path / "linked-source-snapshot.json"

    _run("source-snapshot", "--source-root", str(linked), "--output", str(output))

    assert (linked / ".git").is_file()
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["vcs_revision"] == revision
    assert [entry["path"] for entry in manifest["files"]] == [
        ".gitignore",
        "tracked.txt",
    ]
    assert "CLAIMS_POLICY" not in output.read_text(encoding="utf-8")
    assert "PRIVATE_GO_NO_GO" not in output.read_text(encoding="utf-8")
    assert "PROVENANCE" not in output.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "private_name",
    ["CLAIMS_POLICY.md", "PRIVATE_GO_NO_GO.md", "PROVENANCE.md"],
)
@pytest.mark.skipif(shutil.which("git") is None, reason="Git is required for source snapshots")
def test_source_snapshot_rejects_a_committed_internal_document(
    tmp_path: Path,
    private_name: str,
) -> None:
    source = tmp_path / "source"
    _initialize_git_repository(
        source,
        {"tracked.txt": "tracked\n", f"docs/{private_name}": "must stay local\n"},
    )
    output = tmp_path / "source-snapshot.json"

    rejected = _run(
        "source-snapshot",
        "--source-root",
        str(source),
        "--output",
        str(output),
        expected_exit=2,
    )

    assert "private document red flag" in rejected.stderr
    assert not output.exists()


@pytest.mark.parametrize("index_flag", ["--assume-unchanged", "--skip-worktree"])
@pytest.mark.skipif(shutil.which("git") is None, reason="Git is required for source snapshots")
def test_source_snapshot_rejects_hidden_index_flags(
    tmp_path: Path,
    index_flag: str,
) -> None:
    source = tmp_path / "source"
    environment, _ = _initialize_git_repository(source, {"tracked.txt": "tracked\n"})
    subprocess.run(
        ["git", "-C", str(source), "update-index", index_flag, "tracked.txt"],
        check=True,
        capture_output=True,
        env=environment,
    )
    (source / "tracked.txt").write_text("hidden mutation\n", encoding="utf-8")
    output = tmp_path / "source-snapshot.json"

    rejected = _run(
        "source-snapshot",
        "--source-root",
        str(source),
        "--output",
        str(output),
        expected_exit=2,
    )

    assert "non-ordinary tracked index entries" in rejected.stderr
    assert not output.exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is required for source snapshots")
def test_source_snapshot_rechecks_for_concurrent_worktree_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _initialize_git_repository(source, {"tracked.txt": "tracked\n"})
    output = tmp_path / "source-snapshot.json"
    original = release_artifacts._committed_snapshot_entries

    def mutate_after_read(
        source_root: Path,
        *,
        revision: str,
    ) -> tuple[dict[str, object], ...]:
        entries = original(source_root, revision=revision)
        (source_root / "tracked.txt").write_text("concurrent mutation\n", encoding="utf-8")
        return entries

    monkeypatch.setattr(release_artifacts, "_committed_snapshot_entries", mutate_after_read)

    with pytest.raises(release_artifacts.ReleaseArtifactError, match="clean tracked worktree"):
        release_artifacts.write_source_snapshot(source, output)
    assert not output.exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is required for source snapshots")
def test_source_snapshot_rejects_a_committed_symbolic_link(tmp_path: Path) -> None:
    source = tmp_path / "source"
    environment, _ = _initialize_git_repository(source, {"target.txt": "target\n"})
    (source / "linked.txt").symlink_to("target.txt")
    subprocess.run(
        ["git", "-C", str(source), "add", "linked.txt"],
        check=True,
        capture_output=True,
        env=environment,
    )
    subprocess.run(
        ["git", "-C", str(source), "commit", "-m", "add symlink"],
        check=True,
        capture_output=True,
        env=environment,
    )
    output = tmp_path / "source-snapshot.json"

    rejected = _run(
        "source-snapshot",
        "--source-root",
        str(source),
        "--output",
        str(output),
        expected_exit=2,
    )

    assert "symlinks, submodules, and special committed entries" in rejected.stderr
    assert not output.exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is required for source snapshots")
def test_source_snapshot_rejects_a_committed_submodule(tmp_path: Path) -> None:
    child = tmp_path / "child"
    environment, _ = _initialize_git_repository(child, {"child.txt": "child\n"})
    source = tmp_path / "source"
    _initialize_git_repository(source, {"tracked.txt": "tracked\n"})
    subprocess.run(
        [
            "git",
            "-c",
            "protocol.file.allow=always",
            "-C",
            str(source),
            "submodule",
            "add",
            str(child),
            "vendor/child",
        ],
        check=True,
        capture_output=True,
        env=environment,
    )
    subprocess.run(
        ["git", "-C", str(source), "commit", "-m", "add submodule"],
        check=True,
        capture_output=True,
        env=environment,
    )
    output = tmp_path / "source-snapshot.json"

    rejected = _run(
        "source-snapshot",
        "--source-root",
        str(source),
        "--output",
        str(output),
        expected_exit=2,
    )

    assert "symlinks, submodules, and special committed entries" in rejected.stderr
    assert not output.exists()


def test_repository_member_policies_are_explicit_and_public_safe() -> None:
    source_members = {
        f"erp_security_evidence_workbench/{path.name}"
        for path in (PROJECT_ROOT / "src" / "erp_security_evidence_workbench").glob("*.py")
    }
    wheel_members = {
        line
        for line in WHEEL_POLICY.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    }
    assert wheel_members == source_members | {
        f"{DIST_INFO}/METADATA",
        f"{DIST_INFO}/RECORD",
        f"{DIST_INFO}/WHEEL",
        f"{DIST_INFO}/entry_points.txt",
        f"{DIST_INFO}/licenses/LICENSE",
        f"{DIST_INFO}/top_level.txt",
    }

    sdist_members = {
        line
        for line in SDIST_POLICY.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    }
    assert {f"{SDIST_ROOT}/src/{member}" for member in source_members} <= sdist_members
    assert {
        f"{SDIST_ROOT}/MANIFEST.in",
        f"{SDIST_ROOT}/LICENSE",
        f"{SDIST_ROOT}/PKG-INFO",
        f"{SDIST_ROOT}/README.md",
        f"{SDIST_ROOT}/THIRD_PARTY_NOTICES.md",
        f"{SDIST_ROOT}/pyproject.toml",
    } <= sdist_members
    rendered = "\n".join(sorted(sdist_members)).lower()
    for forbidden in (
        "/docs/",
        "/tests/",
        "/examples/",
        "private_go_no_go",
        "docs/keystone",
        "__pycache__",
        ".pytest_cache",
        "/users/",
    ):
        assert forbidden not in rendered


def test_manifest_and_notices_keep_the_release_boundary_explicit() -> None:
    manifest = (PROJECT_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    for required in (
        "include LICENSE",
        "include README.md",
        "include pyproject.toml",
        "include THIRD_PARTY_NOTICES.md",
        "recursive-include src/erp_security_evidence_workbench *.py",
        "prune docs",
        "prune tests",
        "prune examples",
        "global-exclude *.py[cod]",
    ):
        assert required in manifest

    notices = (PROJECT_ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8").lower()
    for heading in (
        "runtime dependencies",
        "python standard library and platform",
        "build and development tools",
        "oasis sarif 2.1.0 test schema",
        "project license and public-release status",
    ):
        assert heading in notices
    assert "no third-party runtime dependencies" in notices
    assert "not included in the runtime wheel" in notices
    assert "licensed under the mit license" in notices
    assert "public package publication" in notices
    assert "not legal advice" in notices
    assert "not a vulnerability-clearance" in notices
